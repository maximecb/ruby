use crate::cruby::*;
use crate::asm::*;
use crate::asm::x86_64::*;
use crate::core::*;
use crate::options::*;
use crate::stats::*;
use InsnOpnd::*;
use CodegenStatus::*;

use std::cell::{RefCell, RefMut};
use std::rc::Rc;
use std::mem::size_of;
use std::os::raw::{c_uint};

// Callee-saved registers
pub const REG_CFP: X86Opnd = R13;
pub const REG_EC: X86Opnd = R12;
pub const REG_SP: X86Opnd = RBX;

// Scratch registers used by YJIT
pub const REG0: X86Opnd = RAX;
pub const REG0_32: X86Opnd = EAX;
pub const REG0_8: X86Opnd = AL;
pub const REG1: X86Opnd = RCX;
pub const REG1_32: X86Opnd = ECX;

/// Status returned by code generation functions
#[derive(PartialEq)]
enum CodegenStatus {
    EndBlock,
    KeepCompiling,
    CantCompile,
}

/// Code generation function signature
type CodeGenFn = fn(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus;

/// Code generation state
/// This struct only lives while code is being generated
pub struct JITState
{
    // Block version being compiled
    block: BlockRef,

    // Instruction sequence this is associated with
    iseq: IseqPtr,

    // Index of the current instruction being compiled
    insn_idx: u32,

    // Opcode for the instruction being compiled
    opcode: usize,

    // PC of the instruction being compiled
    pc: *mut VALUE,

    // Side exit to the instruction being compiled. See :side-exit:.
    side_exit_for_pc: Option<CodePtr>,

    // Execution context when compilation started
    // This allows us to peek at run-time values
    ec: Option<EcPtr>,

    // Whether we need to record the code address at
    // the end of this bytecode instruction for global invalidation
    record_boundary_patch_point: bool,
}

impl JITState {
    pub fn new(blockref: &BlockRef) -> Self {
        use std::ptr;

        JITState {
            block: blockref.clone(),
            iseq: ptr::null(), // TODO: initialize this from the blockid
            insn_idx: 0,
            opcode: 0,
            pc: ptr::null_mut::<VALUE>(),
            side_exit_for_pc: None,
            ec: None,
            record_boundary_patch_point: false,
        }
    }

    pub fn get_iseq(self:&JITState) -> IseqPtr {
        self.iseq
    }

    pub fn get_opcode(self:&JITState) -> usize {
        self.opcode
    }

    pub fn set_opcode(self:&mut JITState, opcode: usize) {
        self.opcode = opcode;
    }

    pub fn add_gc_object_offset(self:&mut JITState, ptr_offset:u32) {
        let mut gc_obj_vec: RefMut<_> = self.block.borrow_mut();
        gc_obj_vec.add_gc_object_offset(ptr_offset);
    }

    pub fn get_pc(self:&JITState) -> *mut VALUE {
        self.pc
    }

    pub fn set_pc(self:&mut JITState, pc: *mut VALUE) {
        self.pc = pc;
    }
}

pub fn jit_get_arg(jit: &JITState, arg_idx: isize) -> VALUE
{
    // insn_len require non-test config
    #[cfg(not(test))]
    assert!(insn_len(jit.get_opcode()) > (arg_idx + 1).try_into().unwrap());
    unsafe { *(jit.pc.offset(arg_idx + 1)) }
}

// Load a VALUE into a register and keep track of the reference if it is on the GC heap.
pub fn jit_mov_gc_ptr(jit:&mut JITState, cb: &mut CodeBlock, reg:X86Opnd, ptr: VALUE)
{
    assert!( matches!(reg, X86Opnd::Reg(x)) );
    assert!( reg.num_bits() == 64 );

    // Load the pointer constant into the specified register
    let VALUE(ptr_value) = ptr;
    //mov(cb, reg, const_ptr_opnd(ptr_value as *const u8));  // TODO(noah): when uimm_opnd works with mov() properly, change back to this
    mov(cb, reg, imm_opnd(ptr_value as i64));

    // The pointer immediate is encoded as the last part of the mov written out
    let ptr_offset:u32 = (cb.get_write_pos() as u32) - (SIZEOF_VALUE as u32);

    if !ptr.special_const_p() {
        jit.add_gc_object_offset(ptr_offset);
    }
}

/*
// Print the current source location for debugging purposes
RBIMPL_ATTR_MAYBE_UNUSED()
static void
jit_print_loc(jitstate_t *jit, const char *msg)
{
    char *ptr;
    long len;
    VALUE path = rb_iseq_path(jit->iseq);
    RSTRING_GETMEM(path, ptr, len);
    fprintf(stderr, "%s %.*s:%u\n", msg, (int)len, ptr, rb_iseq_line_no(jit->iseq, jit->insn_idx));
}

// dump an object for debugging purposes
RBIMPL_ATTR_MAYBE_UNUSED()
static void
jit_obj_info_dump(codeblock_t *cb, x86opnd_t opnd) {
    push_regs(cb);
    mov(cb, C_ARG_REGS[0], opnd);
    call_ptr(cb, REG0, (void *)rb_obj_info_dump);
    pop_regs(cb);
}
*/
// Get the index of the next instruction
fn jit_next_insn_idx(jit: &JITState) -> u32
{
    jit.insn_idx + insn_len(jit.get_opcode())
}

// Check if we are compiling the instruction at the stub PC
// Meaning we are compiling the instruction that is next to execute
fn jit_at_current_insn(jit: &JITState) -> bool
{
    let ec_pc:*mut VALUE = unsafe { cfp_get_pc(ec_get_cfp(jit.ec.unwrap())) };
    ec_pc == jit.pc
}

// Peek at the nth topmost value on the Ruby stack.
// Returns the topmost value when n == 0.
fn jit_peek_at_stack(jit: &JITState, ctx: &Context, n:isize) -> VALUE
{
    assert!(jit_at_current_insn(jit));

    // Note: this does not account for ctx->sp_offset because
    // this is only available when hitting a stub, and while
    // hitting a stub, cfp->sp needs to be up to date in case
    // codegen functions trigger GC. See :stub-sp-flush:.
    return unsafe {
        let sp:*mut VALUE = cfp_get_sp(ec_get_cfp(jit.ec.unwrap()));

        *(sp.offset(-1 - n))
    }
}

/*
fn jit_peek_at_self(jit: &JITState, ctx: &Context) -> VALUE
{
    unsafe { cfp_get_self(ec_get_cfp(jit.ec.unwrap())) }
}

fn jit_peek_at_local(jit: &JITState, ctx: &Context, n: i32) -> VALUE
{
    assert!(jit_at_current_insn(jit));

    let local_table_size:isize = unsafe { get_iseq_body_local_table_size(jit.iseq) }.try_into().unwrap();
    assert!(n < local_table_size.try_into().unwrap());

    unsafe {
        let ep = cfp_get_ep(ec_get_cfp(jit.ec.unwrap()));
        let n_isize:isize = n.try_into().unwrap();
        let offs:isize = -(VM_ENV_DATA_SIZE as isize) - local_table_size + n_isize + 1;
        * ep.offset(offs)
    }
}
*/



// Add a comment at the current position in the code block
fn add_comment(cb: &mut CodeBlock, comment_str: &str)
{
    #[cfg(feature = "asm_comments")]
    {
        /*
        // We can't add comments to the outlined code block
        if (cb == ocb)
            return;

        // Avoid adding duplicate comment strings (can happen due to deferred codegen)
        size_t num_comments = rb_darray_size(yjit_code_comments);
        if (num_comments > 0) {
            struct yjit_comment last_comment = rb_darray_get(yjit_code_comments, num_comments - 1);
            if (last_comment.offset == cb->write_pos && strcmp(last_comment.comment, comment_str) == 0) {
                return;
            }
        }

        struct yjit_comment new_comment = (struct yjit_comment){ cb->write_pos, comment_str };
        rb_darray_append(&yjit_code_comments, new_comment);
        */
    }
}

/// Increment a profiling counter with counter_name
#[cfg(not(feature = "stats"))]
macro_rules! gen_counter_incr {
    ($cb:tt, $counter_name:ident) => {}
}
#[cfg(feature = "stats")]
macro_rules! gen_counter_incr {
    ($cb:tt, $counter_name:ident) => {
        if (get_option!(gen_stats)) {
            let ptr = ptr_to_counter!(counter_name);

            // Use REG1 because there might be return value in REG0
            mov(cb, REG1, const_ptr_opnd(ptr));
            cb_write_lock_prefix(cb); // for ractors.
            add(cb, mem_opnd(64, REG1, 0), imm_opnd(1));
        }
    };
}

/// Increment a counter then take an existing side exit
#[cfg(not(feature = "stats"))]
macro_rules! counted_exit {
    ($ocb:tt, $existing_side_exit:tt, $counter_name:ident) => {
        $existing_side_exit
    }
}
#[cfg(feature = "stats")]
macro_rules! counted_exit {
    ($ocb:tt, $existing_side_exit:tt, $counter_name:ident) => {
        // The counter is only incremented when stats are enabled
        if (!get_option!(gen_stats)) {
            $existing_side_exit
        }
        else
        {
            let code_ptr = ocb.get_write_ptr();

            // Increment the counter
            gen_counter_incr!(ocb, $counter_name);

            // Jump to the existing side exit
            jmp_ptr(cb, existing_side_exit);

            // Pointer to the side-exit code
            code_ptr
        }
    };
}






// Save the incremented PC on the CFP
// This is necessary when callees can raise or allocate
fn jit_save_pc(jit: &JITState, cb: &mut CodeBlock, scratch_reg: X86Opnd)
{
    let pc: *mut VALUE = jit.get_pc();
    let ptr: *mut VALUE = unsafe {
        let cur_insn_len = insn_len(jit.get_opcode()) as isize;
        pc.offset(cur_insn_len)
    };
    mov(cb, scratch_reg, const_ptr_opnd(ptr as *const u8));
    mov(cb, mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_PC), scratch_reg);
}

// Save the current SP on the CFP
// This realigns the interpreter SP with the JIT SP
// Note: this will change the current value of REG_SP,
//       which could invalidate memory operands
fn gen_save_sp(cb: &mut CodeBlock, ctx: &mut Context)
{
    if ctx.get_sp_offset() != 0 {
        let stack_pointer = ctx.sp_opnd(0);
        lea(cb, REG_SP, stack_pointer);
        let cfp_sp_opnd = mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_SP);
        mov(cb, cfp_sp_opnd, REG_SP);
        ctx.set_sp_offset(0);
    }
}

// jit_save_pc() + gen_save_sp(). Should be used before calling a routine that
// could:
//  - Perform GC allocation
//  - Take the VM lock through RB_VM_LOCK_ENTER()
//  - Perform Ruby method call
fn jit_prepare_routine_call(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, scratch_reg: X86Opnd)
{
    jit.record_boundary_patch_point = true;
    jit_save_pc(jit, cb, scratch_reg);
    gen_save_sp(cb, ctx);
}
/*
// Record the current codeblock write position for rewriting into a jump into
// the outlined block later. Used to implement global code invalidation.
static void
record_global_inval_patch(const codeblock_t *cb, uint32_t outline_block_target_pos)
{
    struct codepage_patch patch_point = { cb->write_pos, outline_block_target_pos };
    if (!rb_darray_append(&global_inval_patches, patch_point)) rb_bug("allocation failed");
}
*/






/*
// Verify the ctx's types and mappings against the compile-time stack, self,
// and locals.
static void
verify_ctx(jitstate_t *jit, ctx_t *ctx)
{
    // Only able to check types when at current insn
    RUBY_ASSERT(jit_at_current_insn(jit));

    VALUE self_val = jit_peek_at_self(jit, ctx);
    if (type_diff(yjit_type_of_value(self_val), ctx->self_type) == INT_MAX) {
        rb_bug("verify_ctx: ctx type (%s) incompatible with actual value of self: %s", yjit_type_name(ctx->self_type), rb_obj_info(self_val));
    }

    for (int i = 0; i < ctx->stack_size && i < MAX_TEMP_TYPES; i++) {
        temp_type_mapping_t learned = ctx.get_opnd_mapping(StackOpnd(i));
        VALUE val = jit_peek_at_stack(jit, ctx, i);
        val_type_t detected = yjit_type_of_value(val);

        if (learned.mapping.kind == TEMP_SELF) {
            if (self_val != val) {
                rb_bug("verify_ctx: stack value was mapped to self, but values did not match\n"
                        "  stack: %s\n"
                        "  self: %s",
                        rb_obj_info(val),
                        rb_obj_info(self_val));
            }
        }

        if (learned.mapping.kind == TEMP_LOCAL) {
            int local_idx = learned.mapping.idx;
            VALUE local_val = jit_peek_at_local(jit, ctx, local_idx);
            if (local_val != val) {
                rb_bug("verify_ctx: stack value was mapped to local, but values did not match\n"
                        "  stack: %s\n"
                        "  local %i: %s",
                        rb_obj_info(val),
                        local_idx,
                        rb_obj_info(local_val));
            }
        }

        if (type_diff(detected, learned.type) == INT_MAX) {
            rb_bug("verify_ctx: ctx type (%s) incompatible with actual value on stack: %s", yjit_type_name(learned.type), rb_obj_info(val));
        }
    }

    int32_t local_table_size = jit->iseq->body->local_table_size;
    for (int i = 0; i < local_table_size && i < MAX_TEMP_TYPES; i++) {
        val_type_t learned = ctx->local_types[i];
        VALUE val = jit_peek_at_local(jit, ctx, i);
        val_type_t detected = yjit_type_of_value(val);

        if (type_diff(detected, learned) == INT_MAX) {
            rb_bug("verify_ctx: ctx type (%s) incompatible with actual value of local: %s", yjit_type_name(learned), rb_obj_info(val));
        }
    }
}
*/

// Generate an exit to return to the interpreter
fn gen_exit(exit_pc: *mut VALUE, ctx: &Context, cb: &mut CodeBlock) -> CodePtr
{
    let code_ptr = cb.get_write_ptr();

    add_comment(cb, "exit to interpreter");

    // Generate the code to exit to the interpreters
    // Write the adjusted SP back into the CFP
    if ctx.get_sp_offset() != 0 {
        let stack_pointer = ctx.sp_opnd(0);
        lea(cb, REG_SP, stack_pointer);
        mov(cb, mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_SP), REG_SP);
    }

    // Update CFP->PC
    //mov(cb, RAX, const_ptr_opnd(exit_pc as *const u8));
    mov(cb, mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_PC), RAX);

    // Accumulate stats about interpreter exits
    #[cfg(feature = "stats")]
    if get_option!(gen_stats) {
        mov(cb, RDI, const_ptr_opnd(exit_pc));
        call_ptr(cb, RSI, CodePtr(yjit_count_side_exit_op));
    }

    pop(cb, REG_SP);
    pop(cb, REG_EC);
    pop(cb, REG_CFP);

    mov(cb, RAX, uimm_opnd(Qundef.into()));
    ret(cb);

    return code_ptr;
}

// Fill code_for_exit_from_stub. This is used by branch_stub_hit() to exit
// to the interpreter when it cannot service a stub by generating new code.
// Before coming here, branch_stub_hit() takes care of fully reconstructing
// interpreter state.
fn gen_code_for_exit_from_stub(ocb: &mut OutlinedCb) -> CodePtr
{
    let ocb = ocb.unwrap();
    let code_ptr = ocb.get_write_ptr();

    gen_counter_incr!(cb, exit_from_branch_stub);

    pop(ocb, REG_SP);
    pop(ocb, REG_EC);
    pop(ocb, REG_CFP);

    mov(ocb, RAX, uimm_opnd(Qundef.into()));
    ret(ocb);

    return code_ptr;
}

// :side-exit:
// Get an exit for the current instruction in the outlined block. The code
// for each instruction often begins with several guards before proceeding
// to do work. When guards fail, an option we have is to exit to the
// interpreter at an instruction boundary. The piece of code that takes
// care of reconstructing interpreter state and exiting out of generated
// code is called the side exit.
//
// No guards change the logic for reconstructing interpreter state at the
// moment, so there is one unique side exit for each context. Note that
// it's incorrect to jump to the side exit after any ctx stack push/pop operations
// since they change the logic required for reconstructing interpreter state.
fn get_side_exit(jit: &mut JITState, ocb: &mut OutlinedCb, ctx: &Context) -> CodePtr
{
    match jit.side_exit_for_pc {
        None => {
            let exit_code = gen_exit(jit.pc, ctx, ocb.unwrap());
            jit.side_exit_for_pc = Some(exit_code);
            exit_code
        },
        Some(code_ptr) => code_ptr
    }
}

/*
// Ensure that there is an exit for the start of the block being compiled.
// Block invalidation uses this exit.
static void
jit_ensure_block_entry_exit(jitstate_t *jit)
{
    block_t *block = jit->block;
    if (block->entry_exit) return;

    if (jit->insn_idx == block->blockid.idx) {
        // We are compiling the first instruction in the block.
        // Generate the exit with the cache in jitstate.
        block->entry_exit = get_side_exit(jit, &block->ctx);
    }
    else {
        VALUE *pc = yjit_iseq_pc_at_idx(block->blockid.iseq, block->blockid.idx);
        uint32_t pos = gen_exit(pc, &block->ctx, ocb);
        block->entry_exit = cb_get_ptr(ocb, pos);
    }
}
*/

// Generate a runtime guard that ensures the PC is at the start of the iseq,
// otherwise take a side exit.  This is to handle the situation of optional
// parameters.  When a function with optional parameters is called, the entry
// PC for the method isn't necessarily 0, but we always generated code that
// assumes the entry point is 0.
fn gen_pc_guard(cb: &mut CodeBlock, iseq: IseqPtr)
{
    todo!();

    /*
    RUBY_ASSERT(cb != NULL);

    mov(cb, REG0, member_opnd(REG_CFP, rb_control_frame_t, pc));
    mov(cb, REG1, const_ptr_opnd(iseq->body->iseq_encoded));
    xor(cb, REG0, REG1);

    // xor should impact ZF, so we can jz here
    uint32_t pc_is_zero = cb_new_label(cb, "pc_is_zero");
    jz_label(cb, pc_is_zero);

    // We're not starting at the first PC, so we need to exit.
    gen_counter_incr!(cb, leave_start_pc_non_zero);

    pop(cb, REG_SP);
    pop(cb, REG_EC);
    pop(cb, REG_CFP);

    mov(cb, RAX, imm_opnd(Qundef));
    ret(cb);

    // PC should be at the beginning
    cb_write_label(cb, pc_is_zero);
    cb_link_labels(cb);
    */
}

/*
// The code we generate in gen_send_cfunc() doesn't fire the c_return TracePoint event
// like the interpreter. When tracing for c_return is enabled, we patch the code after
// the C method return to call into this to fire the event.
static void
full_cfunc_return(rb_execution_context_t *ec, VALUE return_value)
{
    rb_control_frame_t *cfp = ec->cfp;
    RUBY_ASSERT_ALWAYS(cfp == GET_EC()->cfp);
    const rb_callable_method_entry_t *me = rb_vm_frame_method_entry(cfp);

    RUBY_ASSERT_ALWAYS(RUBYVM_CFUNC_FRAME_P(cfp));
    RUBY_ASSERT_ALWAYS(me->def->type == VM_METHOD_TYPE_CFUNC);

    // CHECK_CFP_CONSISTENCY("full_cfunc_return"); TODO revive this

    // Pop the C func's frame and fire the c_return TracePoint event
    // Note that this is the same order as vm_call_cfunc_with_frame().
    rb_vm_pop_frame(ec);
    EXEC_EVENT_HOOK(ec, RUBY_EVENT_C_RETURN, cfp->self, me->def->original_id, me->called_id, me->owner, return_value);
    // Note, this deviates from the interpreter in that users need to enable
    // a c_return TracePoint for this DTrace hook to work. A reasonable change
    // since the Ruby return event works this way as well.
    RUBY_DTRACE_CMETHOD_RETURN_HOOK(ec, me->owner, me->def->original_id);

    // Push return value into the caller's stack. We know that it's a frame that
    // uses cfp->sp because we are patching a call done with gen_send_cfunc().
    ec->cfp->sp[0] = return_value;
    ec->cfp->sp++;
}

// Landing code for when c_return tracing is enabled. See full_cfunc_return().
static void
gen_full_cfunc_return(void)
{
    codeblock_t *cb = ocb;
    outline_full_cfunc_return_pos = ocb->write_pos;

    // This chunk of code expect REG_EC to be filled properly and
    // RAX to contain the return value of the C method.

    // Call full_cfunc_return()
    mov(cb, C_ARG_REGS[0], REG_EC);
    mov(cb, C_ARG_REGS[1], RAX);
    call_ptr(cb, REG0, (void *)full_cfunc_return);

    // Count the exit
    gen_counter_incr!(cb, traced_cfunc_return);

    // Return to the interpreter
    pop(cb, REG_SP);
    pop(cb, REG_EC);
    pop(cb, REG_CFP);

    mov(cb, RAX, imm_opnd(Qundef));
    ret(cb);
}
*/




/// Generate a continuation for leave that exits to the interpreter at REG_CFP->pc.
/// This is used by gen_leave() and gen_entry_prologue()
fn gen_leave_exit(ocb: &mut OutlinedCb) -> CodePtr
{
    let ocb = ocb.unwrap();
    let code_ptr = ocb.get_write_ptr();

    // Note, gen_leave() fully reconstructs interpreter state and leaves the
    // return value in RAX before coming here.

    // Every exit to the interpreter should be counted
    gen_counter_incr!(ocb, leave_interp_return);

    pop(ocb, REG_SP);
    pop(ocb, REG_EC);
    pop(ocb, REG_CFP);

    ret(ocb);

    return code_ptr;
}

/// Compile an interpreter entry block to be inserted into an iseq
/// Returns None if compilation fails.
pub fn gen_entry_prologue(cb: &mut CodeBlock, iseq: IseqPtr) -> Option<CodePtr>
{
    const MAX_PROLOGUE_SIZE: usize = 1024;

    // Check if we have enough executable memory
    if !cb.has_capacity(MAX_PROLOGUE_SIZE) {
        return None;
    }

    let old_write_pos = cb.get_write_pos();

    // Align the current write position to cache line boundaries
    cb.align_pos(64);

    let code_ptr = cb.get_write_ptr();
    add_comment(cb, "yjit entry");

    push(cb, REG_CFP);
    push(cb, REG_EC);
    push(cb, REG_SP);

    // We are passed EC and CFP
    mov(cb, REG_EC, C_ARG_REGS[0]);
    mov(cb, REG_CFP, C_ARG_REGS[1]);

    // Load the current SP from the CFP into REG_SP
    mov(cb, REG_SP, mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_SP));

    // Setup cfp->jit_return
    mov(cb, REG0, code_ptr_opnd(CodegenGlobals::get_leave_exit_code()));
    mov(cb, mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_JIT_RETURN), REG0);

    // We're compiling iseqs that we *expect* to start at `insn_idx`. But in
    // the case of optional parameters, the interpreter can set the pc to a
    // different location depending on the optional parameters.  If an iseq
    // has optional parameters, we'll add a runtime check that the PC we've
    // compiled for is the same PC that the interpreter wants us to run with.
    // If they don't match, then we'll take a side exit.
    //if get_iseq_flags_has_opt(iseq) != 0 {
    //    gen_pc_guard(cb, iseq);
    //}

    // Verify MAX_PROLOGUE_SIZE
    assert!(cb.get_write_pos() - old_write_pos <= MAX_PROLOGUE_SIZE);

    return Some(code_ptr);
}

// Generate code to check for interrupts and take a side-exit.
// Warning: this function clobbers REG0
fn gen_check_ints(cb: &mut CodeBlock, side_exit: CodePtr)
{
    // Check for interrupts
    // see RUBY_VM_CHECK_INTS(ec) macro
    add_comment(cb, "RUBY_VM_CHECK_INTS(ec)");
    mov(cb, REG0_32, mem_opnd(32, REG_EC, RUBY_OFFSET_EC_INTERRUPT_MASK));
    not(cb, REG0_32);
    test(cb, mem_opnd(32, REG_EC, RUBY_OFFSET_EC_INTERRUPT_FLAG), REG0_32);
    jnz_ptr(cb, side_exit);
}

/*
// Generate a stubbed unconditional jump to the next bytecode instruction.
// Blocks that are part of a guard chain can use this to share the same successor.
static void
jit_jump_to_next_insn(jitstate_t *jit, const ctx_t *current_context)
{
    // Reset the depth since in current usages we only ever jump to to
    // chain_depth > 0 from the same instruction.
    ctx_t reset_depth = *current_context;
    reset_depth.chain_depth = 0;

    blockid_t jump_block = { jit->iseq, jit_next_insn_idx(jit) };

    // We are at the end of the current instruction. Record the boundary.
    if (jit->record_boundary_patch_point) {
        uint32_t exit_pos = gen_exit(jit->pc + insn_len(jit->opcode), &reset_depth, jit->ocb);
        record_global_inval_patch(jit->cb, exit_pos);
        jit->record_boundary_patch_point = false;
    }

    // Generate the jump instruction
    gen_direct_jump(
        jit,
        &reset_depth,
        jump_block
    );
}
*/

// Compile a sequence of bytecode instructions for a given basic block version.
// Part of gen_block_version().
// Note: this function will mutate its context while generating code,
//       but the input start_ctx argument should remain immutable.
pub fn gen_single_block(blockref: &BlockRef, ec: EcPtr, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> Result<(), ()>
{
    let mut block = blockref.borrow_mut();
    let blockid = block.get_blockid();
    //verify_blockid(blockid);

    assert!(!(blockid.idx == 0 && block.get_ctx().get_stack_size() > 0));

    let iseq = blockid.iseq;
    let iseq_size = unsafe { get_iseq_encoded_size(iseq) };
    let mut insn_idx: c_uint = blockid.idx;
    let starting_insn_idx = insn_idx;
    let mut ctx = Context::new();

    // Initialize a JIT state object
    let mut jit = JITState::new(blockref);
    jit.iseq = blockid.iseq;
    jit.ec = Some(ec);

    // Mark the start position of the block
    block.set_start_addr(cb.get_write_ptr());

    // For each instruction to compile
    // NOTE: could rewrite this loop with a std::iter::Iterator
    while insn_idx < iseq_size {
        // Get the current pc and opcode
        let pc = unsafe { rb_iseq_pc_at_idx(iseq, insn_idx) };
        // try_into() call below is unfortunate. Maybe pick i32 instead of usize for opcodes.
        let opcode: usize = unsafe { rb_iseq_opcode_at_pc(iseq, pc) }.try_into().unwrap();

        // opt_getinlinecache wants to be in a block all on its own. Cut the block short
        // if we run into it. See gen_opt_getinlinecache() for details.
        if opcode == OP_OPT_GETINLINECACHE && insn_idx > starting_insn_idx {
            todo!();
            /*
            jit_jump_to_next_insn(&jit, ctx);
            break;
            */
        }

        // Set the current instruction
        jit.insn_idx = insn_idx;
        jit.opcode = opcode.try_into().unwrap();
        jit.pc = pc;
        jit.side_exit_for_pc = None;

        // If previous instruction requested to record the boundary
        if jit.record_boundary_patch_point {
            todo!();
            /*
            // Generate an exit to this instruction and record it
            uint32_t exit_pos = gen_exit(jit.pc, ctx, ocb);
            record_global_inval_patch(cb, exit_pos);
            jit.record_boundary_patch_point = false;
            */
        }

        // Verify our existing assumption (DEBUG)
        //if (jit_at_current_insn(&jit)) {
        //    verify_ctx(&jit, ctx);
        //}

        // Lookup the codegen function for this instruction
        let mut status = CantCompile;
        if let Some(gen_fn) = get_gen_fn(VALUE(opcode)) {
            // :count-placement:
            // Count bytecode instructions that execute in generated code.
            // Note that the increment happens even when the output takes side exit.
            gen_counter_incr!(cb, exec_instruction);

            // Add a comment for the name of the YARV instruction
            // TODO: missing insn_name()
            // add_comment(cb, insn_name(opcode));

            // Call the code generation function
            status = gen_fn(&mut jit, &mut ctx, cb, ocb);
        }

        // If we can't compile this instruction
        // exit to the interpreter and stop compiling
        if status == CantCompile {
            // TODO: if the codegen function makes changes to ctx and then return YJIT_CANT_COMPILE,
            // the exit this generates would be wrong. We could save a copy of the entry context
            // and assert that ctx is the same here.
            let exit = gen_exit(jit.pc, &ctx, cb);

            // If this is the first instruction in the block, then we can use
            // the exit for block->entry_exit.
            if insn_idx == block.get_blockid().idx {
                block.entry_exit = Some(exit);
            }
            break;
        }

        // For now, reset the chain depth after each instruction as only the
        // first instruction in the block can concern itself with the depth.
        ctx.reset_chain_depth();

        // Move to the next instruction to compile
        insn_idx += insn_len(opcode);

        // If the instruction terminates this block
        if status == EndBlock {
            break;
        }
    }

    // Mark the end position of the block
    block.set_end_addr(cb.get_write_ptr());

    // Store the index of the last instruction in the block
    block.set_end_idx(insn_idx);

    // We currently can't handle cases where the request is for a block that
    // doesn't go to the next instruction.
    assert!(!jit.record_boundary_patch_point);

    // If code for the block doesn't fit, free the block and fail.
    if cb.has_dropped_bytes() || ocb.unwrap().has_dropped_bytes() {

        // TODO: do we need to call drop on the block?
        // TODO: do we need to free assumptions/invariants?
        //yjit_free_block(block);

        return Err(());
    }

    // TODO: we may want a feature for this called dump_insns? Can leave commented for now
    /*
    if (YJIT_DUMP_MODE >= 2) {
        // Dump list of compiled instrutions
        fprintf(stderr, "Compiled the following for iseq=%p:\n", (void *)iseq);
        for (uint32_t idx = block->blockid.idx; idx < insn_idx; ) {
            int opcode = yjit_opcode_at_pc(iseq, yjit_iseq_pc_at_idx(iseq, idx));
            fprintf(stderr, "  %04d %s\n", idx, insn_name(opcode));
            idx += insn_len(opcode);
        }
    }
    */

    // Block compiled successfully
    Ok(())
}

fn gen_nop(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Do nothing
    KeepCompiling
}

fn gen_pop(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Decrement SP
    ctx.stack_pop(1);
    KeepCompiling
}

fn gen_dup(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let dup_val = ctx.stack_pop(0);
    let (mapping, tmp_type) = ctx.get_opnd_mapping(StackOpnd(0));

    let loc0 = ctx.stack_push_mapping((mapping, tmp_type));
    mov(cb, REG0, dup_val);
    mov(cb, loc0, REG0);

    KeepCompiling
}

// duplicate stack top n elements
fn gen_dupn(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let nval:VALUE = jit_get_arg(jit, 0);
    let VALUE(n) = nval;

    // In practice, seems to be only used for n==2
    if n != 2 {
        return CantCompile
    }

    let opnd1:X86Opnd = ctx.stack_opnd(1);
    let opnd0:X86Opnd = ctx.stack_opnd(0);

    let mapping1 = ctx.get_opnd_mapping(StackOpnd(1));
    let mapping0 = ctx.get_opnd_mapping(StackOpnd(0));

    let dst1:X86Opnd = ctx.stack_push_mapping(mapping1);
    mov(cb, REG0, opnd1);
    mov(cb, dst1, REG0);

    let dst0:X86Opnd = ctx.stack_push_mapping(mapping0);
    mov(cb, REG0, opnd0);
    mov(cb, dst0, REG0);

    KeepCompiling
}

// Swap top 2 stack entries
fn gen_swap(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    stack_swap(ctx, cb, 0, 1, REG0, REG1);
    KeepCompiling
}

fn stack_swap(ctx: &mut Context, cb: &mut CodeBlock, offset0: u16, offset1: u16, reg0: X86Opnd, reg1: X86Opnd)
{
    let opnd0 = ctx.stack_opnd(offset0 as i32);
    let opnd1 = ctx.stack_opnd(offset1 as i32);

    let mapping0 = ctx.get_opnd_mapping(StackOpnd(offset0));
    let mapping1 = ctx.get_opnd_mapping(StackOpnd(offset1));

    mov(cb, REG0, opnd0);
    mov(cb, REG1, opnd1);
    mov(cb, opnd0, REG1);
    mov(cb, opnd1, REG0);

    ctx.set_opnd_mapping(StackOpnd(offset0), mapping1);
    ctx.set_opnd_mapping(StackOpnd(offset1), mapping0);
}

fn gen_putnil(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    jit_putobject(jit, ctx, cb, Qnil);
    KeepCompiling
}

fn jit_putobject(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, arg: VALUE)
{
    let val_type:Type = Type::from(arg);
    let VALUE(arg_value) = arg;
    let stack_top = ctx.stack_push(val_type);

    if arg.special_const_p() {
        // Immediates will not move and do not need to be tracked for GC
        // Thanks to this we can mov directly to memory when possible.

        let imm = uimm_opnd(arg_value as u64);

        // 64-bit immediates can't be directly written to memory
        if arg_value <= 0xFF_FF_FF_FF {
            mov(cb, stack_top, imm);
        } else {
            mov(cb, REG0, imm);
            mov(cb, stack_top, REG0);
        }
    } else {
        // Load the value to push into REG0
        // Note that this value may get moved by the GC
        jit_mov_gc_ptr(jit, cb, REG0, arg);

        // Write argument at SP
        mov(cb, stack_top, REG0);
    }
}

fn gen_putobject_int2fix(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let opcode = jit.opcode;
    let cst_val:usize = if opcode == OP_PUTOBJECT_INT2FIX_0_ { 0 } else { 1 };

    jit_putobject(jit, ctx, cb, VALUE::from(cst_val));
    KeepCompiling
}

fn gen_putobject(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let arg:VALUE = jit_get_arg(jit, 0);

    jit_putobject(jit, ctx, cb, arg);
    KeepCompiling
}

fn gen_putself(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Load self from CFP
    let cf_opnd = mem_opnd((8 * SIZEOF_VALUE) as u8, REG_CFP, RUBY_OFFSET_CFP_SELF);
    mov(cb, REG0, cf_opnd);

    // Write it on the stack
    let stack_top:X86Opnd = ctx.stack_push_self();
    mov(cb, stack_top, REG0);

    KeepCompiling
}

fn gen_putspecialobject(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let object_type = jit_get_arg(jit, 0);

    if object_type == VALUE(VM_SPECIAL_OBJECT_VMCORE) {
        let stack_top:X86Opnd = ctx.stack_push(Type::UnknownHeap);
        jit_mov_gc_ptr(jit, cb, REG0, get_ruby_vm_frozen_core());
        mov(cb, stack_top, REG0);
        KeepCompiling
    }
    else {
        // TODO: implement for VM_SPECIAL_OBJECT_CBASE and
        // VM_SPECIAL_OBJECT_CONST_BASE
        CantCompile
    }
}

// set Nth stack entry to stack top
fn gen_setn(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let nval:VALUE = jit_get_arg(jit, 0);
    let VALUE(n) = nval;

    let top_val:X86Opnd = ctx.stack_pop(0);
    let dst_opnd:X86Opnd = ctx.stack_opnd(n.try_into().unwrap());
    mov(cb, REG0, top_val);
    mov(cb, dst_opnd, REG0);

    let mapping = ctx.get_opnd_mapping(StackOpnd(0));
    ctx.set_opnd_mapping(StackOpnd(n.try_into().unwrap()), mapping);

    KeepCompiling
}

// get nth stack value, then push it
fn gen_topn(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let nval:VALUE = jit_get_arg(jit, 0);
    let VALUE(n) = nval;

    let top_n_val = ctx.stack_opnd(n.try_into().unwrap());
    let mapping = ctx.get_opnd_mapping(StackOpnd(n.try_into().unwrap()));

    let loc0 = ctx.stack_push_mapping(mapping);
    mov(cb, REG0, top_n_val);
    mov(cb, loc0, REG0);

    KeepCompiling
}

// Pop n values off the stack
fn gen_adjuststack(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let nval:VALUE = jit_get_arg(jit, 0);
    let VALUE(n) = nval;

    ctx.stack_pop(n);
    KeepCompiling
}

fn gen_opt_plus(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    if !jit_at_current_insn(jit) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    let comptime_a = jit_peek_at_stack(jit, ctx, 1);
    let comptime_b = jit_peek_at_stack(jit, ctx, 0);

    if comptime_a.fixnum_p() && comptime_b.fixnum_p() {
        // Create a side-exit to fall back to the interpreter
        // Note: we generate the side-exit before popping operands from the stack
        let side_exit = get_side_exit(jit, ocb, ctx);

        /*
        if (!assume_bop_not_redefined(jit, INTEGER_REDEFINED_OP_FLAG, BOP_PLUS)) {
            return YJIT_CANT_COMPILE;
        }
        */

        // Check that both operands are fixnums
        guard_two_fixnums(ctx, cb, side_exit);

        // Get the operands and destination from the stack
        let arg1 = ctx.stack_pop(1);
        let arg0 = ctx.stack_pop(1);

        // Add arg0 + arg1 and test for overflow
        mov(cb, REG0, arg0);
        sub(cb, REG0, imm_opnd(1));
        add(cb, REG0, arg1);
        jo_ptr(cb, side_exit);

        // Push the output on the stack
        let dst = ctx.stack_push(Type::Fixnum);
        mov(cb, dst, REG0);

        KeepCompiling
    } else {
        gen_opt_send_without_block(jit, ctx, cb, ocb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asm::x86_64::*;

    fn setup_codegen() -> (JITState, Context, CodeBlock, OutlinedCb) {
        let block = Block::new(BLOCKID_NULL, &Context::default());
        return (
            JITState::new(&block),
            Context::new(),
            CodeBlock::new(),
            OutlinedCb::wrap(CodeBlock::new())
        );
    }

    #[test]
    fn test_gen_leave_exit() {
        let mut ocb = OutlinedCb::wrap(CodeBlock::new());
        gen_leave_exit(&mut ocb);
        assert!(ocb.unwrap().get_write_pos() > 0);
    }

    #[test]
    fn test_gen_exit() {
        let (_, ctx, mut cb, _) = setup_codegen();
        gen_exit(0 as *mut VALUE, &ctx, &mut cb);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_get_side_exit() {
        let (mut jit, ctx, _, mut ocb) = setup_codegen();
        get_side_exit(&mut jit, &mut ocb, &ctx);
        assert!(ocb.unwrap().get_write_pos() > 0);
    }

    #[test]
    fn test_gen_check_ints() {
        let (_, ctx, mut cb, mut ocb) = setup_codegen();
        let side_exit = ocb.unwrap().get_write_ptr();
        gen_check_ints(&mut cb, side_exit);
    }

    #[test]
    fn test_gen_nop() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        let status = gen_nop(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));
        assert_eq!(context.diff(&Context::new()), 0);
        assert_eq!(cb.get_write_pos(), 0);
    }

    #[test]
    fn test_gen_pop() {
        let (mut jit, _, mut cb, mut ocb) = setup_codegen();
        let mut context = Context::new_with_stack_size(1);
        let status = gen_pop(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));
        assert_eq!(context.diff(&Context::new()), 0);
    }

    #[test]
    fn test_gen_dup() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        context.stack_push(Type::Fixnum);
        let status = gen_dup(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));

        // Did we duplicate the type information for the Fixnum type?
        assert_eq!(Type::Fixnum, context.get_opnd_type(StackOpnd(0)));
        assert_eq!(Type::Fixnum, context.get_opnd_type(StackOpnd(1)));

        assert!(cb.get_write_pos() > 0); // Write some movs
    }

    #[test]
    fn test_gen_dupn() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        context.stack_push(Type::Fixnum);
        context.stack_push(Type::Flonum);

        let mut value_array: [u64; 2] = [ 0, 2 ]; // We only compile for n == 2
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        jit.set_pc(pc);

        let status = gen_dupn(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));

        assert_eq!(Type::Fixnum, context.get_opnd_type(StackOpnd(3)));
        assert_eq!(Type::Flonum, context.get_opnd_type(StackOpnd(2)));
        assert_eq!(Type::Fixnum, context.get_opnd_type(StackOpnd(1)));
        assert_eq!(Type::Flonum, context.get_opnd_type(StackOpnd(0)));

        assert!(cb.get_write_pos() > 0); // Write some movs
    }

    #[test]
    fn test_gen_swap() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        context.stack_push(Type::Fixnum);
        context.stack_push(Type::Flonum);

        let status = gen_swap(&mut jit, &mut context, &mut cb, &mut ocb);

        let (_, tmp_type_top) = context.get_opnd_mapping(StackOpnd(0));
        let (_, tmp_type_next) = context.get_opnd_mapping(StackOpnd(1));

        assert!(matches!(KeepCompiling, status));
        assert_eq!(tmp_type_top, Type::Fixnum);
        assert_eq!(tmp_type_next, Type::Flonum);
    }

    #[test]
    fn test_putnil() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        let status = gen_putnil(&mut jit, &mut context, &mut cb, &mut ocb);

        let (_, tmp_type_top) = context.get_opnd_mapping(StackOpnd(0));

        assert!(matches!(KeepCompiling, status));
        assert_eq!(tmp_type_top, Type::Nil);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_putobject_qtrue() {
        // Test gen_putobject with Qtrue
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();

        let mut value_array: [u64; 2] = [ 0, Qtrue.into() ];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        jit.set_pc(pc);

        let status = gen_putobject(&mut jit, &mut context, &mut cb, &mut ocb);

        let (_, tmp_type_top) = context.get_opnd_mapping(StackOpnd(0));

        assert!(matches!(KeepCompiling, status));
        assert_eq!(tmp_type_top, Type::True);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_putobject_fixnum() {
        // Test gen_putobject with a Fixnum to test another conditional branch
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();

        // The Fixnum 7 is encoded as 7 * 2 + 1, or 15
        let mut value_array: [u64; 2] = [ 0, 15 ];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        jit.set_pc(pc);

        let status = gen_putobject(&mut jit, &mut context, &mut cb, &mut ocb);

        let (_, tmp_type_top) = context.get_opnd_mapping(StackOpnd(0));

        assert!(matches!(KeepCompiling, status));
        assert_eq!(tmp_type_top, Type::Fixnum);
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_int2fix() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        jit.opcode = OP_PUTOBJECT_INT2FIX_0_;
        let status = gen_putobject_int2fix(&mut jit, &mut context, &mut cb, &mut ocb);

        let (_, tmp_type_top) = context.get_opnd_mapping(StackOpnd(0));

        // Right now we're not testing the generated machine code to make sure a literal 1 or 0 was pushed. I've checked locally.
        assert!(matches!(KeepCompiling, status));
        assert_eq!(tmp_type_top, Type::Fixnum);
    }

    #[test]
    fn test_putself() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        let status = gen_putself(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_putspecialobject() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();

        let mut value_array: [u64; 2] = [ 0, VM_SPECIAL_OBJECT_VMCORE as u64 ];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        jit.set_pc(pc);

        let status = gen_putspecialobject(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));
        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_gen_setn() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        context.stack_push(Type::Fixnum);
        context.stack_push(Type::Flonum);
        context.stack_push(Type::String);

        let mut value_array: [u64; 2] = [ 0, 2 ];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        jit.set_pc(pc);

        let status = gen_setn(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));

        assert_eq!(Type::String, context.get_opnd_type(StackOpnd(2)));
        assert_eq!(Type::Flonum, context.get_opnd_type(StackOpnd(1)));
        assert_eq!(Type::String, context.get_opnd_type(StackOpnd(0)));

        assert!(cb.get_write_pos() > 0);
    }

    #[test]
    fn test_gen_topn() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        context.stack_push(Type::Flonum);
        context.stack_push(Type::String);

        let mut value_array: [u64; 2] = [ 0, 1 ];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        jit.set_pc(pc);

        let status = gen_topn(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));

        assert_eq!(Type::Flonum, context.get_opnd_type(StackOpnd(2)));
        assert_eq!(Type::String, context.get_opnd_type(StackOpnd(1)));
        assert_eq!(Type::Flonum, context.get_opnd_type(StackOpnd(0)));

        assert!(cb.get_write_pos() > 0); // Write some movs
    }

    #[test]
    fn test_gen_adjuststack() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        context.stack_push(Type::Flonum);
        context.stack_push(Type::String);
        context.stack_push(Type::Fixnum);

        let mut value_array: [u64; 3] = [ 0, 2, 0 ];
        let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
        jit.set_pc(pc);

        let status = gen_adjuststack(&mut jit, &mut context, &mut cb, &mut ocb);

        assert!(matches!(KeepCompiling, status));

        assert_eq!(Type::Flonum, context.get_opnd_type(StackOpnd(0)));

        assert!(cb.get_write_pos() == 0); // No instructions written
    }

    #[test]
    fn test_gen_leave() {
        let (mut jit, mut context, mut cb, mut ocb) = setup_codegen();
        // Push return value
        context.stack_push(Type::Fixnum);
        gen_leave(&mut jit, &mut context, &mut cb, &mut ocb);
    }
}

// new array initialized from top N values
fn gen_newarray(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let n = jit_get_arg(jit, 0).as_u32();

    // Save the PC and SP because we are allocating
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    let offset_magnitude = SIZEOF_VALUE as u32 * n;
    let values_ptr = ctx.sp_opnd(-(offset_magnitude as isize));

    // call rb_ec_ary_new_from_values(struct rb_execution_context_struct *ec, long n, const VALUE *elts);
    mov(cb, C_ARG_REGS[0], REG_EC);
    mov(cb, C_ARG_REGS[1], imm_opnd(n.into()));
    lea(cb, C_ARG_REGS[2], values_ptr);
    let ary_new = CodePtr::from(rb_ec_ary_new_from_values as *mut u8);
    call_ptr(cb, REG0, ary_new);

    ctx.stack_pop(n as usize);
    let stack_ret = ctx.stack_push(Type::Array);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}

// dup array
fn gen_duparray(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let ary = jit_get_arg(jit, 0);

    // Save the PC and SP because we are allocating
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    // call rb_ary_resurrect(VALUE ary);
    jit_mov_gc_ptr(jit, cb, C_ARG_REGS[0], ary);
    let ary_res = CodePtr::from(rb_ary_resurrect as *mut u8);
    call_ptr(cb, REG0, ary_res);

    let stack_ret = ctx.stack_push(Type::Array);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}

// dup hash
fn gen_duphash(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let hash = jit_get_arg(jit, 0);

    // Save the PC and SP because we are allocating
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    // call rb_hash_resurrect(VALUE hash);
    jit_mov_gc_ptr(jit, cb, C_ARG_REGS[0], hash);
    let hash_res = CodePtr::from(rb_hash_resurrect as *mut u8);
    call_ptr(cb, REG0, hash_res);

    let stack_ret = ctx.stack_push(Type::Hash);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}

/*
// call to_a on the array on the stack
fn gen_splatarray(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    VALUE flag = (VALUE) jit_get_arg(jit, 0);

    // Save the PC and SP because the callee may allocate
    // Note that this modifies REG_SP, which is why we do it first
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    // Get the operands from the stack
    let ary_opnd = ctx.stack_pop(1);

    // Call rb_vm_splat_array(flag, ary)
    jit_mov_gc_ptr(jit, cb, C_ARG_REGS[0], flag);
    mov(cb, C_ARG_REGS[1], ary_opnd);
    call_ptr(cb, REG1, (void *) rb_vm_splat_array);

    let stack_ret = ctx.stack_push(Type::Array);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}

// new range initialized from top 2 values
fn gen_newrange(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    rb_num_t flag = (rb_num_t)jit_get_arg(jit, 0);

    // rb_range_new() allocates and can raise
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    // val = rb_range_new(low, high, (int)flag);
    mov(cb, C_ARG_REGS[0], ctx.stack_opnd(1));
    mov(cb, C_ARG_REGS[1], ctx.stack_opnd(0));
    mov(cb, C_ARG_REGS[2], imm_opnd(flag));
    call_ptr(cb, REG0, (void *)rb_range_new);

    ctx.stack_pop(2);
    let stack_ret = ctx.stack_push(Type::UnknownHeap);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}
*/

fn guard_object_is_heap(cb: &mut CodeBlock, object_opnd: X86Opnd, ctx: &mut Context, side_exit: CodePtr)
{
    add_comment(cb, "guard object is heap");

    // Test that the object is not an immediate
    test(cb, object_opnd, uimm_opnd(RUBY_IMMEDIATE_MASK as u64));
    jnz_ptr(cb, side_exit);

    // Test that the object is not false or nil
    let VALUE(qnilval) = Qnil;
    cmp(cb, object_opnd, uimm_opnd(Qnil.into()));
    jbe_ptr(cb, side_exit);
}

fn guard_object_is_array(cb: &mut CodeBlock, object_opnd: X86Opnd, flags_opnd: X86Opnd, ctx: &mut Context, side_exit: CodePtr)
{
    add_comment(cb, "guard object is array");

    // Pull out the type mask
    mov(cb, flags_opnd, mem_opnd(8 * SIZEOF_VALUE as u8, object_opnd, RUBY_OFFSET_RBASIC_FLAGS));
    and(cb, flags_opnd, uimm_opnd(RUBY_T_MASK as u64));

    // Compare the result with T_ARRAY
    cmp(cb, flags_opnd, uimm_opnd(RUBY_T_ARRAY as u64));
    jne_ptr(cb, side_exit);
}

// push enough nils onto the stack to fill out an array
fn gen_expandarray(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let flag = jit_get_arg(jit, 1);
    let VALUE(flag_value) = flag;

    // If this instruction has the splat flag, then bail out.
    if flag_value & 0x01 != 0 {
        incr_counter!(expandarray_splat);
        return CantCompile;
    }

    // If this instruction has the postarg flag, then bail out.
    if flag_value & 0x02 != 0 {
        incr_counter!(expandarray_postarg);
        return CantCompile;
    }

    let side_exit = get_side_exit(jit, ocb, ctx);

    // num is the number of requested values. If there aren't enough in the
    // array then we're going to push on nils.
    let num = jit_get_arg(jit, 0);
    let array_type = ctx.get_opnd_type(StackOpnd(0));
    let array_opnd = ctx.stack_pop(1);

    if matches!(array_type, Type::Nil) {
        // special case for a, b = nil pattern
        // push N nils onto the stack
        for i in 0..(num.into()) {
            let push_opnd = ctx.stack_push(Type::Nil);
            mov(cb, push_opnd, uimm_opnd(Qnil.into()));
        }
        return KeepCompiling;
    }

    // Move the array from the stack into REG0 and check that it's an array.
    mov(cb, REG0, array_opnd);
    guard_object_is_heap(cb, REG0, ctx, counted_exit!(ocb, side_exit, expandarray_not_array));
    guard_object_is_array(cb, REG0, REG1, ctx, counted_exit!(ocb, side_exit, expandarray_not_array));

    // If we don't actually want any values, then just return.
    if num == VALUE(0) {
        return KeepCompiling;
    }

    // Pull out the embed flag to check if it's an embedded array.
    let flags_opnd = mem_opnd((8 * SIZEOF_VALUE) as u8, REG0, RUBY_OFFSET_RBASIC_FLAGS);
    mov(cb, REG1, flags_opnd);

    // Move the length of the embedded array into REG1.
    and(cb, REG1, uimm_opnd(RARRAY_EMBED_LEN_MASK as u64));
    shr(cb, REG1, uimm_opnd(RARRAY_EMBED_LEN_SHIFT as u64));

    // Conditionally move the length of the heap array into REG1.
    test(cb, flags_opnd, uimm_opnd(RARRAY_EMBED_FLAG as u64));
    let array_len_opnd = mem_opnd((8 * size_of::<std::os::raw::c_long>()) as u8, REG0, RUBY_OFFSET_RARRAY_AS_HEAP_LEN);
    cmovz(cb, REG1, array_len_opnd);

    // Only handle the case where the number of values in the array is greater
    // than or equal to the number of values requested.
    cmp(cb, REG1, uimm_opnd(num.into()));
    jl_ptr(cb, counted_exit!(ocb, side_exit, expandarray_rhs_too_small));

    // Load the address of the embedded array into REG1.
    // (struct RArray *)(obj)->as.ary
    let ary_opnd = mem_opnd((8 * SIZEOF_VALUE) as u8, REG0, RUBY_OFFSET_RARRAY_AS_ARY);
    lea(cb, REG1, ary_opnd);

    // Conditionally load the address of the heap array into REG1.
    // (struct RArray *)(obj)->as.heap.ptr
    test(cb, flags_opnd, uimm_opnd(RARRAY_EMBED_FLAG as u64));
    let heap_ptr_opnd = mem_opnd((8 * size_of::<usize>()) as u8, REG0, RUBY_OFFSET_RARRAY_AS_HEAP_PTR);
    cmovz(cb, REG1, heap_ptr_opnd);

    // Loop backward through the array and push each element onto the stack.
    for i in (0..(num.as_i32())).rev() {
        let top = ctx.stack_push(Type::Unknown);
        mov(cb, REG0, mem_opnd(64, REG1, i * (SIZEOF_VALUE as i32)));
        mov(cb, top, REG0);
    }

    KeepCompiling
}

fn gen_getlocal_wc0(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Compute the offset from BP to the local
    let slot_idx = jit_get_arg(jit, 0).as_i32();
    let offs:i32 = -(SIZEOF_VALUE as i32) * slot_idx;
    let local_idx = slot_to_local_idx(jit.get_iseq(), slot_idx);

    // Load environment pointer EP (level 0) from CFP
    gen_get_ep(cb, REG0, 0);

    // Load the local from the EP
    mov(cb, REG0, mem_opnd(64, REG0, offs));

    // Write the local at SP
    let stack_top = ctx.stack_push_local(local_idx.try_into().unwrap());
    mov(cb, stack_top, REG0);

    KeepCompiling
}

// Compute the index of a local variable from its slot index
fn slot_to_local_idx(iseq: IseqPtr, slot_idx:i32) -> u32
{
    // Convoluted rules from local_var_name() in iseq.c
    // Equivalent of iseq->body->local_table_size
    let local_table_size:i32 = unsafe {
        let val:i32 = get_iseq_body_local_table_size(iseq).try_into().unwrap();
        val // return values from unsafe blocks don't pick up type inference from let bindings outside the block
    };
    let op = slot_idx - (VM_ENV_DATA_SIZE as i32);
    let local_idx = local_table_size - op - 1;
    assert!(local_idx >= 0 && local_idx < local_table_size);
    local_idx.try_into().unwrap()
}

// Get EP at level from CFP
fn gen_get_ep(cb:&mut CodeBlock, reg:X86Opnd, level:u32)
{
    // Load environment pointer EP from CFP
    let ep_opnd = mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_EP);
    mov(cb, reg, ep_opnd);

    for _ in (0..level).rev() {
        // Get the previous EP from the current EP
        // See GET_PREV_EP(ep) macro
        // VALUE *prev_ep = ((VALUE *)((ep)[VM_ENV_DATA_INDEX_SPECVAL] & ~0x03))
        let offs = (SIZEOF_VALUE as i32) * (VM_ENV_DATA_INDEX_SPECVAL as i32);
        mov(cb, reg, mem_opnd(64, REG0, offs));
        and(cb, reg, imm_opnd(!0x03));
    }
}

fn gen_getlocal_generic(ctx:&mut Context, cb: &mut CodeBlock, local_idx: u32, level: u32) -> CodegenStatus
{
    gen_get_ep(cb, REG0, level);

    // Load the local from the block
    // val = *(vm_get_ep(GET_EP(), level) - idx);
    let offs = -(SIZEOF_VALUE as i32 * local_idx as i32);
    mov(cb, REG0, mem_opnd(64, REG0, offs));

    // Write the local at SP
    let stack_top = ctx.stack_push(Type::Unknown);
    mov(cb, stack_top, REG0);

    KeepCompiling
}

fn gen_getlocal(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let idx = jit_get_arg(jit, 0);
    let level = jit_get_arg(jit, 1);
    gen_getlocal_generic(ctx, cb, idx.as_u32(), level.as_u32())
}

fn gen_getlocal_wc1(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let idx = jit_get_arg(jit, 0);
    gen_getlocal_generic(ctx, cb, idx.as_u32(), 1)
}

fn gen_setlocal_wc0(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    /*
    vm_env_write(const VALUE *ep, int index, VALUE v)
    {
        VALUE flags = ep[VM_ENV_DATA_INDEX_FLAGS];
        if (LIKELY((flags & VM_ENV_FLAG_WB_REQUIRED) == 0)) {
            VM_STACK_ENV_WRITE(ep, index, v);
        }
        else {
            vm_env_write_slowpath(ep, index, v);
        }
    }
    */

    let slot_idx = jit_get_arg(jit, 0).as_i32();
    let local_idx = slot_to_local_idx(jit.get_iseq(), slot_idx) as usize;

    // Load environment pointer EP (level 0) from CFP
    gen_get_ep(cb, REG0, 0);

    // flags & VM_ENV_FLAG_WB_REQUIRED
    let flags_opnd = mem_opnd(64, REG0, SIZEOF_VALUE as i32 * VM_ENV_DATA_INDEX_FLAGS as i32);
    test(cb, flags_opnd, imm_opnd(VM_ENV_FLAG_WB_REQUIRED as i64));

    // Create a side-exit to fall back to the interpreter
    let side_exit = get_side_exit(jit, ocb, ctx);

    // if (flags & VM_ENV_FLAG_WB_REQUIRED) != 0
    jnz_ptr(cb, side_exit);

    // Set the type of the local variable in the context
    let temp_type = ctx.get_opnd_type(InsnOpnd::StackOpnd(0));
    ctx.set_local_type(local_idx, temp_type);

    // Pop the value to write from the stack
    let stack_top = ctx.stack_pop(1);
    mov(cb, REG1, stack_top);

    // Write the value at the environment pointer
    let offs:i32 = -8 * slot_idx;
    mov(cb, mem_opnd(64, REG0, offs), REG1);

    KeepCompiling
}

fn gen_setlocal_generic(jit:&mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb, local_idx:i32, level:u32) -> CodegenStatus
{
    // Load environment pointer EP at level
    gen_get_ep(cb, REG0, level);

    // flags & VM_ENV_FLAG_WB_REQUIRED
    let flags_opnd = mem_opnd(64, REG0, SIZEOF_VALUE as i32 * VM_ENV_DATA_INDEX_FLAGS as i32);
    test(cb, flags_opnd, imm_opnd(VM_ENV_FLAG_WB_REQUIRED as i64));

    // Create a side-exit to fall back to the interpreter
    let side_exit = get_side_exit(jit, ocb, ctx);

    // if (flags & VM_ENV_FLAG_WB_REQUIRED) != 0
    jnz_ptr(cb, side_exit);

    // Pop the value to write from the stack
    let stack_top = ctx.stack_pop(1);
    mov(cb, REG1, stack_top);

    // Write the value at the environment pointer
    let offs = -(SIZEOF_VALUE as i32 * local_idx);
    mov(cb, mem_opnd(64, REG0, offs), REG1);

    KeepCompiling
}

fn gen_setlocal(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let idx = jit_get_arg(jit, 0).as_i32();
    let level = jit_get_arg(jit, 1).as_u32();
    gen_setlocal_generic(jit, ctx, cb, ocb, idx, level)
}

fn gen_setlocal_wc1(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let idx = jit_get_arg(jit, 0).as_i32();
    gen_setlocal_generic(jit, ctx, cb, ocb, idx, 1)
}

// new hash initialized from top N values
fn gen_newhash(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let num:i64 = jit_get_arg(jit, 0).as_i64();

    // Save the PC and SP because we are allocating
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    if num != 0 {
        // val = rb_hash_new_with_size(num / 2);
        mov(cb, C_ARG_REGS[0], imm_opnd(num / 2));
        let hn_code_ptr = CodePtr::from(rb_hash_new_with_size as *mut u8);
        call_ptr(cb, REG0, hn_code_ptr);

        // save the allocated hash as we want to push it after insertion
        push(cb, RAX);
        push(cb, RAX); // alignment

        // rb_hash_bulk_insert(num, STACK_ADDR_FROM_TOP(num), val);
        mov(cb, C_ARG_REGS[0], imm_opnd(num));
        lea(cb, C_ARG_REGS[1], ctx.stack_opnd((num - 1).try_into().unwrap()));
        mov(cb, C_ARG_REGS[2], RAX);
        let bi_code_opnd = CodePtr::from(rb_hash_bulk_insert as *mut u8);
        call_ptr(cb, REG0, bi_code_opnd);

        pop(cb, RAX); // alignment
        pop(cb, RAX);

        ctx.stack_pop(num.try_into().unwrap());
        let stack_ret = ctx.stack_push(Type::Hash);
        mov(cb, stack_ret, RAX);
    }
    else {
        // val = rb_hash_new();
        let hn_code_ptr = CodePtr::from(rb_hash_new as *mut u8);
        call_ptr(cb, REG0, hn_code_ptr);

        let stack_ret = ctx.stack_push(Type::Hash);
        mov(cb, stack_ret, RAX);
    }

    KeepCompiling
}

/*
fn gen_putstring(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    VALUE put_val = jit_get_arg(jit, 0);

    // Save the PC and SP because the callee will allocate
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    mov(cb, C_ARG_REGS[0], REG_EC);
    jit_mov_gc_ptr(jit, cb, C_ARG_REGS[1], put_val);
    call_ptr(cb, REG0, (void *)rb_ec_str_resurrect);

    let stack_top = ctx.stack_push(Type::String);
    mov(cb, stack_top, RAX);

    KeepCompiling
}

// Push Qtrue or Qfalse depending on whether the given keyword was supplied by
// the caller
fn gen_checkkeyword(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // When a keyword is unspecified past index 32, a hash will be used
    // instead. This can only happen in iseqs taking more than 32 keywords.
    if (jit->iseq->body->param.keyword->num >= 32) {
        return CantCompile;
    }

    // The EP offset to the undefined bits local
    int32_t bits_offset = (int32_t)jit_get_arg(jit, 0);

    // The index of the keyword we want to check
    int32_t index = (int32_t)jit_get_arg(jit, 1);

    // Load environment pointer EP
    gen_get_ep(cb, REG0, 0);

    // VALUE kw_bits = *(ep - bits);
    let bits_opnd = mem_opnd(64, REG0, SIZEOF_VALUE * -bits_offset);

    // unsigned int b = (unsigned int)FIX2ULONG(kw_bits);
    // if ((b & (0x01 << idx))) {
    //
    // We can skip the FIX2ULONG conversion by shifting the bit we test
    int64_t bit_test = 0x01 << (index + 1);
    test(cb, bits_opnd, imm_opnd(bit_test));
    mov(cb, REG0, imm_opnd(Qfalse));
    mov(cb, REG1, imm_opnd(Qtrue));
    cmovz(cb, REG0, REG1);

    let stack_ret = ctx.stack_push(Type::UnknownImm);
    mov(cb, stack_ret, REG0);

    KeepCompiling
}

static void
gen_jnz_to_target0(codeblock_t *cb, uint8_t *target0, uint8_t *target1, uint8_t shape)
{
    switch (shape) {
      case SHAPE_NEXT0:
      case SHAPE_NEXT1:
        RUBY_ASSERT(false);
        break;

      case SHAPE_DEFAULT:
        jnz_ptr(cb, target0);
        break;
    }
}

static void
gen_jz_to_target0(codeblock_t *cb, uint8_t *target0, uint8_t *target1, uint8_t shape)
{
    switch (shape) {
      case SHAPE_NEXT0:
      case SHAPE_NEXT1:
        RUBY_ASSERT(false);
        break;

      case SHAPE_DEFAULT:
        jz_ptr(cb, target0);
        break;
    }
}

static void
gen_jbe_to_target0(codeblock_t *cb, uint8_t *target0, uint8_t *target1, uint8_t shape)
{
    switch (shape) {
      case SHAPE_NEXT0:
      case SHAPE_NEXT1:
        RUBY_ASSERT(false);
        break;

      case SHAPE_DEFAULT:
        jbe_ptr(cb, target0);
        break;
    }
}

enum jcc_kinds {
    JCC_JNE,
    JCC_JNZ,
    JCC_JZ,
    JCC_JE,
    JCC_JBE,
    JCC_JNA,
};

// Generate a jump to a stub that recompiles the current YARV instruction on failure.
// When depth_limitk is exceeded, generate a jump to a side exit.
static void
jit_chain_guard(enum jcc_kinds jcc, jitstate_t *jit, const ctx_t *ctx, uint8_t depth_limit, uint8_t *side_exit)
{
    branchgen_fn target0_gen_fn;

    switch (jcc) {
      case JCC_JNE:
      case JCC_JNZ:
        target0_gen_fn = gen_jnz_to_target0;
        break;
      case JCC_JZ:
      case JCC_JE:
        target0_gen_fn = gen_jz_to_target0;
        break;
      case JCC_JBE:
      case JCC_JNA:
        target0_gen_fn = gen_jbe_to_target0;
        break;
      default:
        rb_bug("yjit: unimplemented jump kind");
        break;
    };

    if (ctx->chain_depth < depth_limit) {
        ctx_t deeper = *ctx;
        deeper.chain_depth++;

        gen_branch(
            jit,
            ctx,
            (blockid_t) { jit->iseq, jit->insn_idx },
            &deeper,
            BLOCKID_NULL,
            NULL,
            target0_gen_fn
        );
    }
    else {
        target0_gen_fn(cb, side_exit, NULL, SHAPE_DEFAULT);
    }
}

enum {
    GETIVAR_MAX_DEPTH = 10,       // up to 5 different classes, and embedded or not for each
    OPT_AREF_MAX_CHAIN_DEPTH = 2, // hashes and arrays
    SEND_MAX_DEPTH = 5,           // up to 5 different classes
};

VALUE rb_vm_set_ivar_idx(VALUE obj, uint32_t idx, VALUE val);

// Codegen for setting an instance variable.
// Preconditions:
//   - receiver is in REG0
//   - receiver has the same class as CLASS_OF(comptime_receiver)
//   - no stack push or pops to ctx since the entry to the codegen of the instruction being compiled
fn gen_set_ivar(jitstate_t *jit, ctx_t *ctx, VALUE recv, VALUE klass, ID ivar_name)
{
    // Save the PC and SP because the callee may allocate
    // Note that this modifies REG_SP, which is why we do it first
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    // Get the operands from the stack
    let val_opnd = ctx.stack_pop(1);
    let recv_opnd = ctx.stack_pop(1);

    uint32_t ivar_index = rb_obj_ensure_iv_index_mapping(recv, ivar_name);

    // Call rb_vm_set_ivar_idx with the receiver, the index of the ivar, and the value
    mov(cb, C_ARG_REGS[0], recv_opnd);
    mov(cb, C_ARG_REGS[1], imm_opnd(ivar_index));
    mov(cb, C_ARG_REGS[2], val_opnd);
    call_ptr(cb, REG0, (void *)rb_vm_set_ivar_idx);

    let out_opnd = ctx.stack_push(Type::Unknown);
    mov(cb, out_opnd, RAX);

    KeepCompiling
}

// Codegen for getting an instance variable.
// Preconditions:
//   - receiver is in REG0
//   - receiver has the same class as CLASS_OF(comptime_receiver)
//   - no stack push or pops to ctx since the entry to the codegen of the instruction being compiled
fn gen_get_ivar(jitstate_t *jit, ctx_t *ctx, const int max_chain_depth, VALUE comptime_receiver, ID ivar_name, insn_opnd_t reg0_opnd, uint8_t *side_exit)
{
    VALUE comptime_val_klass = CLASS_OF(comptime_receiver);
    const ctx_t starting_context = *ctx; // make a copy for use with jit_chain_guard

    // If the class uses the default allocator, instances should all be T_OBJECT
    // NOTE: This assumes nobody changes the allocator of the class after allocation.
    //       Eventually, we can encode whether an object is T_OBJECT or not
    //       inside object shapes.
    if (!RB_TYPE_P(comptime_receiver, T_OBJECT) ||
            rb_get_alloc_func(comptime_val_klass) != rb_class_allocate_instance) {
        // General case. Call rb_ivar_get().
        // VALUE rb_ivar_get(VALUE obj, ID id)
        add_comment(cb, "call rb_ivar_get()");

        // The function could raise exceptions.
        jit_prepare_routine_call(jit, ctx, cb, REG1);

        mov(cb, C_ARG_REGS[0], REG0);
        mov(cb, C_ARG_REGS[1], imm_opnd((int64_t)ivar_name));
        call_ptr(cb, REG1, (void *)rb_ivar_get);

        if (!reg0_opnd.is_self) {
            (void)ctx.stack_pop(1);
        }
        // Push the ivar on the stack
        let out_opnd = ctx.stack_push(Type::Unknown);
        mov(cb, out_opnd, RAX);

        // Jump to next instruction. This allows guard chains to share the same successor.
        jit_jump_to_next_insn(jit, ctx);
        return EndBlock;
    }

    /*
    // FIXME:
    // This check was added because of a failure in a test involving the
    // Nokogiri Document class where we see a T_DATA that still has the default
    // allocator.
    // Aaron Patterson argues that this is a bug in the C extension, because
    // people could call .allocate() on the class and still get a T_OBJECT
    // For now I added an extra dynamic check that the receiver is T_OBJECT
    // so we can safely pass all the tests in Shopify Core.
    //
    // Guard that the receiver is T_OBJECT
    // #define RB_BUILTIN_TYPE(x) (int)(((struct RBasic*)(x))->flags & RUBY_T_MASK)
    add_comment(cb, "guard receiver is T_OBJECT");
    mov(cb, REG1, member_opnd(REG0, struct RBasic, flags));
    and(cb, REG1, imm_opnd(RUBY_T_MASK));
    cmp(cb, REG1, imm_opnd(T_OBJECT));
    jit_chain_guard(JCC_JNE, jit, &starting_context, max_chain_depth, side_exit);
    */

    // FIXME: Mapping the index could fail when there is too many ivar names. If we're
    // compiling for a branch stub that can cause the exception to be thrown from the
    // wrong PC.
    uint32_t ivar_index = rb_obj_ensure_iv_index_mapping(comptime_receiver, ivar_name);

    // Pop receiver if it's on the temp stack
    if (!reg0_opnd.is_self) {
        (void)ctx.stack_pop(1);
    }

    // Compile time self is embedded and the ivar index lands within the object
    if (RB_FL_TEST_RAW(comptime_receiver, ROBJECT_EMBED) && ivar_index < ROBJECT_EMBED_LEN_MAX) {
        // See ROBJECT_IVPTR() from include/ruby/internal/core/robject.h

        // Guard that self is embedded
        // TODO: BT and JC is shorter
        add_comment(cb, "guard embedded getivar");
        let flags_opnd = member_opnd(REG0, struct RBasic, flags);
        test(cb, flags_opnd, imm_opnd(ROBJECT_EMBED));
        jit_chain_guard(JCC_JZ, jit, &starting_context, max_chain_depth, counted_exit!(ocb, side_exit, getivar_megamorphic));

        // Load the variable
        let ivar_opnd = mem_opnd(64, REG0, offsetof(struct RObject, as.ary) + ivar_index * SIZEOF_VALUE);
        mov(cb, REG1, ivar_opnd);

        // Guard that the variable is not Qundef
        cmp(cb, REG1, imm_opnd(Qundef));
        mov(cb, REG0, imm_opnd(Qnil));
        cmove(cb, REG1, REG0);

        // Push the ivar on the stack
        let out_opnd = ctx.stack_push(Type::Unknown);
        mov(cb, out_opnd, REG1);
    }
    else {
        // Compile time value is *not* embeded.

        // Guard that value is *not* embedded
        // See ROBJECT_IVPTR() from include/ruby/internal/core/robject.h
        add_comment(cb, "guard extended getivar");
        let flags_opnd = member_opnd(REG0, struct RBasic, flags);
        test(cb, flags_opnd, imm_opnd(ROBJECT_EMBED));
        jit_chain_guard(JCC_JNZ, jit, &starting_context, max_chain_depth, counted_exit!(ocb, side_exit, getivar_megamorphic));

        // check that the extended table is big enough
        if (ivar_index >= ROBJECT_EMBED_LEN_MAX + 1) {
            // Check that the slot is inside the extended table (num_slots > index)
            let num_slots = mem_opnd(32, REG0, offsetof(struct RObject, as.heap.numiv));
            cmp(cb, num_slots, imm_opnd(ivar_index));
            jle_ptr(cb, counted_exit!(ocb, side_exit, getivar_idx_out_of_range));
        }

        // Get a pointer to the extended table
        let tbl_opnd = mem_opnd(64, REG0, offsetof(struct RObject, as.heap.ivptr));
        mov(cb, REG0, tbl_opnd);

        // Read the ivar from the extended table
        let ivar_opnd = mem_opnd(64, REG0, SIZEOF_VALUE * ivar_index);
        mov(cb, REG0, ivar_opnd);

        // Check that the ivar is not Qundef
        cmp(cb, REG0, imm_opnd(Qundef));
        mov(cb, REG1, imm_opnd(Qnil));
        cmove(cb, REG0, REG1);

        // Push the ivar on the stack
        let out_opnd = ctx.stack_push(Type::Unknown);
        mov(cb, out_opnd, REG0);
    }

    // Jump to next instruction. This allows guard chains to share the same successor.
    jit_jump_to_next_insn(jit, ctx);
    EndBlock
}

fn gen_getinstancevariable(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Defer compilation so we can specialize on a runtime `self`
    if (!jit_at_current_insn(jit)) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    ID ivar_name = (ID)jit_get_arg(jit, 0);

    VALUE comptime_val = jit_peek_at_self(jit, ctx);
    VALUE comptime_val_klass = CLASS_OF(comptime_val);

    // Generate a side exit
    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    // Guard that the receiver has the same class as the one from compile time.
    mov(cb, REG0, member_opnd(REG_CFP, rb_control_frame_t, self));

    jit_guard_known_klass(jit, ctx, comptime_val_klass, OPND_SELF, comptime_val, GETIVAR_MAX_DEPTH, side_exit);

    return gen_get_ivar(jit, ctx, GETIVAR_MAX_DEPTH, comptime_val, ivar_name, OPND_SELF, side_exit);
}

void rb_vm_setinstancevariable(const rb_iseq_t *iseq, VALUE obj, ID id, VALUE val, IVC ic);

fn gen_setinstancevariable(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    ID id = (ID)jit_get_arg(jit, 0);
    IVC ic = (IVC)jit_get_arg(jit, 1);

    // Save the PC and SP because the callee may allocate
    // Note that this modifies REG_SP, which is why we do it first
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    // Get the operands from the stack
    let val_opnd = ctx.stack_pop(1);

    // Call rb_vm_setinstancevariable(iseq, obj, id, val, ic);
    mov(cb, C_ARG_REGS[1], member_opnd(REG_CFP, rb_control_frame_t, self));
    mov(cb, C_ARG_REGS[3], val_opnd);
    mov(cb, C_ARG_REGS[2], imm_opnd(id));
    mov(cb, C_ARG_REGS[4], const_ptr_opnd(ic));
    jit_mov_gc_ptr(jit, cb, C_ARG_REGS[0], (VALUE)jit->iseq);
    call_ptr(cb, REG0, (void *)rb_vm_setinstancevariable);

    KeepCompiling
}

bool rb_vm_defined(rb_execution_context_t *ec, rb_control_frame_t *reg_cfp, rb_num_t op_type, VALUE obj, VALUE v);

fn gen_defined(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    rb_num_t op_type = (rb_num_t)jit_get_arg(jit, 0);
    VALUE obj = (VALUE)jit_get_arg(jit, 1);
    VALUE pushval = (VALUE)jit_get_arg(jit, 2);

    // Save the PC and SP because the callee may allocate
    // Note that this modifies REG_SP, which is why we do it first
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    // Get the operands from the stack
    let v_opnd = ctx.stack_pop(1);

    // Call vm_defined(ec, reg_cfp, op_type, obj, v)
    mov(cb, C_ARG_REGS[0], REG_EC);
    mov(cb, C_ARG_REGS[1], REG_CFP);
    mov(cb, C_ARG_REGS[2], imm_opnd(op_type));
    jit_mov_gc_ptr(jit, cb, C_ARG_REGS[3], (VALUE)obj);
    mov(cb, C_ARG_REGS[4], v_opnd);
    call_ptr(cb, REG0, (void *)rb_vm_defined);

    // if (vm_defined(ec, GET_CFP(), op_type, obj, v)) {
    //  val = pushval;
    // }
    jit_mov_gc_ptr(jit, cb, REG1, (VALUE)pushval);
    cmp(cb, AL, imm_opnd(0));
    mov(cb, RAX, imm_opnd(Qnil));
    cmovnz(cb, RAX, REG1);

    // Push the return value onto the stack
    val_type_t out_type = SPECIAL_CONST_P(pushval)? Type::UnknownImm : Type::Unknown;
    let stack_ret = ctx.stack_push(out_type);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}
*/

fn gen_checktype(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let type_val = jit_get_arg(jit, 0).as_usize();

    // Only three types are emitted by compile.c
    if type_val == RUBY_T_STRING || type_val == RUBY_T_ARRAY || type_val == RUBY_T_HASH {
        let val_type = ctx.get_opnd_type(StackOpnd(0));
        let val = ctx.stack_pop(1);

        // Check if we know from type information
        if (type_val == RUBY_T_STRING && val_type == Type::String) ||
                (type_val == RUBY_T_ARRAY && val_type == Type::Array) ||
                (type_val == RUBY_T_HASH && val_type == Type::Hash) {
            // guaranteed type match
            let stack_ret = ctx.stack_push(Type::True);
            mov(cb, stack_ret, uimm_opnd(Qtrue.as_u64()));
            return KeepCompiling;
        }
        else if val_type.is_imm() || val_type != Type::Unknown {
            // guaranteed not to match T_STRING/T_ARRAY/T_HASH
            let stack_ret = ctx.stack_push(Type::False);
            mov(cb, stack_ret, uimm_opnd(Qfalse.as_u64()));
            return KeepCompiling;
        }

        mov(cb, REG0, val);
        mov(cb, REG1, uimm_opnd(Qfalse.as_u64()));

        let ret = cb.new_label("ret".to_string());

        if !val_type.is_heap() {
            // if (SPECIAL_CONST_P(val)) {
            // Return Qfalse via REG1 if not on heap
            test(cb, REG0, uimm_opnd(RUBY_IMMEDIATE_MASK as u64));
            jnz_label(cb, ret);
            cmp(cb, REG0, uimm_opnd(Qnil.as_u64()));
            jbe_label(cb, ret);
        }

        // Check type on object
        mov(cb, REG0, mem_opnd(64, REG0, RUBY_OFFSET_RBASIC_FLAGS));
        and(cb, REG0, uimm_opnd(RUBY_T_MASK as u64));
        cmp(cb, REG0, uimm_opnd(type_val as u64));
        mov(cb, REG0, uimm_opnd(Qtrue.as_u64()));
        // REG1 contains Qfalse from above
        cmove(cb, REG1, REG0);

        cb.write_label(ret);
        let stack_ret = ctx.stack_push(Type::UnknownImm);
        mov(cb, stack_ret, REG1);
        cb.link_labels();

        KeepCompiling
    }
    else {
        CantCompile
    }
}

/*
fn gen_concatstrings(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    rb_num_t n = (rb_num_t)jit_get_arg(jit, 0);

    // Save the PC and SP because we are allocating
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    let values_ptr = ctx.sp_opnd(-(SIZEOF_VALUE * (uint32_t)n));

    // call rb_str_concat_literals(long n, const VALUE *strings);
    mov(cb, C_ARG_REGS[0], imm_opnd(n));
    lea(cb, C_ARG_REGS[1], values_ptr);
    call_ptr(cb, REG0, (void *)rb_str_concat_literals);

    ctx.stack_pop(n);
    let stack_ret = ctx.stack_push(Type::String);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}
*/

fn guard_two_fixnums(ctx: &mut Context, cb: &mut CodeBlock, side_exit: CodePtr)
{
    // Get the stack operand types
    let arg1_type = ctx.get_opnd_type(StackOpnd(0));
    let arg0_type = ctx.get_opnd_type(StackOpnd(1));

    if arg0_type.is_heap() || arg1_type.is_heap() {
        jmp_ptr(cb, side_exit);
        return;
    }

    if arg0_type != Type::Fixnum && arg0_type != Type::Unknown {
        jmp_ptr(cb, side_exit);
        return;
    }

    if arg1_type != Type::Fixnum && arg1_type != Type::Unknown {
        jmp_ptr(cb, side_exit);
        return;
    }

    assert!(! arg0_type.is_heap());
    assert!(! arg1_type.is_heap());
    assert!(arg0_type == Type::Fixnum || arg0_type == Type::Unknown);
    assert!(arg1_type == Type::Fixnum || arg1_type == Type::Unknown);

    // Get stack operands without popping them
    let arg1 = ctx.stack_opnd(0);
    let arg0 = ctx.stack_opnd(1);

    // If not fixnums, fall back
    if arg0_type != Type::Fixnum {
        add_comment(cb, "guard arg0 fixnum");
        test(cb, arg0, uimm_opnd(RUBY_FIXNUM_FLAG as u64));
        jz_ptr(cb, side_exit);
    }
    if arg1_type != Type::Fixnum {
        add_comment(cb, "guard arg1 fixnum");
        test(cb, arg1, uimm_opnd(RUBY_FIXNUM_FLAG as u64));
        jz_ptr(cb, side_exit);
    }

    // Set stack types in context
    ctx.upgrade_opnd_type(StackOpnd(0), Type::Fixnum);
    ctx.upgrade_opnd_type(StackOpnd(1), Type::Fixnum);
}

// Conditional move operation used by comparison operators
type CmovFn = fn(cb: &mut CodeBlock, opnd0: X86Opnd, opnd1: X86Opnd) -> ();

fn gen_fixnum_cmp(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb, cmov_op:CmovFn) -> CodegenStatus
{
    // Defer compilation so we can specialize base on a runtime receiver
    if !jit_at_current_insn(jit) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    let comptime_a = jit_peek_at_stack(jit, ctx, 1);
    let comptime_b = jit_peek_at_stack(jit, ctx, 0);

    if comptime_a.fixnum_p() && comptime_b.fixnum_p() {
        // Create a side-exit to fall back to the interpreter
        // Note: we generate the side-exit before popping operands from the stack
        let side_exit = get_side_exit(jit, ocb, ctx);

        /*
        if (!assume_bop_not_redefined(jit, INTEGER_REDEFINED_OP_FLAG, BOP_LT)) {
            return CantCompile;
        }
        */

        // Check that both operands are fixnums
        guard_two_fixnums(ctx, cb, side_exit);

        // Get the operands from the stack
        let arg1 = ctx.stack_pop(1);
        let arg0 = ctx.stack_pop(1);

        // Compare the arguments
        xor(cb, REG0_32, REG0_32); // REG0 = Qfalse
        mov(cb, REG1, arg0);
        cmp(cb, REG1, arg1);
        mov(cb, REG1, uimm_opnd(Qtrue.into()));
        cmov_op(cb, REG0, REG1);

        // Push the output on the stack
        let dst = ctx.stack_push(Type::Unknown);
        mov(cb, dst, REG0);

        KeepCompiling
    }
    else {
        gen_opt_send_without_block(jit, ctx, cb, ocb)
    }
}

fn gen_opt_lt(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    gen_fixnum_cmp(jit, ctx, cb, ocb, cmovl)
}

fn gen_opt_le(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    gen_fixnum_cmp(jit, ctx, cb, ocb, cmovle)
}

fn gen_opt_ge(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    gen_fixnum_cmp(jit, ctx, cb, ocb, cmovge)
}

fn gen_opt_gt(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    gen_fixnum_cmp(jit, ctx, cb, ocb, cmovg)
}

/*
// Implements specialized equality for either two fixnum or two strings
// Returns true if code was generated, otherwise false
static bool
gen_equality_specialized(jitstate_t *jit, ctx_t *ctx, uint8_t *side_exit)
{
    VALUE comptime_a = jit_peek_at_stack(jit, ctx, 1);
    VALUE comptime_b = jit_peek_at_stack(jit, ctx, 0);

    let a_opnd = ctx.stack_opnd(1);
    let b_opnd = ctx.stack_opnd(0);

    if (FIXNUM_P(comptime_a) && FIXNUM_P(comptime_b)) {
        if (!assume_bop_not_redefined(jit, INTEGER_REDEFINED_OP_FLAG, BOP_EQ)) {
            // if overridden, emit the generic version
            return false;
        }

        guard_two_fixnums(ctx, side_exit);

        mov(cb, REG0, a_opnd);
        cmp(cb, REG0, b_opnd);

        mov(cb, REG0, imm_opnd(Qfalse));
        mov(cb, REG1, imm_opnd(Qtrue));
        cmove(cb, REG0, REG1);

        // Push the output on the stack
        ctx.stack_pop(2);
        let dst = ctx.stack_push(Type::UnknownImm);
        mov(cb, dst, REG0);

        return true;
    }
    else if (CLASS_OF(comptime_a) == rb_cString &&
            CLASS_OF(comptime_b) == rb_cString) {
        if (!assume_bop_not_redefined(jit, STRING_REDEFINED_OP_FLAG, BOP_EQ)) {
            // if overridden, emit the generic version
            return false;
        }

        // Load a and b in preparation for call later
        mov(cb, C_ARG_REGS[0], a_opnd);
        mov(cb, C_ARG_REGS[1], b_opnd);

        // Guard that a is a String
        mov(cb, REG0, C_ARG_REGS[0]);
        jit_guard_known_klass(jit, ctx, rb_cString, StackOpnd(1), comptime_a, SEND_MAX_DEPTH, side_exit);

        uint32_t ret = cb_new_label(cb, "ret");

        // If they are equal by identity, return true
        cmp(cb, C_ARG_REGS[0], C_ARG_REGS[1]);
        mov(cb, RAX, imm_opnd(Qtrue));
        je_label(cb, ret);

        // Otherwise guard that b is a T_STRING (from type info) or String (from runtime guard)
        if (ctx.get_opnd_type(StackOpnd(0)).type != ETYPE_STRING) {
            mov(cb, REG0, C_ARG_REGS[1]);
            // Note: any T_STRING is valid here, but we check for a ::String for simplicity
            jit_guard_known_klass(jit, ctx, rb_cString, StackOpnd(0), comptime_b, SEND_MAX_DEPTH, side_exit);
        }

        // Call rb_str_eql_internal(a, b)
        call_ptr(cb, REG0, (void *)rb_str_eql_internal);

        // Push the output on the stack
        cb_write_label(cb, ret);
        ctx.stack_pop(2);
        let dst = ctx.stack_push(Type::UnknownImm);
        mov(cb, dst, RAX);
        cb_link_labels(cb);

        return true;
    }
    else {
        return false;
    }
}

fn gen_opt_eq(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Defer compilation so we can specialize base on a runtime receiver
    if (!jit_at_current_insn(jit)) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    // Create a side-exit to fall back to the interpreter
    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    if (gen_equality_specialized(jit, ctx, side_exit)) {
        jit_jump_to_next_insn(jit, ctx);
        return EndBlock;
    }
    else {
        return gen_opt_send_without_block(jit, ctx, cb);
    }
}

static codegen_status_t gen_send_general(jitstate_t *jit, ctx_t *ctx, struct rb_call_data *cd, rb_iseq_t *block);

fn gen_opt_neq(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // opt_neq is passed two rb_call_data as arguments:
    // first for ==, second for !=
    struct rb_call_data *cd = (struct rb_call_data *)jit_get_arg(jit, 1);
    return gen_send_general(jit, ctx, cd, NULL);
}

fn gen_opt_aref(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    struct rb_call_data * cd = (struct rb_call_data *)jit_get_arg(jit, 0);
    int32_t argc = (int32_t)vm_ci_argc(cd->ci);

    // Only JIT one arg calls like `ary[6]`
    if (argc != 1) {
        gen_counter_incr!(cb, oaref_argc_not_one);
        return CantCompile;
    }

    // Defer compilation so we can specialize base on a runtime receiver
    if (!jit_at_current_insn(jit)) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    // Remember the context on entry for adding guard chains
    const ctx_t starting_context = *ctx;

    // Specialize base on compile time values
    VALUE comptime_idx = jit_peek_at_stack(jit, ctx, 0);
    VALUE comptime_recv = jit_peek_at_stack(jit, ctx, 1);

    // Create a side-exit to fall back to the interpreter
    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    if (CLASS_OF(comptime_recv) == rb_cArray && RB_FIXNUM_P(comptime_idx)) {
        if (!assume_bop_not_redefined(jit, ARRAY_REDEFINED_OP_FLAG, BOP_AREF)) {
            return CantCompile;
        }

        // Pop the stack operands
        let idx_opnd = ctx.stack_pop(1);
        let recv_opnd = ctx.stack_pop(1);
        mov(cb, REG0, recv_opnd);

        // if (SPECIAL_CONST_P(recv)) {
        // Bail if receiver is not a heap object
        test(cb, REG0, imm_opnd(RUBY_IMMEDIATE_MASK));
        jnz_ptr(cb, side_exit);
        cmp(cb, REG0, imm_opnd(Qfalse));
        je_ptr(cb, side_exit);
        cmp(cb, REG0, imm_opnd(Qnil));
        je_ptr(cb, side_exit);

        // Bail if recv has a class other than ::Array.
        // BOP_AREF check above is only good for ::Array.
        mov(cb, REG1, mem_opnd(64, REG0, offsetof(struct RBasic, klass)));
        mov(cb, REG0, const_ptr_opnd((void *)rb_cArray));
        cmp(cb, REG0, REG1);
        jit_chain_guard(JCC_JNE, jit, &starting_context, OPT_AREF_MAX_CHAIN_DEPTH, side_exit);

        // Bail if idx is not a FIXNUM
        mov(cb, REG1, idx_opnd);
        test(cb, REG1, imm_opnd(RUBY_FIXNUM_FLAG));
        jz_ptr(cb, counted_exit!(ocb, side_exit, oaref_arg_not_fixnum));

        // Call VALUE rb_ary_entry_internal(VALUE ary, long offset).
        // It never raises or allocates, so we don't need to write to cfp->pc.
        {
            mov(cb, RDI, recv_opnd);
            sar(cb, REG1, imm_opnd(1)); // Convert fixnum to int
            mov(cb, RSI, REG1);
            call_ptr(cb, REG0, (void *)rb_ary_entry_internal);

            // Push the return value onto the stack
            let stack_ret = ctx.stack_push(Type::Unknown);
            mov(cb, stack_ret, RAX);
        }

        // Jump to next instruction. This allows guard chains to share the same successor.
        jit_jump_to_next_insn(jit, ctx);
        return EndBlock;
    }
    else if (CLASS_OF(comptime_recv) == rb_cHash) {
        if (!assume_bop_not_redefined(jit, HASH_REDEFINED_OP_FLAG, BOP_AREF)) {
            return CantCompile;
        }

        let key_opnd = ctx.stack_opnd(0);
        let recv_opnd = ctx.stack_opnd(1);

        // Guard that the receiver is a hash
        mov(cb, REG0, recv_opnd);
        jit_guard_known_klass(jit, ctx, rb_cHash, StackOpnd(1), comptime_recv, OPT_AREF_MAX_CHAIN_DEPTH, side_exit);

        // Setup arguments for rb_hash_aref().
        mov(cb, C_ARG_REGS[0], REG0);
        mov(cb, C_ARG_REGS[1], key_opnd);

        // Prepare to call rb_hash_aref(). It might call #hash on the key.
        jit_prepare_routine_call(jit, ctx, cb, REG0);

        call_ptr(cb, REG0, (void *)rb_hash_aref);

        // Pop the key and the reciever
        (void)ctx.stack_pop(2);

        // Push the return value onto the stack
        let stack_ret = ctx.stack_push(Type::Unknown);
        mov(cb, stack_ret, RAX);

        // Jump to next instruction. This allows guard chains to share the same successor.
        jit_jump_to_next_insn(jit, ctx);
        EndBlock
    }
    else {
        // General case. Call the [] method.
        return gen_opt_send_without_block(jit, ctx, cb);
    }
}

fn gen_opt_aset(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Defer compilation so we can specialize on a runtime `self`
    if (!jit_at_current_insn(jit)) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    VALUE comptime_recv = jit_peek_at_stack(jit, ctx, 2);
    VALUE comptime_key  = jit_peek_at_stack(jit, ctx, 1);

    // Get the operands from the stack
    let recv = ctx.stack_opnd(2);
    let key = ctx.stack_opnd(1);
    let val = ctx.stack_opnd(0);

    if (CLASS_OF(comptime_recv) == rb_cArray && FIXNUM_P(comptime_key)) {
        uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

        // Guard receiver is an Array
        mov(cb, REG0, recv);
        jit_guard_known_klass(jit, ctx, rb_cArray, StackOpnd(2), comptime_recv, SEND_MAX_DEPTH, side_exit);

        // Guard key is a fixnum
        mov(cb, REG0, key);
        jit_guard_known_klass(jit, ctx, rb_cInteger, StackOpnd(1), comptime_key, SEND_MAX_DEPTH, side_exit);

        // Call rb_ary_store
        mov(cb, C_ARG_REGS[0], recv);
        mov(cb, C_ARG_REGS[1], key);
        sar(cb, C_ARG_REGS[1], imm_opnd(1)); // FIX2LONG(key)
        mov(cb, C_ARG_REGS[2], val);

        // We might allocate or raise
        jit_prepare_routine_call(jit, ctx, cb, REG0);

        call_ptr(cb, REG0, (void *)rb_ary_store);

        // rb_ary_store returns void
        // stored value should still be on stack
        mov(cb, REG0, ctx.stack_opnd(0));

        // Push the return value onto the stack
        ctx.stack_pop(3);
        let stack_ret = ctx.stack_push(Type::Unknown);
        mov(cb, stack_ret, REG0);

        jit_jump_to_next_insn(jit, ctx);
        return EndBlock;
    }
    else if (CLASS_OF(comptime_recv) == rb_cHash) {
        uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

        // Guard receiver is a Hash
        mov(cb, REG0, recv);
        jit_guard_known_klass(jit, ctx, rb_cHash, StackOpnd(2), comptime_recv, SEND_MAX_DEPTH, side_exit);

        // Call rb_hash_aset
        mov(cb, C_ARG_REGS[0], recv);
        mov(cb, C_ARG_REGS[1], key);
        mov(cb, C_ARG_REGS[2], val);

        // We might allocate or raise
        jit_prepare_routine_call(jit, ctx, cb, REG0);

        call_ptr(cb, REG0, (void *)rb_hash_aset);

        // Push the return value onto the stack
        ctx.stack_pop(3);
        let stack_ret = ctx.stack_push(Type::Unknown);
        mov(cb, stack_ret, RAX);

        jit_jump_to_next_insn(jit, ctx);
        EndBlock
    }
    else {
        return gen_opt_send_without_block(jit, ctx, cb);
    }
}
*/

fn gen_opt_and(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Defer compilation so we can specialize on a runtime `self`
    if !jit_at_current_insn(jit) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    let comptime_a = jit_peek_at_stack(jit, ctx, 1);
    let comptime_b = jit_peek_at_stack(jit, ctx, 0);

    if comptime_a.fixnum_p() && comptime_b.fixnum_p() {
        // Create a side-exit to fall back to the interpreter
        // Note: we generate the side-exit before popping operands from the stack
        let side_exit = get_side_exit(jit, ocb, ctx);

        /*
        if (!assume_bop_not_redefined(jit, INTEGER_REDEFINED_OP_FLAG, BOP_AND)) {
            return CantCompile;
        }
        */

        // Check that both operands are fixnums
        guard_two_fixnums(ctx, cb, side_exit);

        // Get the operands and destination from the stack
        let arg1 = ctx.stack_pop(1);
        let arg0 = ctx.stack_pop(1);

        // Do the bitwise and arg0 & arg1
        mov(cb, REG0, arg0);
        and(cb, REG0, arg1);

        // Push the output on the stack
        let dst = ctx.stack_push(Type::Fixnum);
        mov(cb, dst, REG0);

        KeepCompiling
    }
    else {
        // Delegate to send, call the method on the recv
        gen_opt_send_without_block(jit, ctx, cb, ocb)
    }
}

fn gen_opt_or(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Defer compilation so we can specialize on a runtime `self`
    if !jit_at_current_insn(jit) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    let comptime_a = jit_peek_at_stack(jit, ctx, 1);
    let comptime_b = jit_peek_at_stack(jit, ctx, 0);

    if comptime_a.fixnum_p() && comptime_b.fixnum_p() {
        // Create a side-exit to fall back to the interpreter
        // Note: we generate the side-exit before popping operands from the stack
        let side_exit = get_side_exit(jit, ocb, ctx);

        /*
        if (!assume_bop_not_redefined(jit, INTEGER_REDEFINED_OP_FLAG, BOP_OR)) {
            return CantCompile;
        }
        */

        // Check that both operands are fixnums
        guard_two_fixnums(ctx, cb, side_exit);

        // Get the operands and destination from the stack
        let arg1 = ctx.stack_pop(1);
        let arg0 = ctx.stack_pop(1);

        // Do the bitwise or arg0 | arg1
        mov(cb, REG0, arg0);
        or(cb, REG0, arg1);

        // Push the output on the stack
        let dst = ctx.stack_push(Type::Fixnum);
        mov(cb, dst, REG0);

        KeepCompiling
    }
    else {
        // Delegate to send, call the method on the recv
        gen_opt_send_without_block(jit, ctx, cb, ocb)
    }
}

fn gen_opt_minus(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Defer compilation so we can specialize on a runtime `self`
    if !jit_at_current_insn(jit) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    let comptime_a = jit_peek_at_stack(jit, ctx, 1);
    let comptime_b = jit_peek_at_stack(jit, ctx, 0);

    if comptime_a.fixnum_p() && comptime_b.fixnum_p() {
        // Create a side-exit to fall back to the interpreter
        // Note: we generate the side-exit before popping operands from the stack
        let side_exit = get_side_exit(jit, ocb, ctx);

        /*
        if (!assume_bop_not_redefined(jit, INTEGER_REDEFINED_OP_FLAG, BOP_MINUS)) {
            return CantCompile;
        }
        */

        // Check that both operands are fixnums
        guard_two_fixnums(ctx, cb, side_exit);

        // Get the operands and destination from the stack
        let arg1 = ctx.stack_pop(1);
        let arg0 = ctx.stack_pop(1);

        // Subtract arg0 - arg1 and test for overflow
        mov(cb, REG0, arg0);
        sub(cb, REG0, arg1);
        jo_ptr(cb, side_exit);
        add(cb, REG0, imm_opnd(1));

        // Push the output on the stack
        let dst = ctx.stack_push(Type::Fixnum);
        mov(cb, dst, REG0);

        KeepCompiling
    }
    else {
        // Delegate to send, call the method on the recv
        gen_opt_send_without_block(jit, ctx, cb, ocb)
    }
}

/*
fn gen_opt_mult(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Delegate to send, call the method on the recv
    return gen_opt_send_without_block(jit, ctx, cb);
}

fn gen_opt_div(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Delegate to send, call the method on the recv
    return gen_opt_send_without_block(jit, ctx, cb);
}

VALUE rb_vm_opt_mod(VALUE recv, VALUE obj);

fn gen_opt_mod(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Save the PC and SP because the callee may allocate bignums
    // Note that this modifies REG_SP, which is why we do it first
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    // Get the operands from the stack
    let arg1 = ctx.stack_pop(1);
    let arg0 = ctx.stack_pop(1);

    // Call rb_vm_opt_mod(VALUE recv, VALUE obj)
    mov(cb, C_ARG_REGS[0], arg0);
    mov(cb, C_ARG_REGS[1], arg1);
    call_ptr(cb, REG0, (void *)rb_vm_opt_mod);

    // If val == Qundef, bail to do a method call
    cmp(cb, RAX, imm_opnd(Qundef));
    je_ptr(cb, side_exit);

    // Push the return value onto the stack
    let stack_ret = ctx.stack_push(Type::Unknown);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}

fn gen_opt_ltlt(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Delegate to send, call the method on the recv
    return gen_opt_send_without_block(jit, ctx, cb);
}

fn gen_opt_nil_p(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Delegate to send, call the method on the recv
    return gen_opt_send_without_block(jit, ctx, cb);
}

fn gen_opt_empty_p(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Delegate to send, call the method on the recv
    return gen_opt_send_without_block(jit, ctx, cb);
}

fn gen_opt_str_freeze(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    if (!assume_bop_not_redefined(jit, STRING_REDEFINED_OP_FLAG, BOP_FREEZE)) {
        return CantCompile;
    }

    VALUE str = jit_get_arg(jit, 0);
    jit_mov_gc_ptr(jit, cb, REG0, str);

    // Push the return value onto the stack
    let stack_ret = ctx.stack_push(Type::String);
    mov(cb, stack_ret, REG0);

    KeepCompiling
}

fn gen_opt_str_uminus(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    if (!assume_bop_not_redefined(jit, STRING_REDEFINED_OP_FLAG, BOP_UMINUS)) {
        return CantCompile;
    }

    VALUE str = jit_get_arg(jit, 0);
    jit_mov_gc_ptr(jit, cb, REG0, str);

    // Push the return value onto the stack
    let stack_ret = ctx.stack_push(Type::String);
    mov(cb, stack_ret, REG0);

    KeepCompiling
}

fn gen_opt_not(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    return gen_opt_send_without_block(jit, ctx, cb);
}

fn gen_opt_size(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    return gen_opt_send_without_block(jit, ctx, cb);
}

fn gen_opt_length(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    return gen_opt_send_without_block(jit, ctx, cb);
}

fn gen_opt_regexpmatch2(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    return gen_opt_send_without_block(jit, ctx, cb);
}

fn gen_opt_case_dispatch(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Normally this instruction would lookup the key in a hash and jump to an
    // offset based on that.
    // Instead we can take the fallback case and continue with the next
    // instruciton.
    // We'd hope that our jitted code will be sufficiently fast without the
    // hash lookup, at least for small hashes, but it's worth revisiting this
    // assumption in the future.

    ctx.stack_pop(1);

    KeepCompiling // continue with the next instruction
}
*/

fn gen_branchif_branch(cb: &mut CodeBlock, target0: CodePtr, target1: CodePtr, shape: BranchShape)
{
    match shape {
        BranchShape::Next0 => {
            jz_ptr(cb, target1);
        },
        BranchShape::Next1 => {
            jnz_ptr(cb, target0);
        },
        BranchShape::Default => {
            jnz_ptr(cb, target0);
            jmp_ptr(cb, target1);
        }
    }
}

fn gen_branchif(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let jump_offset = jit_get_arg(jit, 0).as_i32();

    // Check for interrupts, but only on backward branches that may create loops
    if jump_offset < 0 {
        let side_exit = get_side_exit(jit, ocb, ctx);
        gen_check_ints(cb, side_exit);
    }

    // Test if any bit (outside of the Qnil bit) is on
    // RUBY_Qfalse  /* ...0000 0000 */
    // RUBY_Qnil    /* ...0000 1000 */
    let val_opnd = ctx.stack_pop(1);
    test(cb, val_opnd, imm_opnd(!Qnil.as_i64()));

    // Get the branch target instruction offsets
    let next_idx = jit_next_insn_idx(jit);
    let jump_idx = (next_idx as i32) + jump_offset;
    let next_block = BlockId { iseq: jit.iseq, idx: next_idx };
    let jump_block = BlockId { iseq: jit.iseq, idx: jump_idx as u32 };

    // Generate the branch instructions
    gen_branch(
        jit,
        ctx,
        jump_block,
        ctx,
        next_block,
        ctx,
        gen_branchif_branch
    );

    EndBlock
}

/*
static void
gen_branchunless_branch(codeblock_t *cb, uint8_t *target0, uint8_t *target1, uint8_t shape)
{
    switch (shape) {
      case SHAPE_NEXT0:
        jnz_ptr(cb, target1);
        break;

      case SHAPE_NEXT1:
        jz_ptr(cb, target0);
        break;

      case SHAPE_DEFAULT:
        jz_ptr(cb, target0);
        jmp_ptr(cb, target1);
        break;
    }
}

fn gen_branchunless(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    int32_t jump_offset = (int32_t)jit_get_arg(jit, 0);

    // Check for interrupts, but only on backward branches that may create loops
    if (jump_offset < 0) {
        uint8_t *side_exit = get_side_exit(jit, ocb, ctx);
        gen_check_ints(cb, side_exit);
    }

    // Test if any bit (outside of the Qnil bit) is on
    // RUBY_Qfalse  /* ...0000 0000 */
    // RUBY_Qnil    /* ...0000 1000 */
    let val_opnd = ctx.stack_pop(1);
    test(cb, val_opnd, imm_opnd(~Qnil));

    // Get the branch target instruction offsets
    uint32_t next_idx = jit_next_insn_idx(jit);
    uint32_t jump_idx = next_idx + jump_offset;
    blockid_t next_block = { jit->iseq, next_idx };
    blockid_t jump_block = { jit->iseq, jump_idx };

    // Generate the branch instructions
    gen_branch(
        jit,
        ctx,
        jump_block,
        ctx,
        next_block,
        ctx,
        gen_branchunless_branch
    );

    EndBlock
}

static void
gen_branchnil_branch(codeblock_t *cb, uint8_t *target0, uint8_t *target1, uint8_t shape)
{
    switch (shape) {
      case SHAPE_NEXT0:
        jne_ptr(cb, target1);
        break;

      case SHAPE_NEXT1:
        je_ptr(cb, target0);
        break;

      case SHAPE_DEFAULT:
        je_ptr(cb, target0);
        jmp_ptr(cb, target1);
        break;
    }
}

fn gen_branchnil(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    int32_t jump_offset = (int32_t)jit_get_arg(jit, 0);

    // Check for interrupts, but only on backward branches that may create loops
    if (jump_offset < 0) {
        uint8_t *side_exit = get_side_exit(jit, ocb, ctx);
        gen_check_ints(cb, side_exit);
    }

    // Test if the value is Qnil
    // RUBY_Qnil    /* ...0000 1000 */
    let val_opnd = ctx.stack_pop(1);
    cmp(cb, val_opnd, imm_opnd(Qnil));

    // Get the branch target instruction offsets
    uint32_t next_idx = jit_next_insn_idx(jit);
    uint32_t jump_idx = next_idx + jump_offset;
    blockid_t next_block = { jit->iseq, next_idx };
    blockid_t jump_block = { jit->iseq, jump_idx };

    // Generate the branch instructions
    gen_branch(
        jit,
        ctx,
        jump_block,
        ctx,
        next_block,
        ctx,
        gen_branchnil_branch
    );

    EndBlock
}
*/

fn gen_jump(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    let jump_offset = jit_get_arg(jit, 0).as_i32();

    // Check for interrupts, but only on backward branches that may create loops
    if jump_offset < 0 {
        let side_exit = get_side_exit(jit, ocb, ctx);
        gen_check_ints(cb, side_exit);
    }

    // Get the branch target instruction offsets
    let jump_idx = (jit_next_insn_idx(jit) as i32) + jump_offset;
    let jump_block = BlockId { iseq: jit.iseq, idx: jump_idx as u32 };

    // Generate the jump instruction
    gen_direct_jump(
        jit,
        ctx,
        jump_block
    );

    EndBlock
}

/*
/// Guard that self or a stack operand has the same class as `known_klass`, using
/// `sample_instance` to speculate about the shape of the runtime value.
/// FIXNUM and on-heap integers are treated as if they have distinct classes, and
/// the guard generated for one will fail for the other.
///
/// Recompile as contingency if possible, or take side exit a last resort.
static bool
jit_guard_known_klass(jitstate_t *jit, ctx_t *ctx, VALUE known_klass, insn_opnd_t insn_opnd, VALUE sample_instance, const int max_chain_depth, uint8_t *side_exit)
{
    val_type_t val_type = ctx.get_opnd_type(insn_opnd);

    if (known_klass == rb_cNilClass) {
        RUBY_ASSERT(!val_type.is_heap);
        if (val_type.type != ETYPE_NIL) {
            RUBY_ASSERT(val_type.type == ETYPE_UNKNOWN);

            add_comment(cb, "guard object is nil");
            cmp(cb, REG0, imm_opnd(Qnil));
            jit_chain_guard(JCC_JNE, jit, ctx, max_chain_depth, side_exit);

            ctx.upgrade_opnd_type(insn_opnd, Type::Nil);
        }
    }
    else if (known_klass == rb_cTrueClass) {
        RUBY_ASSERT(!val_type.is_heap);
        if (val_type.type != ETYPE_TRUE) {
            RUBY_ASSERT(val_type.type == ETYPE_UNKNOWN);

            add_comment(cb, "guard object is true");
            cmp(cb, REG0, imm_opnd(Qtrue));
            jit_chain_guard(JCC_JNE, jit, ctx, max_chain_depth, side_exit);

            ctx.upgrade_opnd_type(insn_opnd, Type::True);
        }
    }
    else if (known_klass == rb_cFalseClass) {
        RUBY_ASSERT(!val_type.is_heap);
        if (val_type.type != ETYPE_FALSE) {
            RUBY_ASSERT(val_type.type == ETYPE_UNKNOWN);

            add_comment(cb, "guard object is false");
            STATIC_ASSERT(qfalse_is_zero, Qfalse == 0);
            test(cb, REG0, REG0);
            jit_chain_guard(JCC_JNZ, jit, ctx, max_chain_depth, side_exit);

            ctx.upgrade_opnd_type(insn_opnd, Type::False);
        }
    }
    else if (known_klass == rb_cInteger && FIXNUM_P(sample_instance)) {
        RUBY_ASSERT(!val_type.is_heap);
        // We will guard fixnum and bignum as though they were separate classes
        // BIGNUM can be handled by the general else case below
        if (val_type.type != ETYPE_FIXNUM || !val_type.is_imm) {
            RUBY_ASSERT(val_type.type == ETYPE_UNKNOWN);

            add_comment(cb, "guard object is fixnum");
            test(cb, REG0, imm_opnd(RUBY_FIXNUM_FLAG));
            jit_chain_guard(JCC_JZ, jit, ctx, max_chain_depth, side_exit);
            ctx.upgrade_opnd_type(insn_opnd, Type::Fixnum);
        }
    }
    else if (known_klass == rb_cSymbol && STATIC_SYM_P(sample_instance)) {
        RUBY_ASSERT(!val_type.is_heap);
        // We will guard STATIC vs DYNAMIC as though they were separate classes
        // DYNAMIC symbols can be handled by the general else case below
        if (val_type.type != ETYPE_SYMBOL || !val_type.is_imm) {
            RUBY_ASSERT(val_type.type == ETYPE_UNKNOWN);

            add_comment(cb, "guard object is static symbol");
            STATIC_ASSERT(special_shift_is_8, RUBY_SPECIAL_SHIFT == 8);
            cmp(cb, REG0_8, imm_opnd(RUBY_SYMBOL_FLAG));
            jit_chain_guard(JCC_JNE, jit, ctx, max_chain_depth, side_exit);
            ctx.upgrade_opnd_type(insn_opnd, Type::ImmSymbol);
        }
    }
    else if (known_klass == rb_cFloat && FLONUM_P(sample_instance)) {
        RUBY_ASSERT(!val_type.is_heap);
        if (val_type.type != ETYPE_FLONUM || !val_type.is_imm) {
            RUBY_ASSERT(val_type.type == ETYPE_UNKNOWN);

            // We will guard flonum vs heap float as though they were separate classes
            add_comment(cb, "guard object is flonum");
            mov(cb, REG1, REG0);
            and(cb, REG1, imm_opnd(RUBY_FLONUM_MASK));
            cmp(cb, REG1, imm_opnd(RUBY_FLONUM_FLAG));
            jit_chain_guard(JCC_JNE, jit, ctx, max_chain_depth, side_exit);
            ctx.upgrade_opnd_type(insn_opnd, Type::Flonum);
        }
    }
    else if (FL_TEST(known_klass, FL_SINGLETON) && sample_instance == rb_attr_get(known_klass, id__attached__)) {
        // Singleton classes are attached to one specific object, so we can
        // avoid one memory access (and potentially the is_heap check) by
        // looking for the expected object directly.
        // Note that in case the sample instance has a singleton class that
        // doesn't attach to the sample instance, it means the sample instance
        // has an empty singleton class that hasn't been materialized yet. In
        // this case, comparing against the sample instance doesn't gurantee
        // that its singleton class is empty, so we can't avoid the memory
        // access. As an example, `Object.new.singleton_class` is an object in
        // this situation.
        add_comment(cb, "guard known object with singleton class");
        // TODO: jit_mov_gc_ptr keeps a strong reference, which leaks the object.
        jit_mov_gc_ptr(jit, cb, REG1, sample_instance);
        cmp(cb, REG0, REG1);
        jit_chain_guard(JCC_JNE, jit, ctx, max_chain_depth, side_exit);
    }
    else {
        RUBY_ASSERT(!val_type.is_imm);

        // Check that the receiver is a heap object
        // Note: if we get here, the class doesn't have immediate instances.
        if (!val_type.is_heap) {
            add_comment(cb, "guard not immediate");
            RUBY_ASSERT(Qfalse < Qnil);
            test(cb, REG0, imm_opnd(RUBY_IMMEDIATE_MASK));
            jit_chain_guard(JCC_JNZ, jit, ctx, max_chain_depth, side_exit);
            cmp(cb, REG0, imm_opnd(Qnil));
            jit_chain_guard(JCC_JBE, jit, ctx, max_chain_depth, side_exit);

            ctx.upgrade_opnd_type(insn_opnd, Type::UnknownHeap);
        }

        let klass_opnd = mem_opnd(64, REG0, offsetof(struct RBasic, klass));

        // Bail if receiver class is different from known_klass
        // TODO: jit_mov_gc_ptr keeps a strong reference, which leaks the class.
        add_comment(cb, "guard known class");
        jit_mov_gc_ptr(jit, cb, REG1, known_klass);
        cmp(cb, klass_opnd, REG1);
        jit_chain_guard(JCC_JNE, jit, ctx, max_chain_depth, side_exit);
    }

    return true;
}

// Generate ancestry guard for protected callee.
// Calls to protected callees only go through when self.is_a?(klass_that_defines_the_callee).
static void
jit_protected_callee_ancestry_guard(jitstate_t *jit, codeblock_t *cb, const rb_callable_method_entry_t *cme, uint8_t *side_exit)
{
    // See vm_call_method().
    mov(cb, C_ARG_REGS[0], member_opnd(REG_CFP, rb_control_frame_t, self));
    jit_mov_gc_ptr(jit, cb, C_ARG_REGS[1], cme->defined_class);
    // Note: PC isn't written to current control frame as rb_is_kind_of() shouldn't raise.
    // VALUE rb_obj_is_kind_of(VALUE obj, VALUE klass);
    call_ptr(cb, REG0, (void *)&rb_obj_is_kind_of);
    test(cb, RAX, RAX);
    jz_ptr(cb, counted_exit!(ocb, side_exit, send_se_protected_check_failed));
}

// Return true when the codegen function generates code.
// known_recv_klass is non-NULL when the caller has used jit_guard_known_klass().
// See yjit_reg_method().
typedef bool (*method_codegen_t)(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *known_recv_klass);

// Register a specialized codegen function for a particular method. Note that
// the if the function returns true, the code it generates runs without a
// control frame and without interrupt checks. To avoid creating observable
// behavior changes, the codegen function should only target simple code paths
// that do not allocate and do not make method calls.
static void
yjit_reg_method(VALUE klass, const char *mid_str, method_codegen_t gen_fn)
{
    ID mid = rb_intern(mid_str);
    const rb_method_entry_t *me = rb_method_entry_at(klass, mid);

    if (!me) {
        rb_bug("undefined optimized method: %s", rb_id2name(mid));
    }

    // For now, only cfuncs are supported
    RUBY_ASSERT(me && me->def);
    RUBY_ASSERT(me->def->type == VM_METHOD_TYPE_CFUNC);

    st_insert(yjit_method_codegen_table, (st_data_t)me->def->method_serial, (st_data_t)gen_fn);
}

// Codegen for rb_obj_not().
// Note, caller is responsible for generating all the right guards, including
// arity guards.
static bool
jit_rb_obj_not(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *known_recv_klass)
{
    const val_type_t recv_opnd = ctx.get_opnd_type(StackOpnd(0));

    if (recv_opnd.type == ETYPE_NIL || recv_opnd.type == ETYPE_FALSE) {
        add_comment(cb, "rb_obj_not(nil_or_false)");
        ctx.stack_pop(1);
        let out_opnd = ctx.stack_push(Type::True);
        mov(cb, out_opnd, imm_opnd(Qtrue));
    }
    else if (recv_opnd.is_heap || recv_opnd.type != ETYPE_UNKNOWN) {
        // Note: recv_opnd.type != ETYPE_NIL && recv_opnd.type != ETYPE_FALSE.
        add_comment(cb, "rb_obj_not(truthy)");
        ctx.stack_pop(1);
        let out_opnd = ctx.stack_push(Type::False);
        mov(cb, out_opnd, imm_opnd(Qfalse));
    }
    else {
        // jit_guard_known_klass() already ran on the receiver which should
        // have deduced deduced the type of the receiver. This case should be
        // rare if not unreachable.
        return false;
    }
    return true;
}

// Codegen for rb_true()
static bool
jit_rb_true(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *known_recv_klass)
{
    add_comment(cb, "nil? == true");
    ctx.stack_pop(1);
    let stack_ret = ctx.stack_push(Type::True);
    mov(cb, stack_ret, imm_opnd(Qtrue));
    return true;
}

// Codegen for rb_false()
static bool
jit_rb_false(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *known_recv_klass)
{
    add_comment(cb, "nil? == false");
    ctx.stack_pop(1);
    let stack_ret = ctx.stack_push(Type::False);
    mov(cb, stack_ret, imm_opnd(Qfalse));
    return true;
}

// Codegen for rb_obj_equal()
// object identity comparison
static bool
jit_rb_obj_equal(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *known_recv_klass)
{
    add_comment(cb, "equal?");
    let obj1 = ctx.stack_pop(1);
    let obj2 = ctx.stack_pop(1);

    mov(cb, REG0, obj1);
    cmp(cb, REG0, obj2);
    mov(cb, REG0, imm_opnd(Qtrue));
    mov(cb, REG1, imm_opnd(Qfalse));
    cmovne(cb, REG0, REG1);

    let stack_ret = ctx.stack_push(Type::UnknownImm);
    mov(cb, stack_ret, REG0);
    return true;
}

static VALUE
yjit_str_bytesize(VALUE str)
{
    return LONG2NUM(RSTRING_LEN(str));
}

static bool
jit_rb_str_bytesize(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *known_recv_klass)
{
    add_comment(cb, "String#bytesize");

    let recv = ctx.stack_pop(1);
    mov(cb, C_ARG_REGS[0], recv);
    call_ptr(cb, REG0, (void *)&yjit_str_bytesize);

    let out_opnd = ctx.stack_push(Type::Fixnum);
    mov(cb, out_opnd, RAX);

    return true;
}

// Codegen for rb_str_to_s()
// When String#to_s is called on a String instance, the method returns self and
// most of the overhead comes from setting up the method call. We observed that
// this situation happens a lot in some workloads.
static bool
jit_rb_str_to_s(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *recv_known_klass)
{
    if (recv_known_klass && *recv_known_klass == rb_cString) {
        add_comment(cb, "to_s on plain string");
        // The method returns the receiver, which is already on the stack.
        // No stack movement.
        return true;
    }
    return false;
}

static bool
jit_thread_s_current(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *recv_known_klass)
{
    add_comment(cb, "Thread.current");
    ctx.stack_pop(1);

    // ec->thread_ptr
    mov(cb, REG0, member_opnd(REG_EC, rb_execution_context_t, thread_ptr));

    // thread->self
    mov(cb, REG0, member_opnd(REG0, rb_thread_t, self));

    let stack_ret = ctx.stack_push(Type::UnknownHeap);
    mov(cb, stack_ret, REG0);
    return true;
}

// Check if we know how to codegen for a particular cfunc method
static method_codegen_t
lookup_cfunc_codegen(const rb_method_definition_t *def)
{
    method_codegen_t gen_fn;
    if (st_lookup(yjit_method_codegen_table, def->method_serial, (st_data_t *)&gen_fn)) {
        return gen_fn;
    }
    return NULL;
}

// Is anyone listening for :c_call and :c_return event currently?
static bool
c_method_tracing_currently_enabled(const jitstate_t *jit)
{
    rb_event_flag_t tracing_events;
    if (rb_multi_ractor_p()) {
        tracing_events = ruby_vm_event_enabled_global_flags;
    }
    else {
        // At the time of writing, events are never removed from
        // ruby_vm_event_enabled_global_flags so always checking using it would
        // mean we don't compile even after tracing is disabled.
        tracing_events = rb_ec_ractor_hooks(jit->ec)->events;
    }

    return tracing_events & (RUBY_EVENT_C_CALL | RUBY_EVENT_C_RETURN);
}

fn gen_send_cfunc(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, const int32_t argc, VALUE *recv_known_klass)
{
    const rb_method_cfunc_t *cfunc = UNALIGNED_MEMBER_PTR(cme->def, body.cfunc);

    // If the function expects a Ruby array of arguments
    if (cfunc->argc < 0 && cfunc->argc != -1) {
        gen_counter_incr!(cb, send_cfunc_ruby_array_varg);
        return CantCompile;
    }

    // If the argument count doesn't match
    if (cfunc->argc >= 0 && cfunc->argc != argc) {
        gen_counter_incr!(cb, send_cfunc_argc_mismatch);
        return CantCompile;
    }

    // Don't JIT functions that need C stack arguments for now
    if (cfunc->argc >= 0 && argc + 1 > NUM_C_ARG_REGS) {
        gen_counter_incr!(cb, send_cfunc_toomany_args);
        return CantCompile;
    }

    if (c_method_tracing_currently_enabled(jit)) {
        // Don't JIT if tracing c_call or c_return
        gen_counter_incr!(cb, send_cfunc_tracing);
        return CantCompile;
    }

    // Delegate to codegen for C methods if we have it.
    {
        method_codegen_t known_cfunc_codegen;
        if ((known_cfunc_codegen = lookup_cfunc_codegen(cme->def))) {
            if (known_cfunc_codegen(jit, ctx, ci, cme, block, argc, recv_known_klass)) {
                // cfunc codegen generated code. Terminate the block so
                // there isn't multiple calls in the same block.
                jit_jump_to_next_insn(jit, ctx);
                return EndBlock;
            }
        }
    }

    // Callee method ID
    //ID mid = vm_ci_mid(ci);
    //printf("JITting call to C function \"%s\", argc: %lu\n", rb_id2name(mid), argc);
    //print_str(cb, "");
    //print_str(cb, "calling CFUNC:");
    //print_str(cb, rb_id2name(mid));
    //print_str(cb, "recv");
    //print_ptr(cb, recv);

    // Create a side-exit to fall back to the interpreter
    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    // Check for interrupts
    gen_check_ints(cb, side_exit);

    // Stack overflow check
    // #define CHECK_VM_STACK_OVERFLOW0(cfp, sp, margin)
    // REG_CFP <= REG_SP + 4 * SIZEOF_VALUE + sizeof(rb_control_frame_t)
    lea(cb, REG0, ctx.sp_opnd(SIZEOF_VALUE * 4 + 2 * sizeof(rb_control_frame_t)));
    cmp(cb, REG_CFP, REG0);
    jle_ptr(cb, counted_exit!(ocb, side_exit, send_se_cf_overflow));

    // Points to the receiver operand on the stack
    let recv = ctx.stack_opnd(argc);

    // Store incremented PC into current control frame in case callee raises.
    jit_save_pc(jit, REG0);

    if (block) {
        // Change cfp->block_code in the current frame. See vm_caller_setup_arg_block().
        // VM_CFP_TO_CAPTURED_BLCOK does &cfp->self, rb_captured_block->code.iseq aliases
        // with cfp->block_code.
        jit_mov_gc_ptr(jit, cb, REG0, (VALUE)block);
        mov(cb, member_opnd(REG_CFP, rb_control_frame_t, block_code), REG0);
    }

    // Increment the stack pointer by 3 (in the callee)
    // sp += 3
    lea(cb, REG0, ctx.sp_opnd(SIZEOF_VALUE * 3));

    // Write method entry at sp[-3]
    // sp[-3] = me;
    // Put compile time cme into REG1. It's assumed to be valid because we are notified when
    // any cme we depend on become outdated. See rb_yjit_method_lookup_change().
    jit_mov_gc_ptr(jit, cb, REG1, (VALUE)cme);
    mov(cb, mem_opnd(64, REG0, 8 * -3), REG1);

    // Write block handler at sp[-2]
    // sp[-2] = block_handler;
    if (block) {
        // reg1 = VM_BH_FROM_ISEQ_BLOCK(VM_CFP_TO_CAPTURED_BLOCK(reg_cfp));
        lea(cb, REG1, member_opnd(REG_CFP, rb_control_frame_t, self));
        or(cb, REG1, imm_opnd(1));
        mov(cb, mem_opnd(64, REG0, 8 * -2), REG1);
    }
    else {
        mov(cb, mem_opnd(64, REG0, 8 * -2), imm_opnd(VM_BLOCK_HANDLER_NONE));
    }

    // Write env flags at sp[-1]
    // sp[-1] = frame_type;
    uint64_t frame_type = VM_FRAME_MAGIC_CFUNC | VM_FRAME_FLAG_CFRAME | VM_ENV_FLAG_LOCAL;
    mov(cb, mem_opnd(64, REG0, 8 * -1), imm_opnd(frame_type));

    // Allocate a new CFP (ec->cfp--)
    sub(
        cb,
        member_opnd(REG_EC, rb_execution_context_t, cfp),
        imm_opnd(sizeof(rb_control_frame_t))
    );

    // Setup the new frame
    // *cfp = (const struct rb_control_frame_struct) {
    //    .pc         = 0,
    //    .sp         = sp,
    //    .iseq       = 0,
    //    .self       = recv,
    //    .ep         = sp - 1,
    //    .block_code = 0,
    //    .__bp__     = sp,
    // };
    mov(cb, REG1, member_opnd(REG_EC, rb_execution_context_t, cfp));
    mov(cb, member_opnd(REG1, rb_control_frame_t, pc), imm_opnd(0));
    mov(cb, member_opnd(REG1, rb_control_frame_t, sp), REG0);
    mov(cb, member_opnd(REG1, rb_control_frame_t, iseq), imm_opnd(0));
    mov(cb, member_opnd(REG1, rb_control_frame_t, block_code), imm_opnd(0));
    mov(cb, member_opnd(REG1, rb_control_frame_t, __bp__), REG0);
    sub(cb, REG0, imm_opnd(SIZEOF_VALUE));
    mov(cb, member_opnd(REG1, rb_control_frame_t, ep), REG0);
    mov(cb, REG0, recv);
    mov(cb, member_opnd(REG1, rb_control_frame_t, self), REG0);

    // Verify that we are calling the right function
    if (YJIT_CHECK_MODE > 0) {
        // Call check_cfunc_dispatch
        mov(cb, C_ARG_REGS[0], recv);
        jit_mov_gc_ptr(jit, cb, C_ARG_REGS[1], (VALUE)ci);
        mov(cb, C_ARG_REGS[2], const_ptr_opnd((void *)cfunc->func));
        jit_mov_gc_ptr(jit, cb, C_ARG_REGS[3], (VALUE)cme);
        call_ptr(cb, REG0, (void *)&check_cfunc_dispatch);
    }

    // Copy SP into RAX because REG_SP will get overwritten
    lea(cb, RAX, ctx.sp_opnd(0));

    // Pop the C function arguments from the stack (in the caller)
    ctx.stack_pop(argc + 1);

    // Write interpreter SP into CFP.
    // Needed in case the callee yields to the block.
    jit_save_sp(jit, ctx);

    // Non-variadic method
    if (cfunc->argc >= 0) {
        // Copy the arguments from the stack to the C argument registers
        // self is the 0th argument and is at index argc from the stack top
        for (int32_t i = 0; i < argc + 1; ++i)
        {
            let stack_opnd = mem_opnd(64, RAX, -(argc + 1 - i) * SIZEOF_VALUE);
            let c_arg_reg = C_ARG_REGS[i];
            mov(cb, c_arg_reg, stack_opnd);
        }
    }
    // Variadic method
    if (cfunc->argc == -1) {
        // The method gets a pointer to the first argument
        // rb_f_puts(int argc, VALUE *argv, VALUE recv)
        mov(cb, C_ARG_REGS[0], imm_opnd(argc));
        lea(cb, C_ARG_REGS[1], mem_opnd(64, RAX, -(argc) * SIZEOF_VALUE));
        mov(cb, C_ARG_REGS[2], mem_opnd(64, RAX, -(argc + 1) * SIZEOF_VALUE));
    }

    // Call the C function
    // VALUE ret = (cfunc->func)(recv, argv[0], argv[1]);
    // cfunc comes from compile-time cme->def, which we assume to be stable.
    // Invalidation logic is in rb_yjit_method_lookup_change()
    call_ptr(cb, REG0, (void*)cfunc->func);

    // Record code position for TracePoint patching. See full_cfunc_return().
    record_global_inval_patch(cb, outline_full_cfunc_return_pos);

    // Push the return value on the Ruby stack
    let stack_ret = ctx.stack_push(Type::Unknown);
    mov(cb, stack_ret, RAX);

    // Pop the stack frame (ec->cfp++)
    add(
        cb,
        member_opnd(REG_EC, rb_execution_context_t, cfp),
        imm_opnd(sizeof(rb_control_frame_t))
    );

    // cfunc calls may corrupt types
    ctx.clear_local_types();

    // Note: the return block of gen_send_iseq() has ctx->sp_offset == 1
    // which allows for sharing the same successor.

    // Jump (fall through) to the call continuation block
    // We do this to end the current block after the call
    jit_jump_to_next_insn(jit, ctx);
    EndBlock
}

static void
gen_return_branch(codeblock_t *cb, uint8_t *target0, uint8_t *target1, uint8_t shape)
{
    switch (shape) {
      case SHAPE_NEXT0:
      case SHAPE_NEXT1:
        RUBY_ASSERT(false);
        break;

      case SHAPE_DEFAULT:
        mov(cb, REG0, const_ptr_opnd(target0));
        mov(cb, member_opnd(REG_CFP, rb_control_frame_t, jit_return), REG0);
        break;
    }
}

// Returns whether the iseq only needs positional (lead) argument setup.
static bool
iseq_lead_only_arg_setup_p(const rb_iseq_t *iseq)
{
    // When iseq->body->local_iseq == iseq, setup_parameters_complex()
    // doesn't do anything to setup the block parameter.
    bool takes_block = iseq->body->param.flags.has_block;
    return (!takes_block || iseq->body->local_iseq == iseq) &&
        iseq->body->param.flags.has_opt          == false &&
        iseq->body->param.flags.has_rest         == false &&
        iseq->body->param.flags.has_post         == false &&
        iseq->body->param.flags.has_kw           == false &&
        iseq->body->param.flags.has_kwrest       == false &&
        iseq->body->param.flags.accepts_no_kwarg == false;
}

bool rb_iseq_only_optparam_p(const rb_iseq_t *iseq);
bool rb_iseq_only_kwparam_p(const rb_iseq_t *iseq);

// If true, the iseq is leaf and it can be replaced by a single C call.
static bool
rb_leaf_invokebuiltin_iseq_p(const rb_iseq_t *iseq)
{
    unsigned int invokebuiltin_len = insn_len(BIN(opt_invokebuiltin_delegate_leave));
    unsigned int leave_len = insn_len(BIN(leave));

    return (iseq->body->iseq_size == (invokebuiltin_len + leave_len) &&
        rb_vm_insn_addr2opcode((void *)iseq->body->iseq_encoded[0]) == BIN(opt_invokebuiltin_delegate_leave) &&
        rb_vm_insn_addr2opcode((void *)iseq->body->iseq_encoded[invokebuiltin_len]) == BIN(leave) &&
        iseq->body->builtin_inline_p
    );
 }

// Return an rb_builtin_function if the iseq contains only that leaf builtin function.
static const struct rb_builtin_function*
rb_leaf_builtin_function(const rb_iseq_t *iseq)
{
    if (!rb_leaf_invokebuiltin_iseq_p(iseq))
        return NULL;
    return (const struct rb_builtin_function *)iseq->body->iseq_encoded[1];
}

fn gen_send_iseq(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, rb_iseq_t *block, int32_t argc)
{
    const rb_iseq_t *iseq = def_iseq_ptr(cme->def);

    // When you have keyword arguments, there is an extra object that gets
    // placed on the stack the represents a bitmap of the keywords that were not
    // specified at the call site. We need to keep track of the fact that this
    // value is present on the stack in order to properly set up the callee's
    // stack pointer.
    bool doing_kw_call = false;

    if (vm_ci_flag(ci) & VM_CALL_TAILCALL) {
        // We can't handle tailcalls
        gen_counter_incr!(cb, send_iseq_tailcall);
        return CantCompile;
    }

    // Arity handling and optional parameter setup
    int num_params = iseq->body->param.size;
    uint32_t start_pc_offset = 0;

    if (iseq_lead_only_arg_setup_p(iseq)) {
        // If we have keyword arguments being passed to a callee that only takes
        // positionals, then we need to allocate a hash. For now we're going to
        // call that too complex and bail.
        if (vm_ci_flag(ci) & VM_CALL_KWARG) {
            gen_counter_incr!(cb, send_iseq_complex_callee);
            return CantCompile;
        }

        num_params = iseq->body->param.lead_num;

        if (num_params != argc) {
            gen_counter_incr!(cb, send_iseq_arity_error);
            return CantCompile;
        }
    }
    else if (rb_iseq_only_optparam_p(iseq)) {
        // If we have keyword arguments being passed to a callee that only takes
        // positionals and optionals, then we need to allocate a hash. For now
        // we're going to call that too complex and bail.
        if (vm_ci_flag(ci) & VM_CALL_KWARG) {
            gen_counter_incr!(cb, send_iseq_complex_callee);
            return CantCompile;
        }

        // These are iseqs with 0 or more required parameters followed by 1
        // or more optional parameters.
        // We follow the logic of vm_call_iseq_setup_normal_opt_start()
        // and these are the preconditions required for using that fast path.
        RUBY_ASSERT(vm_ci_markable(ci) && ((vm_ci_flag(ci) &
                        (VM_CALL_KW_SPLAT | VM_CALL_KWARG | VM_CALL_ARGS_SPLAT)) == 0));

        const int required_num = iseq->body->param.lead_num;
        const int opts_filled = argc - required_num;
        const int opt_num = iseq->body->param.opt_num;

        if (opts_filled < 0 || opts_filled > opt_num) {
            gen_counter_incr!(cb, send_iseq_arity_error);
            return CantCompile;
        }

        num_params -= opt_num - opts_filled;
        start_pc_offset = (uint32_t)iseq->body->param.opt_table[opts_filled];
    }
    else if (rb_iseq_only_kwparam_p(iseq)) {
        const int lead_num = iseq->body->param.lead_num;

        doing_kw_call = true;

        // Here we're calling a method with keyword arguments and specifying
        // keyword arguments at this call site.

        // This struct represents the metadata about the caller-specified
        // keyword arguments.
        const struct rb_callinfo_kwarg *kw_arg = vm_ci_kwarg(ci);

        // This struct represents the metadata about the callee-specified
        // keyword parameters.
        const struct rb_iseq_param_keyword *keyword = iseq->body->param.keyword;

        if (keyword->num > 30) {
            // We have so many keywords that (1 << num) encoded as a FIXNUM
            // (which shifts it left one more) no longer fits inside a 32-bit
            // immediate.
            gen_counter_incr!(cb, send_iseq_complex_callee);
            return CantCompile;
        }

        if (vm_ci_flag(ci) & VM_CALL_KWARG) {
            // Check that the size of non-keyword arguments matches
            if (lead_num != argc - kw_arg->keyword_len) {
                gen_counter_incr!(cb, send_iseq_complex_callee);
                return CantCompile;
            }

            // This is the list of keyword arguments that the callee specified
            // in its initial declaration.
            const ID *callee_kwargs = keyword->table;

            // Here we're going to build up a list of the IDs that correspond to
            // the caller-specified keyword arguments. If they're not in the
            // same order as the order specified in the callee declaration, then
            // we're going to need to generate some code to swap values around
            // on the stack.
            ID *caller_kwargs = ALLOCA_N(VALUE, kw_arg->keyword_len);
            for (int kwarg_idx = 0; kwarg_idx < kw_arg->keyword_len; kwarg_idx++)
                caller_kwargs[kwarg_idx] = SYM2ID(kw_arg->keywords[kwarg_idx]);

            // First, we're going to be sure that the names of every
            // caller-specified keyword argument correspond to a name in the
            // list of callee-specified keyword parameters.
            for (int caller_idx = 0; caller_idx < kw_arg->keyword_len; caller_idx++) {
                int callee_idx;

                for (callee_idx = 0; callee_idx < keyword->num; callee_idx++) {
                    if (caller_kwargs[caller_idx] == callee_kwargs[callee_idx]) {
                        break;
                    }
                }

                // If the keyword was never found, then we know we have a
                // mismatch in the names of the keyword arguments, so we need to
                // bail.
                if (callee_idx == keyword->num) {
                    gen_counter_incr!(cb, send_iseq_kwargs_mismatch);
                    return CantCompile;
                }
            }
        }
        else if (argc == lead_num) {
            // Here we are calling a method that accepts keyword arguments
            // (optional or required) but we're not passing any keyword
            // arguments at this call site

            if (keyword->required_num != 0) {
                // If any of the keywords are required this is a mismatch
                gen_counter_incr!(cb, send_iseq_kwargs_mismatch);
                return CantCompile;
            }

            doing_kw_call = true;
        }
        else {
            gen_counter_incr!(cb, send_iseq_complex_callee);
            return CantCompile;
        }
    }
    else {
        // Only handle iseqs that have simple parameter setup.
        // See vm_callee_setup_arg().
        gen_counter_incr!(cb, send_iseq_complex_callee);
        return CantCompile;
    }

    // Number of locals that are not parameters
    const int num_locals = iseq->body->local_table_size - num_params;

    // Create a side-exit to fall back to the interpreter
    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    // Check for interrupts
    gen_check_ints(cb, side_exit);

    const struct rb_builtin_function *leaf_builtin = rb_leaf_builtin_function(iseq);

    if (leaf_builtin && !block && leaf_builtin->argc + 1 <= NUM_C_ARG_REGS) {
        add_comment(cb, "inlined leaf builtin");

        // Call the builtin func (ec, recv, arg1, arg2, ...)
        mov(cb, C_ARG_REGS[0], REG_EC);

        // Copy self and arguments
        for (int32_t i = 0; i < leaf_builtin->argc + 1; i++) {
            let stack_opnd = ctx.stack_opnd(leaf_builtin->argc - i);
            let c_arg_reg = C_ARG_REGS[i + 1];
            mov(cb, c_arg_reg, stack_opnd);
        }
        ctx.stack_pop(leaf_builtin->argc + 1);
        call_ptr(cb, REG0, (void *)leaf_builtin->func_ptr);

        // Push the return value
        let stack_ret = ctx.stack_push(Type::Unknown);
        mov(cb, stack_ret, RAX);

        // Note: assuming that the leaf builtin doesn't change local variables here.
        // Seems like a safe assumption.

        KeepCompiling
    }

    // Stack overflow check
    // Note that vm_push_frame checks it against a decremented cfp, hence the multiply by 2.
    // #define CHECK_VM_STACK_OVERFLOW0(cfp, sp, margin)
    add_comment(cb, "stack overflow check");
    lea(cb, REG0, ctx.sp_opnd(SIZEOF_VALUE * (num_locals + iseq->body->stack_max) + 2 * sizeof(rb_control_frame_t)));
    cmp(cb, REG_CFP, REG0);
    jle_ptr(cb, counted_exit!(ocb, side_exit, send_se_cf_overflow));

    if (doing_kw_call) {
        // Here we're calling a method with keyword arguments and specifying
        // keyword arguments at this call site.
        const int lead_num = iseq->body->param.lead_num;

        // This struct represents the metadata about the caller-specified
        // keyword arguments.
        int caller_keyword_len = 0;
        const VALUE *caller_keywords = NULL;
        if (vm_ci_kwarg(ci)) {
            caller_keyword_len = vm_ci_kwarg(ci)->keyword_len;
            caller_keywords = &vm_ci_kwarg(ci)->keywords[0];
        }

        // This struct represents the metadata about the callee-specified
        // keyword parameters.
        const struct rb_iseq_param_keyword *keyword = iseq->body->param.keyword;

        add_comment(cb, "keyword args");

        // This is the list of keyword arguments that the callee specified
        // in its initial declaration.
        const ID *callee_kwargs = keyword->table;

        int total_kwargs = keyword->num;

        // Here we're going to build up a list of the IDs that correspond to
        // the caller-specified keyword arguments. If they're not in the
        // same order as the order specified in the callee declaration, then
        // we're going to need to generate some code to swap values around
        // on the stack.
        ID *caller_kwargs = ALLOCA_N(VALUE, total_kwargs);
        int kwarg_idx;
        for (kwarg_idx = 0; kwarg_idx < caller_keyword_len; kwarg_idx++) {
                caller_kwargs[kwarg_idx] = SYM2ID(caller_keywords[kwarg_idx]);
        }

        int unspecified_bits = 0;

        for (int callee_idx = keyword->required_num; callee_idx < total_kwargs; callee_idx++) {
            bool already_passed = false;
            ID callee_kwarg = callee_kwargs[callee_idx];

            for (int caller_idx = 0; caller_idx < caller_keyword_len; caller_idx++) {
                if (caller_kwargs[caller_idx] == callee_kwarg) {
                    already_passed = true;
                    break;
                }
            }

            if (!already_passed) {
                // Reserve space on the stack for each default value we'll be
                // filling in (which is done in the next loop). Also increments
                // argc so that the callee's SP is recorded correctly.
                argc++;
                let default_arg = ctx.stack_push(Type::Unknown);
                VALUE default_value = keyword->default_values[callee_idx - keyword->required_num];

                if (default_value == Qundef) {
                    // Qundef means that this value is not constant and must be
                    // recalculated at runtime, so we record it in unspecified_bits
                    // (Qnil is then used as a placeholder instead of Qundef).
                    unspecified_bits |= 0x01 << (callee_idx - keyword->required_num);
                    default_value = Qnil;
                }

                mov(cb, default_arg, imm_opnd(default_value));

                caller_kwargs[kwarg_idx++] = callee_kwarg;
            }
        }
        RUBY_ASSERT(kwarg_idx == total_kwargs);

        // Next, we're going to loop through every keyword that was
        // specified by the caller and make sure that it's in the correct
        // place. If it's not we're going to swap it around with another one.
        for (kwarg_idx = 0; kwarg_idx < total_kwargs; kwarg_idx++) {
            ID callee_kwarg = callee_kwargs[kwarg_idx];

            // If the argument is already in the right order, then we don't
            // need to generate any code since the expected value is already
            // in the right place on the stack.
            if (callee_kwarg == caller_kwargs[kwarg_idx]) continue;

            // In this case the argument is not in the right place, so we
            // need to find its position where it _should_ be and swap with
            // that location.
            for (int swap_idx = kwarg_idx + 1; swap_idx < total_kwargs; swap_idx++) {
                if (callee_kwarg == caller_kwargs[swap_idx]) {
                    // First we're going to generate the code that is going
                    // to perform the actual swapping at runtime.
                    stack_swap(ctx, cb, argc - 1 - swap_idx - lead_num, argc - 1 - kwarg_idx - lead_num, REG1, REG0);

                    // Next we're going to do some bookkeeping on our end so
                    // that we know the order that the arguments are
                    // actually in now.
                    ID tmp = caller_kwargs[kwarg_idx];
                    caller_kwargs[kwarg_idx] = caller_kwargs[swap_idx];
                    caller_kwargs[swap_idx] = tmp;

                    break;
                }
            }
        }

        // Keyword arguments cause a special extra local variable to be
        // pushed onto the stack that represents the parameters that weren't
        // explicitly given a value and have a non-constant default.
        mov(cb, ctx.stack_opnd(-1), imm_opnd(INT2FIX(unspecified_bits)));
    }

    // Points to the receiver operand on the stack
    let recv = ctx.stack_opnd(argc);

    // Store the updated SP on the current frame (pop arguments and receiver)
    add_comment(cb, "store caller sp");
    lea(cb, REG0, ctx.sp_opnd(SIZEOF_VALUE * -(argc + 1)));
    mov(cb, member_opnd(REG_CFP, rb_control_frame_t, sp), REG0);

    // Store the next PC in the current frame
    jit_save_pc(jit, REG0);

    if (block) {
        // Change cfp->block_code in the current frame. See vm_caller_setup_arg_block().
        // VM_CFP_TO_CAPTURED_BLCOK does &cfp->self, rb_captured_block->code.iseq aliases
        // with cfp->block_code.
        jit_mov_gc_ptr(jit, cb, REG0, (VALUE)block);
        mov(cb, member_opnd(REG_CFP, rb_control_frame_t, block_code), REG0);
    }

    // Adjust the callee's stack pointer
    lea(cb, REG0, ctx.sp_opnd(SIZEOF_VALUE * (3 + num_locals + doing_kw_call)));

    // Initialize local variables to Qnil
    for (int i = 0; i < num_locals; i++) {
        mov(cb, mem_opnd(64, REG0, SIZEOF_VALUE * (i - num_locals - 3)), imm_opnd(Qnil));
    }

    add_comment(cb, "push env");
    // Put compile time cme into REG1. It's assumed to be valid because we are notified when
    // any cme we depend on become outdated. See rb_yjit_method_lookup_change().
    jit_mov_gc_ptr(jit, cb, REG1, (VALUE)cme);
    // Write method entry at sp[-3]
    // sp[-3] = me;
    mov(cb, mem_opnd(64, REG0, 8 * -3), REG1);

    // Write block handler at sp[-2]
    // sp[-2] = block_handler;
    if (block) {
        // reg1 = VM_BH_FROM_ISEQ_BLOCK(VM_CFP_TO_CAPTURED_BLOCK(reg_cfp));
        lea(cb, REG1, member_opnd(REG_CFP, rb_control_frame_t, self));
        or(cb, REG1, imm_opnd(1));
        mov(cb, mem_opnd(64, REG0, 8 * -2), REG1);
    }
    else {
        mov(cb, mem_opnd(64, REG0, 8 * -2), imm_opnd(VM_BLOCK_HANDLER_NONE));
    }

    // Write env flags at sp[-1]
    // sp[-1] = frame_type;
    uint64_t frame_type = VM_FRAME_MAGIC_METHOD | VM_ENV_FLAG_LOCAL;
    mov(cb, mem_opnd(64, REG0, 8 * -1), imm_opnd(frame_type));

    add_comment(cb, "push callee CFP");
    // Allocate a new CFP (ec->cfp--)
    sub(cb, REG_CFP, imm_opnd(sizeof(rb_control_frame_t)));
    mov(cb, member_opnd(REG_EC, rb_execution_context_t, cfp), REG_CFP);

    // Setup the new frame
    // *cfp = (const struct rb_control_frame_struct) {
    //    .pc         = pc,
    //    .sp         = sp,
    //    .iseq       = iseq,
    //    .self       = recv,
    //    .ep         = sp - 1,
    //    .block_code = 0,
    //    .__bp__     = sp,
    // };
    mov(cb, REG1, recv);
    mov(cb, member_opnd(REG_CFP, rb_control_frame_t, self), REG1);
    mov(cb, REG_SP, REG0); // Switch to the callee's REG_SP
    mov(cb, member_opnd(REG_CFP, rb_control_frame_t, sp), REG0);
    mov(cb, member_opnd(REG_CFP, rb_control_frame_t, __bp__), REG0);
    sub(cb, REG0, imm_opnd(SIZEOF_VALUE));
    mov(cb, member_opnd(REG_CFP, rb_control_frame_t, ep), REG0);
    jit_mov_gc_ptr(jit, cb, REG0, (VALUE)iseq);
    mov(cb, member_opnd(REG_CFP, rb_control_frame_t, iseq), REG0);
    mov(cb, member_opnd(REG_CFP, rb_control_frame_t, block_code), imm_opnd(0));

    // No need to set cfp->pc since the callee sets it whenever calling into routines
    // that could look at it through jit_save_pc().
    // mov(cb, REG0, const_ptr_opnd(start_pc));
    // mov(cb, member_opnd(REG_CFP, rb_control_frame_t, pc), REG0);

    // Stub so we can return to JITted code
    blockid_t return_block = { jit->iseq, jit_next_insn_idx(jit) };

    // Create a context for the callee
    ctx_t callee_ctx = DEFAULT_CTX;

    // Set the argument types in the callee's context
    for (int32_t arg_idx = 0; arg_idx < argc; ++arg_idx) {
        val_type_t arg_type = ctx.get_opnd_type(StackOpnd(argc - arg_idx - 1));
        ctx.set_local_type(&callee_ctx, arg_idx, arg_type);
    }
    val_type_t recv_type = ctx.get_opnd_type(StackOpnd(argc));
    ctx.upgrade_opnd_type(&callee_ctx, OPND_SELF, recv_type);

    // The callee might change locals through Kernel#binding and other means.
    ctx.clear_local_types();

    // Pop arguments and receiver in return context, push the return value
    // After the return, sp_offset will be 1. The codegen for leave writes
    // the return value in case of JIT-to-JIT return.
    ctx_t return_ctx = *ctx;
    ctx.stack_pop(&return_ctx, argc + 1);
    ctx.stack_push(&return_ctx, Type::Unknown);
    return_ctx.sp_offset = 1;
    return_ctx.chain_depth = 0;

    // Write the JIT return address on the callee frame
    gen_branch(
        jit,
        ctx,
        return_block,
        &return_ctx,
        return_block,
        &return_ctx,
        gen_return_branch
    );

    //print_str(cb, "calling Ruby func:");
    //print_str(cb, rb_id2name(vm_ci_mid(ci)));

    // Directly jump to the entry point of the callee
    gen_direct_jump(
        jit,
        &callee_ctx,
        (blockid_t){ iseq, start_pc_offset }
    );

    EndBlock
}

fn gen_struct_aref(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, VALUE comptime_recv, VALUE comptime_recv_klass) {
    if (vm_ci_argc(ci) != 0) {
        return CantCompile;
    }

    const unsigned int off = cme->def->body.optimized.index;

    // Confidence checks
    RUBY_ASSERT_ALWAYS(RB_TYPE_P(comptime_recv, T_STRUCT));
    RUBY_ASSERT_ALWAYS((long)off < RSTRUCT_LEN(comptime_recv));

    // We are going to use an encoding that takes a 4-byte immediate which
    // limits the offset to INT32_MAX.
    {
        uint64_t native_off = (uint64_t)off * (uint64_t)SIZEOF_VALUE;
        if (native_off > (uint64_t)INT32_MAX) {
            return CantCompile;
        }
    }

    // All structs from the same Struct class should have the same
    // length. So if our comptime_recv is embedded all runtime
    // structs of the same class should be as well, and the same is
    // true of the converse.
    bool embedded = FL_TEST_RAW(comptime_recv, RSTRUCT_EMBED_LEN_MASK);

    add_comment(cb, "struct aref");

    let recv = ctx.stack_pop(1);

    mov(cb, REG0, recv);

    if (embedded) {
        mov(cb, REG0, member_opnd_idx(REG0, struct RStruct, as.ary, off));
    }
    else {
        mov(cb, REG0, member_opnd(REG0, struct RStruct, as.heap.ptr));
        mov(cb, REG0, mem_opnd(64, REG0, SIZEOF_VALUE * off));
    }

    let ret = ctx.stack_push(Type::Unknown);
    mov(cb, ret, REG0);

    jit_jump_to_next_insn(jit, ctx);
    EndBlock
}

fn gen_struct_aset(jitstate_t *jit, ctx_t *ctx, const struct rb_callinfo *ci, const rb_callable_method_entry_t *cme, VALUE comptime_recv, VALUE comptime_recv_klass) {
    if (vm_ci_argc(ci) != 1) {
        return CantCompile;
    }

    const unsigned int off = cme->def->body.optimized.index;

    // Confidence checks
    RUBY_ASSERT_ALWAYS(RB_TYPE_P(comptime_recv, T_STRUCT));
    RUBY_ASSERT_ALWAYS((long)off < RSTRUCT_LEN(comptime_recv));

    add_comment(cb, "struct aset");

    let val = ctx.stack_pop(1);
    let recv = ctx.stack_pop(1);

    mov(cb, C_ARG_REGS[0], recv);
    mov(cb, C_ARG_REGS[1], imm_opnd(off));
    mov(cb, C_ARG_REGS[2], val);
    call_ptr(cb, REG0, (void *)RSTRUCT_SET);

    let ret = ctx.stack_push(Type::Unknown);
    mov(cb, ret, RAX);

    jit_jump_to_next_insn(jit, ctx);
    EndBlock
}

const rb_callable_method_entry_t *
rb_aliased_callable_method_entry(const rb_callable_method_entry_t *me);

fn gen_send_general(jitstate_t *jit, ctx_t *ctx, struct rb_call_data *cd, rb_iseq_t *block)
{
    // Relevant definitions:
    // rb_execution_context_t       : vm_core.h
    // invoker, cfunc logic         : method.h, vm_method.c
    // rb_callinfo                  : vm_callinfo.h
    // rb_callable_method_entry_t   : method.h
    // vm_call_cfunc_with_frame     : vm_insnhelper.c
    //
    // For a general overview for how the interpreter calls methods,
    // see vm_call_method().

    const struct rb_callinfo *ci = cd->ci; // info about the call site

    int32_t argc = (int32_t)vm_ci_argc(ci);
    ID mid = vm_ci_mid(ci);

    // Don't JIT calls with keyword splat
    if (vm_ci_flag(ci) & VM_CALL_KW_SPLAT) {
        gen_counter_incr!(cb, send_kw_splat);
        return CantCompile;
    }

    // Don't JIT calls that aren't simple
    // Note, not using VM_CALL_ARGS_SIMPLE because sometimes we pass a block.
    if ((vm_ci_flag(ci) & VM_CALL_ARGS_SPLAT) != 0) {
        gen_counter_incr!(cb, send_args_splat);
        return CantCompile;
    }
    if ((vm_ci_flag(ci) & VM_CALL_ARGS_BLOCKARG) != 0) {
        gen_counter_incr!(cb, send_block_arg);
        return CantCompile;
    }

    // Defer compilation so we can specialize on class of receiver
    if (!jit_at_current_insn(jit)) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    VALUE comptime_recv = jit_peek_at_stack(jit, ctx, argc);
    VALUE comptime_recv_klass = CLASS_OF(comptime_recv);

    // Guard that the receiver has the same class as the one from compile time
    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    // Points to the receiver operand on the stack
    let recv = ctx.stack_opnd(argc);
    insn_opnd_t recv_opnd = StackOpnd(argc);
    mov(cb, REG0, recv);
    if (!jit_guard_known_klass(jit, ctx, comptime_recv_klass, recv_opnd, comptime_recv, SEND_MAX_DEPTH, side_exit)) {
        return CantCompile;
    }

    // Do method lookup
    const rb_callable_method_entry_t *cme = rb_callable_method_entry(comptime_recv_klass, mid);
    if (!cme) {
        // TODO: counter
        return CantCompile;
    }

    switch (METHOD_ENTRY_VISI(cme)) {
      case METHOD_VISI_PUBLIC:
        // Can always call public methods
        break;
      case METHOD_VISI_PRIVATE:
        if (!(vm_ci_flag(ci) & VM_CALL_FCALL)) {
            // Can only call private methods with FCALL callsites.
            // (at the moment they are callsites without a receiver or an explicit `self` receiver)
            return CantCompile;
        }
        break;
      case METHOD_VISI_PROTECTED:
        jit_protected_callee_ancestry_guard(jit, cb, cme, side_exit);
        break;
      case METHOD_VISI_UNDEF:
        RUBY_ASSERT(false && "cmes should always have a visibility");
        break;
    }

    // Register block for invalidation
    RUBY_ASSERT(cme->called_id == mid);
    assume_method_lookup_stable(comptime_recv_klass, cme, jit);

    // To handle the aliased method case (VM_METHOD_TYPE_ALIAS)
    while (true) {
        // switch on the method type
        switch (cme->def->type) {
          case VM_METHOD_TYPE_ISEQ:
            return gen_send_iseq(jit, ctx, ci, cme, block, argc);
          case VM_METHOD_TYPE_CFUNC:
            if ((vm_ci_flag(ci) & VM_CALL_KWARG) != 0) {
                gen_counter_incr!(cb, send_cfunc_kwargs);
                return CantCompile;
            }
            return gen_send_cfunc(jit, ctx, ci, cme, block, argc, &comptime_recv_klass);
          case VM_METHOD_TYPE_IVAR:
            if (argc != 0) {
                // Argument count mismatch. Getters take no arguments.
                gen_counter_incr!(cb, send_getter_arity);
                return CantCompile;
            }
            if (c_method_tracing_currently_enabled(jit)) {
                // Can't generate code for firing c_call and c_return events
                // :attr-tracing:
                // Handling the C method tracing events for attr_accessor
                // methods is easier than regular C methods as we know the
                // "method" we are calling into never enables those tracing
                // events. Once global invalidation runs, the code for the
                // attr_accessor is invalidated and we exit at the closest
                // instruction boundary which is always outside of the body of
                // the attr_accessor code.
                gen_counter_incr!(cb, send_cfunc_tracing);
                return CantCompile;
            }

            mov(cb, REG0, recv);

            ID ivar_name = cme->def->body.attr.id;
            return gen_get_ivar(jit, ctx, SEND_MAX_DEPTH, comptime_recv, ivar_name, recv_opnd, side_exit);
          case VM_METHOD_TYPE_ATTRSET:
            if ((vm_ci_flag(ci) & VM_CALL_KWARG) != 0) {
                gen_counter_incr!(cb, send_attrset_kwargs);
                return CantCompile;
            }
            else if (argc != 1 || !RB_TYPE_P(comptime_recv, T_OBJECT)) {
                gen_counter_incr!(cb, send_ivar_set_method);
                return CantCompile;
            }
            else if (c_method_tracing_currently_enabled(jit)) {
                // Can't generate code for firing c_call and c_return events
                // See :attr-tracing:
                gen_counter_incr!(cb, send_cfunc_tracing);
                return CantCompile;
            }
            else {
                ID ivar_name = cme->def->body.attr.id;
                return gen_set_ivar(jit, ctx, comptime_recv, comptime_recv_klass, ivar_name);
            }
          // Block method, e.g. define_method(:foo) { :my_block }
          case VM_METHOD_TYPE_BMETHOD:
            gen_counter_incr!(cb, send_bmethod);
            return CantCompile;
          case VM_METHOD_TYPE_ZSUPER:
            gen_counter_incr!(cb, send_zsuper_method);
            return CantCompile;
          case VM_METHOD_TYPE_ALIAS: {
            // Retrieve the alised method and re-enter the switch
            cme = rb_aliased_callable_method_entry(cme);
            continue;
          }
          case VM_METHOD_TYPE_UNDEF:
            gen_counter_incr!(cb, send_undef_method);
            return CantCompile;
          case VM_METHOD_TYPE_NOTIMPLEMENTED:
            gen_counter_incr!(cb, send_not_implemented_method);
            return CantCompile;
          // Send family of methods, e.g. call/apply
          case VM_METHOD_TYPE_OPTIMIZED:
            switch (cme->def->body.optimized.type) {
              case OPTIMIZED_METHOD_TYPE_SEND:
                gen_counter_incr!(cb, send_optimized_method_send);
                return CantCompile;
              case OPTIMIZED_METHOD_TYPE_CALL:
                gen_counter_incr!(cb, send_optimized_method_call);
                return CantCompile;
              case OPTIMIZED_METHOD_TYPE_BLOCK_CALL:
                gen_counter_incr!(cb, send_optimized_method_block_call);
                return CantCompile;
              case OPTIMIZED_METHOD_TYPE_STRUCT_AREF:
                return gen_struct_aref(jit, ctx, ci, cme, comptime_recv, comptime_recv_klass);
              case OPTIMIZED_METHOD_TYPE_STRUCT_ASET:
                return gen_struct_aset(jit, ctx, ci, cme, comptime_recv, comptime_recv_klass);
              default:
                rb_bug("unknown optimized method type (%d)", cme->def->body.optimized.type);
                UNREACHABLE_RETURN(YJIT_CANT_COMPILE);
            }
          case VM_METHOD_TYPE_MISSING:
            gen_counter_incr!(cb, send_missing_method);
            return CantCompile;
          case VM_METHOD_TYPE_REFINED:
            gen_counter_incr!(cb, send_refined_method);
            return CantCompile;
            // no default case so compiler issues a warning if this is not exhaustive
        }

        // Unreachable
        RUBY_ASSERT(false);
    }
}
*/

fn gen_opt_send_without_block(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    /*
    struct rb_call_data *cd = (struct rb_call_data *)jit_get_arg(jit, 0);
    gen_send_general(jit, ctx, cd, NULL)
    */

    todo!()
}

/*
fn gen_send(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    struct rb_call_data *cd = (struct rb_call_data *)jit_get_arg(jit, 0);
    rb_iseq_t *block = (rb_iseq_t *)jit_get_arg(jit, 1);
    return gen_send_general(jit, ctx, cd, block);
}

fn gen_invokesuper(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    struct rb_call_data *cd = (struct rb_call_data *)jit_get_arg(jit, 0);
    rb_iseq_t *block = (rb_iseq_t *)jit_get_arg(jit, 1);

    // Defer compilation so we can specialize on class of receiver
    if (!jit_at_current_insn(jit)) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    const rb_callable_method_entry_t *me = rb_vm_frame_method_entry(jit->ec->cfp);
    if (!me) {
        return CantCompile;
    }

    // FIXME: We should track and invalidate this block when this cme is invalidated
    VALUE current_defined_class = me->defined_class;
    ID mid = me->def->original_id;

    if (me != rb_callable_method_entry(current_defined_class, me->called_id)) {
        // Though we likely could generate this call, as we are only concerned
        // with the method entry remaining valid, assume_method_lookup_stable
        // below requires that the method lookup matches as well
        return CantCompile;
    }

    // vm_search_normal_superclass
    if (BUILTIN_TYPE(current_defined_class) == T_ICLASS && FL_TEST_RAW(RBASIC(current_defined_class)->klass, RMODULE_IS_REFINEMENT)) {
        return CantCompile;
    }
    VALUE comptime_superclass = RCLASS_SUPER(RCLASS_ORIGIN(current_defined_class));

    const struct rb_callinfo *ci = cd->ci;
    int32_t argc = (int32_t)vm_ci_argc(ci);

    // Don't JIT calls that aren't simple
    // Note, not using VM_CALL_ARGS_SIMPLE because sometimes we pass a block.
    if ((vm_ci_flag(ci) & VM_CALL_ARGS_SPLAT) != 0) {
        gen_counter_incr!(cb, send_args_splat);
        return CantCompile;
    }
    if ((vm_ci_flag(ci) & VM_CALL_KWARG) != 0) {
        gen_counter_incr!(cb, send_keywords);
        return CantCompile;
    }
    if ((vm_ci_flag(ci) & VM_CALL_KW_SPLAT) != 0) {
        gen_counter_incr!(cb, send_kw_splat);
        return CantCompile;
    }
    if ((vm_ci_flag(ci) & VM_CALL_ARGS_BLOCKARG) != 0) {
        gen_counter_incr!(cb, send_block_arg);
        return CantCompile;
    }

    // Ensure we haven't rebound this method onto an incompatible class.
    // In the interpreter we try to avoid making this check by performing some
    // cheaper calculations first, but since we specialize on the method entry
    // and so only have to do this once at compile time this is fine to always
    // check and side exit.
    VALUE comptime_recv = jit_peek_at_stack(jit, ctx, argc);
    if (!rb_obj_is_kind_of(comptime_recv, current_defined_class)) {
        return CantCompile;
    }

    // Do method lookup
    const rb_callable_method_entry_t *cme = rb_callable_method_entry(comptime_superclass, mid);

    if (!cme) {
        return CantCompile;
    }

    // Check that we'll be able to write this method dispatch before generating checks
    switch (cme->def->type) {
      case VM_METHOD_TYPE_ISEQ:
      case VM_METHOD_TYPE_CFUNC:
        break;
      default:
        // others unimplemented
        return CantCompile;
    }

    // Guard that the receiver has the same class as the one from compile time
    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    if (jit->ec->cfp->ep[VM_ENV_DATA_INDEX_ME_CREF] != (VALUE)me) {
        // This will be the case for super within a block
        return CantCompile;
    }

    add_comment(cb, "guard known me");
    mov(cb, REG0, member_opnd(REG_CFP, rb_control_frame_t, ep));
    let ep_me_opnd = mem_opnd(64, REG0, SIZEOF_VALUE * VM_ENV_DATA_INDEX_ME_CREF);
    jit_mov_gc_ptr(jit, cb, REG1, (VALUE)me);
    cmp(cb, ep_me_opnd, REG1);
    jne_ptr(cb, counted_exit!(ocb, side_exit, invokesuper_me_changed));

    if (!block) {
        // Guard no block passed
        // rb_vm_frame_block_handler(GET_EC()->cfp) == VM_BLOCK_HANDLER_NONE
        // note, we assume VM_ASSERT(VM_ENV_LOCAL_P(ep))
        //
        // TODO: this could properly forward the current block handler, but
        // would require changes to gen_send_*
        add_comment(cb, "guard no block given");
        // EP is in REG0 from above
        let ep_specval_opnd = mem_opnd(64, REG0, SIZEOF_VALUE * VM_ENV_DATA_INDEX_SPECVAL);
        cmp(cb, ep_specval_opnd, imm_opnd(VM_BLOCK_HANDLER_NONE));
        jne_ptr(cb, counted_exit!(ocb, side_exit, invokesuper_block));
    }

    // Points to the receiver operand on the stack
    let recv = ctx.stack_opnd(argc);
    mov(cb, REG0, recv);

    // We need to assume that both our current method entry and the super
    // method entry we invoke remain stable
    assume_method_lookup_stable(current_defined_class, me, jit);
    assume_method_lookup_stable(comptime_superclass, cme, jit);

    // Method calls may corrupt types
    ctx.clear_local_types();

    switch (cme->def->type) {
      case VM_METHOD_TYPE_ISEQ:
        return gen_send_iseq(jit, ctx, ci, cme, block, argc);
      case VM_METHOD_TYPE_CFUNC:
        return gen_send_cfunc(jit, ctx, ci, cme, block, argc, NULL);
      default:
        break;
    }

    RUBY_ASSERT_ALWAYS(false);
}
*/

fn gen_leave(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Only the return value should be on the stack
    assert!(ctx.get_stack_size() == 1);

    // Create a side-exit to fall back to the interpreter
    let side_exit = get_side_exit(jit, ocb, ctx);

    // Load environment pointer EP from CFP
    mov(cb, REG1, mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_EP));

    // Check for interrupts
    add_comment(cb, "check for interrupts");
    gen_check_ints(cb, counted_exit!(ocb, side_exit, leave_se_interrupt));

    // Load the return value
    mov(cb, REG0, ctx.stack_pop(1));

    // Pop the current frame (ec->cfp++)
    // Note: the return PC is already in the previous CFP
    add(cb, REG_CFP, uimm_opnd(RUBY_SIZEOF_CONTROL_FRAME as u64));
    mov(cb, mem_opnd(64, REG_EC, RUBY_OFFSET_EC_CFP), REG_CFP);

    // Reload REG_SP for the caller and write the return value.
    // Top of the stack is REG_SP[0] since the caller has sp_offset=1.
    mov(cb, REG_SP, mem_opnd(64, REG_CFP, RUBY_OFFSET_CFP_SP));
    mov(cb, mem_opnd(64, REG_SP, 0), REG0);

    // Jump to the JIT return address on the frame that was just popped
    let offset_to_jit_return = -(RUBY_SIZEOF_CONTROL_FRAME as i32) + (RUBY_OFFSET_CFP_JIT_RETURN as i32);
    jmp_rm(cb, mem_opnd(64, REG_CFP, offset_to_jit_return));

    EndBlock
}

/*
fn gen_getglobal(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    ID gid = jit_get_arg(jit, 0);

    // Save the PC and SP because we might make a Ruby call for warning
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    mov(cb, C_ARG_REGS[0], imm_opnd(gid));

    call_ptr(cb, REG0, (void *)&rb_gvar_get);

    let top = ctx.stack_push(Type::Unknown);
    mov(cb, top, RAX);

    KeepCompiling
}

fn gen_setglobal(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    ID gid = jit_get_arg(jit, 0);

    // Save the PC and SP because we might make a Ruby call for
    // Kernel#set_trace_var
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    mov(cb, C_ARG_REGS[0], imm_opnd(gid));

    let val = ctx.stack_pop(1);

    mov(cb, C_ARG_REGS[1], val);

    call_ptr(cb, REG0, (void *)&rb_gvar_set);

    KeepCompiling
}

fn gen_anytostring(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // Save the PC and SP because we might make a Ruby call for
    // Kernel#set_trace_var
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    let str = ctx.stack_pop(1);
    let val = ctx.stack_pop(1);

    mov(cb, C_ARG_REGS[0], str);
    mov(cb, C_ARG_REGS[1], val);

    call_ptr(cb, REG0, (void *)&rb_obj_as_string_result);

    // Push the return value
    let stack_ret = ctx.stack_push(Type::String);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}

fn gen_objtostring(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    if (!jit_at_current_insn(jit)) {
        defer_compilation(jit, cb, ctx);
        return EndBlock;
    }

    let recv = ctx.stack_opnd(0);
    VALUE comptime_recv = jit_peek_at_stack(jit, ctx, 0);

    if (RB_TYPE_P(comptime_recv, T_STRING)) {
        uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

        mov(cb, REG0, recv);
        jit_guard_known_klass(jit, ctx, CLASS_OF(comptime_recv), StackOpnd(0), comptime_recv, SEND_MAX_DEPTH, side_exit);
        // No work needed. The string value is already on the top of the stack.
        KeepCompiling
    }
    else {
        struct rb_call_data *cd = (struct rb_call_data *)jit_get_arg(jit, 0);
        return gen_send_general(jit, ctx, cd, NULL);
    }
}

fn gen_toregexp(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    rb_num_t opt = jit_get_arg(jit, 0);
    rb_num_t cnt = jit_get_arg(jit, 1);

    // Save the PC and SP because this allocates an object and could
    // raise an exception.
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    let values_ptr = ctx.sp_opnd(-(SIZEOF_VALUE * (uint32_t)cnt));
    ctx.stack_pop(cnt);

    mov(cb, C_ARG_REGS[0], imm_opnd(0));
    mov(cb, C_ARG_REGS[1], imm_opnd(cnt));
    lea(cb, C_ARG_REGS[2], values_ptr);
    call_ptr(cb, REG0, (void *)&rb_ary_tmp_new_from_values);

    // Save the array so we can clear it later
    push(cb, RAX);
    push(cb, RAX); // Alignment
    mov(cb, C_ARG_REGS[0], RAX);
    mov(cb, C_ARG_REGS[1], imm_opnd(opt));
    call_ptr(cb, REG0, (void *)&rb_reg_new_ary);

    // The actual regex is in RAX now.  Pop the temp array from
    // rb_ary_tmp_new_from_values into C arg regs so we can clear it
    pop(cb, REG1); // Alignment
    pop(cb, C_ARG_REGS[0]);

    // The value we want to push on the stack is in RAX right now
    let stack_ret = ctx.stack_push(Type::Unknown);
    mov(cb, stack_ret, RAX);

    // Clear the temp array.
    call_ptr(cb, REG0, (void *)&rb_ary_clear);

    KeepCompiling
}

fn gen_getspecial(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // This takes two arguments, key and type
    // key is only used when type == 0
    // A non-zero type determines which type of backref to fetch
    //rb_num_t key = jit_get_arg(jit, 0);
    rb_num_t type = jit_get_arg(jit, 1);

    if (type == 0) {
        // not yet implemented
        return CantCompile;
    }
    else if (type & 0x01) {
        // Fetch a "special" backref based on a char encoded by shifting by 1

        // Can raise if matchdata uninitialized
        jit_prepare_routine_call(jit, ctx, cb, REG0);

        // call rb_backref_get()
        add_comment(cb, "rb_backref_get");
        call_ptr(cb, REG0, (void *)rb_backref_get);
        mov(cb, C_ARG_REGS[0], RAX);

        switch (type >> 1) {
          case '&':
            add_comment(cb, "rb_reg_last_match");
            call_ptr(cb, REG0, (void *)rb_reg_last_match);
            break;
          case '`':
            add_comment(cb, "rb_reg_match_pre");
            call_ptr(cb, REG0, (void *)rb_reg_match_pre);
            break;
          case '\'':
            add_comment(cb, "rb_reg_match_post");
            call_ptr(cb, REG0, (void *)rb_reg_match_post);
            break;
          case '+':
            add_comment(cb, "rb_reg_match_last");
            call_ptr(cb, REG0, (void *)rb_reg_match_last);
            break;
          default:
            rb_bug("invalid back-ref");
        }

        let stack_ret = ctx.stack_push(Type::Unknown);
        mov(cb, stack_ret, RAX);

        KeepCompiling
    }
    else {
        // Fetch the N-th match from the last backref based on type shifted by 1

        // Can raise if matchdata uninitialized
        jit_prepare_routine_call(jit, ctx, cb, REG0);

        // call rb_backref_get()
        add_comment(cb, "rb_backref_get");
        call_ptr(cb, REG0, (void *)rb_backref_get);

        // rb_reg_nth_match((int)(type >> 1), backref);
        add_comment(cb, "rb_reg_nth_match");
        mov(cb, C_ARG_REGS[0], imm_opnd(type >> 1));
        mov(cb, C_ARG_REGS[1], RAX);
        call_ptr(cb, REG0, (void *)rb_reg_nth_match);

        let stack_ret = ctx.stack_push(Type::Unknown);
        mov(cb, stack_ret, RAX);

        KeepCompiling
    }
}

VALUE
rb_vm_getclassvariable(const rb_iseq_t *iseq, const rb_control_frame_t *cfp, ID id, ICVARC ic);

fn gen_getclassvariable(jitstate_t* jit, ctx_t* ctx, codeblock_t* cb)
{
    // rb_vm_getclassvariable can raise exceptions.
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    mov(cb, C_ARG_REGS[0], member_opnd(REG_CFP, rb_control_frame_t, iseq));
    mov(cb, C_ARG_REGS[1], REG_CFP);
    mov(cb, C_ARG_REGS[2], imm_opnd(jit_get_arg(jit, 0)));
    mov(cb, C_ARG_REGS[3], imm_opnd(jit_get_arg(jit, 1)));

    call_ptr(cb, REG0, (void *)rb_vm_getclassvariable);

    let stack_top = ctx.stack_push(Type::Unknown);
    mov(cb, stack_top, RAX);

    KeepCompiling
}

VALUE
rb_vm_setclassvariable(const rb_iseq_t *iseq, const rb_control_frame_t *cfp, ID id, VALUE val, ICVARC ic);

fn gen_setclassvariable(jitstate_t* jit, ctx_t* ctx, codeblock_t* cb)
{
    // rb_vm_setclassvariable can raise exceptions.
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    mov(cb, C_ARG_REGS[0], member_opnd(REG_CFP, rb_control_frame_t, iseq));
    mov(cb, C_ARG_REGS[1], REG_CFP);
    mov(cb, C_ARG_REGS[2], imm_opnd(jit_get_arg(jit, 0)));
    mov(cb, C_ARG_REGS[3], ctx.stack_pop(1));
    mov(cb, C_ARG_REGS[4], imm_opnd(jit_get_arg(jit, 1)));

    call_ptr(cb, REG0, (void *)rb_vm_setclassvariable);

    KeepCompiling
}

fn gen_opt_getinlinecache(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    VALUE jump_offset = jit_get_arg(jit, 0);
    VALUE const_cache_as_value = jit_get_arg(jit, 1);
    IC ic = (IC)const_cache_as_value;

    // See vm_ic_hit_p(). The same conditions are checked in yjit_constant_ic_update().
    struct iseq_inline_constant_cache_entry *ice = ic->entry;
    if (!ice || // cache not filled
        GET_IC_SERIAL(ice) != ruby_vm_global_constant_state /* cache out of date */) {
        // In these cases, leave a block that unconditionally side exits
        // for the interpreter to invalidate.
        return CantCompile;
    }

    // Make sure there is an exit for this block as the interpreter might want
    // to invalidate this block from yjit_constant_ic_update().
    jit_ensure_block_entry_exit(jit);

    if (ice->ic_cref) {
        // Cache is keyed on a certain lexical scope. Use the interpreter's cache.
        uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

        // Call function to verify the cache. It doesn't allocate or call methods.
        bool rb_vm_ic_hit_p(IC ic, const VALUE *reg_ep);
        mov(cb, C_ARG_REGS[0], const_ptr_opnd((void *)ic));
        mov(cb, C_ARG_REGS[1], member_opnd(REG_CFP, rb_control_frame_t, ep));
        call_ptr(cb, REG0, (void *)rb_vm_ic_hit_p);

        // Check the result. _Bool is one byte in SysV.
        test(cb, AL, AL);
        jz_ptr(cb, counted_exit!(ocb, side_exit, opt_getinlinecache_miss));

        // Push ic->entry->value
        mov(cb, REG0, const_ptr_opnd((void *)ic));
        mov(cb, REG0, member_opnd(REG0, struct iseq_inline_constant_cache, entry));
        let stack_top = ctx.stack_push(Type::Unknown);
        mov(cb, REG0, member_opnd(REG0, struct iseq_inline_constant_cache_entry, value));
        mov(cb, stack_top, REG0);
    }
    else {
        // Optimize for single ractor mode.
        // FIXME: This leaks when st_insert raises NoMemoryError
        if (!assume_single_ractor_mode(jit)) return CantCompile;

        // Invalidate output code on any and all constant writes
        // FIXME: This leaks when st_insert raises NoMemoryError
        assume_stable_global_constant_state(jit);

        jit_putobject(jit, ctx, ice->value);
    }

    // Jump over the code for filling the cache
    uint32_t jump_idx = jit_next_insn_idx(jit) + (int32_t)jump_offset;
    gen_direct_jump(
        jit,
        ctx,
        (blockid_t){ .iseq = jit->iseq, .idx = jump_idx }
    );

    EndBlock
}

// Push the explict block parameter onto the temporary stack. Part of the
// interpreter's scheme for avoiding Proc allocations when delegating
// explict block parameters.
fn gen_getblockparamproxy(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    // A mirror of the interpreter code. Checking for the case
    // where it's pushing rb_block_param_proxy.
    uint8_t *side_exit = get_side_exit(jit, ocb, ctx);

    // EP level
    uint32_t level = (uint32_t)jit_get_arg(jit, 1);

    // Load environment pointer EP from CFP
    gen_get_ep(cb, REG0, level);

    // Bail when VM_ENV_FLAGS(ep, VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM) is non zero
    test(cb, mem_opnd(64, REG0, SIZEOF_VALUE * VM_ENV_DATA_INDEX_FLAGS), imm_opnd(VM_FRAME_FLAG_MODIFIED_BLOCK_PARAM));
    jnz_ptr(cb, counted_exit!(ocb, side_exit, gbpp_block_param_modified));

    // Load the block handler for the current frame
    // note, VM_ASSERT(VM_ENV_LOCAL_P(ep))
    mov(cb, REG0, mem_opnd(64, REG0, SIZEOF_VALUE * VM_ENV_DATA_INDEX_SPECVAL));

    // Block handler is a tagged pointer. Look at the tag. 0x03 is from VM_BH_ISEQ_BLOCK_P().
    and(cb, REG0_8, imm_opnd(0x3));

    // Bail unless VM_BH_ISEQ_BLOCK_P(bh). This also checks for null.
    cmp(cb, REG0_8, imm_opnd(0x1));
    jnz_ptr(cb, counted_exit!(ocb, side_exit, gbpp_block_handler_not_iseq));

    // Push rb_block_param_proxy. It's a root, so no need to use jit_mov_gc_ptr.
    mov(cb, REG0, const_ptr_opnd((void *)rb_block_param_proxy));
    RUBY_ASSERT(!SPECIAL_CONST_P(rb_block_param_proxy));
    let top = ctx.stack_push(Type::UnknownHeap);
    mov(cb, top, REG0);

    KeepCompiling
}

fn gen_invokebuiltin(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    const struct rb_builtin_function *bf = (struct rb_builtin_function *)jit_get_arg(jit, 0);

    // ec, self, and arguments
    if (bf->argc + 2 > NUM_C_ARG_REGS) {
        return CantCompile;
    }

    // If the calls don't allocate, do they need up to date PC, SP?
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    // Call the builtin func (ec, recv, arg1, arg2, ...)
    mov(cb, C_ARG_REGS[0], REG_EC);
    mov(cb, C_ARG_REGS[1], member_opnd(REG_CFP, rb_control_frame_t, self));

    // Copy arguments from locals
    for (int32_t i = 0; i < bf->argc; i++) {
        let stack_opnd = ctx.stack_opnd(bf->argc - i - 1);
        let c_arg_reg = C_ARG_REGS[2 + i];
        mov(cb, c_arg_reg, stack_opnd);
    }

    call_ptr(cb, REG0, (void *)bf->func_ptr);

    // Push the return value
    ctx.stack_pop(bf->argc);
    let stack_ret = ctx.stack_push(Type::Unknown);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}

// opt_invokebuiltin_delegate calls a builtin function, like
// invokebuiltin does, but instead of taking arguments from the top of the
// stack uses the argument locals (and self) from the current method.
fn gen_opt_invokebuiltin_delegate(jit: &mut JITState, ctx: &mut Context, cb: &mut CodeBlock, ocb: &mut OutlinedCb) -> CodegenStatus
{
    const struct rb_builtin_function *bf = (struct rb_builtin_function *)jit_get_arg(jit, 0);
    int32_t start_index = (int32_t)jit_get_arg(jit, 1);

    // ec, self, and arguments
    if (bf->argc + 2 > NUM_C_ARG_REGS) {
        return CantCompile;
    }

    // If the calls don't allocate, do they need up to date PC, SP?
    jit_prepare_routine_call(jit, ctx, cb, REG0);

    if (bf->argc > 0) {
        // Load environment pointer EP from CFP
        mov(cb, REG0, member_opnd(REG_CFP, rb_control_frame_t, ep));
    }

    // Call the builtin func (ec, recv, arg1, arg2, ...)
    mov(cb, C_ARG_REGS[0], REG_EC);
    mov(cb, C_ARG_REGS[1], member_opnd(REG_CFP, rb_control_frame_t, self));

    // Copy arguments from locals
    for (int32_t i = 0; i < bf->argc; i++) {
        const int32_t offs = -jit->iseq->body->local_table_size - VM_ENV_DATA_SIZE + 1 + start_index + i;
        let local_opnd = mem_opnd(64, REG0, offs * SIZEOF_VALUE);
        let c_arg_reg = C_ARG_REGS[i + 2];
        mov(cb, c_arg_reg, local_opnd);
    }
    call_ptr(cb, REG0, (void *)bf->func_ptr);

    // Push the return value
    let stack_ret = ctx.stack_push(Type::Unknown);
    mov(cb, stack_ret, RAX);

    KeepCompiling
}

// Invalidate all generated code and patch C method return code to contain
// logic for firing the c_return TracePoint event. Once rb_vm_barrier()
// returns, all other ractors are pausing inside RB_VM_LOCK_ENTER(), which
// means they are inside a C routine. If there are any generated code on-stack,
// they are waiting for a return from a C routine. For every routine call, we
// patch in an exit after the body of the containing VM instruction. This makes
// it so all the invalidated code exit as soon as execution logically reaches
// the next VM instruction. The interpreter takes care of firing the tracing
// event if it so happens that the next VM instruction has one attached.
//
// The c_return event needs special handling as our codegen never outputs code
// that contains tracing logic. If we let the normal output code run until the
// start of the next VM instruction by relying on the patching scheme above, we
// would fail to fire the c_return event. The interpreter doesn't fire the
// event at an instruction boundary, so simply exiting to the interpreter isn't
// enough. To handle it, we patch in the full logic at the return address. See
// full_cfunc_return().
//
// In addition to patching, we prevent future entries into invalidated code by
// removing all live blocks from their iseq.
void
rb_yjit_tracing_invalidate_all(void)
{
    if (!rb_yjit_enabled_p()) return;

    // Stop other ractors since we are going to patch machine code.
    RB_VM_LOCK_ENTER();
    rb_vm_barrier();

    // Make it so all live block versions are no longer valid branch targets
    rb_objspace_each_objects(tracing_invalidate_all_i, NULL);

    // Apply patches
    const uint32_t old_pos = cb->write_pos;
    rb_darray_for(global_inval_patches, patch_idx) {
        struct codepage_patch patch = rb_darray_get(global_inval_patches, patch_idx);
        cb_set_pos(cb, patch.inline_patch_pos);
        uint8_t *jump_target = cb_get_ptr(ocb, patch.outlined_target_pos);
        jmp_ptr(cb, jump_target);
    }
    cb_set_pos(cb, old_pos);

    // Freeze invalidated part of the codepage. We only want to wait for
    // running instances of the code to exit from now on, so we shouldn't
    // change the code. There could be other ractors sleeping in
    // branch_stub_hit(), for example. We could harden this by changing memory
    // protection on the frozen range.
    RUBY_ASSERT_ALWAYS(yjit_codepage_frozen_bytes <= old_pos && "frozen bytes should increase monotonically");
    yjit_codepage_frozen_bytes = old_pos;

    cb_mark_all_executable(ocb);
    cb_mark_all_executable(cb);
    RB_VM_LOCK_LEAVE();
}

static int
tracing_invalidate_all_i(void *vstart, void *vend, size_t stride, void *data)
{
    VALUE v = (VALUE)vstart;
    for (; v != (VALUE)vend; v += stride) {
        void *ptr = asan_poisoned_object_p(v);
        asan_unpoison_object(v, false);

        if (rb_obj_is_iseq(v)) {
            rb_iseq_t *iseq = (rb_iseq_t *)v;
            invalidate_all_blocks_for_tracing(iseq);
        }

        asan_poison_object_if(ptr, v);
    }
    return 0;
}

static void
invalidate_all_blocks_for_tracing(const rb_iseq_t *iseq)
{
    struct rb_iseq_constant_body *body = iseq->body;
    if (!body) return; // iseq yet to be initialized

    ASSERT_vm_locking();

    // Empty all blocks on the iseq so we don't compile new blocks that jump to the
    // invalidted region.
    // TODO Leaking the blocks for now since we might have situations where
    // a different ractor is waiting in branch_stub_hit(). If we free the block
    // that ractor can wake up with a dangling block.
    rb_darray_for(body->yjit_blocks, version_array_idx) {
        rb_yjit_block_array_t version_array = rb_darray_get(body->yjit_blocks, version_array_idx);
        rb_darray_for(version_array, version_idx) {
            // Stop listening for invalidation events like basic operation redefinition.
            block_t *block = rb_darray_get(version_array, version_idx);
            yjit_unlink_method_lookup_dependency(block);
            yjit_block_assumptions_free(block);
        }
        rb_darray_free(version_array);
    }
    rb_darray_free(body->yjit_blocks);
    body->yjit_blocks = NULL;

#if USE_MJIT
    // Reset output code entry point
    body->jit_func = NULL;
#endif
}
*/













/// Maps a YARV opcode to a code generation function (if supported)
fn get_gen_fn(opcode: VALUE) -> Option<CodeGenFn>
{
    let VALUE(opcode) = opcode;
    assert!(opcode < VM_INSTRUCTION_SIZE);

    match opcode {
        OP_NOP => Some(gen_nop),
        OP_POP => Some(gen_pop),
        OP_DUP => Some(gen_dup),
        OP_DUPN => Some(gen_dupn),
        OP_SWAP => Some(gen_swap),
        OP_PUTNIL => Some(gen_putnil),
        OP_PUTOBJECT => Some(gen_putobject),
        OP_PUTOBJECT_INT2FIX_0_ => Some(gen_putobject_int2fix),
        OP_PUTOBJECT_INT2FIX_1_ => Some(gen_putobject_int2fix),
        OP_PUTSELF => Some(gen_putself),
        OP_PUTSPECIALOBJECT => Some(gen_putspecialobject),
        OP_SETN => Some(gen_setn),
        OP_TOPN => Some(gen_topn),
        OP_ADJUSTSTACK => Some(gen_adjuststack),
        OP_GETLOCAL => Some(gen_getlocal),
        OP_GETLOCAL_WC_0 => Some(gen_getlocal_wc0),
        OP_GETLOCAL_WC_1 => Some(gen_getlocal_wc1),
        OP_SETLOCAL => Some(gen_setlocal),
        OP_SETLOCAL_WC_0 => Some(gen_setlocal_wc0),
        OP_SETLOCAL_WC_1 => Some(gen_setlocal_wc1),
        OP_OPT_PLUS => Some(gen_opt_plus),
        OP_OPT_MINUS => Some(gen_opt_minus),
        OP_OPT_AND => Some(gen_opt_and),
        OP_OPT_OR => Some(gen_opt_or),
        OP_NEWHASH => Some(gen_newhash),
        OP_DUPHASH => Some(gen_duphash),
        OP_NEWARRAY => Some(gen_newarray),
        OP_DUPARRAY => Some(gen_duparray),
        OP_CHECKTYPE => Some(gen_checktype),
        OP_OPT_LT => Some(gen_opt_lt),
        OP_OPT_LE => Some(gen_opt_le),
        OP_OPT_GT => Some(gen_opt_gt),
        OP_OPT_GE => Some(gen_opt_ge),

        /*
        yjit_reg_op(BIN(splatarray), gen_splatarray);
        yjit_reg_op(BIN(expandarray), gen_expandarray);
        yjit_reg_op(BIN(newrange), gen_newrange);
        yjit_reg_op(BIN(concatstrings), gen_concatstrings);
        yjit_reg_op(BIN(putstring), gen_putstring);
        yjit_reg_op(BIN(getinstancevariable), gen_getinstancevariable);
        yjit_reg_op(BIN(setinstancevariable), gen_setinstancevariable);
        yjit_reg_op(BIN(defined), gen_defined);
        yjit_reg_op(BIN(checkkeyword), gen_checkkeyword);
        yjit_reg_op(BIN(opt_eq), gen_opt_eq);
        yjit_reg_op(BIN(opt_neq), gen_opt_neq);
        yjit_reg_op(BIN(opt_aref), gen_opt_aref);
        yjit_reg_op(BIN(opt_aset), gen_opt_aset);
        yjit_reg_op(BIN(opt_mult), gen_opt_mult);
        yjit_reg_op(BIN(opt_div), gen_opt_div);
        yjit_reg_op(BIN(opt_mod), gen_opt_mod);
        yjit_reg_op(BIN(opt_ltlt), gen_opt_ltlt);
        yjit_reg_op(BIN(opt_nil_p), gen_opt_nil_p);
        yjit_reg_op(BIN(opt_empty_p), gen_opt_empty_p);
        yjit_reg_op(BIN(opt_str_freeze), gen_opt_str_freeze);
        yjit_reg_op(BIN(opt_str_uminus), gen_opt_str_uminus);
        yjit_reg_op(BIN(opt_not), gen_opt_not);
        yjit_reg_op(BIN(opt_size), gen_opt_size);
        yjit_reg_op(BIN(opt_length), gen_opt_length);
        yjit_reg_op(BIN(opt_regexpmatch2), gen_opt_regexpmatch2);
        yjit_reg_op(BIN(opt_getinlinecache), gen_opt_getinlinecache);
        yjit_reg_op(BIN(invokebuiltin), gen_invokebuiltin);
        yjit_reg_op(BIN(opt_invokebuiltin_delegate), gen_opt_invokebuiltin_delegate);
        yjit_reg_op(BIN(opt_invokebuiltin_delegate_leave), gen_opt_invokebuiltin_delegate);
        yjit_reg_op(BIN(opt_case_dispatch), gen_opt_case_dispatch);
        */
        OP_BRANCHIF => Some(gen_branchif),
        //yjit_reg_op(BIN(branchunless), gen_branchunless);
        //yjit_reg_op(BIN(branchnil), gen_branchnil);
        OP_JUMP => Some(gen_jump),
        //yjit_reg_op(BIN(getblockparamproxy), gen_getblockparamproxy);
        //yjit_reg_op(BIN(opt_send_without_block), gen_opt_send_without_block);
        //yjit_reg_op(BIN(send), gen_send);
        //yjit_reg_op(BIN(invokesuper), gen_invokesuper);
        OP_LEAVE => Some(gen_leave),

        /*
        yjit_reg_op(BIN(getglobal), gen_getglobal);
        yjit_reg_op(BIN(setglobal), gen_setglobal);
        yjit_reg_op(BIN(anytostring), gen_anytostring);
        yjit_reg_op(BIN(objtostring), gen_objtostring);
        yjit_reg_op(BIN(toregexp), gen_toregexp);
        yjit_reg_op(BIN(getspecial), gen_getspecial);
        yjit_reg_op(BIN(getclassvariable), gen_getclassvariable);
        yjit_reg_op(BIN(setclassvariable), gen_setclassvariable);
        */

        // Unimplemented opcode, YJIT won't generate code for this yet
        _ => None
    }
}

/// Register codegen functions for some Ruby core methods
fn get_method_gen_fn()
{
    // TODO: implement pattern matching for this

    /*
    // Specialization for C methods. See yjit_reg_method() for details.
    yjit_reg_method(rb_cBasicObject, "!", jit_rb_obj_not);

    yjit_reg_method(rb_cNilClass, "nil?", jit_rb_true);
    yjit_reg_method(rb_mKernel, "nil?", jit_rb_false);

    yjit_reg_method(rb_cBasicObject, "==", jit_rb_obj_equal);
    yjit_reg_method(rb_cBasicObject, "equal?", jit_rb_obj_equal);
    yjit_reg_method(rb_mKernel, "eql?", jit_rb_obj_equal);
    yjit_reg_method(rb_cModule, "==", jit_rb_obj_equal);
    yjit_reg_method(rb_cSymbol, "==", jit_rb_obj_equal);
    yjit_reg_method(rb_cSymbol, "===", jit_rb_obj_equal);

    // rb_str_to_s() methods in string.c
    yjit_reg_method(rb_cString, "to_s", jit_rb_str_to_s);
    yjit_reg_method(rb_cString, "to_str", jit_rb_str_to_s);
    yjit_reg_method(rb_cString, "bytesize", jit_rb_str_bytesize);

    // Thread.current
    yjit_reg_method(rb_singleton_class(rb_cThread), "current", jit_thread_s_current);
    */
}

/// Global state needed for code generation
pub struct CodegenGlobals
{
    /// Inline code block (fast path)
    inline_cb: CodeBlock,

    /// Outlined code block (slow path)
    outlined_cb: OutlinedCb,

    /// Code for exiting back to the interpreter from the leave instruction
    leave_exit_code: CodePtr,

    // For exiting from YJIT frame from branch_stub_hit().
    // Filled by gen_code_for_exit_from_stub().
    stub_exit_code: CodePtr,

    /*
    // Code for full logic of returning from C method and exiting to the interpreter
    static uint32_t outline_full_cfunc_return_pos;

    // For implementing global code invalidation
    struct codepage_patch {
        uint32_t inline_patch_pos;
        uint32_t outlined_target_pos;
    };

    typedef rb_darray(struct codepage_patch) patch_array_t;

    static patch_array_t global_inval_patches = NULL;
    */
}

/// Private singleton instance of the codegen globals
static mut CODEGEN_GLOBALS: Option<CodegenGlobals> = None;

impl CodegenGlobals {
    /// Initialize the codegen globals
    pub fn init() {
        // Executable memory size in MiB
        let mem_size = get_option!(exec_mem_size) * 1024 * 1024;
        let mem_size: u32 = mem_size.try_into().unwrap();

        let mem_block: *mut u8 = unsafe { alloc_exec_mem(mem_size) };

        /*
        cb = &block;
        cb_init(cb, mem_block, mem_size/2);

        ocb = &outline_block;
        cb_init(ocb, mem_block + mem_size/2, mem_size/2);
        */

        let mut cb = CodeBlock::new();

        let mut ocb = OutlinedCb::wrap(CodeBlock::new());

        let leave_exit_code = gen_leave_exit(&mut ocb);

        let stub_exit_code = gen_code_for_exit_from_stub(&mut ocb);

        // TODO
        // Generate full exit code for C func
        //gen_full_cfunc_return();

        cb.mark_all_executable();
        ocb.unwrap().mark_all_executable();

        unsafe {
            CODEGEN_GLOBALS = Some(
                CodegenGlobals {
                    inline_cb: cb,
                    outlined_cb: ocb,
                    leave_exit_code: leave_exit_code,
                    stub_exit_code: stub_exit_code,
                }
            )
        }
    }

    /// Get a mutable reference to the codegen globals instance
    pub fn get_instance() -> &'static mut CodegenGlobals {
        unsafe {
            CODEGEN_GLOBALS.as_mut().unwrap()
        }
    }

    /// Get a mutable reference to the inline code block
    pub fn get_inline_cb() -> &'static mut CodeBlock {
        &mut CodegenGlobals::get_instance().inline_cb
    }

    /// Get a mutable reference to the outlined code block
    pub fn get_outlined_cb() -> &'static mut OutlinedCb {
        &mut CodegenGlobals::get_instance().outlined_cb
    }

    pub fn get_leave_exit_code() -> CodePtr {
        CodegenGlobals::get_instance().leave_exit_code
    }
}
