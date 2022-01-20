use std::rc::{Rc, Weak};
use crate::cruby::*;
use crate::asm::x64::*;
use crate::codegen::*;
use crate::options::*;
use InsnOpnd::*;
use TempMapping::*;

// Maximum number of temp value types we keep track of
const MAX_TEMP_TYPES: usize = 8;

// Maximum number of local variable types we keep track of
const MAX_LOCAL_TYPES: usize = 8;

// Represent the type of a value (local/stack/self) in YJIT
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Type {
    Unknown,
    UnknownImm,
    UnknownHeap,
    Nil,
    True,
    False,
    Fixnum,
    Flonum,
    Array,
    Hash,
    ImmSymbol,
    HeapSymbol,
    String,
}

// Default initialization
impl Default for Type {
    fn default() -> Self {
        Type::Unknown
    }
}

impl Type {
    /// This returns an appropriate Type based on a known value
    fn from(val: VALUE) -> Type
    {
        unreachable!();

        /*
        if (SPECIAL_CONST_P(val)) {
            if (FIXNUM_P(val)) {
                return TYPE_FIXNUM;
            }
            else if (NIL_P(val)) {
                return TYPE_NIL;
            }
            else if (val == Qtrue) {
                return TYPE_TRUE;
            }
            else if (val == Qfalse) {
                return TYPE_FALSE;
            }
            else if (STATIC_SYM_P(val)) {
                return TYPE_STATIC_SYMBOL;
            }
            else if (FLONUM_P(val)) {
                return TYPE_FLONUM;
            }
            else {
                RUBY_ASSERT(false);
                UNREACHABLE_RETURN(TYPE_IMM);
            }
        }
        else {
            switch (BUILTIN_TYPE(val)) {
            case T_ARRAY:
                return TYPE_ARRAY;
            case T_HASH:
                return TYPE_HASH;
            case T_STRING:
                return TYPE_STRING;
            default:
                // generic heap object
                return TYPE_HEAP;
            }
        }
        */
    }

    fn is_imm(&self) -> bool {
        match self {
            Type::UnknownImm => true,
            Type::Nil => true,
            Type::True => true,
            Type::False => true,
            Type::Fixnum => true,
            Type::Flonum => true,
            Type::ImmSymbol => true,
            _ => false,
        }
    }

    fn is_heap(&self) -> bool {
        match self {
            Type::UnknownHeap => true,
            Type::Array => true,
            Type::Hash => true,
            Type::HeapSymbol => true,
            Type::String => true,
            _ => false,
        }
    }

    /// Compute a difference between two value types
    /// Returns 0 if the two are the same
    /// Returns > 0 if different but compatible
    /// Returns INT_MAX if incompatible
    fn diff(self, dst: Self) -> usize
    {
        println!("diff {:?}, {:?}", self, dst);

        // Perfect match, difference is zero
        if self == dst {
            return 0;
        }

        // Any type can flow into an unknown type
        if dst == Type::Unknown {
            return 1;
        }

        // Specific heap type into unknown heap type is imperfect but valid
        if self.is_heap() && dst == Type::UnknownHeap {
            return 1;
        }

        // Specific type into unknown immediate type is imperfect but valid
        if self.is_imm() && dst == Type::UnknownImm {
            return 1;
        }

        // Incompatible types
        return usize::MAX;
    }

    /// Upgrade this type into a more specific compatible type
    /// The new type must be compatible and at least as specific as the previously known type.
    fn upgrade(&mut self, src: Self)
    {
        // Here we're checking that src is more specific than self
        assert!(src.diff(*self) != usize::MAX);
        *self = src;
    }
}

// Potential mapping of a value on the temporary stack to
// self, a local variable or constant so that we can track its type
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TempMapping {
    MapToStack,               // Normal stack value
    MapToSelf,                // Temp maps to the self operand
    MapToLocal { idx: u8 },   // Temp maps to a local variable with index
    //ConstMapping,             // Small constant (0, 1, 2, Qnil, Qfalse, Qtrue)
}

impl Default for TempMapping {
    fn default() -> Self {
        MapToStack
    }
}

// Operand to a bytecode instruction
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InsnOpnd {
    // The value is self
    SelfOpnd,

    // Temporary stack operand with stack index
    StackOpnd { idx: u16 },
}

/**
Code generation context
Contains information we can use to optimize code
*/
#[derive(Copy, Clone, Default, Debug)]
pub struct Context
{
    // Number of values currently on the temporary stack
    stack_size : u16,

    // Offset of the JIT SP relative to the interpreter SP
    // This represents how far the JIT's SP is from the "real" SP
    sp_offset : i16,

    // Depth of this block in the sidechain (eg: inline-cache chain)
    chain_depth: u8,

    // Local variable types we keep track of
    local_types: [Type; MAX_LOCAL_TYPES],

    // Temporary variable types we keep track of
    temp_types: [Type; MAX_TEMP_TYPES],

    // Type we track for self
    self_type: Type,

    // Mapping of temp stack entries to types we track
    temp_mapping: [TempMapping; MAX_TEMP_TYPES],
}

// Tuple of (iseq, idx) used to identify basic blocks
pub struct BlockId
{
    // FIXME: we need a proper pointer type here

    // Instruction sequence
    //const rb_iseq_t *iseq;
    iseq: usize,

    // Index in the iseq where the block starts
    idx: usize,
}

// Null block id constant
pub const BLOCKID_NULL: BlockId = BlockId { iseq: 0, idx: 0 };

/// Pointer to a piece of machine code
/// We may later change this to wrap an u32
pub struct CodePtr(*mut u8);

// TODO: do we want constructor (new) or some from() methods for code pointers?
impl CodePtr {
}

/// Branch code shape enumeration
enum BranchShape
{
    Next0,  // Target 0 is next
    Next1,  // Target 1 is next
    Default // Neither target is next
}

// Branch code generation function signature
type BranchGenFn = fn(cb: &Assembler, target0: CodePtr, target1: CodePtr, shape: BranchShape) -> ();

/// Store info about an outgoing branch in a code segment
/// Note: care must be taken to minimize the size of branch_t objects
struct Branch
{
    // Block this is attached to
    block: Weak<Block>,

    // Positions where the generated code starts and ends
    start_addr: CodePtr,
    end_addr: CodePtr,

    // Context right after the branch instruction
    src_ctx : Context,

    // Branch target blocks and their contexts
    targets: [BlockId; 2],
    target_ctxs: [Context; 2],
    blocks: [Weak<Block>; 2],

    // Jump target addresses
    dst_addrs: [CodePtr; 2],

    // Branch code generation function
    gen_fn: BranchGenFn,

    // Shape of the branch
    shape: BranchShape,
}

/*
// In case this block is invalidated, these two pieces of info
// help to remove all pointers to this block in the system.
typedef struct {
    VALUE receiver_klass;
    VALUE callee_cme;
} cme_dependency_t;

typedef rb_darray(cme_dependency_t) cme_dependency_array_t;

typedef rb_darray(branch_t*) branch_array_t;
*/

/// Basic block version
/// Represents a portion of an iseq compiled with a given context
/// Note: care must be taken to minimize the size of block_t objects
pub struct Block
{
    // Bytecode sequence (iseq, idx) this is a version of
    blockid: BlockId,

    // Index one past the last instruction for this block in the iseq
    end_idx: u32,

    // Context at the start of the block
    ctx: Context,

    // Positions where the generated code starts and ends
    start_addr: CodePtr,
    end_addr: CodePtr,

    // List of incoming branches (from predecessors)
    // These are reference counted (ownership shared between predecessor and successors)
    incoming: Vec<Weak<Branch>>,

    // List of outgoing branches (to successors)
    outgoing: Vec<Rc<Branch>>,

    // FIXME: should these be code pointers instead?
    // Offsets for GC managed objects in the mainline code block
    gc_object_offsets: Vec<u32>,

    // TODO
    // CME dependencies of this block, to help to remove all pointers to this
    // block in the system.
    //cme_dependency_array_t cme_dependencies;

    // Code address of an exit for `ctx` and `blockid`.
    // Used for block invalidation.
    entry_exit: CodePtr,
}

/// List of block versions for a given blockid
type VersionList = Vec<Rc<Block>>;

/// Map from iseq indices to lists of versions for that give blockid
/// An instance of this is stored on each iseq
type VersionMap = Vec<VersionList>;

//===========================================================================
// I put the implementation of traits for core.rs types below
// We can move these closer to the above structs later if we want.
//===========================================================================

// For exiting from YJIT frame from branch_stub_hit().
// Filled by gen_code_for_exit_from_stub().
//static uint8_t *code_for_exit_from_stub = NULL;

impl Context {
    /*
    /// Get an operand for the adjusted stack pointer address
    sp_opnd(ctx_t *ctx, int32_t offset_bytes) -> x86opnd
    {
        int32_t offset = (ctx->sp_offset * sizeof(VALUE)) + offset_bytes;
        return mem_opnd(64, REG_SP, offset);
    }
    */

    /*
    /// Push one new value on the temp stack with an explicit mapping
    /// Return a pointer to the new stack top
    static x86opnd_t
    ctx_stack_push_mapping(ctx_t *ctx, temp_type_mapping_t mapping)
    {
        // If type propagation is disabled, store no types
        if (rb_yjit_opts.no_type_prop) {
            mapping.type = TYPE_UNKNOWN;
        }

        // Keep track of the type and mapping of the value
        if (ctx->stack_size < MAX_TEMP_TYPES) {
            ctx->temp_mapping[ctx->stack_size] = mapping.mapping;
            ctx->temp_types[ctx->stack_size] = mapping.type;

            RUBY_ASSERT(mapping.mapping.kind != TEMP_LOCAL || mapping.mapping.idx < MAX_LOCAL_TYPES);
            RUBY_ASSERT(mapping.mapping.kind != TEMP_STACK || mapping.mapping.idx == 0);
            RUBY_ASSERT(mapping.mapping.kind != TEMP_SELF || mapping.mapping.idx == 0);
        }

        ctx->stack_size += 1;
        ctx->sp_offset += 1;

        // SP points just above the topmost value
        int32_t offset = (ctx->sp_offset - 1) * sizeof(VALUE);
        return mem_opnd(64, REG_SP, offset);
    }

    /*
    Push one new value on the temp stack
    Return a pointer to the new stack top
    */
    static x86opnd_t
    ctx_stack_push(ctx_t *ctx, val_type_t type)
    {
        temp_type_mapping_t mapping = { MAP_STACK, type };
        return ctx_stack_push_mapping(ctx, mapping);
    }

    /*
    Push the self value on the stack
    */
    static x86opnd_t
    ctx_stack_push_self(ctx_t *ctx)
    {
        temp_type_mapping_t mapping = { MAP_SELF, TYPE_UNKNOWN };
        return ctx_stack_push_mapping(ctx, mapping);
    }

    /*
    Push a local variable on the stack
    */
    static x86opnd_t
    ctx_stack_push_local(ctx_t *ctx, size_t local_idx)
    {
        if (local_idx >= MAX_LOCAL_TYPES) {
            return ctx_stack_push(ctx, TYPE_UNKNOWN);
        }

        temp_type_mapping_t mapping = {
            (temp_mapping_t){ .kind = TEMP_LOCAL, .idx = local_idx },
            TYPE_UNKNOWN
        };

        return ctx_stack_push_mapping(ctx, mapping);
    }

    /*
    Pop N values off the stack
    Return a pointer to the stack top before the pop operation
    */
    static x86opnd_t
    ctx_stack_pop(ctx_t *ctx, size_t n)
    {
        RUBY_ASSERT(n <= ctx->stack_size);

        // SP points just above the topmost value
        int32_t offset = (ctx->sp_offset - 1) * sizeof(VALUE);
        x86opnd_t top = mem_opnd(64, REG_SP, offset);

        // Clear the types of the popped values
        for (size_t i = 0; i < n; ++i)
        {
            size_t idx = ctx->stack_size - i - 1;
            if (idx < MAX_TEMP_TYPES) {
                ctx->temp_types[idx] = TYPE_UNKNOWN;
                ctx->temp_mapping[idx] = MAP_STACK;
            }
        }

        ctx->stack_size -= n;
        ctx->sp_offset -= n;

        return top;
    }

    /**
    Get an operand pointing to a slot on the temp stack
    */
    static x86opnd_t
    ctx_stack_opnd(ctx_t *ctx, int32_t idx)
    {
        // SP points just above the topmost value
        int32_t offset = (ctx->sp_offset - 1 - idx) * sizeof(VALUE);
        x86opnd_t opnd = mem_opnd(64, REG_SP, offset);

        return opnd;
    }
    */

    /// Get the type of an instruction operand
    fn get_opnd_type(&self, opnd: InsnOpnd) -> Type
    {
        match opnd {
            SelfOpnd => {
                self.self_type
            },
            StackOpnd{ idx } => {
                let idx = idx as u16;
                assert!(idx < self.stack_size);
                let stack_idx = (self.stack_size - 1 - idx) as usize;

                // If outside of tracked range, do nothing
                if stack_idx >= MAX_TEMP_TYPES {
                    return Type::Unknown;
                }

                let mapping = self.temp_mapping[stack_idx];

                match mapping {
                    MapToSelf => {
                        self.self_type
                    },
                    MapToStack => {
                        self.temp_types[(self.stack_size - 1 - idx) as usize]
                    },
                    MapToLocal{idx} => {
                        assert!((idx as usize) < MAX_LOCAL_TYPES);
                        return self.local_types[idx as usize]
                    },
                }
            }
        }
    }

    /// Upgrade (or "learn") the type of an instruction operand
    /// This value must be compatible and at least as specific as the previously known type.
    /// If this value originated from self, or an lvar, the learned type will be
    /// propagated back to its source.
    fn upgrade_opnd_type(&mut self, opnd: InsnOpnd, opnd_type: Type)
    {
        // If type propagation is disabled, store no types
        if get_option!(no_type_prop) {
            return;
        }

        match opnd {
            SelfOpnd => {
                self.self_type.upgrade(opnd_type)
            },
            StackOpnd{ idx } => {
                let idx = idx as u16;
                assert!(idx < self.stack_size);
                let stack_idx = (self.stack_size - 1 - idx) as usize;

                // If outside of tracked range, do nothing
                if stack_idx >= MAX_TEMP_TYPES {
                    return;
                }

                let mapping = self.temp_mapping[stack_idx];

                match mapping {
                    MapToSelf => {
                        self.self_type.upgrade(opnd_type)
                    },
                    MapToStack => {
                        self.temp_types[stack_idx].upgrade(opnd_type)
                    },
                    MapToLocal{idx} => {
                        let idx = idx as usize;
                        assert!(idx < MAX_LOCAL_TYPES);
                        self.local_types[idx].upgrade(opnd_type);
                    },
                }
            }
        }
    }

    /*
    Get both the type and mapping (where the value originates) of an operand.
    This is can be used with stack_push_mapping or set_opnd_mapping to copy
    a stack value's type while maintaining the mapping.
    */
    fn get_opnd_mapping(&self, opnd: InsnOpnd) -> (TempMapping, Type)
    {
        let opnd_type = self.get_opnd_type(opnd);

        match opnd {
            SelfOpnd => {
                (MapToSelf, opnd_type)
            },
            StackOpnd{ idx } => {
                let idx = idx as u16;
                assert!(idx < self.stack_size);
                let stack_idx = (self.stack_size - 1 - idx) as usize;

                if stack_idx < MAX_TEMP_TYPES {
                    (self.temp_mapping[stack_idx], opnd_type)
                }
                else {
                    // We can't know the source of this stack operand, so we assume it is
                    // a stack-only temporary. type will be UNKNOWN
                    assert!(opnd_type == Type::Unknown);
                    (MapToStack, opnd_type)
                }
            }
        }
    }

    /// Overwrite both the type and mapping of a stack operand.
    fn set_opnd_mapping(&mut self, opnd: InsnOpnd, (mapping, opnd_type): (TempMapping, Type))
    {
        match opnd {
            SelfOpnd => unreachable!("self always maps to self"),
            StackOpnd{ idx } => {
                assert!(idx < self.stack_size);
                let stack_idx = (self.stack_size - 1 - idx) as usize;

                // If type propagation is disabled, store no types
                if get_option!(no_type_prop) {
                    return;
                }

                // If outside of tracked range, do nothing
                if stack_idx >= MAX_TEMP_TYPES {
                    return;
                }

                self.temp_mapping[stack_idx] = mapping;

                // Only used when mapping == MAP_STACK
                self.temp_types[stack_idx] = opnd_type;
            }
        }
    }

    /// Set the type of a local variable
    fn set_local_type(&mut self, local_idx: usize, local_type: Type) {
        let ctx = self;

        // If type propagation is disabled, store no types
        if get_option!(no_type_prop) {
            return;
        }

        if local_idx < MAX_LOCAL_TYPES {
            return;
        }

        // If any values on the stack map to this local we must detach them
        for (i, mapping) in ctx.temp_mapping.iter_mut().enumerate() {
            *mapping = match *mapping {
                MapToStack => MapToStack,
                MapToSelf => MapToSelf,
                MapToLocal{idx} => {
                    if idx as usize == local_idx {
                        ctx.temp_types[i] = ctx.local_types[idx as usize];
                        MapToStack
                    } else {
                        MapToLocal{idx}
                    }
                },
            }
        }

        ctx.local_types[local_idx] = local_type;
    }

    /// Erase local variable type information
    /// eg: because of a call we can't track
    fn clear_local_types(ctx: &mut Self) {
        // When clearing local types we must detach any stack mappings to those
        // locals. Even if local values may have changed, stack values will not.
        for (i, mapping) in ctx.temp_mapping.iter_mut().enumerate() {
            *mapping = match *mapping {
                MapToStack => MapToStack,
                MapToSelf => MapToSelf,
                MapToLocal{idx} => {
                    ctx.temp_types[i] = ctx.local_types[idx as usize];
                    MapToStack
                },
            }
        }

        // Clear the local types
        ctx.local_types = [Type::default(); MAX_LOCAL_TYPES];
    }

    /// Compute a difference score for two context objects
    /// Returns 0 if the two contexts are the same
    /// Returns > 0 if different but compatible
    /// Returns usize::MAX if incompatible
    fn diff(&self, dst: &Context) -> usize
    {
        // Self is the source context (at the end of the predecessor)
        let src = self;

        // Can only lookup the first version in the chain
        if dst.chain_depth != 0 {
            return usize::MAX;
        }

        // Blocks with depth > 0 always produce new versions
        // Sidechains cannot overlap
        if src.chain_depth != 0 {
            return usize::MAX;
        }

        if dst.stack_size != src.stack_size {
            return usize::MAX;
        }

        if dst.sp_offset != src.sp_offset {
            return usize::MAX;
        }

        // Difference sum
        let mut diff = 0;

        // Check the type of self
        let self_diff = src.self_type.diff(dst.self_type);

        if self_diff == usize::MAX {
            return usize::MAX;
        }

        diff += self_diff;

        // For each local type we track
        for i in 0..src.local_types.len() {
            let t_src = src.local_types[i];
            let t_dst = dst.local_types[i];
            let temp_diff = t_src.diff(t_dst);

            if temp_diff == usize::MAX {
                return usize::MAX;
            }

            diff += temp_diff;
        }

        // For each value on the temp stack
        for i in 0..src.stack_size {
            let (src_mapping, src_type) = src.get_opnd_mapping(StackOpnd{idx: i});
            let (dst_mapping, dst_type) = dst.get_opnd_mapping(StackOpnd{idx: i});

            // If the two mappings aren't the same
            if src_mapping != dst_mapping {
                if dst_mapping == MapToStack {
                    // We can safely drop information about the source of the temp
                    // stack operand.
                    diff += 1;
                }
                else {
                    return usize::MAX;
                }
            }

            let temp_diff = src_type.diff(dst_type);

            if temp_diff == usize::MAX {
                return usize::MAX;
            }

            diff += temp_diff;
        }

        return diff;
    }
}

// Get all blocks for a particular place in an iseq.
fn get_version_list(blockid: BlockId) -> VersionList
{
    unimplemented!();

    /*
    struct rb_iseq_constant_body *body = iseq->body;

    if (rb_darray_size(body->yjit_blocks) == 0) {
        return NULL;
    }

    RUBY_ASSERT((unsigned)rb_darray_size(body->yjit_blocks) == body->iseq_size);
    return rb_darray_get(body->yjit_blocks, idx);
    */
}

// Count the number of block versions matching a given blockid
fn get_num_versions(blockid: BlockId) -> usize
{
    return get_version_list(blockid).len();
}

// Keep track of a block version. Block should be fully constructed.
fn add_block_version(block: &mut Block)
{
    unimplemented!();

    /*
    const blockid_t blockid = block->blockid;
    const rb_iseq_t *iseq = blockid.iseq;
    struct rb_iseq_constant_body *body = iseq->body;

    // Function entry blocks must have stack size 0
    RUBY_ASSERT(!(block->blockid.idx == 0 && block->ctx.stack_size > 0));

    // Ensure yjit_blocks is initialized for this iseq
    if (rb_darray_size(body->yjit_blocks) == 0) {
        // Initialize yjit_blocks to be as wide as body->iseq_encoded
        int32_t casted = (int32_t)body->iseq_size;
        if ((unsigned)casted != body->iseq_size) {
            rb_bug("iseq too large");
        }
        if (!rb_darray_make(&body->yjit_blocks, casted)) {
            rb_bug("allocation failed");
        }

#if YJIT_STATS
        // First block compiled for this iseq
        yjit_runtime_counters.compiled_iseq_count++;
#endif
    }

    RUBY_ASSERT((int32_t)blockid.idx < rb_darray_size(body->yjit_blocks));
    rb_yjit_block_array_t *block_array_ref = rb_darray_ref(body->yjit_blocks, blockid.idx);

    // Add the new block
    if (!rb_darray_append(block_array_ref, block)) {
        rb_bug("allocation failed");
    }

    {
        // By writing the new block to the iseq, the iseq now
        // contains new references to Ruby objects. Run write barriers.
        cme_dependency_t *cme_dep;
        rb_darray_foreach(block->cme_dependencies, cme_dependency_idx, cme_dep) {
            RB_OBJ_WRITTEN(iseq, Qundef, cme_dep->receiver_klass);
            RB_OBJ_WRITTEN(iseq, Qundef, cme_dep->callee_cme);
        }

        // Run write barriers for all objects in generated code.
        uint32_t *offset_element;
        rb_darray_foreach(block->gc_object_offsets, offset_idx, offset_element) {
            uint32_t offset_to_value = *offset_element;
            uint8_t *value_address = cb_get_ptr(cb, offset_to_value);

            VALUE object;
            memcpy(&object, value_address, SIZEOF_VALUE);
            RB_OBJ_WRITTEN(iseq, Qundef, object);
        }
    }

#if YJIT_STATS
    yjit_runtime_counters.compiled_block_count++;
#endif
    */
}

/*
static ptrdiff_t
branch_code_size(const branch_t *branch)
{
    return branch->end_addr - branch->start_addr;
}

// Generate code for a branch, possibly rewriting and changing the size of it
static void
regenerate_branch(codeblock_t *cb, branch_t *branch)
{
    if (branch->start_addr < cb_get_ptr(cb, yjit_codepage_frozen_bytes)) {
        // Generating this branch would modify frozen bytes. Do nothing.
        return;
    }

    const uint32_t old_write_pos = cb->write_pos;
    const bool branch_terminates_block = branch->end_addr == branch->block->end_addr;

    RUBY_ASSERT(branch->dst_addrs[0] != NULL);

    cb_set_write_ptr(cb, branch->start_addr);
    branch->gen_fn(cb, branch->dst_addrs[0], branch->dst_addrs[1], branch->shape);
    branch->end_addr = cb_get_write_ptr(cb);

    if (branch_terminates_block) {
        // Adjust block size
        branch->block->end_addr = branch->end_addr;
    }

    // cb->write_pos is both a write cursor and a marker for the end of
    // everything written out so far. Leave cb->write_pos at the end of the
    // block before returning. This function only ever bump or retain the end
    // of block marker since that's what the majority of callers want. When the
    // branch sits at the very end of the codeblock and it shrinks after
    // regeneration, it's up to the caller to drop bytes off the end to
    // not leave a gap and implement branch->shape.
    if (old_write_pos > cb->write_pos) {
        // We rewound cb->write_pos to generate the branch, now restore it.
        cb_set_pos(cb, old_write_pos);
    }
    else {
        // The branch sits at the end of cb and consumed some memory.
        // Keep cb->write_pos.
    }
}
*/

// Create a new outgoing branch entry for a block
fn make_branch_entry(block: &mut Block, src_ctx: Context, gen_fn: BranchGenFn) -> Branch {

    unimplemented!();

    /*
    let branch = Branch {
        block: Weak::new(block),
        src_ctx: *src_ctx,

        gen_fn: gen_fn,

        shape: BranchShape::Default

        // Block this is attached to
        block: Weak<Block>,

        // Positions where the generated code starts and ends
        start_addr: CodePtr,
        end_addr: CodePtr,

        // Context right after the branch instruction
        src_ctx : Context,

        // Branch target blocks and their contexts
        targets: [BlockId; 2],
        target_ctxs: [Context; 2],
        blocks: [Weak<Block>; 2],

        // Jump target addresses
        dst_addrs: [CodePtr; 2],
    };
    */

    // TODO
    // Add to the list of outgoing branches for the block
    //rb_darray_append(&block->outgoing, branch);

    //return branch;
}

/// Retrieve a basic block version for an (iseq, idx) tuple
/// This will return None if no version is found
fn find_block_version(blockid: BlockId, ctx: &Context) -> Option<Rc<Block>>
{
    let versions = get_version_list(blockid);

    // Best match found
    let mut best_version: Option<Rc<Block>> = None;
    let mut best_diff = usize::MAX;

    // For each version matching the blockid
    for version in versions {
        let diff = ctx.diff(&version.ctx);

        // Note that we always prefer the first matching
        // version found because of inline-cache chains
        if diff < best_diff {
            best_version = Some(version);
            best_diff = diff;
        }
    }

    // FIXME
    /*
    // If greedy versioning is enabled
    if get_option!(greedy_versioning) {
        // If we're below the version limit, don't settle for an imperfect match
        if versions.len() + 1 < get_option!(max_versions) && best_diff > 0 {
            return None;
        }
    }
    */

    return best_version;
}

// Produce a generic context when the block version limit is hit for a blockid
// Note that this will mutate the ctx argument
fn limit_block_versions(blockid: BlockId, ctx: &Context) -> Context
{
    // Guard chains implement limits separately, do nothing
    if ctx.chain_depth > 0 {
        return *ctx;
    }

    // If this block version we're about to add will hit the version limit
    if get_num_versions(blockid) + 1 >= get_option!(max_versions) {
        // Produce a generic context that stores no type information,
        // but still respects the stack_size and sp_offset constraints.
        // This new context will then match all future requests.
        let mut generic_ctx = Context::default();
        generic_ctx.stack_size = ctx.stack_size;
        generic_ctx.sp_offset = ctx.sp_offset;

        // Mutate the incoming context
        return generic_ctx;
    }

    return *ctx;
}

/*
// Immediately compile a series of block versions at a starting point and
// return the starting block.
static block_t *
gen_block_version(blockid_t blockid, const ctx_t *start_ctx, rb_execution_context_t *ec)
{
    // Small array to keep track of all the blocks compiled per invocation. We
    // tend to have small batches since we often break up compilation with lazy
    // stubs. Compilation is successful only if the whole batch is successful.
    enum { MAX_PER_BATCH = 64 };
    block_t *batch[MAX_PER_BATCH];
    int compiled_count = 0;
    bool batch_success = true;
    block_t *block;

    // Generate code for the first block
    block = gen_single_block(blockid, start_ctx, ec);
    if (block) {
        // Track the block
        add_block_version(block);

        batch[compiled_count] = block;
        compiled_count++;
    }
    batch_success = block;

    // For each successor block to compile
    while (batch_success) {
        // If the previous block compiled doesn't have outgoing branches, stop
        if (rb_darray_size(block->outgoing) == 0) {
            break;
        }

        // Get the last outgoing branch from the previous block. Blocks can use
        // gen_direct_jump() to request a block to be placed immediately after.
        branch_t *last_branch = rb_darray_back(block->outgoing);

        // If there is no next block to compile, stop
        if (last_branch->dst_addrs[0] || last_branch->dst_addrs[1]) {
            break;
        }

        if (last_branch->targets[0].iseq == NULL) {
            rb_bug("invalid target for last branch");
        }

        // Generate code for the current block using context from the last branch.
        blockid_t requested_id = last_branch->targets[0];
        const ctx_t *requested_ctx = &last_branch->target_ctxs[0];

        batch_success = compiled_count < MAX_PER_BATCH;
        if (batch_success) {
            block = gen_single_block(requested_id, requested_ctx, ec);
            batch_success = block;
        }

        // If the batch failed, stop
        if (!batch_success) {
            break;
        }

        // Connect the last branch and the new block
        last_branch->dst_addrs[0] = block->start_addr;
        rb_darray_append(&block->incoming, last_branch);
        last_branch->blocks[0] = block;

        // This block should immediately follow the last branch
        RUBY_ASSERT(block->start_addr == last_branch->end_addr);

        // Track the block
        add_block_version(block);

        batch[compiled_count] = block;
        compiled_count++;
    }

    if (batch_success) {
        // Success. Return first block in the batch.
        RUBY_ASSERT(compiled_count > 0);
        return batch[0];
    }
    else {
        // The batch failed. Free everything in the batch
        for (int block_idx = 0; block_idx < compiled_count; block_idx++) {
            block_t *const to_free = batch[block_idx];

            // Undo add_block_version()
            rb_yjit_block_array_t versions = yjit_get_version_list(to_free->blockid.iseq, to_free->blockid.idx);
            block_array_remove(versions, to_free);

            // Deallocate
            yjit_free_block(to_free);
        }

#if YJIT_STATS
        yjit_runtime_counters.compilation_failure++;
#endif
        return NULL;
    }
}

// Generate a block version that is an entry point inserted into an iseq
static uint8_t *
gen_entry_point(const rb_iseq_t *iseq, uint32_t insn_idx, rb_execution_context_t *ec)
{
    // If we aren't at PC 0, don't generate code
    // See yjit_pc_guard
    if (iseq->body->iseq_encoded != ec->cfp->pc) {
        return NULL;
    }

    // The entry context makes no assumptions about types
    blockid_t blockid = { iseq, insn_idx };

    rb_vm_barrier();
    // Write the interpreter entry prologue. Might be NULL when out of memory.
    uint8_t *code_ptr = yjit_entry_prologue(cb, iseq);

    // Try to generate code for the entry block
    block_t *block = gen_block_version(blockid, &DEFAULT_CTX, ec);

    cb_mark_all_executable(ocb);
    cb_mark_all_executable(cb);

    // If we couldn't generate any code
    if (!block || block->end_idx == insn_idx) {
        return NULL;
    }

    return code_ptr;
}

// Called by the generated code when a branch stub is executed
// Triggers compilation of branches and code patching
static uint8_t *
branch_stub_hit(branch_t *branch, const uint32_t target_idx, rb_execution_context_t *ec)
{
    uint8_t *dst_addr = NULL;

    // Stop other ractors since we are going to patch machine code.
    // This is how the GC does it.
    RB_VM_LOCK_ENTER();
    rb_vm_barrier();

    const ptrdiff_t branch_size_on_entry = branch_code_size(branch);

    RUBY_ASSERT(branch != NULL);
    RUBY_ASSERT(target_idx < 2);
    blockid_t target = branch->targets[target_idx];
    const ctx_t *target_ctx = &branch->target_ctxs[target_idx];

    // If this branch has already been patched, return the dst address
    // Note: ractors can cause the same stub to be hit multiple times
    if (branch->blocks[target_idx]) {
        dst_addr = branch->dst_addrs[target_idx];
    }
    else {
        rb_vm_barrier();

        // :stub-sp-flush:
        // Generated code do stack operations without modifying cfp->sp, while the
        // cfp->sp tells the GC what values on the stack to root. Generated code
        // generally takes care of updating cfp->sp when it calls runtime routines that
        // could trigger GC, but it's inconvenient to do it before calling this function.
        // So we do it here instead.
        VALUE *const original_interp_sp = ec->cfp->sp;
        ec->cfp->sp += target_ctx->sp_offset;

        // Update the PC in the current CFP, because it
        // may be out of sync in JITted code
        ec->cfp->pc = yjit_iseq_pc_at_idx(target.iseq, target.idx);

        // Try to find an existing compiled version of this block
        block_t *p_block = find_block_version(target, target_ctx);

        // If this block hasn't yet been compiled
        if (!p_block) {
            const uint8_t branch_old_shape = branch->shape;
            bool branch_modified = false;

            // If the new block can be generated right after the branch (at cb->write_pos)
            if (cb_get_write_ptr(cb) == branch->end_addr) {
                // This branch should be terminating its block
                RUBY_ASSERT(branch->end_addr == branch->block->end_addr);

                // Change the branch shape to indicate the target block will be placed next
                branch->shape = (uint8_t)target_idx;

                // Rewrite the branch with the new, potentially more compact shape
                regenerate_branch(cb, branch);
                branch_modified = true;

                // Ensure that the branch terminates the codeblock just like
                // before entering this if block. This drops bytes off the end
                // in case we shrank the branch when regenerating.
                cb_set_write_ptr(cb, branch->end_addr);
            }

            // Compile the new block version
            p_block = gen_block_version(target, target_ctx, ec);

            if (!p_block && branch_modified) {
                // We couldn't generate a new block for the branch, but we modified the branch.
                // Restore the branch by regenerating it.
                branch->shape = branch_old_shape;
                regenerate_branch(cb, branch);
            }
        }

        if (p_block) {
            // Branch shape should reflect layout
            RUBY_ASSERT(!(branch->shape == (uint8_t)target_idx && p_block->start_addr != branch->end_addr));

            // Add this branch to the list of incoming branches for the target
            rb_darray_append(&p_block->incoming, branch);

            // Update the branch target address
            dst_addr = p_block->start_addr;
            branch->dst_addrs[target_idx] = dst_addr;

            // Mark this branch target as patched (no longer a stub)
            branch->blocks[target_idx] = p_block;

            // Rewrite the branch with the new jump target address
            regenerate_branch(cb, branch);

            // Restore interpreter sp, since the code hitting the stub expects the original.
            ec->cfp->sp = original_interp_sp;
        }
        else {
            // Failed to service the stub by generating a new block so now we
            // need to exit to the interpreter at the stubbed location. We are
            // intentionally *not* restoring original_interp_sp. At the time of
            // writing, reconstructing interpreter state only involves setting
            // cfp->sp and cfp->pc. We set both before trying to generate the
            // block. All there is left to do to exit is to pop the native
            // frame. We do that in code_for_exit_from_stub.
            dst_addr = code_for_exit_from_stub;
        }

        cb_mark_all_executable(ocb);
        cb_mark_all_executable(cb);
    }

    const ptrdiff_t new_branch_size = branch_code_size(branch);
    RUBY_ASSERT_ALWAYS(new_branch_size >= 0);
    RUBY_ASSERT_ALWAYS(new_branch_size <= branch_size_on_entry && "branch stubs should not enlarge branches");

    RB_VM_LOCK_LEAVE();

    // Return a pointer to the compiled block version
    return dst_addr;
}

// Get a version or stub corresponding to a branch target
static uint8_t *
get_branch_target(
    blockid_t target,
    const ctx_t *ctx,
    branch_t *branch,
    uint32_t target_idx
)
{
    //fprintf(stderr, "get_branch_target, block (%p, %d)\n", target.iseq, target.idx);

    block_t *p_block = find_block_version(target, ctx);

    // If the block already exists
    if (p_block) {
        // Add an incoming branch for this version
        rb_darray_append(&p_block->incoming, branch);
        branch->blocks[target_idx] = p_block;

        // Return a pointer to the compiled code
        return p_block->start_addr;
    }

    // Do we have enough memory for a stub?
    const long MAX_CODE_SIZE = 64;
    if (ocb->write_pos + MAX_CODE_SIZE >= cb->mem_size) {
        return NULL;
    }

    // Generate an outlined stub that will call branch_stub_hit()
    uint8_t *stub_addr = cb_get_ptr(ocb, ocb->write_pos);

    // Call branch_stub_hit(branch_idx, target_idx, ec)
    mov(ocb, C_ARG_REGS[2], REG_EC);
    mov(ocb, C_ARG_REGS[1], imm_opnd(target_idx));
    mov(ocb, C_ARG_REGS[0], const_ptr_opnd(branch));
    call_ptr(ocb, REG0, (void *)&branch_stub_hit);

    // Jump to the address returned by the
    // branch_stub_hit call
    jmp_rm(ocb, RAX);

    RUBY_ASSERT(cb_get_ptr(ocb, ocb->write_pos) - stub_addr <= MAX_CODE_SIZE);

    return stub_addr;
}

static void
gen_branch(
    jitstate_t *jit,
    const ctx_t *src_ctx,
    blockid_t target0,
    const ctx_t *ctx0,
    blockid_t target1,
    const ctx_t *ctx1,
    branchgen_fn gen_fn
)
{
    RUBY_ASSERT(target0.iseq != NULL);

    branch_t *branch = make_branch_entry(jit->block, src_ctx, gen_fn);
    branch->targets[0] = target0;
    branch->targets[1] = target1;
    branch->target_ctxs[0] = *ctx0;
    branch->target_ctxs[1] = ctx1? *ctx1:DEFAULT_CTX;

    // Get the branch targets or stubs
    branch->dst_addrs[0] = get_branch_target(target0, ctx0, branch, 0);
    branch->dst_addrs[1] = ctx1? get_branch_target(target1, ctx1, branch, 1):NULL;

    // Call the branch generation function
    branch->start_addr = cb_get_write_ptr(cb);
    regenerate_branch(cb, branch);
}

static void
gen_jump_branch(codeblock_t *cb, uint8_t *target0, uint8_t *target1, uint8_t shape)
{
    switch (shape) {
      case SHAPE_NEXT0:
        break;

      case SHAPE_NEXT1:
        RUBY_ASSERT(false);
        break;

      case SHAPE_DEFAULT:
        jmp_ptr(cb, target0);
        break;
    }
}

static void
gen_direct_jump(
    jitstate_t *jit,
    const ctx_t *ctx,
    blockid_t target0
)
{
    RUBY_ASSERT(target0.iseq != NULL);

    branch_t *branch = make_branch_entry(jit->block, ctx, gen_jump_branch);
    branch->targets[0] = target0;
    branch->target_ctxs[0] = *ctx;

    block_t *p_block = find_block_version(target0, ctx);

    // If the version already exists
    if (p_block) {
        rb_darray_append(&p_block->incoming, branch);

        branch->dst_addrs[0] = p_block->start_addr;
        branch->blocks[0] = p_block;
        branch->shape = SHAPE_DEFAULT;

        // Call the branch generation function
        branch->start_addr = cb_get_write_ptr(cb);
        gen_jump_branch(cb, branch->dst_addrs[0], NULL, SHAPE_DEFAULT);
        branch->end_addr = cb_get_write_ptr(cb);
    }
    else {
        // This NULL target address signals gen_block_version() to compile the
        // target block right after this one (fallthrough).
        branch->dst_addrs[0] = NULL;
        branch->shape = SHAPE_NEXT0;
        branch->start_addr = cb_get_write_ptr(cb);
        branch->end_addr = cb_get_write_ptr(cb);
    }
}

// Create a stub to force the code up to this point to be executed
static void
defer_compilation(
    jitstate_t *jit,
    ctx_t *cur_ctx
)
{
    //fprintf(stderr, "defer compilation at (%p, %d) depth=%d\n", block->blockid.iseq, insn_idx, cur_ctx->chain_depth);

    if (cur_ctx->chain_depth != 0) {
        rb_bug("double defer");
    }

    ctx_t next_ctx = *cur_ctx;

    if (next_ctx.chain_depth >= UINT8_MAX) {
        rb_bug("max block version chain depth reached");
    }

    next_ctx.chain_depth += 1;

    branch_t *branch = make_branch_entry(jit->block, cur_ctx, gen_jump_branch);

    // Get the branch targets or stubs
    branch->target_ctxs[0] = next_ctx;
    branch->targets[0] = (blockid_t){ jit->block->blockid.iseq, jit->insn_idx };
    branch->dst_addrs[0] = get_branch_target(branch->targets[0], &next_ctx, branch, 0);

    // Call the branch generation function
    codeblock_t *cb = jit->cb;
    branch->start_addr = cb_get_write_ptr(cb);
    gen_jump_branch(cb, branch->dst_addrs[0], NULL, SHAPE_DEFAULT);
    branch->end_addr = cb_get_write_ptr(cb);
}

// Remove all references to a block then free it.
static void
yjit_free_block(block_t *block)
{
    yjit_unlink_method_lookup_dependency(block);
    yjit_block_assumptions_free(block);

    // Remove this block from the predecessor's targets
    rb_darray_for(block->incoming, incoming_idx) {
        // Branch from the predecessor to us
        branch_t *pred_branch = rb_darray_get(block->incoming, incoming_idx);

        // If this is us, nullify the target block
        for (size_t succ_idx = 0; succ_idx < 2; succ_idx++) {
            if (pred_branch->blocks[succ_idx] == block) {
                pred_branch->blocks[succ_idx] = NULL;
            }
        }
    }

    // For each outgoing branch
    rb_darray_for(block->outgoing, branch_idx) {
        branch_t *out_branch = rb_darray_get(block->outgoing, branch_idx);

        // For each successor block
        for (size_t succ_idx = 0; succ_idx < 2; succ_idx++) {
            block_t *succ = out_branch->blocks[succ_idx];

            if (succ == NULL)
                continue;

            // Remove this block from the successor's incoming list
            rb_darray_for(succ->incoming, incoming_idx) {
                branch_t *pred_branch = rb_darray_get(succ->incoming, incoming_idx);
                if (pred_branch == out_branch) {
                    rb_darray_remove_unordered(succ->incoming, incoming_idx);
                    break;
                }
            }
        }

        // Free the outgoing branch entry
        free(out_branch);
    }

    rb_darray_free(block->incoming);
    rb_darray_free(block->outgoing);
    rb_darray_free(block->gc_object_offsets);

    free(block);
}

// Remove a block version
static void
block_array_remove(rb_yjit_block_array_t block_array, block_t *block)
{
    block_t **element;
    rb_darray_foreach(block_array, idx, element) {
        if (*element == block) {
            rb_darray_remove_unordered(block_array, idx);
            return;
        }
    }

    RUBY_ASSERT(false);
}

// Some runtime checks for integrity of a program location
static void
verify_blockid(const blockid_t blockid)
{
    const rb_iseq_t *const iseq = blockid.iseq;
    RUBY_ASSERT_ALWAYS(IMEMO_TYPE_P(iseq, imemo_iseq));
    RUBY_ASSERT_ALWAYS(blockid.idx < iseq->body->iseq_size);
}

// Invalidate one specific block version
static void
invalidate_block_version(block_t *block)
{
    ASSERT_vm_locking();

    // TODO: want to assert that all other ractors are stopped here. Can't patch
    // machine code that some other thread is running.

    verify_blockid(block->blockid);

    const rb_iseq_t *iseq = block->blockid.iseq;

    //fprintf(stderr, "invalidating block (%p, %d)\n", block->blockid.iseq, block->blockid.idx);
    //fprintf(stderr, "block=%p\n", block);

    // Remove this block from the version array
    rb_yjit_block_array_t versions = yjit_get_version_list(iseq, block->blockid.idx);
    block_array_remove(versions, block);

    // Get a pointer to the generated code for this block
    uint8_t *code_ptr = block->start_addr;

    // Make the the start of the block do an exit. This handles OOM situations
    // and some cases where we can't efficiently patch incoming branches.
    // Do this first, since in case there is a fallthrough branch into this
    // block, the patching loop below can overwrite the start of the block.
    // In those situations, there is hopefully no jumps to the start of the block
    // after patching as the start of the block would be in the middle of something
    // generated by branch_t::gen_fn.
    {
        RUBY_ASSERT_ALWAYS(block->entry_exit && "block invalidation requires an exit");
        if (block->entry_exit == block->start_addr) {
            // Some blocks exit on entry. Patching a jump to the entry at the
            // entry makes an infinite loop.
        }
        else if (block->start_addr >= cb_get_ptr(cb, yjit_codepage_frozen_bytes)) { // Don't patch frozen code region
            // Patch in a jump to block->entry_exit.
            uint32_t cur_pos = cb->write_pos;
            cb_set_write_ptr(cb, block->start_addr);
            jmp_ptr(cb, block->entry_exit);
            RUBY_ASSERT_ALWAYS(cb_get_ptr(cb, cb->write_pos) < block->end_addr && "invalidation wrote past end of block");
            cb_set_pos(cb, cur_pos);
        }
    }

    // For each incoming branch
    rb_darray_for(block->incoming, incoming_idx) {
        branch_t *branch = rb_darray_get(block->incoming, incoming_idx);
        uint32_t target_idx = (branch->dst_addrs[0] == code_ptr)? 0:1;
        RUBY_ASSERT(branch->dst_addrs[target_idx] == code_ptr);
        RUBY_ASSERT(branch->blocks[target_idx] == block);

        // Mark this target as being a stub
        branch->blocks[target_idx] = NULL;

        // Don't patch frozen code region
        if (branch->start_addr < cb_get_ptr(cb, yjit_codepage_frozen_bytes)) {
            continue;
        }

        // Create a stub for this branch target
        uint8_t *branch_target = get_branch_target(
            block->blockid,
            &block->ctx,
            branch,
            target_idx
        );

        if (!branch_target) {
            // We were unable to generate a stub (e.g. OOM). Use the block's
            // exit instead of a stub for the block. It's important that we
            // still patch the branch in this situation so stubs are unique
            // to branches. Think about what could go wrong if we run out of
            // memory in the middle of this loop.
            branch_target = block->entry_exit;
        }

        branch->dst_addrs[target_idx] = branch_target;

        // Check if the invalidated block immediately follows
        bool target_next = (block->start_addr == branch->end_addr);

        if (target_next) {
            // The new block will no longer be adjacent.
            // Note that we could be enlarging the branch and writing into the
            // start of the block being invalidated.
            branch->shape = SHAPE_DEFAULT;
        }

        // Rewrite the branch with the new jump target address
        regenerate_branch(cb, branch);

        if (target_next && branch->end_addr > block->end_addr) {
            fprintf(stderr, "branch_block_idx=%u block_idx=%u over=%ld block_size=%ld\n",
                branch->block->blockid.idx,
                block->blockid.idx,
                branch->end_addr - block->end_addr,
                block->end_addr - block->start_addr);
            yjit_print_iseq(branch->block->blockid.iseq);
            rb_bug("yjit invalidate rewrote branch past end of invalidated block");
        }
    }

    // Clear out the JIT func so that we can recompile later and so the
    // interpreter will run the iseq

#if JIT_ENABLED
    // Only clear the jit_func when we're invalidating the JIT entry block.
    // We only support compiling iseqs from index 0 right now.  So entry
    // points will always have an instruction index of 0.  We'll need to
    // change this in the future when we support optional parameters because
    // they enter the function with a non-zero PC
    if (block->blockid.idx == 0) {
        iseq->body->jit_func = 0;
    }
#endif

    // TODO:
    // May want to recompile a new entry point (for interpreter entry blocks)
    // This isn't necessary for correctness

    // FIXME:
    // Call continuation addresses on the stack can also be atomically replaced by jumps going to the stub.

    yjit_free_block(block);

#if YJIT_STATS
    yjit_runtime_counters.invalidation_count++;
#endif

    cb_mark_all_executable(ocb);
    cb_mark_all_executable(cb);

    // fprintf(stderr, "invalidation done\n");
}
*/

fn init_core() {
    //gen_code_for_exit_from_stub();
    unimplemented!();
}

#[cfg(test)]
mod tests {
    use crate::core::*;

    #[test]
    fn types() {
        // Valid src => dst
        assert_eq!(Type::Unknown.diff(Type::Unknown), 0);
        assert_eq!(Type::UnknownImm.diff(Type::UnknownImm), 0);
        assert_ne!(Type::UnknownImm.diff(Type::Unknown), usize::MAX);
        assert_ne!(Type::Fixnum.diff(Type::Unknown), usize::MAX);
        assert_ne!(Type::Fixnum.diff(Type::UnknownImm), usize::MAX);

        // Invalid src => dst
        assert_eq!(Type::Unknown.diff(Type::UnknownImm), usize::MAX);
        assert_eq!(Type::Unknown.diff(Type::Fixnum), usize::MAX);
        assert_eq!(Type::Fixnum.diff(Type::UnknownHeap), usize::MAX);
    }

    fn context() {
        // Valid src => dst
        assert_eq!(Context::default().diff(&Context::default()), 0);

        // TODO: write more tests for Context type diff
    }
}