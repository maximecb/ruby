use crate::cruby::*;
use crate::asm::x64::*;
use crate::core::*;



// Callee-saved registers
//#define REG_CFP R13
//#define REG_EC R12
//#define REG_SP RBX

// Scratch registers used by YJIT
//#define REG0 RAX
//#define REG0_32 EAX
//#define REG0_8 AL
//#define REG1 RCX
//#define REG1_32 ECX



// Code generation state
pub struct JITState
{
    // Inline and outlined code blocks we are
    // currently generating code into
    //codeblock_t* cb;
    //codeblock_t* ocb;

    // Block version being compiled
    block: Block,

    // Instruction sequence this is associated with
    //const rb_iseq_t *iseq;

    // Index of the current instruction being compiled
    insn_idx: u32,

    /*
    // Opcode for the instruction being compiled
    int opcode;

    // PC of the instruction being compiled
    VALUE *pc;
    */

    // Side exit to the instruction being compiled. See :side-exit:.
    side_exit_for_pc: CodePtr,

    // Execution context when compilation started
    // This allows us to peek at run-time values
    //rb_execution_context_t *ec;

    // Whether we need to record the code address at
    // the end of this bytecode instruction for global invalidation
    record_boundary_patch_point : bool,
}

enum CodegenStatus {
    EndBlock,
    KeepCompiling,
    CantCompile,
}

// TODO: this also needs an Assembler&
// Code generation function signature
type CodeGenFn = fn(jit: &JITState, ctx: &Ctx, cb: &Assembler) -> CodegenStatus;




//static void jit_ensure_block_entry_exit(jitstate_t *jit);

//static uint8_t *yjit_entry_prologue(codeblock_t *cb, const rb_iseq_t *iseq);

//static block_t *gen_single_block(blockid_t blockid, const ctx_t *start_ctx, rb_execution_context_t *ec);

//static void gen_code_for_exit_from_stub(void);

//static void yjit_init_codegen(void);
