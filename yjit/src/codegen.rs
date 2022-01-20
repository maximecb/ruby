use crate::cruby::*;
use crate::asm::x64::*;
use crate::core::*;

// TODO
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
type CodeGenFn = fn(jit: &JITState, ctx: &Context, cb: &Assembler) -> CodegenStatus;

// TODO: I think we may need an init_codegen method
// It looks as though the gen_fns array is dynamic,
// so we may want to use a hash table
//static codegen_fn gen_fns[VM_INSTRUCTION_SIZE] = { NULL };

fn init_codegen()
{
}