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




enum CodegenStatus {
    EndBlock,
    KeepCompiling,
    CantCompile,
}




// Code generation function signature
//typedef codegen_status_t (*codegen_fn)(jitstate_t *jit, ctx_t *ctx, codeblock_t *cb);

//static void jit_ensure_block_entry_exit(jitstate_t *jit);

//static uint8_t *yjit_entry_prologue(codeblock_t *cb, const rb_iseq_t *iseq);

//static block_t *gen_single_block(blockid_t blockid, const ctx_t *start_ctx, rb_execution_context_t *ec);

//static void gen_code_for_exit_from_stub(void);

//static void yjit_init_codegen(void);
