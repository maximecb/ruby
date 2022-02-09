use crate::cruby::*;
use crate::core::*;
use crate::codegen::*;

/// This function is called from C code
/// NOTE: this should be wrapped in RB_VM_LOCK_ENTER(), rb_vm_barrier() on the C side
#[no_mangle]
pub extern "C" fn rb_yjit_init() {
    println!("Entering init_yjit() function");

    CodegenGlobals::init();

    // TODO:
    //Invariants::init() ?

    println!("Leaving init_yjit() function");
}

/// Called from C code to begin compiling a function
/// NOTE: this should be wrapped in RB_VM_LOCK_ENTER(), rb_vm_barrier() on the C side
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_gen_entry_point(iseq: IseqPtr, insn_idx: u32, ec: EcPtr) -> *const u8 {

    let maybe_code_ptr = crate::core::gen_entry_point(iseq, insn_idx, ec);

    match maybe_code_ptr {
        Some(ptr) => ptr.raw_ptr(),
        None => std::ptr::null()
    }
}

// TODO: expose branch_stub_hit() from core
// This one is not ready yet!
