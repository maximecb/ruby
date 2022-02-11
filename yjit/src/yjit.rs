use crate::cruby::{EcPtr, IseqPtr};
use crate::codegen::*;
use crate::core::*;
use crate::options::*;

/// Parse one command-line option
#[no_mangle]
pub extern "C" fn rb_yjit_parse_option(str_ptr: *const std::os::raw::c_char) -> bool
{
    return parse_option(str_ptr);
}

/// This function is called from C code
#[no_mangle]
pub extern "C" fn rb_yjit_init_rust()
{
    println!("Entering rb_yjit_init_rust() function");

    // TODO: need to make sure that command-line options have been
    // initialized by CRuby

    // Catch panics to avoid UB for unwinding into C frames.
    // See https://doc.rust-lang.org/nomicon/exception-safety.html
    // TODO: set a panic handler so the we don't print a message
    //       everytime we panic.
    let result = std::panic::catch_unwind(|| {

        CodegenGlobals::init();

        // TODO:
        //Invariants::init() ?

    });

    if let Err(_) = result {
        println!("YJIT: rb_yjit_init_rust() panicked. Aborting.");
        std::process::abort();
    }

    println!("Leaving rb_yjit_init_rust() function");
}

/// Called from C code to begin compiling a function
/// NOTE: this should be wrapped in RB_VM_LOCK_ENTER(), rb_vm_barrier() on the C side
#[no_mangle]
pub extern "C" fn rb_yjit_iseq_gen_entry_point(iseq: IseqPtr, insn_idx: u32, ec: EcPtr) -> *const u8
{
    let maybe_code_ptr = gen_entry_point(iseq, insn_idx, ec);

    match maybe_code_ptr {
        Some(ptr) => ptr.raw_ptr(),
        None => std::ptr::null()
    }
}

/// Called from C code when a branch stub is hit
/// NOTE: this should be wrapped in RB_VM_LOCK_ENTER(), rb_vm_barrier() on the C side
#[no_mangle]
pub extern "C" fn rb_yjit_branch_stub_hit(/* branch_t *branch, */ target_idx: u32, ec: EcPtr) -> *const u8
{
    // TODO: figure out what to pass instead of a branch pointer?

    // TODO
    todo!("branch_stub_hit not implemented");
}
