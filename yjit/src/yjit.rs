use crate::core::*;
use crate::codegen::*;

/// This function is called from C code
#[no_mangle]
pub extern "C" fn init_yjit() {
    println!("Entering init_yjit() function");

    CodegenGlobals::init();

    // TODO:
    //Invariants::init() ?

    println!("Leaving init_yjit() function");
}
