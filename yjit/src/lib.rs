// Silence dead code warnings until we are done porting YJIT
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_assignments)]

pub mod asm {
    pub mod x86_64;
}

// Types we expose from CRuby
mod cruby;

// Core BBV logic
mod core;

mod codegen;

mod options;

#[no_mangle]
pub extern "C" fn hello_from_rust() {
    println!("Hello from Rust!");
}

#[cfg(test)]
mod tests {
    // use crate::asm::x64::*;

    /// just as a sandbox for playing around
    #[test]
    fn sandbox() {}
}
