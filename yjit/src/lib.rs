// Silence dead code warnings until we are done porting YJIT
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_assignments)]

mod asm;
mod cruby;
mod core;
mod codegen;
mod utils;
mod options;
mod stats;

#[no_mangle]
pub extern "C" fn hello_from_rust() {
    println!("Hello from Rust!");
}

#[cfg(test)]
mod tests {
    /// Just as a sandbox for playing around
    #[test]
    fn sandbox() {
    }
}
