// Silence dead code warnings until we are done porting YJIT
#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]

pub mod asm {
    pub mod x64;
}

// Types we expose from CRuby
mod cruby;

// Core BBV logic
mod core;

mod codegen;

#[cfg(test)]
mod tests {
    // use crate::asm::x64::*;

    /// just as a sandbox for playing around
    #[test]
    fn sandbox() {}
}
