// Silence dead code warnings until we are done porting YJIT
#![allow(dead_code)]

pub mod asm {
    pub mod x64;
}

mod core;

#[cfg(test)]
mod tests {
    // use crate::asm::x64::*;

    /// just as a sandbox for playing around
    #[test]
    fn sandbox() {}
}
