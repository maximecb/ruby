mod libc;
mod memreg;
pub mod x86_64;

/// A trait for defining the requisite functions to support assembly.
pub trait Assembler<Operand> {
    /// Push the given operand onto the assembler's stack.
    fn push(&mut self, opnd: &Operand) -> ();

    /// Return from the current frame.
    fn ret(&mut self) -> ();
}
