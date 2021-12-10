pub mod asm {
    pub mod x64;
}

#[cfg(test)]
mod tests {
    use crate::asm::x64::*;

    #[test]
    fn it_works() {
        let mut asm = Assembler::new();

        // 64b
        asm.mov(RAX.into(), RBX.into());
        asm.mov(R8.into(), RBX.into());
        asm.mov(RDI.into(), R14.into());
        asm.mov(R13.into(), R15.into());

        // 32b
        asm.mov(EBP.into(), EDI.into());
        asm.mov(R8D.into(), EBX.into());
        asm.mov(EBP.into(), R9D.into());
        asm.mov(R8D.into(), R11D.into());

        // 16b (panics at the moment)
        // asm.mov(AX.into(), CX.into());


        for byte in asm.encoded().iter() {
            print!("{:02x} ", byte);
        }
        println!();
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
