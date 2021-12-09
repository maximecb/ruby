mod asm {
    pub mod x64;
}

use asm::x64::*;

fn thing() {
    mov(&Operand::Register(RAX), &Operand::Register(RAX));
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn it_works() {
        thing();
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
