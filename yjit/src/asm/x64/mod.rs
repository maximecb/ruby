/// An x64 assembler with Rust interface.
/// Warning: incomplete and barely tested.

/// x64 general purpose register
#[derive(Debug)]
pub struct Register {
    /// Revision of the ISA in which the register first appeared
    vintage: RegisterVintage,

    /// Bit width of the register
    width: RegisterWidth,

    /// Number for encoding the register
    // Design note: Rust doesn't have refinement types, but we
    // could make do something like enum ZeroToSeven { Zero=0, ... }
    // if we want to go for absolute type safety.
    id: u8,
}

/// Groupings of registers with encoding significance
#[derive(Debug, PartialEq)]
enum RegisterVintage {
    /// The register is in the original x86 ISA
    Original,
    /// The register first appeared in the amd64 ISA
    Extended,
}

/// Bit width of register
#[derive(Debug, PartialEq)]
enum RegisterWidth {
    B8,
    B16,
    B32,
    B64,
}

/// Make constants for general purpose registers.
/// For simplificty, high byte registers such as AH are excluded on purpose.
macro_rules! general_purpose_registers {
    (
        $($vintage:ident $id:literal $b8_name:ident $b16_name:ident $b32_name:ident $b64_name:ident)*
    ) => {
        use RegisterVintage::*;
        use RegisterWidth::*;
        $(
            pub const $b64_name: Register = Register { vintage: $vintage, width: B64, id: $id };
            pub const $b32_name: Register = Register { vintage: $vintage, width: B32, id: $id };
            pub const $b16_name: Register = Register { vintage: $vintage, width: B16, id: $id };
            pub const $b8_name: Register = Register { vintage: $vintage, width: B8, id: $id };
        )*
    }
}

general_purpose_registers! {
    Original 0 AL   AX   EAX  RAX
    Original 1 CL   CX   ECX  RCX
    Original 2 DL   DX   EDX  RDX
    Original 3 BL   BX   EBX  RBX
    Original 4 SPL  SP   ESP  RSP
    Original 5 BPL  BP   EBP  RBP
    Original 6 SIL  SI   ESI  RSI
    Original 7 DIL  DI   EDI  RDI
    Extended 0 R8L  R8W  R8D  R8
    Extended 1 R9L  R9W  R9D  R9
    Extended 2 R10L R10W R10D R10
    Extended 3 R11L R11W R11D R11
    Extended 4 R12L R12W R12D R12
    Extended 5 R13L R13W R13D R13
    Extended 6 R14L R14W R14D R14
    Extended 7 R15L R15W R15D R15
}

/// Allows for usages such as mov(RAX.into(), RBX.into())
impl From<Register> for Operand {
    fn from(reg: Register) -> Self {
        Operand::Register(reg)
    }
}

/// Allows for usages such as mov(RAX.into(), 1.into())
impl From<i32> for Operand {
    fn from(i: i32) -> Self {
        Operand::Immediate(RegWidthInteger::I32(i))
    }
}

#[derive(Debug)]
pub enum RegWidthInteger {
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
}

use RegWidthInteger::*;

/// Operand for x64 instructions
#[derive(Debug)]
pub enum Operand {
    Register(Register),
    Immediate(RegWidthInteger),
    //AddressingForm,
    //Label,
    //Address(usize),
    //IPRelative(),
}

/// x64 assembler
pub struct Assembler {
    /// The encoded bytes for emitted instructions
    encoded: Vec<u8>,
}

/// Temporary
struct Encoding {
    rex: Option<u8>,
    opcode: u8,
    modrm: u8,
    imm32: i32,
}

mod InstructionForms {
    use crate::asm::x64::Encoding;
    pub trait Test {
        fn encode(&self) -> Encoding;
    }
}

impl InstructionForms::Test for (Register, i32) {
    fn encode(&self) -> Encoding {
        let rex = {
            //TODO comment
            let rex_w = (self.0.width == B64) as u8;
            let rex_r = 0;
            let rex_x = 0;
            let rex_b = (self.0.vintage == Extended) as u8;
            if (rex_w, rex_r, rex_x, rex_b) != (0, 0, 0, 0) {
                // <- most significant bit
                // 0 1 0 0 W R X B
                let rex = 0b0100_0000
                    + 0b1000 * rex_w
                    + 0b0100 * rex_r
                    + 0b0010 * rex_x
                    + 0b0001 * rex_b;
                Some(rex)
            } else {
                None
            }
        };

        Encoding {
            rex: rex,
            opcode: 0xf7,
            modrm: 0b11000000 + self.0.id,
            imm32: self.1,
        }
    }
}

impl Assembler {
    pub fn new() -> Self {
        Assembler { encoded: vec![] }
    }
    pub fn encoded(&self) -> &Vec<u8> {
        &self.encoded
    }

    /// Right arithmetic shift
    /// TODO: what I want for rhs is really a RegOrImm type. Probably reusable.
    /// Maybe a RegOrMem type for lhs too? Look for asserts at the top of test(cb) for example.
    pub fn sar(&mut self, lhs: Operand, rhs: Operand) {
        match (lhs, rhs) {
            (Operand::Register(lhs_reg), Operand::Immediate(I32(1))) => {
                // SAR r/m, 1
                let opcode = 0xD1;

                // Decide on the REX byte
                let rex = {
                    let rex_w = (lhs_reg.width == B64) as u8;
                    let rex_r = 0;
                    let rex_x = 0;
                    let rex_b = (lhs_reg.vintage == Extended) as u8;
                    if (rex_w, rex_r, rex_x, rex_b) != (0, 0, 0, 0) {
                        // <- most significant bit
                        // 0 1 0 0 W R X B
                        let rex = 0b0100_0000
                            + 0b1000 * rex_w
                            + 0b0100 * rex_r
                            + 0b0010 * rex_x
                            + 0b0001 * rex_b;
                        Some(rex)
                    } else {
                        None
                    }
                };

                // NOTE: think about selecting mod based on input.
                // Have not studied enough usages as of yet.
                // modrm.mod=0b11 since lhs is a register
                let modrm = 0b11000000 +
                            0b00111000 + // modrm.reg=7 opcode extension
                            lhs_reg.id;

                // Write the bytes
                if let Some(byte) = rex {
                    self.encoded.push(byte);
                }
                self.encoded.push(opcode);
                self.encoded.push(modrm);
            }
            (_, _) => {
                panic!("unknown addressing form");
            }
        }
    }

    pub fn test<T: InstructionForms::Test>(&mut self, operands: T) {
        let encoding = operands.encode();
        if let Some(rex) = encoding.rex {
            self.encoded.push(rex);
        }
        self.encoded.push(encoding.opcode);
        self.encoded.push(encoding.modrm);
        self.encoded.push(encoding.imm32 & 0xFF);
        self.encoded.push((encoding.imm32 & 0xFF00) >> 8);
        self.encoded.push((encoding.imm32 & 0xFF0000) >> 16);
        self.encoded.push((encoding.imm32 & 0xFF000000) >> 24);
    }

    pub fn mov(&mut self, dst: Operand, src: Operand) {
        match (dst, src) {
            (Operand::Register(dst), Operand::Register(src))
                if dst.width == src.width
                    && match dst.width {
                        B32 | B64 => true,
                        _ => false,
                    } =>
            {
                // Temporary. This is code is for doing regr/m encoding
                // and is widely applicable to instructions other than mov.
                // Addressing form: mov reg, regr/m
                let opcode = 0x8B;

                let operand_size = dst.width;

                // Decide on the REX byte
                let rex = {
                    let rex_w = (operand_size == B64) as u8;
                    let rex_r = (dst.vintage == Extended) as u8;
                    let rex_x = (false) as u8;
                    let rex_b = (src.vintage == Extended) as u8;
                    if (rex_w, rex_r, rex_x, rex_b) != (0, 0, 0, 0) {
                        // <- most significant bit
                        // 0 1 0 0 W R X B
                        let rex = 0b0100_0000
                            + 0b1000 * rex_w
                            + 0b0100 * rex_r
                            + 0b0010 * rex_x
                            + 0b0001 * rex_b;
                        Some(rex)
                    } else {
                        None
                    }
                };

                // Decide on modr/m byte
                // mod=0b11 here since we want `mov reg, reg`
                let modrm = 0b11_000_000 +
                            (dst.id << 3) + // modrm.reg
                            (src.id << 0); // modrm.rm

                // Write the bytes
                if let Some(byte) = rex {
                    self.encoded.push(byte);
                }
                self.encoded.push(opcode);
                self.encoded.push(modrm);
            }
            (dst @ _, src @ _) => {
                panic!("Unsupported addressing form dst:{:?} src:{:?}", dst, src);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::asm::x64::*;

    impl Assembler {
        fn byte_string(&self) -> String {
            self.encoded()
                .into_iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<String>>()
                .join(" ")
        }
    }

    #[test]
    fn reg_to_reg_movs() {
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

        let bytes = asm.byte_string();
        assert_eq!(
            "48 8b c3 4c 8b c3 49 8b fe 4d 8b ef 8b ef 44 8b c3 41 8b e9 45 8b c3",
            bytes
        );
    }

    #[test]
    fn sar() {
        let mut asm = Assembler::new();

        // 64b
        asm.sar(RAX.into(), 1.into());
        asm.sar(R9.into(), 1.into());

        // 32b
        asm.sar(RDI.into(), 1.into());
        asm.sar(R10D.into(), 1.into());

        // TODO: write panic tests

        assert_eq!("48 d1 f8 49 d1 f9 48 d1 ff 41 d1 fa", asm.byte_string());
    }

    #[test]
    fn test() {
        let mut asm = Assembler::new();

        // 64b
        asm.test((RAX, 0b111));

        // TODO: write panic tests

        assert_eq!("48 d1 f8 49 d1 f9 48 d1 ff 41 d1 fa", asm.byte_string());
    }
}
