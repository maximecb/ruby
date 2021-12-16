//! An x64 assembler with Rust interface.
//! Warning: incomplete and barely tested.

/// A type implementing this trait groups together general purpose register of a certain bit width.
pub trait Register {
    /// Bit width of the register
    const WIDTH: RegisterWidth;

    /// The bit used to identify the register in the REX byte.
    /// This bit is set for R9-R15, for example.
    fn id_rex_bit(&self) -> u8;

    /// The 3 bit number for identifying the register in the modr/m byte.
    fn id_rm(&self) -> u8;
}

pub struct Reg64(RegId);
pub struct Reg32(RegId);
pub struct Reg16(RegId);
pub struct Reg8(RegId);

pub struct RegId {
    id_rex_bit: u8,
    id_rm: u8,
}

use RegisterWidth::*;

impl Register for Reg64 {
    const WIDTH: RegisterWidth = B64;

    fn id_rex_bit(&self) -> u8 {
        self.0.id_rex_bit
    }
    fn id_rm(&self) -> u8 {
        self.0.id_rm
    }
}

impl Register for Reg32 {
    const WIDTH: RegisterWidth = B32;

    fn id_rex_bit(&self) -> u8 {
        self.0.id_rex_bit
    }
    fn id_rm(&self) -> u8 {
        self.0.id_rm
    }
}

impl Register for Reg16 {
    const WIDTH: RegisterWidth = B16;

    fn id_rex_bit(&self) -> u8 {
        self.0.id_rex_bit
    }
    fn id_rm(&self) -> u8 {
        self.0.id_rm
    }
}

impl Register for Reg8 {
    const WIDTH: RegisterWidth = B8;

    fn id_rex_bit(&self) -> u8 {
        self.0.id_rex_bit
    }
    fn id_rm(&self) -> u8 {
        self.0.id_rm
    }
}

/// Bit width of register
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterWidth {
    B8,
    B16,
    B32,
    B64,
}

/// Make constants for general purpose registers.
/// For simplificty, high byte registers such as AH are excluded on purpose.
macro_rules! general_purpose_registers {
    (
        $(rex:$vintage:literal $id:literal $b8_name:ident $b16_name:ident $b32_name:ident $b64_name:ident)*
    ) => {
        $(
            pub const $b64_name: Reg64 = Reg64(RegId{ id_rex_bit: $vintage, id_rm: $id });
            pub const $b32_name: Reg32 = Reg32(RegId { id_rex_bit: $vintage, id_rm: $id });
            pub const $b16_name: Reg16 = Reg16(RegId { id_rex_bit: $vintage, id_rm: $id });
            pub const $b8_name: Reg8 = Reg8(RegId { id_rex_bit: $vintage, id_rm: $id });
        )*
    }
}

// x64 general purpose register
general_purpose_registers! {
    rex:0 0 AL   AX   EAX  RAX
    rex:0 1 CL   CX   ECX  RCX
    rex:0 2 DL   DX   EDX  RDX
    rex:0 3 BL   BX   EBX  RBX
    rex:0 4 SPL  SP   ESP  RSP
    rex:0 5 BPL  BP   EBP  RBP
    rex:0 6 SIL  SI   ESI  RSI
    rex:0 7 DIL  DI   EDI  RDI
    rex:1 0 R8L  R8W  R8D  R8
    rex:1 1 R9L  R9W  R9D  R9
    rex:1 2 R10L R10W R10D R10
    rex:1 3 R11L R11W R11D R11
    rex:1 4 R12L R12W R12D R12
    rex:1 5 R13L R13W R13D R13
    rex:1 6 R14L R14W R14D R14
    rex:1 7 R15L R15W R15D R15
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

/// x64 assembler
pub struct Assembler {
    /// The encoded bytes for emitted instructions
    encoded: Vec<u8>,
}

/// Temporary
pub struct Encoding {
    rex: Option<u8>,
    opcode: u8,
    modrm: u8,
    disp8: Option<i8>, // We haven't found a use for more than 8 bits of displacement
    sib: Option<u8>,   // Sometimes to do 8 bit displacement you need an SIB byte. We
    // don't have support for the more complex addressing forms such as
    // `base + index * scale + disp` for now.
    imm32: Option<i32>, // Tmporary. Maybe a enum with different imm sizes
}

/// Represent an addressing form encodable through a configuration of the modr/m byte.
/// No scale, index, base (SIB) form support at the moment as we haven't found the need.
/// 64 bit addressing only, meaning the produced addresses are 64 bits.
pub enum AddressingForm {
    RegPlus8BOffset(RegPlus8BOffset),
}

/// An addressing form. See the AddressingForm enum.
pub struct RegPlus8BOffset {
    /// Base register
    reg: Reg64,
    /// 8 bit offset
    offset: i8,
    /// Bit width of the data that resides at the produced address
    pointee: RegisterWidth,
}

mod mnemonic_forms {
    use crate::asm::x64::Encoding;
    pub trait Test {
        // This is a hack to allow use of generic parameter at build time.
        // See https://github.com/rust-lang/rust/issues/91877
        // If I try to use the generic arg in const context inside a function, I get
        // "use of generic parameter from outer function".
        // It gives a more obvious error message if I switch into const context using
        // the size part of an array type:
        // "error: generic parameters may not be used in const operations"
        const ACCEPTABLE: ();
        fn encode(self) -> Encoding;
    }
}

impl<Reg: Register> mnemonic_forms::Test for (Reg, i32) {
    const ACCEPTABLE: () = match Reg::WIDTH {
        B64 | B32 => (),
        _ => panic!("Only Reg64 and Reg32 for now"),
    };
    fn encode(self) -> Encoding {
        // It's surprising that the associated constant
        // is not evaluated unless used. Bug report https://github.com/rust-lang/rust/issues/91877
        let _: () = Self::ACCEPTABLE;

        let rex = {
            //TODO comment
            let rex_w = (Reg::WIDTH == B64) as u8;
            let rex_r = 0;
            let rex_x = 0;
            let rex_b = self.0.id_rex_bit();
            if (rex_w, rex_r, rex_x, rex_b) != (0, 0, 0, 0) {
                // <- most significant bit
                // 0 1 0 0 W R X B
                let rex =
                    0b0100_0000 + 0b1000 * rex_w + 0b0100 * rex_r + 0b0010 * rex_x + 0b0001 * rex_b;
                Some(rex)
            } else {
                None
            }
        };

        Encoding {
            rex: rex,
            opcode: 0xf7,
            modrm: 0b11000000 + self.0.id_rm(),
            disp8: None,
            sib: None,
            imm32: Some(self.1),
        }
    }
}

impl<Reg: Register> mnemonic_forms::Test for (Reg, Reg) {
    const ACCEPTABLE: () = ();
    fn encode(self) -> Encoding {
        let (lhs, rhs) = self;

        // Decide on the REX byte
        let rex = {
            let rex_w = (Reg::WIDTH == B64) as u8;
            let rex_r = rhs.id_rex_bit();
            let rex_x = (false) as u8;
            let rex_b = lhs.id_rex_bit();
            if (rex_w, rex_r, rex_x, rex_b) != (0, 0, 0, 0) {
                // <- most significant bit
                // 0 1 0 0 W R X B
                let rex =
                    0b0100_0000 + 0b1000 * rex_w + 0b0100 * rex_r + 0b0010 * rex_x + 0b0001 * rex_b;
                Some(rex)
            } else {
                None
            }
        };

        Encoding {
            rex: rex,
            opcode: 0x85,
            modrm: 0b11_000_000 + (rhs.id_rm() << 3) + (lhs.id_rm() << 0),
            disp8: None,
            sib: None,
            imm32: None,
        }
    }
}

impl mnemonic_forms::Test for (AddressingForm, i32) {
    const ACCEPTABLE: () = ();
    fn encode(self) -> Encoding {
        match self.0 {
            AddressingForm::RegPlus8BOffset(dest) => {
                let rex = {
                    let rex_w = (dest.pointee == B64) as u8;
                    let rex_r = 0;
                    let rex_x = 0;
                    let rex_b = dest.reg.id_rex_bit();
                    if (rex_w, rex_r, rex_x, rex_b) != (0, 0, 0, 0) {
                        Some(
                            0b0100_0000
                                + 0b1000 * rex_w
                                + 0b0100 * rex_r
                                + 0b0010 * rex_x
                                + 0b0001 * rex_b,
                        )
                    } else {
                        None
                    }
                };
                let id_rm = dest.reg.id_rm();
                const RM_SIB_ESCAPE: u8 = 0b100;
                let sib = if id_rm == RM_SIB_ESCAPE {
                    // | scale |   index   |    base   |
                    // +---+---+---+---+---+---+---+---+
                    // NOTE: huh, this breaks the id_rm naming because we are
                    // not constructing the rm byte here.
                    // mod=0b00 with index=0b100 encodes the [reg+disp8] form.
                    Some(0b00_100_000 + id_rm)
                } else {
                    None
                };
                Encoding {
                    rex: rex,
                    opcode: 0xf7,
                    modrm: 0b01_000_000 + id_rm,
                    disp8: Some(dest.offset),
                    sib: sib,
                    imm32: Some(self.1),
                }
            }
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

    fn push_one_insn(&mut self, encoding: Encoding) {
        if let Some(rex) = encoding.rex {
            self.encoded.push(rex);
        }
        self.encoded.push(encoding.opcode);
        self.encoded.push(encoding.modrm);
        if let Some(sib) = encoding.sib {
            self.encoded.push(sib);
        }
        if let Some(disp8) = encoding.disp8 {
            // Rust gurantees that integers are two's complement and
            // casting between i8 and u8 is a no-op. See
            // https://doc.rust-lang.org/stable/reference/expressions/operator-expr.html#numeric-cast
            self.encoded.push(disp8.to_le() as u8);
        }
        if let Some(imm32) = encoding.imm32 {
            for byte in imm32.to_le_bytes() {
                self.encoded.push(byte);
            }
        }
    }

    /*
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
    */

    pub fn test<T: mnemonic_forms::Test>(&mut self, operands: T) {
        self.push_one_insn(operands.encode());
    }

    /*
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
    */
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

    /*
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
    */

    #[test]
    fn test() {
        let mut asm = Assembler::new();

        // reg64, imm32
        asm.test((RAX, i32::MAX));
        asm.test((R11, 0x0FABCAFE));
        asm.test((RDI, -0xFABCAFE));
        asm.test((R8, -1));

        // reg32, imm32
        asm.test((EDI, i32::MAX));
        asm.test((R9D, 0x0FABCAFE));
        asm.test((EDI, i32::MIN));
        asm.test((R9D, -1));

        // reg64, reg64
        asm.test((RAX, RDX));
        asm.test((RCX, R11));
        asm.test((R12, RBX));
        asm.test((R15, R14));

        // reg32, reg32
        asm.test((EAX, EDX));
        asm.test((ECX, R11D));
        asm.test((R12D, EBX));
        asm.test((R15D, R14D));

        // TODO: write panic tests

        assert_eq!("48 f7 c0 ff ff ff 7f 49 f7 c3 fe ca ab 0f 48 f7 c7 02 35 54 f0 49 f7 c0 ff ff ff ff f7 c7 ff ff ff 7f 41 f7 c1 fe ca ab 0f f7 c7 00 00 00 80 41 f7 c1 ff ff ff ff 48 85 d0 4c 85 d9 49 85 dc 4d 85 f7 85 d0 44 85 d9 41 85 dc 45 85 f7", asm.byte_string());
    }

    #[test]
    fn test_with_memory() {
        use AddressingForm::RegPlus8BOffset as Mem;
        use RegisterWidth::*;

        let mut asm = Assembler::new();

        asm.test((
            Mem(RegPlus8BOffset {
                reg: RAX,
                offset: i8::MIN,
                pointee: B64,
            }),
            i32::MAX,
        ));
        asm.test((
            Mem(RegPlus8BOffset {
                reg: R13,
                offset: i8::MAX,
                pointee: B64,
            }),
            i32::MAX,
        ));

        // TODO: make shorthand for reg + 8
        asm.test((
            Mem(RegPlus8BOffset {
                reg: RSP,
                offset: i8::MIN,
                pointee: B64,
            }),
            i32::MIN,
        ));
        // Note: with offset == 0, there is a shorter encoding possible that does *not*
        // use an SIB byte. Expect this test to fail down the line when we select that.
        // encoding.
        asm.test((
            Mem(RegPlus8BOffset {
                reg: R12,
                offset: 0,
                pointee: B64,
            }),
            0xfabcafe,
        ));

        assert_eq!("48 f7 40 80 ff ff ff 7f 49 f7 45 7f ff ff ff 7f 48 f7 44 24 80 00 00 00 80 49 f7 44 24 00 fe ca ab 0f", asm.byte_string());
    }
}
