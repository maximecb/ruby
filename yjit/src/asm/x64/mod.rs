//! An x64 assembler with Rust interface.
//! Warning: incomplete and barely tested.

/// A type implementing this trait groups together general purpose register of a certain bit width.
pub trait Register {
    /// Bit width of the register
    const WIDTH: RegisterWidth;

    /// The bit used to identify the register in the REX byte.
    /// This bit is set for R9-R15, for example.
    fn id_rex_bit(&self) -> u8;

    /// The lower 3 bits of the number identifying the register. Used in the ModR/M byte, for
    /// example.
    fn id_lower(&self) -> U3;
}

pub struct Reg64(RegId);
pub struct Reg32(RegId);
pub struct Reg16(RegId);
pub struct Reg8(RegId);

pub struct RegId {
    id_rex_bit: u8,
    id_lower: U3,
}

use RegisterWidth::*;

impl Register for Reg64 {
    const WIDTH: RegisterWidth = B64;

    fn id_rex_bit(&self) -> u8 {
        self.0.id_rex_bit
    }
    fn id_lower(&self) -> U3 {
        self.0.id_lower
    }
}

impl Register for Reg32 {
    const WIDTH: RegisterWidth = B32;

    fn id_rex_bit(&self) -> u8 {
        self.0.id_rex_bit
    }
    fn id_lower(&self) -> U3 {
        self.0.id_lower
    }
}

impl Register for Reg16 {
    const WIDTH: RegisterWidth = B16;

    fn id_rex_bit(&self) -> u8 {
        self.0.id_rex_bit
    }
    fn id_lower(&self) -> U3 {
        self.0.id_lower
    }
}

impl Register for Reg8 {
    const WIDTH: RegisterWidth = B8;

    fn id_rex_bit(&self) -> u8 {
        self.0.id_rex_bit
    }
    fn id_lower(&self) -> U3 {
        self.0.id_lower
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

/// A 3-bit unsigned integer. Some fields of the ModR/M and SIB byte use exactly three bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum U3 {
    Dec0 = 0b000,
    Dec1 = 0b001,
    Dec2 = 0b010,
    Dec3 = 0b011,
    Dec4 = 0b100,
    Dec5 = 0b101,
    Dec6 = 0b110,
    Dec7 = 0b111,
}

/// Make constants for general purpose registers.
/// For simplificty, high byte registers such as AH are excluded on purpose.
macro_rules! general_purpose_registers {
    (
        $(rex:$vintage:literal $id:ident $b8_name:ident $b16_name:ident $b32_name:ident $b64_name:ident)*
    ) => {
        $(
            pub const $b64_name: Reg64 = Reg64(RegId{ id_rex_bit: $vintage, id_lower: U3::$id });
            pub const $b32_name: Reg32 = Reg32(RegId { id_rex_bit: $vintage, id_lower: U3::$id });
            pub const $b16_name: Reg16 = Reg16(RegId { id_rex_bit: $vintage, id_lower: U3::$id });
            pub const $b8_name: Reg8 = Reg8(RegId { id_rex_bit: $vintage, id_lower: U3::$id });
        )*
    }
}

// x64 general purpose register
general_purpose_registers! {
    rex:0 Dec0 AL   AX   EAX  RAX
    rex:0 Dec1 CL   CX   ECX  RCX
    rex:0 Dec2 DL   DX   EDX  RDX
    rex:0 Dec3 BL   BX   EBX  RBX
    rex:0 Dec4 SPL  SP   ESP  RSP
    rex:0 Dec5 BPL  BP   EBP  RBP
    rex:0 Dec6 SIL  SI   ESI  RSI
    rex:0 Dec7 DIL  DI   EDI  RDI
    rex:1 Dec0 R8L  R8W  R8D  R8
    rex:1 Dec1 R9L  R9W  R9D  R9
    rex:1 Dec2 R10L R10W R10D R10
    rex:1 Dec3 R11L R11W R11D R11
    rex:1 Dec4 R12L R12W R12D R12
    rex:1 Dec5 R13L R13W R13D R13
    rex:1 Dec6 R14L R14W R14D R14
    rex:1 Dec7 R15L R15W R15D R15
}

/*
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
*/

/// x64 assembler
pub struct Assembler {
    /// The encoded bytes for emitted instructions
    encoded: Vec<u8>,
}

/// The encoding of one instruction from the base set. This is sightly more descriptive than
/// the encoded bytes. Beware that some instances of this struct do not encode valid
/// instructions. For example, nothing stops you from encoding an immediate for an opcode that
/// does not precede any immediates.
pub struct Encoding {
    rex: Option<u8>,
    form: InstructionForm,
    imm32: Option<i32>, // Tmporary. Maybe a enum with different imm sizes
}

/// Different opcodes work with the bytes that follow differently. Each variant represent
/// the meaning prescribed to the bytes that follow the opcode.
pub enum InstructionForm {
    /// An instruction that doesn't have explicit register or memory operands. For example, `JMP`.
    OpcodeOnly(u8),
    /// An instruction with a register operand and another that is a register or a memory location.
    RegRM { opcode: u8, reg: U3, rm: RMForm },
    /// An instruction that uses ModR/M.reg as extension to the opcode. Manuals list these
    /// instructions with the `/n` syntax, where `n` is in the range `[0, 8)`.
    RMOnly { opcode: (u8, U3), rm: RMForm },
}

/// A register operand or a memory operand. Each variant maps to a configuration
/// ModR/M.rm and the SIB byte. For memory operands, this produce 64 bit addresses only.
/// Note that this does not describe how large the memory location is at the encoded
/// address. Other parts of instruction control that.
pub enum RMForm {
    /// Register operand
    RegDirect(U3),
    /// Memory operand. The address is in a register
    RegIndirect(U3),
    /// Memory operand. The address is a register plus an offset
    RegPlus8BDisp { reg: U3, disp: i8 },
    /// Memory operand. The address is a register plus an offset
    RegPlus32BDisp { reg: U3, disp: i32 },
    /// Memory operand. The address is relative to the instruction pointer
    RIPRelative(i32),
    // NOTE: This includes no base + index * scale + displacement forms as we haven't
    // used them in the JIT.
}

//TODO the lower level encoding structs might go over better in a separate module.

/// A 64 bit memory location operand
pub enum Mem64 {
    RegPlusOffset(Reg64, i32),
}

/// Short-hand for making a Mem64 operand.
pub fn mem64(reg: Reg64, offset: i32) -> Mem64 {
    Mem64::RegPlusOffset(reg, offset)
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

        let dest = self.0;

        let rex = {
            //TODO comment
            let rex_w = (Reg::WIDTH == B64) as u8;
            let rex_r = 0;
            let rex_x = 0;
            let rex_b = dest.id_rex_bit();
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
            form: InstructionForm::RMOnly {
                opcode: (0xF7, U3::Dec0),
                rm: RegDirect(dest.id_lower()),
            },
            imm32: Some(self.1),
        }
    }
}

use InstructionForm::*;
use RMForm::*;

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
            form: RegRM {
                opcode: 0x85,
                reg: rhs.id_lower(),
                rm: RegDirect(lhs.id_lower()),
            },
            imm32: None,
        }
    }
}

impl mnemonic_forms::Test for (Mem64, i32) {
    const ACCEPTABLE: () = ();
    fn encode(self) -> Encoding {
        let Mem64::RegPlusOffset(dest_reg, dest_disp) = self.0;
        let rex = {
            let rex_w = 1; // 64 bit operand size
            let rex_r = 0;
            let rex_x = 0;
            let rex_b = dest_reg.id_rex_bit();
            if (rex_w, rex_r, rex_x, rex_b) != (0, 0, 0, 0) {
                Some(
                    0b0100_0000 + 0b1000 * rex_w + 0b0100 * rex_r + 0b0010 * rex_x + 0b0001 * rex_b,
                )
            } else {
                None
            }
        };
        Encoding {
            rex: rex,
            form: InstructionForm::RMOnly {
                opcode: (0xF7, U3::Dec0),
                rm: RegPlus32BDisp {
                    reg: dest_reg.id_lower(),
                    disp: dest_disp,
                },
            },
            imm32: Some(self.1),
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
        /*
         * TODO: remember to handle this
                let id_rm = dest_reg.id_rm();
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

        if let Some(disp8) = encoding.disp8 {
            // Rust gurantees that integers are two's complement and
            // casting between i8 and u8 is a no-op. See
            // https://doc.rust-lang.org/stable/reference/expressions/operator-expr.html#numeric-cast
            self.encoded.push(disp8.to_le() as u8);
        }
            */
        match encoding.form {
            OpcodeOnly(opcode) => {
                self.encoded.push(opcode);
            }
            RegRM { opcode, reg, rm } => {}
            RMOnly {
                opcode: (opcode_byte, opcode_extension),
                rm,
            } => {}
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
                .collect::<Vec<_>>()
                .join(" ")
        }
    }

    macro_rules! test_encoding {
        ($bytes:literal $($disasm:literal, $mnemonic:ident $args:expr)+) => {{
            let mut asm = Assembler::new();

            $( asm.$mnemonic($args); )*

            assert_eq!(asm.byte_string(), $bytes);

            // In case we have a disassembler, compare against a disassembly expectation
            #[cfg(feature = "disassembly")]
            {
                extern crate capstone;
                use capstone::prelude::*;
                let cs = Capstone::new()
                    .x86()
                    .mode(arch::x86::ArchMode::Mode64)
                    .syntax(arch::x86::ArchSyntax::Intel)
                    .build()
                    .expect("Failed to create Capstone object");

                let insns = cs
                    .disasm_all(asm.encoded(), 0x1000)
                    .expect("Failed to disassemble");

                let mut insn_idx = 0;
                $(
                    match insns.as_ref().get(insn_idx).map(|insn| (insn.mnemonic(), insn.op_str())) {
                        Some((Some(mnemonic), op_str)) => {
                            let mut capstone_disasm = mnemonic.to_owned();
                            if let Some(op_str) = op_str {
                                capstone_disasm.push_str(" ");
                                capstone_disasm.push_str(op_str);
                            }
                            assert_eq!($disasm, capstone_disasm, "instruction_index={}", insn_idx);
                        },
                        _ => panic!("Failed to disassemble to a instruction at instruction_index={}", insn_idx),
                    };
                    insn_idx += 1;
                    let _ = insn_idx; // Address unused warning from the last iteration
                )*

            }
        }};
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
        // reg64, imm32
        test_encoding!(
            "48 f7 c0 ff ff ff 7f 49 f7 c3 fe ca ab 0f 48 f7 c7 02 35 54 f0 49 f7 c0 ff ff ff ff"
            "test rax, 0x7fffffff",  test(RAX, i32::MAX)
            "test r11, 0xfabcafe",   test(R11, 0xFABCAFE)
            "test rdi, -0xfabcafe",  test(RDI, -0xFABCAFE)
            "test r8, -1",           test(R8, -1)
        );

        // reg32, imm32
        test_encoding!(
            "f7 c7 ff ff ff 7f 41 f7 c1 fe ca ab 0f f7 c7 00 00 00 80 41 f7 c1 ff ff ff ff"
            "test edi, 0x7fffffff", test(EDI, i32::MAX)
            "test r9d, 0xfabcafe", test(R9D, 0xFABCAFE)
            "test edi, 0x80000000", test(EDI, i32::MIN)
            "test r9d, 0xffffffff", test(R9D, -1)
        );

        // reg64, reg64
        test_encoding!(
            "48 85 d0 4c 85 d9 49 85 dc 4d 85 f7"
            "test rax, rdx", test(RAX, RDX)
            "test rcx, r11", test(RCX, R11)
            "test r12, rbx", test(R12, RBX)
            "test r15, r14", test(R15, R14)
        );

        // reg32, reg32
        test_encoding!(
            "85 d0 44 85 d9 41 85 dc 45 85 f7"
            "test eax, edx", test(EAX, EDX)
            "test ecx, r11d", test(ECX, R11D)
            "test r12d, ebx", test(R12D, EBX)
            "test r15d, r14d", test(R15D, R14D)
        )

        // TODO: write panic tests
    }

    #[test]
    fn test_with_memory() {
        test_encoding!(
            "48 f7 40 80 ff ff ff 7f"
            "test qword ptr [rax - 0x80], 0x7fffffff",
            test(mem64(RAX, i8::MIN.into()), i32::MAX)
        );

        test_encoding!(
            "49 f7 45 7f ff ff ff 7f"
            "test qword ptr [r13 + 0x7f], 0x7fffffff",
            test(mem64(R13, i8::MAX.into()), i32::MAX)
        );

        test_encoding!(
            "48 f7 44 24 80 00 00 00 80"
            "test qword ptr [rsp - 0x80], -0x80000000",
            test(mem64(RSP, i8::MIN.into()), i32::MIN)
        );

        // Note: with offset == 0, there is a shorter encoding possible that does *not*
        // use an SIB byte. Expect this test to fail down the line when we select that.
        // encoding.
        test_encoding!(
            "49 f7 44 24 00 fe ca ab 0f"
            "test qword ptr [r12], 0xfabcafe",
            test(mem64(R12, 0), 0xfabcafe)
        );
    }

    #[test]
    #[cfg(feature = "disassembly")]
    fn basic_capstone_usage() -> Result<(), capstone::Error> {
        // Test drive Capstone with simple input
        extern crate capstone;
        use capstone::prelude::*;
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .build()?;

        let insns = cs.disasm_all(&[0xCC], 0x1000)?;

        match insns.as_ref() {
            [insn] => {
                assert_eq!(Some("int3"), insn.mnemonic());
                Ok(())
            }
            _ => Err(capstone::Error::CustomError(
                "expected to disassemble to int3",
            )),
        }
    }
}
