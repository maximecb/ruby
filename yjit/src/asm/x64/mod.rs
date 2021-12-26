//! An x64 assembler with Rust interface.
//! Warning: incomplete and barely tested.

use std::collections::TryReserveError;

use self::AddressingForm::*;
use InstructionForm::*;
use RMForm::*;
use RegisterWidth::*;

/// A type implementing this trait groups together general purpose register of a certain bit width.
pub trait Register {
    /// Bit width of the register
    const WIDTH: RegisterWidth;

    /// The bit used to identify the register in the REX byte.
    /// This bit is set for R9-R15, for example.
    fn id_rex_bit(&self) -> bool;

    /// The lower 3 bits of the number identifying the register. Used in the ModR/M byte, for
    /// example.
    fn id_lower(&self) -> U3;
}

#[derive(Debug, PartialEq, Eq)]
pub struct RegId {
    id_rex_bit: bool,
    id_lower: U3,
}

impl Register for Reg64 {
    const WIDTH: RegisterWidth = B64;

    fn id_rex_bit(&self) -> bool {
        self.0.id_rex_bit
    }
    fn id_lower(&self) -> U3 {
        self.0.id_lower
    }
}

impl Register for Reg32 {
    const WIDTH: RegisterWidth = B32;

    fn id_rex_bit(&self) -> bool {
        self.0.id_rex_bit
    }
    fn id_lower(&self) -> U3 {
        self.0.id_lower
    }
}

impl Register for Reg16 {
    const WIDTH: RegisterWidth = B16;

    fn id_rex_bit(&self) -> bool {
        self.0.id_rex_bit
    }
    fn id_lower(&self) -> U3 {
        self.0.id_lower
    }
}

impl Register for Reg8 {
    const WIDTH: RegisterWidth = B8;

    fn id_rex_bit(&self) -> bool {
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
#[repr(u8)]
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

/// A 2-bit unsigned integer. Some fields of the ModR/M and SIB byte use exactly two bits.
#[repr(u8)]
pub enum U2 {
    Dec0 = 0b00,
    Dec1 = 0b01,
    Dec2 = 0b10,
    Dec3 = 0b11,
}

/// Make a byte from the format followed by the ModR/M and the SIB byte.
fn u8_from_parts(top: U2, mid: U3, bottom: U3) -> u8 {
    ((top as u8) << 6) + ((mid as u8) << 3) + (bottom as u8)
}

/// Make a ModR/M byte
fn modrm_byte(mod_: U2, reg: U3, rm: U3) -> u8 {
    u8_from_parts(mod_, reg, rm)
}

/// Make a scale, index, and base (SIB) byte
fn sib_byte(scale: U2, index: U3, base: U3) -> u8 {
    u8_from_parts(scale, index, base)
}

/// 64 bit register operand
#[derive(Debug, PartialEq, Eq)]
pub struct Reg64(RegId);
/// 32 bit register operand
#[derive(Debug, PartialEq, Eq)]
pub struct Reg32(RegId);
/// 16 bit register operand
#[derive(Debug, PartialEq, Eq)]
pub struct Reg16(RegId);
/// 8 bit register operand
#[derive(Debug, PartialEq, Eq)]
pub struct Reg8(RegId);

/// Make constants for general purpose registers.
/// For simplificty, high byte registers such as AH are excluded on purpose.
macro_rules! general_purpose_registers {
    (
        $(rex:$rex_bit:literal $id:ident $b8_name:ident $b16_name:ident $b32_name:ident $b64_name:ident)*
    ) => {
        $(
            pub const $b64_name: Reg64 = Reg64(RegId{ id_rex_bit: $rex_bit != 0, id_lower: U3::$id });
            pub const $b32_name: Reg32 = Reg32(RegId{ id_rex_bit: $rex_bit != 0, id_lower: U3::$id });
            pub const $b16_name: Reg16 = Reg16(RegId{ id_rex_bit: $rex_bit != 0, id_lower: U3::$id });
            pub const $b8_name: Reg8   =  Reg8(RegId{ id_rex_bit: $rex_bit != 0, id_lower: U3::$id });
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

/// 64 bit memory operands
pub struct Mem64(AddressingForm);
/// 32 bit memory operands
pub struct Mem32(AddressingForm);
/// 16 bit memory operands
pub struct Mem16(AddressingForm);
/// 8 bit memory operands
pub struct Mem8(AddressingForm);

/// Short-hand for making a Mem64 operand.
pub fn mem64(reg: Reg64, offset: i32) -> Mem64 {
    Mem64(AddressingForm::RegPlusDisp(reg, offset))
}

/// x64 assembler
pub struct Assembler {
    /// The encoded bytes for emitted instructions
    encoded: Vec<u8>,
}

//TODO the lower level encoding structs might go over better in a separate module.

/// The encoding of one instruction from the base set. This is sightly more descriptive than
/// the encoded bytes. Beware that some instances of this struct do not encode valid
/// instructions. For example, nothing stops you from encoding an immediate for an opcode that
/// does not precede any immediates.
pub struct Encoding<const IMM_SIZE: usize> {
    rex: Option<u8>,
    form: InstructionForm,
    immediate: Option<[u8; IMM_SIZE]>,
}

impl<const IMM_SIZE: usize> Encoding<IMM_SIZE> {
    /// This is a strange dance to get stable rustc to run this check at build time.
    /// Maybe a future version of Rust will offer a more intuitive way to do this.
    /// See <https://github.com/rust-lang/rust/issues/79429>
    /// TODO: ask around about this
    const RUN_BUILD_TIME_IMM_SIZE_CHECK: () = match IMM_SIZE {
        0 | 1 | 2 | 4 | 8 => (),
        _ => panic!("Attempt encode strangely sized immediate"),
    };
}

/// An opcode. Might be up to 3 byte
#[derive(Debug)]
pub enum Opcode {
    Plain(u8),
    Escape0F(u8),
    Escape0F38(u8),
    Escape0F3A(u8),
}

impl Opcode {
    fn encode_and_push(self, sink: &mut Vec<u8>) -> Result<(), TryReserveError> {
        use Opcode::*;
        match self {
            Plain(byte) => sink.try_reserve(1).map(|_| sink.push(byte)),
            Escape0F(byte) => sink.try_reserve(2).map(|_| {
                sink.push(0x0F);
                sink.push(byte);
            }),
            Escape0F38(byte) => sink.try_reserve(3).map(|_| {
                sink.push(0x0F);
                sink.push(0x38);
                sink.push(byte);
            }),
            Escape0F3A(byte) => sink.try_reserve(3).map(|_| {
                sink.push(0x0F);
                sink.push(0x3A);
                sink.push(byte);
            }),
        }
    }
}

/// Different opcodes work with the bytes that follow differently. Each variant represent
/// the meaning prescribed to the bytes that follow the opcode.
pub enum InstructionForm {
    /// An instruction that doesn't have explicit register or memory operands. For example, `JMP`.
    OpcodeOnly(Opcode),
    /// An instruction with a register operand and another that is a register or a memory location.
    RegRM { opcode: Opcode, reg: U3, rm: RMForm },
    /// An instruction that uses ModR/M.reg as extension to the opcode. Manuals list these
    /// instructions with the `/n` syntax, where `n` is in the range `[0, 8)`.
    RMOnly { opcode: (Opcode, U3), rm: RMForm },
}

/// A register operand or a memory operand. Each variants map to configurations of
/// ModR/M.rm and the SIB byte. For memory operands, this produces 64 bit addresses only.
/// Note that this does not describe how large the memory location is at the encoded
/// address. Other parts of instruction control that.
#[derive(Debug)]
pub enum RMForm {
    /// Register operand
    RegDirect(U3),
    /// Memory operand where the address is calculated through an encodable form, for example,
    /// `register + displacement`.
    Mem(AddressingForm),
}

impl RMForm {
    /// Encode into ModR/M, SIB, and displacement bytes and push the result into a byte vector.
    fn encode_and_push(self, modrm_reg: U3, sink: &mut Vec<u8>) -> Result<(), TryReserveError> {
        match self {
            RegDirect(rm) => {
                // mod=0b11. Everything fits in the ModR/M byte.
                let mod_rm = modrm_byte(U2::Dec3, modrm_reg, rm);
                sink.try_reserve(1).map(|_| sink.push(mod_rm))
            }
            Mem(RegPlusDisp(reg, disp)) => {
                let reg = reg.id_lower();

                match (i8::try_from(disp), reg) {
                    // Go for shorter encodings when the displacement is zero.
                    (Ok(0), U3::Dec4) => {
                        // rm=0b101 so no encoding available with mod=0b00 for [reg]. Use
                        // mod=0b01 with a special SIB byte to encode [rm_reg].
                        let mod_rm = modrm_byte(U2::Dec0, modrm_reg, U3::Dec4);
                        // scale=0b00 index=0b100 base=rm_reg
                        let sib = sib_byte(U2::Dec0, U3::Dec4, reg);
                        sink.try_reserve(2).map(|_| {
                            sink.push(mod_rm);
                            sink.push(sib);
                        })
                    }
                    (Ok(0), U3::Dec5) => {
                        // rm=0b101 so no encoding available with mod=0b00 for [reg]. Use
                        // mod=0b01 with a zero 8 bit displacement.
                        let mod_rm = modrm_byte(U2::Dec1, modrm_reg, reg);
                        sink.try_reserve(3).map(|_| {
                            sink.push(mod_rm);
                            sink.push(0);
                        })
                    }
                    (Ok(0), rm_reg) => {
                        // The register we want to encode does not have a special id that acts as
                        // an escape code in the encoding. Everything fits in a mod=0b00 ModR/M.
                        let mod_rm = modrm_byte(U2::Dec0, modrm_reg, rm_reg);
                        sink.try_reserve(1).map(|_| sink.push(mod_rm))
                    }
                    // Displacement fits in one byte
                    (Ok(disp8), reg) => {
                        // mod=0b01, rm=0b100, and index=0b100.
                        let mod_rm = modrm_byte(U2::Dec1, modrm_reg, reg);
                        let sib: Option<u8> =
                            (reg == U3::Dec4).then(|| sib_byte(U2::Dec0, U3::Dec4, reg));
                        let disp_parts: [u8; 1] = disp8.to_le_bytes();
                        sink.try_reserve(3).map(|_| {
                            sink.push(mod_rm);
                            sib.map(|byte| sink.push(byte));
                            sink.push(disp_parts[0]);
                        })
                    }
                    // General case. Need 4 bytes for the displacement
                    (Err(_), reg) => {
                        // mod=0b10, rm=0b100, and index=0b100.
                        let disp32: i32 = disp;
                        let mod_rm = modrm_byte(U2::Dec2, modrm_reg, U3::Dec4);
                        let sib: u8 = sib_byte(U2::Dec0, U3::Dec4, reg);
                        let disp_parts: [u8; 4] = disp32.to_le_bytes();
                        sink.try_reserve(3).map(|_| {
                            sink.push(mod_rm);
                            sink.push(sib);
                            sink.push(disp_parts[0]);
                            sink.push(disp_parts[1]);
                            sink.push(disp_parts[2]);
                            sink.push(disp_parts[3]);
                        })
                    }
                }
            }
            Mem(RIPRelative(offset)) => {
                // mod=0b00 and rm=0b101
                let mod_rm = modrm_byte(U2::Dec0, modrm_reg, U3::Dec0);
                let offset_parts: [u8; 4] = offset.to_le_bytes();
                sink.try_reserve(5).map(|_| {
                    sink.push(mod_rm);
                    sink.push(offset_parts[0]);
                    sink.push(offset_parts[1]);
                    sink.push(offset_parts[2]);
                    sink.push(offset_parts[3]);
                })
            }
        }
    }
}

/// A way to compute an address that is encodable.
#[derive(Debug)]
pub enum AddressingForm {
    /// The address is a register plus a displacement.
    RegPlusDisp(Reg64, i32),
    /// The address the instruction pointer plus a displacement.
    RIPRelative(i32),
    // NOTE: This includes no base + index * scale + displacement forms as we haven't
    // used them in the JIT.
}

impl AddressingForm {
    fn rex_xb(&self) -> (bool, bool) {
        match self {
            RegPlusDisp(reg, _) => (false, reg.id_rex_bit()),
            RIPRelative(_) => (false, false),
        }
    }
}

/// Represents a REX byte. Mostly for code asethetics.
struct Rex {
    /// Usually makes instruction have 64 bit oprand size when set
    w: bool,
    /// Usually combines with ModR/M.reg to refer to a register
    r: bool,
    /// Usually combines with SIB.index to refer to a register
    x: bool,
    /// Usually combines with ModR/M.rm or SIB.base to refer to a register
    b: bool,
}

impl Rex {
    fn assemble(self) -> Option<u8> {
        match self {
            // The prefix is unnecessary when all fields are zero.
            Rex {
                w: false,
                r: false,
                b: false,
                x: false,
            } => None,
            Rex { w, r, b, x } => {
                #[rustfmt::skip]
                let byte = 0b0100_0000
                             + 0b_1000 * w as u8
                             + 0b_0100 * r as u8
                             + 0b_0010 * x as u8
                             + 0b_0001 * b as u8;
                Some(byte)
            }
        }
    }
}

macro_rules! opcode_enum {
    ($opcode:literal) => {
        Opcode::Plain($opcode)
    };
    (0x0F $opcode:literal) => {
        Opcode::Escape0F($opcode)
    };
    (0x0F 0x38 $opcode:literal) => {
        Opcode::Escape0F38($opcode)
    };
    (0x0F 0x3A $opcode:literal) => {
        Opcode::Escape0F3A($opcode)
    };
}

macro_rules! w_given {
    () => {
        false
    };
    (W) => {
        true
    };
}

/// Select between two expressions depending on whether a token tree is given.
/// Useful for working with $(...)? macro patterns.
macro_rules! if_first_arg {
    (, $_given:tt else $not_given:tt) => {{
        $not_given
    }};
    ($first:tt, $given:tt else $_not_given:tt) => {{
        $given
    }};

    (, $_given:item else $not_given:item) => {
        $not_given
    };
    ($first:tt, $given:item else $_not_given:item) => {
        $given
    };
}

/***
//if_first_arg!(, {} else thatthing);
//if_first_arg!(34, {} else thatthing);

macro_rules! play {
    ($($ext:literal)?) => { if_first_arg!($($ext)?, {} else {}); };
}

fn thing() {
play!(4);
play!();
}
*/

/// Const function for use at build time with macros to convert a digit to U3.
const fn u3_literal(n: u8) -> U3 {
    match n {
        0 => U3::Dec0,
        1 => U3::Dec1,
        2 => U3::Dec2,
        3 => U3::Dec3,
        4 => U3::Dec4,
        5 => U3::Dec5,
        6 => U3::Dec6,
        7 => U3::Dec7,
        _ => panic!("Numeric literal for U3 not in the range 0..=7"),
    }
}

/// Select between two expressions based on if the first arg is "reg" or "imm".
macro_rules! reg_or_imm {
    (reg, reg: $reg:expr , imm: $_imm:expr) => {
        $reg
    };
    (imm, reg: $_reg:expr , imm: $imm:expr) => {
        $imm
    };
    (reg, reg: $reg:item , imm: $_imm:item) => {
        $reg
    };
    (imm, reg: $_reg:item , imm: $imm:item) => {
        $imm
    };
}

/// Manual +{rb,rw,rd,rq} syntax to our sized register types.
macro_rules! reg_size_to_type {
    (+rb) => {
        Reg8
    };
    (+rw) => {
        Reg16
    };
    (+rd) => {
        Reg32
    };
    (+rq) => {
        Reg64
    };
}

/// Implement one particular instruction form for a two tuple. The syntax is inspired by the
/// manuals. It's a bit complex, but hopefully not too bad to use once you look at a few examples.
macro_rules! impl_binary {
    // For binary instructions that follow the form (r/m, (reg|imm)) where r/m is a register
    (
        $trait:ident $(REX.$w:tt)? $($opcode:literal)+ $(/$extension:literal)? rm_reg:$reg:ident, $src_type:tt : $rhs:ident
        $(, let $specialize_pattern:pat = &self, $specialize_body:stmt)?
    ) => {
        // Version where the lhs R/M is a register
        impl mnemonic_forms::$trait for ($reg, $rhs) {
            reg_or_imm!(
                $src_type,
                reg: type Output = Encoding::<0>;,
                imm: type Output = Encoding::<{($rhs::BITS/8) as usize}>;
            );

            fn encode(self) -> Self::Output {
                // Transcribe specialization, if given
                $({
                    let $specialize_pattern = &self;
                    $specialize_body
                })?

                let (dest_reg, _src) = &self;

                let rex = Rex {
                    w: w_given!($( $w )?),
                    r: reg_or_imm!($src_type, reg: _src.id_rex_bit(), imm: false),
                    x: false,
                    b: dest_reg.id_rex_bit(),
                }.assemble();

                let opcode = opcode_enum!($($opcode)+);
                let rm = RMForm::RegDirect(dest_reg.id_lower());
                let form = if_first_arg!($($extension)?,
                    {
                        let _ = reg_or_imm!(
                            $src_type,
                            reg: compile_error!("Can't have both a ModRM.reg opcode extension and a register operand"),
                            imm: ()
                        );
                        const EXT: U3 = u3_literal( $($extension)? );
                        InstructionForm::RMOnly { opcode: (opcode, EXT), rm }
                    } else {
                        reg_or_imm!(
                            $src_type,
                            reg: InstructionForm::RegRM { opcode, reg: _src.id_lower(), rm },
                            imm: compile_error!("Not sure what to put for ModR/M.reg since there is no extension and no register operand")
                        )
                    }
                );

                Encoding {
                    rex,
                    form,
                    immediate: reg_or_imm!($src_type, reg: None, imm: Some(_src.to_le_bytes())),
                }
            }
        }
    };
    // For binary instructions that follow the form (r/m, (reg|imm)) where r/m is a memory location
    (
        $trait:ident $(REX.$w:tt)? $($opcode:literal)+ $(/$extension:literal)? rm_mem:$mem:ident, $src_type:tt : $rhs:ident
        $(, let $specialize_pattern:pat = &self, $specialize_body:stmt)?
    ) => {
        // Version where the lhs R/M is a memory location
        impl mnemonic_forms::$trait for ($mem, $rhs) {
            reg_or_imm!(
                $src_type,
                reg: type Output = Encoding::<0>;,
                imm: type Output = Encoding::<{($rhs::BITS/8) as usize}>;
            );

            fn encode(self) -> Self::Output {
                // Transcribe specialization, if given
                $({
                    let $specialize_pattern = &self;
                    $specialize_body
                })?

                let ($mem(addressing), _src) = self;

                let (x, b) = addressing.rex_xb();
                let rex = Rex {
                    w: w_given!($( $w )?),
                    r: reg_or_imm!($src_type, reg: _src.id_rex_bit(), imm: false),
                    x,
                    b,
                }.assemble();

                let opcode = opcode_enum!($($opcode)+);
                let rm = RMForm::Mem(addressing);

                let form = if_first_arg!($($extension)?,
                    {
                        let _ = reg_or_imm!(
                            $src_type,
                            reg: compile_error!("Can't have both a ModRM.reg opcode extension and a register operand"),
                            imm: ()
                        );
                        const EXT: U3 = u3_literal( $($extension)? );
                        InstructionForm::RMOnly { opcode: (opcode, EXT), rm }
                    } else {
                        reg_or_imm!(
                            $src_type,
                            reg: InstructionForm::RegRM { opcode, reg: _src.id_lower(), rm },
                            imm: compile_error!("Not sure what to put for ModR/M.reg since there is no extension and no register operand")
                        )
                    }
                );

                Encoding {
                    rex,
                    form,
                    immediate: reg_or_imm!($src_type, reg: None, imm: Some(_src.to_le_bytes())),
                }
            }
        }
    };
    // TODO: reg, r/m forms. Should be easier because no need for reg or imm
}

/// Implement an instruction that takes a single R/M operand.
/// All of the ones we want so far use ModR/M.reg as an opcode extension.
macro_rules! impl_unary {
    // Version where the R/M operand is a register
    ($trait:ident $(REX.$w:tt)? $opcode:literal /$extension:literal rm_reg:$reg:ident) => {
        impl mnemonic_forms::$trait for $reg {
            type Output = Encoding<0>;

            fn encode(self) -> Self::Output {
                let reg = self;

                let rex = Rex {
                    w: w_given!($( $w )?),
                    r: false,
                    x: false,
                    b: reg.id_rex_bit(),
                }.assemble();

                let form = {
                    let rm = RMForm::RegDirect(reg.id_lower());
                    const EXT: U3 = u3_literal($extension);
                    let opcode = (Opcode::Plain($opcode), EXT);
                    InstructionForm::RMOnly { opcode, rm }
                };

                Encoding {
                    rex,
                    form,
                    immediate: None,
                }
            }
        }
    };
    // Version where the R/M operand is a memory location
    ($trait:ident $(REX.$w:tt)? $opcode:literal /$extension:literal rm_mem:$mem:ident) => {
        impl mnemonic_forms::$trait for $mem {
            type Output = Encoding<0>;

            fn encode(self) -> Self::Output {
                let mem = self;

                let (x, b) = mem.0.rex_xb();
                let rex = Rex {
                    w: w_given!($( $w )?),
                    r: false,
                    x,
                    b,
                }.assemble();

                let form = {
                    let rm = RMForm::Mem(mem.0);
                    const EXT: U3 = u3_literal($extension);
                    let opcode = (Opcode::Plain($opcode), EXT);
                    InstructionForm::RMOnly { opcode, rm }
                };

                Encoding {
                    rex,
                    form,
                    immediate: None,
                }
            }
        }
    };
}

/// For instructions that use the lower 3 bits of the opcode to refer to a register.
/// Exercise: how would you change this to support BSWAP?
macro_rules! impl_reg_in_opcode {
    (
        $trait:ident $(REX.$w:tt)? $opcode:literal +$reg:tt $(imm: $rhs_imm:ident)?
    ) => {
        #[allow(unused_parens)] // silence warning in the unary case
        impl mnemonic_forms::$trait for (reg_size_to_type!(+$reg) $(, $rhs_imm)?) {
            if_first_arg!(
                $($rhs_imm)?,
                type Output = Encoding::<{($($rhs_imm)?::BITS/8) as usize}>;
                else type Output = Encoding::<0>;
            );

            fn encode(self) -> Self::Output {
                #[allow(unused)]
                let reg = &self;
                $(
                    let reg = &self.0;
                    let _: $rhs_imm = 0;
                )?

                let reg_id: U3 = reg.id_lower();

                #[allow(unused)]
                let immediate: Option<[u8; 0]> = None;
                $(
                    let immediate = Some(self.1.to_le_bytes());
                    let _: $rhs_imm = 0;
                )?

                Encoding {
                    rex: Rex {
                        w: w_given!($( $w )?),
                        r: false,
                        x: false,
                        b: reg.id_rex_bit(),
                    }.assemble(),
                    form: InstructionForm::OpcodeOnly(Opcode::Plain($opcode + (reg_id as u8))),
                    immediate,
                }
            }
        }
    }
}

mod mnemonic_forms {
    use crate::asm::x64::{Assembler, Encoding};

    /// The interface to the assembler has each mnemonic as a method taking a
    /// tuple that implements the different forms of the instruction. Mnemonic methods
    /// have very similar signatures so this macro helps to stay DRY.
    macro_rules! asm_method {
        ($mnemonic:ident, $trait:ident) => {
            asm_method!(make trait $trait);
            asm_method!($mnemonic, alias $trait);
        };
        // Same encoding, different mnemonics. For example, shl and sal, je and jz.
        ($mnemonic:ident, alias $trait:ident) => {
            impl Assembler {
                pub fn $mnemonic<T, const IMM_SIZE: usize>(&mut self, operands: T)
                where
                    T: $trait<Output = Encoding<IMM_SIZE>>,
                {
                    self.push_one_insn(operands.encode());
                }
            }
        };
        (make trait $trait:ident) => {
            pub trait $trait {
                type Output;
                fn encode(self) -> Self::Output;
            }
        };
    }

    asm_method!(mov, MOV);
    asm_method!(test, TEST);
    asm_method!(push, PUSH);
    asm_method!(pop, POP);

    asm_method!(shl, SHL);
    asm_method!(sal, alias SHL);

    asm_method!(shr, SHR);
    asm_method!(sar, SAR);

    asm_method!(jmp, JMP);

    asm_method!(call, CALL);
    asm_method!(not, NOT);
}

// TODO: Write a test generation script
//
impl_reg_in_opcode!(PUSH 0x50 +rq);

impl_reg_in_opcode!(POP 0x58 +rq);

impl_reg_in_opcode!(MOV       0xB0 +rb imm: u8);
impl_reg_in_opcode!(MOV       0xB8 +rd imm:u32);
impl_reg_in_opcode!(MOV REX.W 0xB8 +rq imm:u64);

impl_binary!(MOV       0xC7 /0 rm_mem: Mem8, imm: u8);
impl_binary!(MOV       0xC7 /0 rm_mem:Mem32, imm:u32);
impl_binary!(MOV REX.W 0xC7 /0 rm_mem:Mem64, imm:u32);

impl_binary!(TEST REX.W 0xF6 /0 rm_reg: Reg8, imm: u8, let (reg, imm) = &self, if *reg == AL  { return test_ax_imm_special(reg, imm.to_le_bytes()) });
impl_binary!(TEST       0xF7 /0 rm_reg:Reg32, imm:u32, let (reg, imm) = &self, if *reg == EAX { return test_ax_imm_special(reg, imm.to_le_bytes()) });
impl_binary!(TEST REX.W 0xF7 /0 rm_reg:Reg64, imm:i32, let (reg, imm) = &self, if *reg == RAX { return test_ax_imm_special(reg, imm.to_le_bytes()) });

impl_binary!(TEST REX.W 0xF6 /0 rm_mem: Mem8, imm: u8);
impl_binary!(TEST       0xF7 /0 rm_mem:Mem32, imm:u32);
impl_binary!(TEST REX.W 0xF7 /0 rm_mem:Mem64, imm:i32);

impl_binary!(TEST       0x84 rm_reg: Reg8, reg: Reg8);
impl_binary!(TEST       0x85 rm_reg:Reg32, reg:Reg32);
impl_binary!(TEST REX.W 0x85 rm_reg:Reg64, reg:Reg64);

impl_binary!(TEST       0x84 rm_mem: Mem8, reg: Reg8);
impl_binary!(TEST       0x85 rm_mem:Mem32, reg:Reg32);
impl_binary!(TEST REX.W 0x85 rm_mem:Mem64, reg:Reg64);

// NOTE: Shift amounts are masked to the lower 5/6 bits.
impl_binary!(SHL REX.W 0xC1 /4 rm_reg:Reg64, imm:u8, let (reg, imm) = &self, if *imm == 1 { return left_shift_by_one(reg) });

impl_unary!(NOT       0xF6 /2 rm_reg: Reg8);
impl_unary!(NOT       0xF7 /2 rm_reg:Reg32);
impl_unary!(NOT REX.W 0xF7 /2 rm_reg:Reg64);

impl_unary!(CALL 0xFF /2 rm_reg:Reg64);
impl_unary!(CALL 0xFF /2 rm_mem:Mem64);

impl_unary!(JMP 0xFF /4 rm_reg:Reg64);
impl_unary!(JMP 0xFF /4 rm_mem:Mem64);

/// Special shorter encoding for test {al,ax,eax,rax}, imm{8,16,32,64}
fn test_ax_imm_special<R: Register, const IMM_SIZE: usize>(
    _reg: &R,
    imm_le_bytes: [u8; IMM_SIZE],
) -> Encoding<IMM_SIZE> {
    Encoding {
        rex: Rex {
            w: (R::WIDTH == B64),
            r: false,
            x: false,
            b: false,
        }
        .assemble(),
        form: InstructionForm::OpcodeOnly(Opcode::Plain(if R::WIDTH == B8 { 0xA8 } else { 0xA9 })),
        immediate: Some(imm_le_bytes),
    }
}

/// Special shorter encoding for shl rm, 1
fn left_shift_by_one<R: Register>(reg: &R) -> Encoding<1> {
    let opcode = Opcode::Plain(if R::WIDTH == B8 { 0xD0 } else { 0xD1 });
    Encoding {
        rex: Rex {
            w: (R::WIDTH == B64),
            r: false,
            x: false,
            b: reg.id_rex_bit(),
        }
        .assemble(),
        form: InstructionForm::RMOnly {
            opcode: (opcode, U3::Dec4),
            rm: RMForm::RegDirect(reg.id_lower()),
        },
        immediate: None,
    }
}

/*
impl<Reg: Register> mnemonic_forms::Test for (Reg, i32) {
    fn encode(self) -> Encoding {
        let dest = self.0;

        let rex = Rex {
            w: Reg::WIDTH == B64,
            r: false,
            x: false,
            b: dest.id_rex_bit(),
        }
        .assemble();

        Encoding {
            rex,
            form: InstructionForm::RMOnly {
                opcode: (Opcode::Plain(0xF7), U3::Dec0),
                rm: RegDirect(dest.id_lower()),
            },
            imm32: Some(self.1),
        }
    }
}

impl<Reg: Register> mnemonic_forms::Test for (Reg, Reg) {
    fn encode(self) -> Encoding {
        let (lhs, rhs) = self;
        // Decide on the REX byte
        let rex = Rex {
            w: Reg::WIDTH == B64,
            r: rhs.id_rex_bit(),
            x: false,
            b: lhs.id_rex_bit(),
        }
        .assemble();

        Encoding {
            rex,
            form: RegRM {
                opcode: Opcode::Plain(0x85),
                reg: rhs.id_lower(),
                rm: RegDirect(lhs.id_lower()),
            },
            imm32: None,
        }
    }
}
*/

/*
impl mnemonic_forms::Test for (Mem64, i32) {
    fn encode(self) -> Encoding {
        let Mem64::RegPlusOffset(dest_reg, dest_disp) = self.0;
        let rex = Rex {
            w: true, // 64 bit operand size
            r: false,
            x: false,
            b: dest_reg.id_rex_bit(),
        }
        .assemble();
        Encoding {
            rex,
            form: InstructionForm::RMOnly {
                opcode: (Opcode::Plain(0xF7), U3::Dec0),
                rm: RMForm::RegPlusDisp {
                    reg: dest_reg.id_lower(),
                    disp: dest_disp,
                },
            },
            imm32: Some(self.1),
        }
    }
}
*/

impl Assembler {
    fn push_one_insn<const IMM_SIZE: usize>(&mut self, encoding: Encoding<IMM_SIZE>) {
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
                opcode
                    .encode_and_push(&mut self.encoded)
                    .expect("alloc failure");
            }
            RegRM { opcode, reg, rm } => {
                opcode
                    .encode_and_push(&mut self.encoded)
                    .and_then(|_| rm.encode_and_push(reg, &mut self.encoded))
                    .expect("alloc failure");
            }
            RMOnly {
                opcode: (opcode_bytes, opcode_extension),
                rm,
            } => {
                opcode_bytes
                    .encode_and_push(&mut self.encoded)
                    .and_then(|_| rm.encode_and_push(opcode_extension, &mut self.encoded))
                    .expect("alloc failure");
            }
        }

        // See doc about this constant.
        let _ = Encoding::<IMM_SIZE>::RUN_BUILD_TIME_IMM_SIZE_CHECK;

        self.encoded
            .try_reserve(IMM_SIZE)
            .map(|_| {
                if let Some(bytes) = encoding.immediate {
                    for byte in bytes {
                        self.encoded.push(byte)
                    }
                }
            })
            .expect("alloc failure");
    }
}

impl Assembler {
    pub fn new() -> Self {
        Assembler { encoded: vec![] }
    }
    pub fn encoded(&self) -> &Vec<u8> {
        &self.encoded
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
        ($bytes:literal $($disasm:literal, $mnemonic:ident ($args:expr))+) => {{
            let mut asm = Assembler::new();

            $( asm.$mnemonic($args); )*

            assert_eq!($bytes, asm.byte_string());

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
    fn shl_and_sal() {
        test_encoding!(
            "48 c1 e0 02 48 d1 e1 49 d1 e7 49 c1 e3 03 49 d1 e4 49 c1 e4 02 49 d1 e5 49 c1 e5 03"
            "shl rax, 2",  shl((RAX, 2))
            "shl rcx, 1",  shl((RCX, 1))

            "shl r15, 1",  shl((R15, 1))
            "shl r11, 3",  shl((R11, 3))

            "shl r12, 1",  shl((R12, 1))
            "shl r12, 2",  shl((R12, 2))

            "shl r13, 1",  shl((R13, 1))
            "shl r13, 3",  shl((R13, 3))
        );
    }

    #[test]
    fn test() {
        // reg64, imm32
        test_encoding!(
            "48 a9 ff ff ff 7f 49 f7 c3 fe ca ab 0f 48 f7 c7 02 35 54 f0 49 f7 c0 ff ff ff ff"
            "test rax, 0x7fffffff",  test((RAX, i32::MAX))
            "test r11, 0xfabcafe",   test((R11, 0xFABCAFE))
            "test rdi, -0xfabcafe",  test((RDI, -0xFABCAFE))
            "test r8, -1",           test((R8, -1))
        );

        // reg32, imm32
        test_encoding!(
            "f7 c7 ff ff ff ff 41 f7 c1 fe ca ab 0f f7 c7 ef be ad de 41 f7 c1 ff ff ff ff"
            "test edi, 0xffffffff", test((EDI, u32::MAX))
            "test r9d, 0xfabcafe", test((R9D, 0xFABCAFE))
            "test edi, 0xdeadbeef", test((EDI, 0xDEADBEEF))
            "test r9d, 0xffffffff", test((R9D, u32::MAX))
        );

        // reg64, reg64
        test_encoding!(
            "48 85 d0 4c 85 d9 49 85 dc 4d 85 f7"
            "test rax, rdx", test((RAX, RDX))
            "test rcx, r11", test((RCX, R11))
            "test r12, rbx", test((R12, RBX))
            "test r15, r14", test((R15, R14))
        );

        // reg32, reg32
        test_encoding!(
            "85 d0 44 85 d9 41 85 dc 45 85 f7"
            "test eax, edx", test((EAX, EDX))
            "test ecx, r11d", test((ECX, R11D))
            "test r12d, ebx", test((R12D, EBX))
            "test r15d, r14d", test((R15D, R14D))
        )

        // TODO: write panic tests
    }

    #[test]
    fn test_rmm_r() {
        test_encoding!(
            "48 85 40 80"
            "test qword ptr [rax - 0x80], rax",
            test((mem64(RAX, i8::MIN.into()), RAX))
        );

        test_encoding!(
            "49 85 44 24 80"
            "test qword ptr [r12 - 0x80], rax",
            test((mem64(R12, i8::MIN.into()), RAX))
        );

        test_encoding!(
            "4d 85 6d 80"
            "test qword ptr [r13 - 0x80], r13",
            test((mem64(R13, i8::MIN.into()), R13))
        );
    }

    #[test]
    fn test_with_memory() {
        test_encoding!(
            "48 f7 40 80 ff ff ff 7f"
            "test qword ptr [rax - 0x80], 0x7fffffff",
            test((mem64(RAX, i8::MIN.into()), i32::MAX))
        );

        test_encoding!(
            "49 f7 45 7f ff ff ff 7f"
            "test qword ptr [r13 + 0x7f], 0x7fffffff",
            test((mem64(R13, i8::MAX.into()), i32::MAX))
        );

        test_encoding!(
            "48 f7 44 24 80 00 00 00 80"
            "test qword ptr [rsp - 0x80], -0x80000000",
            test((mem64(RSP, i8::MIN.into()), i32::MIN))
        );

        // RSP, RBP, R12 and R13 are special because the lower part of their regiser id
        // are escape codes in the ModR/M byte.
        test_encoding!(
            "48 f7 04 24 ff ff ff 7f 49 f7 04 24 00 00 00 80 \
             48 f7 45 00 ff ff ff 7f 49 f7 45 00 00 00 00 80"

            "test qword ptr [rsp], 0x7fffffff", test((mem64(RSP, 0), i32::MAX))
            "test qword ptr [r12], -0x80000000", test((mem64(R12, 0), i32::MIN))

            "test qword ptr [rbp], 0x7fffffff", test((mem64(RBP, 0), i32::MAX))
            "test qword ptr [r13], -0x80000000", test((mem64(R13, 0), i32::MIN))
        );

        test_encoding!(
            "49 f7 84 24 80 00 00 00 01 00 00 00"
            "test qword ptr [r12 + 0x80], 1",
            test((mem64(R12, 1 + i32::from(i8::MAX)), 1))
        );

        test_encoding!(
            "48 f7 84 24 7f ff ff ff fe ca ab 0f"
            "test qword ptr [rsp - 0x81], 0xfabcafe",
            test((mem64(RSP, i32::from(i8::MIN) - 1), 0xfabcafe))
        );
    }

    #[test]
    fn push() {
        test_encoding!(
            "50 41 54 41 55"
            "push rax", push(RAX)
            "push r12", push(R12)
            "push r13", push(R13)
        );
    }

    #[test]
    fn pop() {
        test_encoding!(
            "58 41 5c 41 5d"
            "pop rax", pop(RAX)
            "pop r12", pop(R12)
            "pop r13", pop(R13)
        );
    }

    #[test]
    fn randoms() {
        test_encoding!(
            "ff e0 41 ff e0 ff 21 41 ff 63 f6"
            "jmp rax", jmp(RAX)
            "jmp r8", jmp(R8)
            "jmp qword ptr [rcx]", jmp(mem64(RCX, 0))
            "jmp qword ptr [r11 - 0xa]", jmp(mem64(R11, -0xa))
        );

        test_encoding!(
            "f6 d0 f7 d0 48 f7 d0 49 f7 d0"
            "not al", not(AL)
            "not eax", not(EAX)
            "not rax", not(RAX)
            "not r8", not(R8)
        );

        test_encoding!(
            "ff d0 41 ff d0 ff 11 41 ff 53 f6"
            "call rax", call(RAX)
            "call r8", call(R8)
            "call qword ptr [rcx]", call(mem64(RCX, 0))
            "call qword ptr [r11 - 0xa]", call(mem64(R11, -0xa))
        );
    }

    #[test]
    fn mov() {
        test_encoding!(
            "b0 00 b8 fe ca ab 0f 41 b8 fe ca ab 0f 48 b8 ff ff ff ff ff ff ff ff 49 bf 00 00 00 00 01 00 00 00"
            "mov al, 0", mov((AL, 0))
            "mov eax, 0xfabcafe", mov((EAX, 0xfabcafe))
            "mov r8d, 0xfabcafe", mov((R8D, 0xfabcafe))
            "movabs rax, 0xffffffffffffffff", mov((RAX, u64::MAX))
            "movabs r15, 0x100000000", mov((R15, u64::from(u32::MAX)+1))
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
