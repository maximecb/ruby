/// x64 general purpose register
#[derive(Debug)]
pub struct Register {
    vintage: RegisterVintage,

        /// Bit width of the register
        width: RegisterWidth,
        /// Number for encoding the register
        id: u8,
}

/// Groupings of registers with encoding significance
#[derive(Debug)]
#[derive(PartialEq)]
enum RegisterVintage {
    /// The register is in the original x86 ISA
    Original,
    /// The register first appeared in the amd64 ISA
    Extended,
}

/// Bit width of register
#[derive(Debug)]
#[derive(PartialEq)]
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
        $(pub const $b64_name: Register = Register { vintage: $vintage, width: B64, id: $id };)*
        $(pub const $b32_name: Register = Register { vintage: $vintage, width: B32, id: $id };)*
        $(pub const $b16_name: Register = Register { vintage: $vintage, width: B16, id: $id };)*
        $(pub const $b8_name: Register = Register { vintage: $vintage, width: B8, id: $id };)*
    }
}

general_purpose_registers! {
    Original 0 AL AX EAX RAX
    Original 1 CL CX ECX RCX
    Original 2 DL DX EDX RDX
    Original 3 BL BX EBX RBX
    Original 4 SPL SP ESP RSP
    Original 5 BPL BP EBP RBP
    Original 6 SIL SI ESI RSI
    Original 7 DIL DI EDI RDI
    Extended 0 R8L R8W R8D R8
    Extended 1 R9L R9W R9D R9
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

/// Operand for x64 instructions
#[derive(Debug)]
pub enum Operand {
    Register(Register),
    //AddressingForm,
    //Label,
    //Address(usize),
    //IPRelative(),
}

/// x64 assembler
pub struct Assembler {
    /// The encoded bytes for emitted instructions 
    encoded: Vec<u8>
}

impl Assembler {
    pub fn new() -> Self {
        Assembler { encoded: vec!() } 
    }
    pub fn encoded(&self) -> &Vec<u8> {
        &self.encoded
    }
    pub fn mov(&mut self, dst: Operand, src: Operand) {
        use RegisterWidth::*;
        match (dst, src) {
            (Operand::Register(dst), Operand::Register(src)) if dst.width == src.width && match dst.width { B32 | B64 => true, _ => false } => {
                // Temporary.
                // Addressing form: mov reg, reg/rm
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
                        let rex = 0b0100_0000 +
                                  0b1000 * rex_w +
                                  0b0100 * rex_r +
                                  0b0010 * rex_x +
                                  0b0001 * rex_b;
                        Some(rex)
                    } else {
                        None
                    }
                };

                // Decide on modr/m byte
                // mod=0b11 here since we want `mov reg, reg`
                let modrm = 0b11_000_000 +
                            (dst.id << 3) + // modrm.reg
                            (src.id << 0);  // modrm.rm

                // Write the bytes
                if let Some(byte) = rex {
                    self.encoded.push(byte);
                }
                self.encoded.push(opcode);
                self.encoded.push(modrm);
            },
            (dst @ _, src @ _) => {
                panic!("Unsupported addressing form dst:{:?} src:{:?}",dst, src);
            }
        }
    }
}
