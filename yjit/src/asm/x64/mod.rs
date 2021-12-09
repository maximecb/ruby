pub struct Register {
    /// The number identifying the register in the encoding
    id: u8,
    /// Needs a bit set in the rex byte to encode
    needs_rex: bool,
    /// Bit width of the register
    bit_width: RegisterWidth,
}

pub const RAX: Register = Register {
    id: 0,
    needs_rex: true,
    bit_width: RegisterWidth::B64,
};

pub enum RegisterWidth {
    B8,
    B16,
    B32,
    B64,
}

pub enum Operand {
    Register(Register),
    AddressingForm,
    // IPRelative(),
}

pub fn mov(dst: &Operand, src: &Operand) {}
