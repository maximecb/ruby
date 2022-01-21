// TODO: need wrappers for:
// VALUE
// rb_iseq_t*
// rb_execution_context_t *
// RBasic
// ... and more!

pub struct VALUE(pub usize);

/// Pointer to an ISEQ
pub struct IseqPtr(pub usize);

// TODO: need constants for
// Qtrue
// Qfalse
// Qnil

// TODO: these could be in a trait for VALUE ?
// SPECIAL_CONST_P(val)
// STATIC_SYM_P(val)
// FIXNUM_P(val)
// FLONUM_P(val)
// NIL_P(val)
// BUILTIN_TYPE(val)

// TODO: need constants for all the YARV opcodes
pub const OP_NOP: usize = 0;

// TODO: need the actual value of VM_INSTRUCTION_SIZE
pub const VM_INSTRUCTION_SIZE: usize = 128;