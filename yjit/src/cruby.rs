// TODO: need wrappers for:
// VALUE
// rb_iseq_t*
// rb_execution_context_t *
// RBasic
// ... and more!

// FIXME: I don't know what the actual value of this constant is
// I suspect it gets defined while CRuby is being built
pub const VM_INSTRUCTION_SIZE: usize = 128;

pub struct VALUE(usize);

// TODO: need constants for
// Qtrue
// Qfalse
// Qnil

// TODO: these could be in a trait for VALUE
// SPECIAL_CONST_P(val)
// STATIC_SYM_P(val)
// FIXNUM_P(val)
// FLONUM_P(val)
// NIL_P(val)
// BUILTIN_TYPE(val)
