pub mod x86_64;

/// Pointer to a piece of machine code
/// We may later change this to wrap an u32
/// Note: there is no null constant for CodePtr. You should use Option<CodePtr> instead.
pub struct CodePtr(*mut u8);

impl CodePtr {
    fn raw_ptr(self) -> *mut u8 {
        let CodePtr(ptr) = self;
        return ptr;
    }
}

impl From<*mut u8> for CodePtr {
    fn from(value: *mut u8) -> Self {
        assert!(value as usize != 0);
        return CodePtr(value);
    }
}
