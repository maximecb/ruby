pub mod x86_64;

/// Pointer to a piece of machine code
/// We may later change this to wrap an u32
/// Note: there is no NULL constant for CodePtr. You should use Option<CodePtr> instead.
pub struct CodePtr(*const u8);

impl CodePtr {
    fn raw_ptr(self) -> *const u8 {
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

/// Compute an offset in bytes of a given struct field
macro_rules! offset_of {
    ($struct_type:ty, $field_name:tt) => {
        {
            // Null pointer to our struct type
            let foo = (0 as * const $struct_type);

            unsafe {
                let ptr_field = (&(*foo).$field_name as *const _ as usize);
                let ptr_base = (foo as usize);
                ptr_field - ptr_base
            }
        }
    };
}
pub(crate) use offset_of;

// TODO: need a field_size_of macro, to compute the size of a struct field in bytes

// TODO: move CodeBlock here so it can be shared between x86/ARM
