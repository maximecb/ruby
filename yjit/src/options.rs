use std::ffi::CStr;

const YJIT_DEFAULT_CALL_THRESHOLD: usize = 10;

// Command-line options
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct Options {
    // Enable compilation with YJIT
    pub yjit_enabled: bool,

    // Size of the executable memory block to allocate in MiB
    pub exec_mem_size : usize,

    // Number of method calls after which to start generating code
    // Threshold==1 means compile on first execution
    pub call_threshold : usize,

    // Generate versions greedily until the limit is hit
    pub greedy_versioning : bool,

    // Disable the propagation of type information
    pub no_type_prop : bool,

    // Maximum number of versions per block
    // 1 means always create generic versions
    pub max_versions : usize,

    // Capture and print out stats
    pub gen_stats : bool
}

// The mutable options can be initialized in a simple unsafe block
// https://stackoverflow.com/questions/19605132/is-it-possible-to-use-global-variables-in-rust
pub static mut OPTIONS: Options = Options {
    yjit_enabled: false,
    exec_mem_size : 256,
    call_threshold : YJIT_DEFAULT_CALL_THRESHOLD,
    greedy_versioning : false,
    no_type_prop : false,
    max_versions : 4,
    gen_stats : false,
};

/// Macro to get an option value by name
macro_rules! get_option {
    // Unsafe is ok here because options are initialized
    // once before any Ruby code executes
    ($option_name:ident) => {
        unsafe {
            OPTIONS.$option_name
        }
    };
}
pub(crate) use get_option;

pub fn parse_option(str_ptr: *const std::os::raw::c_char) -> bool
{
    let c_str: &CStr = unsafe { CStr::from_ptr(str_ptr) };
    let str_slice: &str = c_str.to_str().unwrap();
    //let str_buf: String = str_slice.to_owned();




    return false;
}