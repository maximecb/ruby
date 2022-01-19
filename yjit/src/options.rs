const YJIT_DEFAULT_CALL_THRESHOLD: usize = 10;

// NOTE: we may want packed storage or some way to specify storage that maps to C?
// Or we may actually want to use bindgen to export rb_yjit_options from C

// Command-line options
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

// TODO: the mutable options can be initialized in a simple unsafe block
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
    ($option_name:ident) => {
        unsafe
        {
            OPTIONS.$option_name
        }
    };
}
pub(crate) use get_option;

// Just to demonstrate how this can be initialized
fn init_options()
{
    unsafe {
        OPTIONS.yjit_enabled = true;
    }
}
