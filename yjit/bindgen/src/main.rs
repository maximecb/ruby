extern crate bindgen;

use std::path::PathBuf;
use std::env;

fn main() {
    // assume CWD is Ruby repo root so we could copy paste include path
    // args from make.
    let bindings = bindgen::builder()
        .clang_args(env::args())
        .header("internal.h")
        .header("vm_core.h")
        .header("yjit.c")

        // Don't want to copy over C comment
        .generate_comments(false)

        // Don't want layout tests as they are platform dependent
        .layout_tests(false)

        // This struct is public to extensions
        .allowlist_type("RBasic")

        .allowlist_function("rb_hash_new")
        .allowlist_function("rb_hash_aset")

        // We define VALUE manually
        .blocklist_type("VALUE")

        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    let mut out_path: PathBuf = env::current_dir().expect("bad cwd");
    out_path.push("yjit");
    out_path.push("src");
    out_path.push("cruby_bindings.inc.rs");

    bindings
        .write_to_file(out_path)
        .expect("Couldn't write bindings!");
}
