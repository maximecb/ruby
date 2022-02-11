# Rust YJIT

⚠️ *Warning:* this project is a work-in-progress prototype. You may find crashes,
subtle bugs, lack of documentation, questionable designs, broken builds,
nondescript commit messages, etc.

## Getting Rust tools

I used the [recommended installation method][rust-install] on an Intel-based
MacBook and it went smoothly. Rust provides first class [support][editor-tools]
for many editors which might interest you.

## Useful commands

Cargo is your friend. Make sure you are in this folder (`cd yjit` from
repository root).

```sh
cargo build                       # build the static library
cargo test                        # run tests
cargo test --features disassembly # run additional tests that use the optional libcapstone for verification
cargo doc --document-private-items --open # build documentation site and open it in your browser
cargo fmt                         # reformat the source code (idempotent)
```

## Using Rust-YJIT

* Do a "make distclean" first
* Supply CC=clang and the "--enable-yjit=dev" parameter to configure
* Make sure you're running on x86_64 hardware and Linux or MacOS
* Run "make -j miniruby" then "./miniruby --yjit"
* Just "make" will currently fail. That's expected.

### Adding C bindings to Rust-YJIT

On an Intel-based host configured with CC=clang, you can run "make yjit-bindgen" to create or update YJIT's C bindings in
yjit/src/cruby_bindings.inc.rs. The list of allowed and blocked symbols can be found in yjit/bindgen/src/main.rs.

If you add one or more functions as allowlisted, keep in mind that you may need to list appropriate types as opaque or blocklist to avoid extensive additional bindings being added.

## Are you going to use Rust in other parts of CRuby?

No.

## Current Limitations of Rust-YJIT

* Requires Clang
* USE_FLONUM == 1                // Affects how VALUEs are encoded

[rust-install]: https://www.rust-lang.org/tools/install
[editor-tools]: https://www.rust-lang.org/tools
