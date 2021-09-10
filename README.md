<p align="center">
  <a href="https://yjit.org/" target="_blank" rel="noopener noreferrer">
    <img src="https://user-images.githubusercontent.com/224488/131155756-aa8fb528-a813-4dfd-99ac-8785c3d5eed7.png" width="400">
  </a>
</p>


YJIT - Yet Another Ruby JIT
===========================

**DISCLAIMER: Please note that this project is in early stages of development. It is very much a work in progress, it may cause your software to crash, and current performance results are likely to leave you feeling underwhelmed.**

YJIT is a lightweight, minimalistic Ruby JIT built inside the CRuby/MRI binary.
It lazily compiles code using a Basic Block Versioning (BBV) architecture. The target use case is that of servers running
Ruby on Rails, an area where CRuby's MJIT has not yet managed to deliver speedups.
To simplify development, we currently support only macOS and Linux on x86-64, but an ARM64 backend
is part of future plans.
This project is open source and falls under the same license as CRuby.

If you wish to learn more about the approach taken, here are some written resources and conference talks:
- [YJIT: Building a New JIT Compiler Inside CRuby](https://pointersgonewild.com/2021/06/02/yjit-building-a-new-jit-compiler-inside-cruby/) ([MoreVMs 2021 talk](https://www.youtube.com/watch?v=vucLAqv7qpc))
- [Simple and Effective Type Check Removal through Lazy Basic Block Versioning](https://arxiv.org/pdf/1411.0352.pdf) ([ECOOP 2015 talk](https://www.youtube.com/watch?v=S-aHBuoiYE0))
- [Interprocedural Type Specialization of JavaScript Programs Without Type Analysis](https://drops.dagstuhl.de/opus/volltexte/2016/6101/pdf/LIPIcs-ECOOP-2016-7.pdf) ([ECOOP 2016 talk](https://www.youtube.com/watch?v=sRNBY7Ss97A))

To cite this repository in your publications, please use this bibtex snippet:

```
@misc{yjit_ruby_jit,
  author = {Chevalier-Boisvert, Maxime and Wu, Alan and Patterson, Aaron},
  title = {YJIT - Yet Another Ruby JIT},
  year = {2021},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://github.com/Shopify/yjit}},
}
```

## Current Limitations

YJIT is a work in progress and as such may not yet be mature enough for mission-critical software. Below is a list of known limitations, all of which we plan to eventually address:

- No garbage collection for generated code.

Because there is no GC for generated code yet, your software could run out of executable memory if it is large enough. You can change how much executable memory is allocated using [YJIT's command-line options](https://github.com/Shopify/yjit#command-line-options).

## Installation

Start by cloning the `Shopify/yjit` repository:

```
git clone https://github.com/Shopify/yjit
cd yjit
```

The YJIT `ruby` binary can be built with either GCC or Clang. For development, we recommend enabling debug symbols so that assertions are enabled as this makes debugging easier. Enabling debug mode will also make it possible for you to disassemble code generated by YJIT. However, this causes a performance hit. For maximum performance, compile with GCC, without the `DRUBY_DEBUG` or `YJIT_STATS` build options. More detailed build instructions are provided in the [Ruby README](https://github.com/ruby/ruby#how-to-compile-and-install).
To support disassembly of the generated code, `libcapstone` is also required (`brew install capstone` on MacOS, `sudo apt-get install -y libcapstone-dev` on Ubuntu/Debian and `sudo dnf -y install capstone-devel` on Fedora).

```
# Configure with debugging/stats options for development, build and install
./autogen.sh
./configure cppflags="-DRUBY_DEBUG -DYJIT_STATS" --prefix=$HOME/.rubies/ruby-yjit
make -j16 install
```

Typically configure will choose default C compiler. To specify the C compiler, use
```
# Choosing a specific c compiler
export CC=/path/to/my/choosen/c/compiler
```
before runing `./configure`.

You can test that YJIT works correctly by running:

```
# Quick tests found in /bootstraptest
make btest

# Complete set of tests
make -j16 test-all
```

## Usage

### Examples

Once YJIT is built, you can either use `./miniruby` from within your build directory, or switch to the YJIT version of `ruby`
by using the `chruby` tool:

```
chruby ruby-yjit
ruby myscript.rb
```

You can dump statistics about compilation and execution by running YJIT with the `--yjit-stats` command-line option:

```
./miniruby --yjit-stats myscript.rb
```

The machine code generated for a given method can be printed by adding `puts YJIT.disasm(method(:method_name))` to a Ruby script. Note that no code will be generated if the method is not compiled.


### Command-Line Options

YJIT supports all command-line options supported by upstream CRuby, but also adds a few YJIT-specific options:

- `--disable-yjit`: turn off YJIT (enabled by default)
- `--yjit-stats`: produce statistics after the execution of a program (must compile with `cppflags=-DRUBY_DEBUG` to use this)
- `--yjit-exec-mem-size=N`: size of the executable memory block to allocate (default 256 MiB)
- `--yjit-call-threshold=N`: number of calls after which YJIT begins to compile a function (default 2)
- `--yjit-max-versions=N`: maximum number of versions to generate per basic block (default 4)
- `--yjit-greedy-versioning`: greedy versioning mode (disabled by default, may increase code size)

### Benchmarking

We have collected a set of benchmarks and implemented a simple benchmarking harness in the [yjit-bench](https://github.com/Shopify/yjit-bench) repository. This benchmarking harness is designed to disable CPU frequency scaling, set process affinity and disable address space randomization so that the variance between benchmarking runs will be as small as possible. Please kindly note that we are at an early stage in this project.

### Performance Tips

This section contains tips on writing Ruby code that will run as fast as possible on YJIT. Some of this advice is based on current limitations of YJIT, while other advice is broadly applicable. It probably won't be practical to apply these tips everywhere in your codebase, but you can profile your code using a tool such as [stackprof](https://github.com/tmm1/stackprof) and refactor the specific methods that make up the largest fractions of the execution time.

- Use exceptions for error recovery only, not as part of normal control-flow
- Avoid redefining basic integer operations (i.e. +, -, <, >, etc.)
- Avoid redefining the meaning of `nil`, equality, etc.
- Avoid allocating objects in the hot parts of your code
- Use while loops if you can, instead of `integer.times`
- Minimize layers of indirection
  - Avoid classes that wrap objects if you can
  - Avoid methods that just call another method, trivial one liner methods
- CRuby method calls are costly. Favor larger methods over smaller methods.
- Try to write code so that the same variables always have the same type

You can also compile YJIT in debug mode and use the `--yjit-stats` command-line option to see which bytecodes cause YJIT to exit, and refactor your code to avoid using these instructions in the hottest methods of your code.

## Contributing

We welcome open source contributors. You should feel free to open new issues to report bugs or just to ask questions.
Suggestions on how to make this readme file more helpful for new contributors are most welcome.

Bug fixes and bug reports are very valuable to us. If you find a bug in YJIT, it's very possible be that nobody has reported it before,
or that we don't have a good reproduction for it, so please open an issue and provide as much information as you can about your configuration and a description of how you encountered the problem. List the commands you used to run YJIT so that we can easily reproduce the issue on our end and investigate it. If you are able to produce a small program reproducing the error to help us track it down, that is very much appreciated as well.

If you would like to contribute a large patch to YJIT, we suggest opening an issue or a discussion on this repository so that
we can have an active discussion. A common problem is that sometimes people submit large pull requests to open source projects
without prior communication, and we have to reject them because the work they implemented does not fit within the design of the
project. We want to save you time and frustration, so please reach out and we can have a productive discussion as to how
you can contribute things we will want to merge into YJIT.

### Source Code Organization

The YJIT source code is divided between:
- `yjit_asm.c`: x86 in-memory assembler we use to generate machine code
- `yjit_asm_tests.c`: tests for the in-memory assembler
- `yjit_codegen.c`: logic for translating Ruby bytecode to machine code
- `yjit_core.c`: basic block versioning logic, core structure of YJIT
- `yjit_iface.c`: code YJIT uses to interface with the rest of CRuby
- `yjit.h`: C definitions YJIT exposes to the rest of the CRuby
- `yjit.rb`: `YJIT` Ruby module that is exposed to Ruby
- `test_asm.sh`: script to compile and run the in-memory assembler tests
- `tool/ruby_vm/views/vm.inc.erb`: template instruction handler used to hook into the interpreter

The core of CRuby's interpreter logic is found in:
- `insns.def`: defines Ruby's bytecode instructions (gets compiled into `vm.inc`)
- `vm_insnshelper.c`: logic used by Ruby's bytecode instructions
- `vm_exec.c`: Ruby interpreter loop

### Coding & Debugging Protips

There are 3 test suites:
- `make btest` (see `/bootstraptest`)
- `make test-all`
- `make test-spec`
- `make check` runs all of the above

The tests can be run in parallel like this:

```
make -j16 test-all RUN_OPTS="--yjit-call-threshold=1"
```

Or single-threaded like this, to more easily identify which specific test is failing:

```
make test-all TESTOPTS=--verbose RUN_OPTS="--yjit-call-threshold=1"
```

To debug a single test in `test-all`:

```
make test-all TESTS='test/-ext-/marshal/test_usrmarshal.rb' RUNRUBYOPT=--debugger=lldb RUN_OPTS="--yjit-call-threshold=1"
```

You can also run one specific test in `btest`:

```
make btest BTESTS=bootstraptest/test_ractor.rb RUN_OPTS="--yjit-call-threshold=1"
```

There are shortcuts to run/debug your own test/repro in `test.rb`:

```
make run  # runs ./miniruby test.rb
make lldb # launches ./miniruby test.rb in lldb
```

You can use the Intel syntax for disassembly in LLDB, keeping it consistent with YJIT's disassembly:

```
echo "settings set target.x86-disassembly-flavor intel" >> ~/.lldbinit
```
