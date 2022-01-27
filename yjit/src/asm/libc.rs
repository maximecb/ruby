/// This module represents various bindings to functions and constants we need
/// from libc. Since we don't rely on external crates, a lot of this is lifted
/// pretty directly from https://github.com/rust-lang/libc and
/// https://github.com/danburkert/memmap-rs.
///
/// If we want to increase portability at some point in the future, we'll need
/// to provide some additional cfg switches, as we've directly taken the x86_64
/// options.

use core::ffi::c_void;
use std::io::{Error, Result};
use std::ptr;

/// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/mod.rs#L10
#[allow(non_camel_case_types)]
pub type c_int = i32;

/// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/bsd/apple/b64/mod.rs#L3
#[allow(non_camel_case_types)]
pub type c_long = i64;

/// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/bsd/mod.rs#L1
#[allow(non_camel_case_types)]
pub type off_t = u64;

/// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/mod.rs#L19
#[allow(non_camel_case_types)]
pub type size_t = usize;

/// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/bsd/apple/mod.rs#L2732-L2852
pub const MAP_SHARED: c_int = 0x0001;
pub const MAP_ANON: c_int = 0x1000;
pub const MAP_FAILED: *mut c_void = !0 as *mut c_void;

/// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/linux_like/mod.rs#L552-L554
pub const PROT_READ: c_int = 1;
pub const PROT_WRITE: c_int = 2;
pub const PROT_EXEC: c_int = 4;

/// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/bsd/apple/mod.rs#L3697
pub const _SC_PAGESIZE: c_int = 29;

/// https://github.com/danburkert/memmap-rs/blob/3b047cc2b04558d8a1de3933be5f573c74bc8e0f/src/unix.rs#L30-L67
pub fn safe_mmap_anonymous(len: size_t, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> Result<*mut c_void> {
    let alignment = offset % page_size() as u64;
    let aligned_offset = offset - alignment;
    let aligned_len = len + alignment as usize;

    unsafe {
        let ptr = mmap(ptr::null_mut(), aligned_len as size_t, prot, flags, fd, aligned_offset as off_t);

        if ptr == MAP_FAILED {
            Err(Error::last_os_error())
        } else {
            Ok(ptr.offset(alignment as isize))
        }
    }
}

/// https://github.com/danburkert/memmap-rs/blob/3b047cc2b04558d8a1de3933be5f573c74bc8e0f/src/unix.rs#L152-L163
pub fn safe_mprotect(addr: *mut c_void, len: size_t, prot: c_int) -> Result<()> {
    unsafe {
        let alignment = addr as usize % page_size();
        let pointer = addr.offset(-(alignment as isize));
        let length = len.wrapping_add(alignment);

        if mprotect(pointer, length, prot) == 0 {
            Ok(())
        } else {
            Err(Error::last_os_error())
        }
    }
}

/// https://github.com/danburkert/memmap-rs/blob/3b047cc2b04558d8a1de3933be5f573c74bc8e0f/src/unix.rs#L212-L214
pub fn page_size() -> usize {
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

extern "C" {
    /// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/mod.rs#L1317
    fn mmap(addr: *mut c_void, len: size_t, prot: c_int, flags: c_int, fd: c_int, offset: off_t) -> *mut c_void;

    /// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/linux_like/linux/mod.rs#L3449
    fn mprotect(addr: *mut c_void, len: size_t, prot: c_int) -> c_int;

    /// https://github.com/rust-lang/libc/blob/1068fee1011e08cd4a3bcf1c3e54af3f8339c372/src/unix/mod.rs#L1317
    fn sysconf(name: c_int) -> c_long;
}
