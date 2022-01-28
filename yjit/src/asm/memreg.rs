/// The function of this module is to wrap the memory region where we're going
/// to write out our assembly instructions, as well as the common operations
/// we're going to perform on it (e.g., mmap and mprotect).

use core::ffi::c_void;
use core::ops::{Deref, DerefMut};
use std::io::{Error, ErrorKind, Result};
use std::slice;

use crate::asm::libc;

/// Represents the region in memory where we're going to write out our assembly
/// instructions.
pub struct MemoryRegion {
    /// The memory that has already been mmap-ed.
    region: *mut u8,

    /// The size of the memory region.
    length: usize
}

impl MemoryRegion {
    /// Instantiate a new MemoryRegion struct by mmap-ing a region of memory of
    /// the given size.
    pub fn new(length: usize) -> Result<Self> {
        let region = libc::safe_mmap_anonymous(
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0
        )?;

        Ok(MemoryRegion { region: region as *mut u8, length })
    }

    /// Gets a raw pointer from the memory region at the given offset.
    pub fn get_raw_ptr(&self, offset: usize) -> Result<*mut u8> {
        if offset < self.length {
            Ok(unsafe { self.as_ptr().offset(offset as isize) } as *mut u8)
        } else {
            Err(Error::new(ErrorKind::Other, "Attempting to protect a position outside the memory region"))
        }
    }

    /// Call mprotect on the allocated memory region at the given position with
    /// the PROT_READ and PROT_WRITE flags.
    pub fn mark_writable(&self, offset: usize, length: usize) -> Result<()> {
        self.mark_prot(offset, length, libc::PROT_READ | libc::PROT_WRITE)
    }

    /// Call mprotect on the allocated memory region at the given position with
    /// the PROT_READ and PROT_EXEC flags.
    pub fn mark_executable(&self, offset: usize, length: usize) -> Result<()> {
        self.mark_prot(offset, length, libc::PROT_READ | libc::PROT_EXEC)
    }

    /// Call out to the external mprotect function with the given flags at the
    /// given offset.
    #[inline]
    fn mark_prot(&self, offset: usize, length: usize, prot: i32) -> Result<()> {
        libc::safe_mprotect(
            self.get_raw_ptr(offset)? as *mut c_void,
            length,
            prot
        )
    }
}

impl Deref for MemoryRegion {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.region, self.length) }
    }
}

impl DerefMut for MemoryRegion {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.region, self.length) }
    }
}

impl AsRef<[u8]> for MemoryRegion {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deref() {
        let mut region = MemoryRegion::new(64).unwrap();
        region[0] = 7;

        assert_eq!(7, region[0]);
    }

    #[test]
    fn get_raw_ptr_inside() {
        let region = MemoryRegion::new(64).unwrap();
        let result = region.get_raw_ptr(32);

        assert!(matches!(result, Ok(_)));
    }

    #[test]
    fn get_raw_ptr_outside() {
        let region = MemoryRegion::new(64).unwrap();
        let result = region.get_raw_ptr(65);

        assert!(matches!(result, Err(_)));
    }

    #[test]
    fn mark_writable() {
        let region = MemoryRegion::new(64).unwrap();
        let result = region.mark_writable(0, 64);

        assert!(matches!(result, Ok(_)));
    }

    #[test]
    fn mark_executable() {
        let region = MemoryRegion::new(64).unwrap();
        let result = region.mark_executable(0, 64);

        assert!(matches!(result, Ok(_)));
    }
}
