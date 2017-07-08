extern crate libc;

use std::{io, ptr};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::ffi::CString;

use ::Protection;

impl Protection {

    /// Returns the `Protection` value as a POSIX protection flag.
    fn as_prot(self) -> libc::c_int {
        match self {
            Protection::Read => libc::PROT_READ,
            Protection::ReadWrite => libc::PROT_READ | libc::PROT_WRITE,
            Protection::ReadCopy => libc::PROT_READ | libc::PROT_WRITE,
            Protection::ReadExecute => libc::PROT_READ | libc::PROT_EXEC,
        }
    }

    fn as_flag(self) -> libc::c_int {
        match self {
            Protection::Read => libc::MAP_SHARED,
            Protection::ReadWrite => libc::MAP_SHARED,
            Protection::ReadCopy => libc::MAP_PRIVATE,
            Protection::ReadExecute => libc::MAP_SHARED,
        }
    }

    fn as_mode(self) -> libc::mode_t {
        match self {
            Protection::Read => 0o400,
            Protection::ReadWrite => 0o600,
            Protection::ReadCopy => 0o600,
            Protection::ReadExecute => 0o500,
        }
    }
}

#[cfg(any(all(target_os = "linux", not(target_arch="mips")),
          target_os = "freebsd",
          target_os = "android"))]
const MAP_STACK: libc::c_int = libc::MAP_STACK;

#[cfg(not(any(all(target_os = "linux", not(target_arch="mips")),
              target_os = "freebsd",
              target_os = "android")))]
const MAP_STACK: libc::c_int = 0;

pub struct MmapInner {
    ptr: *mut libc::c_void,
    len: usize,
    shm: Option<(libc::c_int, String)>,
}

impl MmapInner {

    pub fn open(file: &File, prot: Protection, offset: usize, len: usize) -> io::Result<MmapInner> {
        let alignment = offset % page_size();
        let aligned_offset = offset - alignment;
        let aligned_len = len + alignment;
        if aligned_len == 0 {
            // Normally the OS would catch this, but it segfaults under QEMU.
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                      "memory map must have a non-zero length"));
        }

        unsafe {
            let ptr = libc::mmap(ptr::null_mut(),
                                 aligned_len as libc::size_t,
                                 prot.as_prot(),
                                 prot.as_flag(),
                                 file.as_raw_fd(),
                                 aligned_offset as libc::off_t);

            if ptr == libc::MAP_FAILED {
                Err(io::Error::last_os_error())
            } else {
                Ok(MmapInner {
                    ptr: ptr.offset(alignment as isize),
                    len: len,
                    shm: None,
                })
            }
        }
    }

    fn stack_as_flag(stack: bool) -> libc::c_int {
        let mut flag = 0;
        if stack { flag |= MAP_STACK }
        flag
    }

    /// Open an anonymous memory map.
    pub fn anonymous(len: usize, prot: Protection, stack: bool) -> io::Result<MmapInner> {
        let ptr = unsafe {
            libc::mmap(ptr::null_mut(),
                       len as libc::size_t,
                       prot.as_prot(),
                       prot.as_flag() | libc::MAP_ANON | MmapInner::stack_as_flag(stack),
                       -1,
                       0)
        };

        if ptr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(MmapInner {
                ptr: ptr,
                len: len as usize,
                shm: None,
            })
        }
    }

    pub fn paged(len: usize, prot: Protection, name: &str, exclusive: bool) -> io::Result<MmapInner> {
        // Adds a forward slash to work with the shm_open in POSIX systems.
        let name = format!("/{}", name);

        // Create a shared memory object. By default this will create a new object if the specified
        // name does not already exist.
        let fd = unsafe {
            libc::shm_open(CString::new(name.clone()).unwrap()).as_ptr(),
                           libc::O_CREAT
                           | if let Protection::Read = prot { libc::O_RDONLY } else { libc::O_RDWR }
                           | if exclusive { libc::O_EXCL } else { 0 },
                           prot.as_mode())
        };

        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        // Truncate shared memory object to specified size.
        unsafe { libc::ftruncate(fd, len as libc::off_t) };

        let ptr = unsafe {
            libc::mmap(ptr::null_mut(),
                       len as libc::size_t,
                       prot.as_prot(),
                       prot.as_flag(),
                       fd,
                       0)
        };

        if ptr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(MmapInner {
                ptr: ptr,
                len: len as usize,
                shm: Some((fd, name)),
            })
        }
    }

    pub fn flush(&self, offset: usize, len: usize) -> io::Result<()> {
        let alignment = (self.ptr as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = len + alignment;
        let result = unsafe { libc::msync(self.ptr.offset(offset),
                                          len as libc::size_t,
                                          libc::MS_SYNC) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn flush_async(&self, offset: usize, len: usize) -> io::Result<()> {
        let alignment = offset % page_size();
        let aligned_offset = offset - alignment;
        let aligned_len = len + alignment;
        let result = unsafe { libc::msync(self.ptr.offset(aligned_offset as isize),
                                          aligned_len as libc::size_t,
                                          libc::MS_ASYNC) };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn set_protection(&mut self, prot: Protection) -> io::Result<()> {
        unsafe {
            let alignment = self.ptr as usize % page_size();
            let ptr = self.ptr.offset(- (alignment as isize));
            let len = self.len + alignment;
            let result = libc::mprotect(ptr,
                                        len,
                                        prot.as_prot());
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    pub fn ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.ptr as *mut u8
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl Drop for MmapInner {
    fn drop(&mut self) {
        let alignment = self.ptr as usize % page_size();
        unsafe {
            assert!(libc::munmap(self.ptr.offset(- (alignment as isize)),
                                 (self.len + alignment) as libc::size_t) == 0,
                    "unable to unmap mmap: {}", io::Error::last_os_error());
            
            // If there's an attached shared memory.
            if let Some(ref shm) = self.shm {
                // Close the file descriptor
                assert!(libc::close(shm.0) == 0,
                        "unabled to close shm fd: {}", io::Error::last_os_error());
                
                // Unlink shared memory object.
                let unlink = libc::shm_unlink(CString::new(shm.1.clone()).unwrap().as_ptr()) == 0;
                let enoent = io::Error::last_os_error().raw_os_error().unwrap() == libc::ENOENT;

                // Asserts that either the unlink was successful or ther ewas no object with the
                // associated name, meaning a matching named mMap was destroyed earlier.
                assert!(unlink || enoent,
                        "unabled to unlink shm object: {}", io::Error::last_os_error());
            }
        }
    }
}

unsafe impl Sync for MmapInner { }
unsafe impl Send for MmapInner { }

fn page_size() -> usize {
    unsafe {
        libc::sysconf(libc::_SC_PAGESIZE) as usize
    }
}
