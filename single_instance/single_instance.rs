//! A rust library for single instance application.
//!
//! single-instance provides a single API to check if there are any other running instance.
//!
//! ## Detail
//! On linux init will bind abstract unix domain socket with given name . On macos, init will create or open a file which path is given `&str`,
//! then call `flock` to apply an advisory lock on the open file.
//!
//! ### Examples
//! ```rust
//! extern crate single_instance;
//!
//! use std::thread;
//! use single_instance::SingleInstance;
//!
//! fn main() {
//!     let instance = SingleInstance::new("whatever").unwrap();
//!     assert!(instance.is_single());
//! }
//! ```

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[cfg(any(target_os = "linux", target_os="android"))]
    #[error("new abstract addr error")]
    Nix(#[from] nix::Error),

    #[cfg(target_os = "macos")]
    #[error("file open or create error")]
    Io(#[from] std::io::Error),
}


// #[cfg(target_os = "macos")]
// extern crate libc;
// #[cfg(any(target_os = "linux", target_os ="android"))]
// extern crate nix;
// extern crate thiserror;
// #[cfg(target_os = "windows")]
// extern crate widestring;
// #[cfg(target_os = "windows")]
// extern crate winapi;

pub use self::inner::*;

#[cfg(any(target_os = "linux", target_os="android"))]
mod inner {
    use super::Error;
    use nix::sys::socket::{self, UnixAddr};
    use nix::unistd;
    use std::os::unix::prelude::RawFd;

    /// A struct representing one running instance.
    pub struct SingleInstance {
        maybe_sock: Option<RawFd>,
    }

    impl SingleInstance {
        /// Returns a new SingleInstance object.
        pub fn new(name: &str) -> Result<Self, Error> {
            let addr = UnixAddr::new_abstract(name.as_bytes())?;
            let sock = socket::socket(
                socket::AddressFamily::Unix,
                socket::SockType::Stream,
                // If we fork and exec, then make sure the child process doesn't
                // hang on to this file descriptor.
                socket::SockFlag::SOCK_CLOEXEC,
                None,
            )?;

            let maybe_sock = match socket::bind(sock, &socket::SockAddr::Unix(addr)) {
                Ok(()) => Some(sock),
                Err(nix::errno::Errno::EADDRINUSE) => None,
                Err(e) => return Err(e.into()),
            };

            Ok(Self { maybe_sock })
        }

        /// Returns whether this instance is single.
        pub fn is_single(&self) -> bool {
            self.maybe_sock.is_some()
        }
    }

    impl Drop for SingleInstance {
        fn drop(&mut self) {
            if let Some(sock) = self.maybe_sock {
                // Intentionally discard any close errors.
                let _ = unistd::close(sock);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod inner {
    use super::Error;
    use libc::{__error, flock, EWOULDBLOCK, LOCK_EX, LOCK_NB};
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;

    /// A struct representing one running instance.
    pub struct SingleInstance {
        _file: File,
        is_single: bool,
    }

    impl SingleInstance {
        /// Returns a new SingleInstance object.
        pub fn new(name: &str) -> Result<Self, Error> {
            let path = Path::new(name);
            let file = if path.exists() {
                File::open(path)?
            } else {
                File::create(path)?
            };
            unsafe {
                let rc = flock(file.as_raw_fd(), LOCK_EX | LOCK_NB);
                let is_single = rc == 0 || EWOULDBLOCK != *__error();
                Ok(Self {
                    _file: file,
                    is_single,
                })
            }
        }

        /// Returns whether this instance is single.
        pub fn is_single(&self) -> bool {
            self.is_single
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static UNIQ_ID : &'static str   = "aa2d0258-ffe9-11e7-ba89-0ed5f89f718b";
    #[test]
    fn test_single_instance() {
        {
            let instance_a = SingleInstance::new(UNIQ_ID).unwrap();
            assert!(instance_a.is_single());
            let instance_b = SingleInstance::new(UNIQ_ID).unwrap();
            assert!(!instance_b.is_single());
        }
        let instance_c = SingleInstance::new(UNIQ_ID).unwrap();
        assert!(instance_c.is_single());
    }
}
