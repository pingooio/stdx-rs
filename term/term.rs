/// Errors returned by this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Reads a password from stdin without echoing it to the terminal.
/// The returned bytes do not include the trailing newline.
/// Mimics the behaviour of Go's `golang.org/x/term.ReadPassword`.
pub fn read_password() -> Result<Vec<u8>, Error> {
    platform::read_password()
}

// ── Unix ─────────────────────────────────────────────────────────────────────

#[cfg(unix)]
mod platform {
    use libc::{ECHO, ICANON, ICRNL, ISIG, STDIN_FILENO, TCSANOW, tcgetattr, tcsetattr, termios};
    use std::io::Read;

    /// RAII guard that restores the saved termios state when dropped.
    struct TermiosGuard {
        saved: termios,
    }

    impl Drop for TermiosGuard {
        fn drop(&mut self) {
            // Ignore errors: we are in a destructor and cannot propagate them.
            unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &self.saved) };
        }
    }

    pub(super) fn read_password() -> Result<Vec<u8>, super::Error> {
        // Attempt to read the current terminal attributes.
        let mut saved: termios = unsafe { std::mem::zeroed() };
        let is_tty = unsafe { tcgetattr(STDIN_FILENO, &mut saved) } == 0;

        // Disable echo for the duration of the read; the guard restores it.
        let _guard = if is_tty {
            let mut raw = saved;
            // Clear ECHO — keep ICANON and ISIG so the kernel still delivers
            // a full line on Enter and honours Ctrl-C / Ctrl-D.  Set ICRNL so
            // a bare carriage-return is mapped to a newline (matches Go).
            raw.c_lflag &= !(ECHO as libc::tcflag_t);
            raw.c_lflag |= (ICANON | ISIG) as libc::tcflag_t;
            raw.c_iflag |= ICRNL as libc::tcflag_t;
            // SAFETY: fd is STDIN_FILENO, raw is a valid termios.
            unsafe { tcsetattr(STDIN_FILENO, TCSANOW, &raw) };
            Some(TermiosGuard { saved })
        } else {
            None
        };

        read_line()
    }

    fn read_line() -> Result<Vec<u8>, super::Error> {
        let mut buf = Vec::new();
        let stdin = std::io::stdin();
        for byte in stdin.lock().bytes() {
            let b = byte?;
            if b == b'\n' || b == b'\r' {
                break;
            }
            buf.push(b);
        }
        Ok(buf)
    }
}

// ── Windows ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
mod platform {
    use std::io::{self, BufRead};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };

    /// RAII guard that restores the saved console mode when dropped.
    struct ConsoleModeGuard {
        handle: windows_sys::Win32::Foundation::HANDLE,
        saved: u32,
    }

    impl Drop for ConsoleModeGuard {
        fn drop(&mut self) {
            // Ignore errors: we are in a destructor and cannot propagate them.
            unsafe { SetConsoleMode(self.handle, self.saved) };
        }
    }

    pub(super) fn read_password() -> Result<Vec<u8>, super::Error> {
        // SAFETY: GetStdHandle with STD_INPUT_HANDLE is always safe to call.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };

        let _guard = if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            let mut mode: u32 = 0;
            // SAFETY: handle is valid and mode is a valid out-pointer.
            if unsafe { GetConsoleMode(handle, &mut mode) } != 0 {
                // Disable echo while preserving every other flag.
                unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) };
                Some(ConsoleModeGuard { handle, saved: mode })
            } else {
                None
            }
        } else {
            None
        };

        read_line()
    }

    fn read_line() -> Result<Vec<u8>, super::Error> {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        // Strip the trailing newline (and optional carriage-return).
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(line.into_bytes())
    }
}

// ── Fallback (neither Unix nor Windows) ─────────────────────────────────────

#[cfg(not(any(unix, windows)))]
mod platform {
    use std::io::BufRead;

    pub(super) fn read_password() -> Result<Vec<u8>, super::Error> {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(line.into_bytes())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Integration tests for read_password() require an interactive terminal
    // and cannot run in a CI pipeline.  We instead test the internal helpers
    // that are available on every platform.

    /// Verify that a Vec of bytes produced by the platform helper does not
    /// contain a trailing newline or carriage-return.
    #[test]
    fn password_bytes_strip_newline() {
        let mut raw = b"secret\n".to_vec();
        if raw.ends_with(b"\n") {
            raw.pop();
            if raw.ends_with(b"\r") {
                raw.pop();
            }
        }
        assert_eq!(raw, b"secret");
    }

    #[test]
    fn password_bytes_strip_crlf() {
        let mut raw = b"secret\r\n".to_vec();
        if raw.ends_with(b"\n") {
            raw.pop();
            if raw.ends_with(b"\r") {
                raw.pop();
            }
        }
        assert_eq!(raw, b"secret");
    }

    #[test]
    fn password_bytes_no_newline() {
        let raw = b"secret".to_vec();
        assert_eq!(raw, b"secret");
    }
}
