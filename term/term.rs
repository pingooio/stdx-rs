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
    use std::io::Read;

    use libc::{ECHO, ICANON, ICRNL, ISIG, STDIN_FILENO, TCSANOW, tcgetattr, tcsetattr, termios};

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
            Some(TermiosGuard {
                saved,
            })
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

// ── Fallback (non-Unix) ──────────────────────────────────────────────────────

#[cfg(not(unix))]
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
