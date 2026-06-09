use core::fmt;

/// Kinds of errors that can occur when reading CSV data.
#[derive(Debug)]
pub enum ReadErrorKind {
    /// A quoted field was opened but never closed before end of input.
    UnterminatedQuote,
    /// Non-delimiter, non-newline content appeared after a closing quote.
    TrailingContent,
    /// An I/O error from the underlying read source.
    #[cfg(feature = "std")]
    Io(std::io::Error),
    /// The CSV data contains invalid UTF-8.
    InvalidUtf8,
}

impl fmt::Display for ReadErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadErrorKind::UnterminatedQuote => f.write_str("unterminated quote"),
            ReadErrorKind::TrailingContent => f.write_str("trailing content after closing quote"),
            ReadErrorKind::InvalidUtf8 => f.write_str("invalid UTF-8 in CSV data"),
            #[cfg(feature = "std")]
            ReadErrorKind::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

/// Errors that can occur when reading CSV data.
pub struct ReadError {
    kind: ReadErrorKind,
    /// 1-indexed line number
    pub line: usize,
    /// 1-indexed byte offset within the line
    pub column: usize,
}

impl ReadError {
    pub(crate) fn new(kind: ReadErrorKind, line: usize, column: usize) -> Self {
        ReadError {
            kind,
            line,
            column,
        }
    }

    /// Returns a reference to the [`ReadErrorKind`] of this error.
    pub fn kind(&self) -> &ReadErrorKind {
        &self.kind
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ReadErrorKind::UnterminatedQuote => {
                write!(f, "unterminated quote at line {}, column {}", self.line, self.column)
            }
            ReadErrorKind::TrailingContent => {
                write!(
                    f,
                    "trailing content after closing quote at line {}, column {}",
                    self.line, self.column
                )
            }
            ReadErrorKind::InvalidUtf8 => {
                write!(f, "invalid UTF-8 at line {}", self.line)
            }
            #[cfg(feature = "std")]
            ReadErrorKind::Io(e) => write!(f, "I/O error at line {}, column {}: {}", self.line, self.column, e),
        }
    }
}

impl fmt::Debug for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReadError({})", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ReadErrorKind::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        ReadError::new(ReadErrorKind::Io(e), 0, 0)
    }
}

/// Errors that can occur when writing CSV data.
#[derive(Debug)]
pub enum WriteError {
    /// The records have inconsistent field counts.
    InconsistentFieldCount {
        /// Number of fields expected.
        expected: usize,
        /// Number of fields found in the offending record.
        found: usize,
        /// The 1-indexed record number where the mismatch occurred.
        row: usize,
    },
    /// An I/O error from the underlying writer.
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::InconsistentFieldCount {
                expected,
                found,
                row,
            } => {
                write!(f, "expected {expected} fields, found {found} fields at row {row}")
            }
            #[cfg(feature = "std")]
            WriteError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WriteError::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for WriteError {
    fn from(e: std::io::Error) -> Self {
        WriteError::Io(e)
    }
}
