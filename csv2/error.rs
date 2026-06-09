use core::fmt;

/// Kinds of errors that can occur while reading CSV data.
#[derive(Clone, Debug, PartialEq)]
pub enum ReadErrorKind {
    /// A quoted field was opened but never closed before end of input.
    UnterminatedQuote,
    /// Characters appeared after a closing quote before a delimiter or newline.
    TrailingContent,
    /// An I/O error occurred while reading the underlying source.
    Io,
}

/// An error returned when parsing a CSV row.
///
/// Includes the line number and the kind of error.
#[derive(Clone, Debug)]
pub struct ReadError {
    pub kind: ReadErrorKind,
    pub line: usize,
    pub column: usize,
}

impl ReadError {
    pub fn new(kind: ReadErrorKind, line: usize, column: usize) -> Self {
        ReadError {
            kind,
            line,
            column,
        }
    }

    pub fn kind(&self) -> &ReadErrorKind {
        &self.kind
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ReadErrorKind::UnterminatedQuote => {
                write!(f, "unterminated quote at line {}, column {}", self.line, self.column)
            }
            ReadErrorKind::TrailingContent => {
                write!(
                    f,
                    "trailing content after quoted field at line {}, column {}",
                    self.line, self.column
                )
            }
            ReadErrorKind::Io => {
                write!(f, "I/O error at line {}, column {}", self.line, self.column)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReadError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for ReadError {
    fn from(_e: std::io::Error) -> Self {
        ReadError {
            kind: ReadErrorKind::Io,
            line: 0,
            column: 0,
        }
    }
}

/// An error returned when writing CSV data.
#[derive(Debug)]
pub enum WriteError {
    /// The number of fields in a row differs from previous rows.
    InconsistentFieldCount { expected: usize, found: usize, row: usize },
    /// An I/O error occurred while writing.
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
                write!(f, "expected {expected} fields, found {found} in row {row}")
            }
            #[cfg(feature = "std")]
            WriteError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WriteError {}

#[cfg(feature = "std")]
impl From<std::io::Error> for WriteError {
    fn from(e: std::io::Error) -> Self {
        WriteError::Io(e)
    }
}
