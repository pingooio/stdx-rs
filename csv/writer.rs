use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use crate::error::WriteError;

/// Custom write abstraction that allows `Writer` to work without `std::io::Write`.
///
/// This trait is automatically implemented for `Vec<u8>` and, when the `std`
/// feature is enabled, for any `std::io::Write` type.
pub trait Write {
    /// Write all bytes in `buf` to the sink.
    ///
    /// Returns `Err` if the write could not be completed.
    fn write(&mut self, buf: &[u8]) -> Result<(), WriteError>;
    /// Flush any buffered data to the underlying sink.
    fn flush(&mut self) -> Result<(), WriteError>;
}

#[cfg(not(feature = "std"))]
impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        self.extend_from_slice(buf);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), WriteError> {
        Ok(())
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write> Write for W {
    fn write(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        self.write_all(buf)?;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), WriteError> {
        self.flush()?;
        Ok(())
    }
}

/// Writes CSV data to a [`Write`] sink.
///
/// Fields containing the delimiter, a newline, or a double-quote are
/// automatically quoted. `""` escape sequences are used for quotes
/// within quoted fields.
///
/// Internal buffering is used to avoid many small writes. Callers should
/// not wrap the writer in a `BufWriter`.
///
/// # Example
///
/// ```no_run
/// use csv::Writer;
///
/// let mut w = Writer::new(Vec::new());
/// w.write_row(["name", "age", "city"])?;
/// w.write_row(["Alice", "30", "New York, NY"])?;
/// let result = String::from_utf8(w.into_inner()?).unwrap();
/// assert_eq!(result, "name,age,city\r\nAlice,30,\"New York, NY\"\r\n");
/// # Ok::<_, csv::WriteError>(())
/// ```
pub struct Writer<W: Write> {
    pub(crate) writer: Option<W>,
    pub(crate) delimiter: u8,
    pub(crate) flexible: bool,
    pub(crate) num_fields: Option<usize>,
    pub(crate) row_count: usize,
    pub(crate) buf: Vec<u8>,
    pub(crate) headers: Option<Vec<String>>,
    pub(crate) headers_written: bool,
    #[cfg(feature = "serde")]
    pub(crate) ser_values: Vec<Option<Vec<u8>>>,
    #[cfg(feature = "serde")]
    pub(crate) ser_capture_buf: Vec<u8>,
}

impl<W: Write> Writer<W> {
    /// Create a new writer wrapping the given output sink.
    ///
    /// The writer starts with default comma delimiter and strict
    /// field-count validation (all rows must have the same number of fields).
    pub fn new(writer: W) -> Self {
        Writer {
            writer: Some(writer),
            delimiter: b',',
            flexible: false,
            num_fields: None,
            row_count: 0,
            buf: Vec::with_capacity(8192),
            headers: None,
            headers_written: false,
            #[cfg(feature = "serde")]
            ser_values: Vec::new(),
            #[cfg(feature = "serde")]
            ser_capture_buf: Vec::new(),
        }
    }

    /// Set the field delimiter byte (default is `,`).
    ///
    /// ```no_run
    /// use csv::Writer;
    /// let mut w = Writer::new(Vec::new()).set_delimiter(b'\t');
    /// w.write_row(["a", "b", "c"])?;
    /// # Ok::<_, csv::WriteError>(())
    /// ```
    pub fn set_delimiter(mut self, byte: u8) -> Self {
        self.delimiter = byte;
        self
    }

    /// Set whether variable field counts are allowed (default is `false`).
    ///
    /// When `false` (strict), all rows must have the same number of fields.
    /// When `true`, rows may vary in field count.
    pub fn set_flexible(mut self, yes: bool) -> Self {
        self.flexible = yes;
        self
    }

    /// Store column names for schema awareness.
    ///
    /// This sets the expected header names for future serde support and strict
    /// field-count validation. It does **not** write anything to the output.
    /// Use [`write_headers`](Self::write_headers) to emit the header row.
    pub fn set_headers(mut self, headers: Vec<String>) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Returns the stored header names, if any.
    pub fn headers(&self) -> Option<&[String]> {
        self.headers.as_deref()
    }

    /// Write a header row to the output and store the column names internally.
    ///
    /// The header row is written as a single CSV line. The field count from
    /// this row becomes the expected count for all subsequent rows (unless
    /// flexible mode is enabled).
    ///
    /// If this method has already been called, subsequent calls return
    /// [`WriteError::HeadersAlreadyWritten`].
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::HeadersAlreadyWritten`] if headers have already
    /// been written. Returns [`WriteError::InconsistentFieldCount`] if the
    /// number of headers differs from a prior [`write_row`](Self::write_row)
    /// or from headers stored via [`set_headers`](Self::set_headers).
    /// Returns [`WriteError::Io`] if the underlying writer fails.
    pub fn write_headers<I, T>(&mut self, headers: I) -> Result<(), WriteError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        if self.headers_written {
            return Err(WriteError::HeadersAlreadyWritten);
        }

        let strings: Vec<String> = headers.into_iter().map(|s| s.as_ref().to_string()).collect();
        let count = strings.len();

        for (i, s) in strings.iter().enumerate() {
            if i > 0 {
                self.buf.push(self.delimiter);
            }
            self.write_field(s.as_bytes())?;
        }

        self.buf.extend_from_slice(b"\r\n");
        self.row_count += 1;
        self.headers = Some(strings);
        self.headers_written = true;
        self.num_fields = Some(count);

        if self.buf.len() >= 8192 {
            self.flush()?;
        }

        Ok(())
    }

    /// Write a single row.
    ///
    /// Each element in the iterator is written as a CSV field. Fields are
    /// auto-quoted if they contain the delimiter, a newline (`\n` or `\r`),
    /// or a double-quote (`"`).
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::InconsistentFieldCount`] if the number of
    /// fields differs from previous rows (unless flexible mode is enabled).
    /// Returns [`WriteError::Io`] if the underlying writer fails.
    pub fn write_row<I, T>(&mut self, row: I) -> Result<(), WriteError>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        if self.flexible {
            let mut first = true;
            let mut field_count = 0;
            for field in row {
                if !first {
                    self.buf.push(self.delimiter);
                }
                first = false;
                self.write_field(field.as_ref())?;
                field_count += 1;
            }
            if self.num_fields.is_none() && field_count > 0 {
                self.num_fields = Some(field_count);
            }
            self.buf.extend_from_slice(b"\r\n");
            self.row_count += 1;
        } else {
            let buf_start = self.buf.len();
            let mut field_count = 0;
            for (i, field) in row.into_iter().enumerate() {
                if i > 0 {
                    self.buf.push(self.delimiter);
                }
                self.write_field(field.as_ref())?;
                field_count += 1;
            }

            match self.num_fields {
                Some(expected) if field_count != expected => {
                    self.buf.truncate(buf_start);
                    return Err(WriteError::InconsistentFieldCount {
                        expected,
                        found: field_count,
                        row: self.row_count + 1,
                    });
                }
                None => {
                    self.num_fields = Some(field_count);
                }
                _ => {}
            }

            self.buf.extend_from_slice(b"\r\n");
            self.row_count += 1;
        }

        if self.buf.len() >= 8192 {
            self.flush()?;
        }

        Ok(())
    }

    fn write_field(&mut self, field: &[u8]) -> Result<(), WriteError> {
        write_csv_field(&mut self.buf, self.delimiter, field);
        Ok(())
    }

    /// Flush the internal buffer to the underlying writer.
    pub fn flush(&mut self) -> Result<(), WriteError> {
        if let Some(writer) = self.writer.as_mut() {
            Write::write(writer, &self.buf)?;
            Write::flush(writer)?;
        }
        self.buf.clear();
        Ok(())
    }

    /// Flush any remaining data and return
    /// the underlying writer.
    pub fn into_inner(mut self) -> Result<W, WriteError> {
        self.flush()?;
        Ok(self.writer.take().unwrap())
    }
}

impl<W: Write> Drop for Writer<W> {
    fn drop(&mut self) {
        if self.writer.is_some() {
            let _ = self.flush();
        }
    }
}

/// Write a single CSV field to `buf`, applying quoting as needed.
///
/// Writes directly into `buf` to avoid intermediate buffering.
pub(crate) fn write_csv_field(buf: &mut Vec<u8>, delimiter: u8, field: &[u8]) {
    let needs_quoting = field.is_empty()
        || memchr::memchr3(delimiter, b'\r', b'\n', field).is_some()
        || memchr::memchr(b'"', field).is_some();

    if !needs_quoting {
        buf.extend_from_slice(field);
        return;
    }

    buf.push(b'"');

    let mut pos = 0;
    while let Some(quote_offset) = memchr::memchr(b'"', &field[pos..]) {
        let abs_pos = pos + quote_offset;
        buf.extend_from_slice(&field[pos..abs_pos]);
        buf.extend_from_slice(b"\"\"");
        pos = abs_pos + 1;
    }
    buf.extend_from_slice(&field[pos..]);
    buf.push(b'"');
}
