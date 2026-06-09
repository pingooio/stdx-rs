use std::io::Write;

use crate::error::WriteError;

/// Writes CSV data to a `std::io::Write` sink.
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
/// use csv2::Writer;
///
/// let mut w = Writer::new(Vec::new());
/// w.write_row(["name", "age", "city"])?;
/// w.write_row(["Alice", "30", "New York, NY"])?;
/// let result = String::from_utf8(w.into_inner()?).unwrap();
/// assert_eq!(result, "name,age,city\r\nAlice,30,\"New York, NY\"\r\n");
/// # Ok::<_, csv2::WriteError>(())
/// ```
pub struct Writer<W: Write> {
    writer: Option<W>,
    delimiter: u8,
    flexible: bool,
    num_fields: Option<usize>,
    row_count: usize,
    buf: Vec<u8>,
    field_buf: Vec<u8>,
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
            field_buf: Vec::new(),
        }
    }

    /// Set the field delimiter byte (default is `,`).
    ///
    /// ```no_run
    /// use csv2::Writer;
    /// let mut w = Writer::new(Vec::new());
    /// w.delimiter(b'\t');
    /// w.write_row(["a", "b", "c"])?;
    /// # Ok::<_, csv2::WriteError>(())
    /// ```
    pub fn delimiter(&mut self, byte: u8) -> &mut Self {
        self.delimiter = byte;
        self
    }

    /// Enable or disable the field count consistency check.
    ///
    /// When `false` (default), all rows must have the same number of fields.
    /// When `true`, rows are allowed to vary in width.
    pub fn flexible(&mut self, yes: bool) -> &mut Self {
        self.flexible = yes;
        self
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
        let mut field_count = 0;

        for field_bytes in row {
            if field_count > 0 {
                self.buf.push(self.delimiter);
            }
            self.write_field(field_bytes.as_ref())?;
            field_count += 1;
        }

        self.buf.extend_from_slice(b"\r\n");
        self.row_count += 1;

        match self.num_fields {
            Some(expected) if !self.flexible && field_count != expected => {
                return Err(WriteError::InconsistentFieldCount {
                    expected,
                    found: field_count,
                    row: self.row_count,
                });
            }
            None => {
                self.num_fields = Some(field_count);
            }
            _ => {}
        }

        if self.buf.len() >= 8192 {
            self.flush()?;
        }

        Ok(())
    }

    fn write_field(&mut self, field: &[u8]) -> Result<(), WriteError> {
        let needs_quoting = field.is_empty()
            || field.contains(&self.delimiter)
            || field.contains(&b'\n')
            || field.contains(&b'\r')
            || field.contains(&b'"');

        if !needs_quoting {
            self.buf.extend_from_slice(field);
            return Ok(());
        }

        self.buf.push(b'"');
        self.field_buf.clear();

        for &byte in field {
            if byte == b'"' {
                self.field_buf.push(b'"');
                self.field_buf.push(b'"');
            } else {
                self.field_buf.push(byte);
            }
        }

        self.buf.extend_from_slice(&self.field_buf);
        self.buf.push(b'"');

        Ok(())
    }

    /// Flush the internal buffer to the underlying writer.
    pub fn flush(&mut self) -> Result<(), WriteError> {
        if let Some(writer) = self.writer.as_mut() {
            writer.write_all(&self.buf)?;
        }
        self.buf.clear();
        Ok(())
    }

    /// Unwrap the writer, flushing any remaining data and returning
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
