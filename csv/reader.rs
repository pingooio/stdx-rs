#[cfg(feature = "serde")]
use alloc::collections::BTreeMap;
#[cfg(feature = "serde")]
use alloc::sync::Arc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use crate::error::{ReadError, ReadErrorKind};

/// Custom read abstraction that allows `Reader` to work without `std::io::Read`.
///
/// This trait is automatically implemented for `&[u8]` and, when the `std`
/// feature is enabled, for any `std::io::Read` type.
pub trait Read {
    /// Read data into `buf`, appending to its contents.
    ///
    /// Returns `Ok(true)` if more data *may* be available (caller should try
    /// again), or `Ok(false)` to signal end-of-input.
    fn read(&mut self, buf: &mut Vec<u8>) -> Result<bool, ReadError>;
}

#[cfg(not(feature = "std"))]
impl Read for &[u8] {
    fn read(&mut self, buf: &mut Vec<u8>) -> Result<bool, ReadError> {
        let chunk = 16384;
        let to_copy = chunk.min(self.len());
        if to_copy == 0 {
            return Ok(false);
        }
        buf.extend_from_slice(&self[..to_copy]);
        *self = &self[to_copy..];
        Ok(true)
    }
}

#[cfg(feature = "std")]
impl<R: std::io::Read> Read for R {
    fn read(&mut self, buf: &mut Vec<u8>) -> Result<bool, ReadError> {
        let mut tmp = [0u8; 16384];
        let n = std::io::Read::read(self, &mut tmp)?;
        if n == 0 {
            return Ok(false);
        }
        buf.extend_from_slice(&tmp[..n]);
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    StartOfField,
    InUnquoted,
    InQuoted,
    AfterQuote,
}

#[derive(Clone, Copy, Debug)]
enum Src {
    Buf,
    Scratch,
}

#[derive(Clone, Copy, Debug)]
struct RawField {
    start: usize,
    end: usize,
    src: Src,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FieldRange {
    pub start: usize,
    pub end: usize,
}

pub struct Reader<R: Read> {
    /// Raw input data read from source.
    buf: Vec<u8>,
    /// Temporary storage for quoted field content (unescaped).
    scratch: Vec<u8>,
    /// Field ranges into `buf` or `scratch` for the current row.
    ranges: Vec<RawField>,
    /// Start of unconsumed data in `buf`.
    start: usize,
    /// End of valid data in `buf`.
    end: usize,
    /// Current line number (1-based).
    line: usize,
    /// Start of current unquoted field within `buf`.
    field_start: usize,
    /// Start of current quoted field within `scratch`.
    scratch_field_start: usize,
    /// Current parser state machine position.
    state: State,
    /// Field delimiter byte (default `,`).
    delimiter: u8,
    /// If true, rows may have varying field counts.
    flexible: bool,
    /// Expected field count per row, inferred from the first data row.
    num_fields: Option<usize>,
    /// Running max row-byte-length, used to pre-size the next row buffer.
    row_size_hint: usize,
    /// True once `parse_headers` or `set_headers` has been called.
    headers_parsed: bool,
    /// A bare `\r` was the last byte of the previous buffer; next `\n` should be skipped.
    pending_cr: bool,
    /// Column names, populated by `parse_headers` or `set_headers`.
    headers: Vec<String>,
    #[cfg(feature = "serde")]
    /// Map from header name -> column index for serde field lookup.
    header_map: Option<Arc<BTreeMap<String, usize>>>,
    /// The underlying data source.
    source: R,
    /// True when the source has signalled end-of-input.
    eof: bool,
}

// ── Common methods (always available) ─────────────────────────────────

impl<R: Read> Reader<R> {
    /// Creates a new `Reader` from any [`Read`] source.
    ///
    /// This works with `&[u8]`, `std::io::Cursor`, `std::fs::File`, etc.
    pub fn new(source: R) -> Self {
        Reader {
            buf: Vec::with_capacity(65536),
            scratch: Vec::new(),
            ranges: Vec::new(),
            start: 0,
            end: 0,
            line: 1,
            field_start: 0,
            scratch_field_start: 0,
            state: State::StartOfField,
            delimiter: b',',
            flexible: false,
            num_fields: None,
            row_size_hint: 0,
            headers_parsed: false,
            pending_cr: false,
            headers: Vec::new(),
            #[cfg(feature = "serde")]
            header_map: None,
            source,
            eof: false,
        }
    }

    /// Sets the field delimiter byte (default is `,`).
    pub fn set_delimiter(&mut self, byte: u8) -> &mut Self {
        self.delimiter = byte;
        self
    }

    /// Sets whether variable field counts are allowed (default is `false`).
    pub fn set_flexible(&mut self, yes: bool) -> &mut Self {
        self.flexible = yes;
        self
    }

    /// Sets the column names for header-based serde deserialization.
    ///
    /// Calling this marks headers as parsed so `reader.headers()` returns `Some`.
    pub fn set_headers(&mut self, headers: Vec<String>) -> &mut Self {
        self.headers_parsed = true;
        self.headers = headers;
        #[cfg(feature = "serde")]
        {
            let map: BTreeMap<String, usize> = self
                .headers
                .iter()
                .enumerate()
                .map(|(i, name)| (name.clone(), i))
                .collect();
            self.header_map = Some(Arc::new(map));
        }
        self
    }

    /// Returns `Some(&[String])` if headers were parsed or set, `None` otherwise.
    pub fn headers(&self) -> Option<&[String]> {
        if self.headers_parsed { Some(&self.headers) } else { None }
    }

    /// Parses the first row as column headers and stores them internally.
    ///
    /// Returns the header strings as a slice. Returns an empty slice if the CSV is empty.
    /// After calling this, `reader.headers()` returns `Some(...)` and serde
    /// deserialization matches struct fields by name.
    pub fn parse_headers(&mut self) -> Result<&[String], ReadError> {
        let row = match self.read_row() {
            Some(row) => row,
            None => return Ok(&[]),
        };
        let headers: Vec<String> = row.to_vec()?.iter().map(|s| s.to_string()).collect();
        self.headers_parsed = true;
        self.num_fields = Some(headers.len());
        self.headers = headers;
        #[cfg(feature = "serde")]
        {
            let map: BTreeMap<String, usize> = self
                .headers
                .iter()
                .enumerate()
                .map(|(i, name)| (name.clone(), i))
                .collect();
            self.header_map = Some(Arc::new(map));
        }
        Ok(&self.headers)
    }

    /// Returns an iterator over `Row` values (validated as UTF-8).
    pub fn rows(&mut self) -> Rows<'_, R> {
        Rows {
            reader: self,
        }
    }

    /// Returns an iterator over `BytesRow` values (no UTF-8 validation).
    pub fn rows_bytes(&mut self) -> BytesRows<'_, R> {
        BytesRows {
            reader: self,
        }
    }

    /// Reads more data from the source into `buf`, updating `self.end`.
    ///
    /// Returns `Ok(true)` if new data was loaded, `Ok(false)` at EOF, or `Err` on I/O error.
    /// Once EOF is reached, subsequent calls return `Ok(false)` without re-reading.
    fn fill_buf(&mut self) -> Result<bool, ReadError> {
        if self.eof {
            return Ok(false);
        }
        if self.source.read(&mut self.buf)? {
            self.end = self.buf.len();
            Ok(true)
        } else {
            self.eof = true;
            Ok(false)
        }
    }

    /// Parses one CSV row from the input, or returns `None` at EOF.
    ///
    /// The row's fields are assembled into an owned `Row`. Errors (I/O,
    /// unterminated quotes, trailing content, inconsistent field counts)
    /// are stored on the `Row` and deferred until access.
    fn read_row(&mut self) -> Option<Row> {
        self.compact();
        self.ranges.clear();
        self.scratch.clear();
        self.state = State::StartOfField;

        loop {
            if self.start >= self.end {
                match self.fill_buf() {
                    Err(e) => {
                        self.eof = true;
                        return match self.state {
                            State::InQuoted => Some(self.build_row(Some(e))),
                            _ => {
                                self.finalize_current_field();
                                Some(self.build_row(Some(e)))
                            }
                        };
                    }
                    Ok(false) => {
                        if self.ranges.is_empty() && self.state == State::StartOfField {
                            return None;
                        }
                        return match self.state {
                            State::InQuoted => Some(self.build_row(Some(ReadError::new(
                                ReadErrorKind::UnterminatedQuote,
                                self.line,
                                0,
                            )))),
                            _ => {
                                self.finalize_current_field();
                                Some(self.build_row(None))
                            }
                        };
                    }
                    Ok(true) => {}
                }
            }

            if self.pending_cr {
                if self.buf[self.start] == b'\n' {
                    self.start += 1;
                }
                self.pending_cr = false;
                continue;
            }

            let byte = self.buf[self.start];

            match self.state {
                State::StartOfField => {
                    if byte == b'\r' || byte == b'\n' {
                        if !self.ranges.is_empty() {
                            self.ranges.push(RawField {
                                start: self.start,
                                end: self.start,
                                src: Src::Buf,
                            });
                        }
                        self.consume_newline();
                        if self.ranges.is_empty() {
                            continue;
                        }
                        return Some(self.build_row(None));
                    }
                    self.field_start = self.start;
                    if byte == self.delimiter {
                        self.ranges.push(RawField {
                            start: self.start,
                            end: self.start,
                            src: Src::Buf,
                        });
                        self.start += 1;
                        continue;
                    }
                    if byte == b'"' {
                        self.scratch_field_start = self.scratch.len();
                        self.start += 1;
                        self.state = State::InQuoted;
                    } else {
                        self.start += 1;
                        self.state = State::InUnquoted;
                    }
                }

                State::InUnquoted => {
                    let haystack = &self.buf[self.start..self.end];
                    match memchr::memchr3(self.delimiter, b'\r', b'\n', haystack) {
                        Some(offset) => {
                            let pos = self.start + offset;
                            self.ranges.push(RawField {
                                start: self.field_start,
                                end: pos,
                                src: Src::Buf,
                            });
                            let b = self.buf[pos];
                            if b == self.delimiter {
                                self.start = pos + 1;
                                self.state = State::StartOfField;
                            } else {
                                self.start = pos;
                                self.consume_newline();
                                return Some(self.build_row(None));
                            }
                        }
                        None => {
                            self.start = self.end;
                        }
                    }
                }

                State::InQuoted => {
                    let haystack = &self.buf[self.start..self.end];
                    match memchr::memchr(b'"', haystack) {
                        Some(offset) => {
                            let quote_pos = self.start + offset;
                            self.scratch.extend_from_slice(&self.buf[self.start..quote_pos]);
                            let after_quote = quote_pos + 1;
                            if after_quote < self.end && self.buf[after_quote] == b'"' {
                                self.scratch.push(b'"');
                                self.start = after_quote + 1;
                            } else if after_quote < self.end {
                                self.ranges.push(RawField {
                                    start: self.scratch_field_start,
                                    end: self.scratch.len(),
                                    src: Src::Scratch,
                                });
                                self.start = after_quote;
                                self.state = State::AfterQuote;
                            } else {
                                match self.fill_buf() {
                                    Ok(true) if self.buf[after_quote] == b'"' => {
                                        self.scratch.push(b'"');
                                        self.start = after_quote + 1;
                                    }
                                    Err(e) => {
                                        self.ranges.push(RawField {
                                            start: self.scratch_field_start,
                                            end: self.scratch.len(),
                                            src: Src::Scratch,
                                        });
                                        self.start = after_quote;
                                        self.state = State::AfterQuote;
                                        return Some(self.build_row(Some(e)));
                                    }
                                    _ => {
                                        self.ranges.push(RawField {
                                            start: self.scratch_field_start,
                                            end: self.scratch.len(),
                                            src: Src::Scratch,
                                        });
                                        self.start = after_quote;
                                        self.state = State::AfterQuote;
                                    }
                                }
                            }
                        }
                        None => {
                            self.scratch.extend_from_slice(&self.buf[self.start..self.end]);
                            self.start = self.end;
                        }
                    }
                }

                State::AfterQuote => {
                    if byte == self.delimiter {
                        self.start += 1;
                        self.state = State::StartOfField;
                    } else if is_newline(byte) {
                        self.consume_newline();
                        return Some(self.build_row(None));
                    } else {
                        return Some(self.build_row(Some(ReadError::new(
                            ReadErrorKind::TrailingContent,
                            self.line,
                            0,
                        ))));
                    }
                }
            }
        }
    }

    /// Moves unconsumed data to the front of `buf` and truncates.
    fn compact(&mut self) {
        if self.start > 0 {
            let remaining = self.end - self.start;
            if remaining > 0 {
                self.buf.copy_within(self.start..self.end, 0);
            }
            self.buf.truncate(remaining);
            self.end = remaining;
            self.start = 0;
        }
    }

    /// Consumes a `\r\n`, `\n`, or `\r` line ending, incrementing the line counter.
    ///
    /// If a bare `\r` is at the end of the buffer, sets `pending_cr` so the
    /// following `\n` is skipped on the next read.
    fn consume_newline(&mut self) {
        if self.start < self.end && self.buf[self.start] == b'\r' {
            self.start += 1;
            if self.start >= self.end {
                self.pending_cr = true;
            }
        }
        if self.start < self.end && self.buf[self.start] == b'\n' {
            self.start += 1;
        }
        self.line += 1;
    }

    /// Pushes a `RawField` entry for the current unquoted or empty field.
    ///
    /// Does nothing in the `AfterQuote` state (field already recorded).
    /// Panics (unreachable) if called in the `InQuoted` state.
    fn finalize_current_field(&mut self) {
        match self.state {
            State::InUnquoted => {
                self.ranges.push(RawField {
                    start: self.field_start,
                    end: self.start,
                    src: Src::Buf,
                });
            }
            State::AfterQuote => {}
            State::StartOfField => {
                if !self.ranges.is_empty() {
                    self.ranges.push(RawField {
                        start: self.start,
                        end: self.start,
                        src: Src::Buf,
                    });
                }
            }
            State::InQuoted => unreachable!(),
        }
    }

    /// Wraps the bytes row into a `Row`, attaching the header map if available.
    fn build_row(&mut self, error: Option<ReadError>) -> Row {
        let bytes_row = self.build_bytes_row(error);
        Row {
            inner: bytes_row,
            #[cfg(feature = "serde")]
            header_map: self.header_map.clone(),
        }
    }

    /// Assembles the parsed fields into an owned `BytesRow`, checking field-count consistency.
    fn build_bytes_row(&mut self, error: Option<ReadError>) -> BytesRow {
        let mut total: usize = 0;
        for r in &self.ranges {
            total += r.end - r.start;
        }

        let row_buf_capacity = if total > 0 { total } else { self.row_size_hint.max(64) };
        let mut row_buf = Vec::with_capacity(row_buf_capacity);
        let mut row_ranges = Vec::with_capacity(self.num_fields.unwrap_or(self.ranges.len()));

        for r in &self.ranges {
            let slice = match r.src {
                Src::Buf => &self.buf[r.start..r.end],
                Src::Scratch => &self.scratch[r.start..r.end],
            };
            let start = row_buf.len();
            row_buf.extend_from_slice(slice);
            let end = row_buf.len();
            row_ranges.push(FieldRange {
                start,
                end,
            });
        }

        let field_count = row_ranges.len();

        let error = if !self.flexible {
            error.or_else(|| match self.num_fields {
                Some(expected) if field_count != expected => Some(ReadError::new(
                    ReadErrorKind::InconsistentFieldCount {
                        expected,
                        found: field_count,
                    },
                    self.line,
                    0,
                )),
                _ => None,
            })
        } else {
            error
        };

        if self.num_fields.is_none() && field_count > 0 {
            self.num_fields = Some(field_count);
        }

        if row_buf.len() > self.row_size_hint {
            self.row_size_hint = row_buf.len();
        }

        BytesRow {
            buf: row_buf,
            ranges: row_ranges,
            error,
            line: self.line,
        }
    }
}

fn is_newline(b: u8) -> bool {
    b == b'\n' || b == b'\r'
}

// ── BytesRow ──────────────────────────────────────────────────────────

pub struct BytesRow {
    pub(crate) buf: Vec<u8>,
    pub(crate) ranges: Vec<FieldRange>,
    pub(crate) error: Option<ReadError>,
    line: usize,
}

impl BytesRow {
    pub fn error(&self) -> Option<&ReadError> {
        self.error.as_ref()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&[u8]> {
        self.ranges.get(index).map(|r| &self.buf[r.start..r.end])
    }

    pub fn to_vec(&self) -> Result<Vec<&[u8]>, ReadError> {
        if let Some(ref e) = self.error {
            return Err(e.clone());
        }
        Ok(self.ranges.iter().map(|r| &self.buf[r.start..r.end]).collect())
    }

    pub fn iter(&self) -> BytesFields<'_> {
        BytesFields {
            buf: &self.buf,
            iter: self.ranges.iter(),
        }
    }
}

impl fmt::Debug for BytesRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error {
            Some(e) => write!(f, "BytesRow(Err({e}))"),
            None => f
                .debug_list()
                .entries(self.ranges.iter().map(|r| &self.buf[r.start..r.end]))
                .finish(),
        }
    }
}

pub struct BytesFields<'a> {
    buf: &'a [u8],
    iter: core::slice::Iter<'a, FieldRange>,
}

impl<'a> Iterator for BytesFields<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        let r = self.iter.next()?;
        Some(&self.buf[r.start..r.end])
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for BytesFields<'a> {}

// ── Row ───────────────────────────────────────────────────────────────

pub struct Row {
    pub(crate) inner: BytesRow,
    #[cfg(feature = "serde")]
    pub(crate) header_map: Option<Arc<BTreeMap<String, usize>>>,
}

impl Row {
    pub fn error(&self) -> Option<&ReadError> {
        self.inner.error()
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<Result<&str, ReadError>> {
        self.inner.get(index).map(|bytes| {
            core::str::from_utf8(bytes).map_err(|_| ReadError::new(ReadErrorKind::InvalidUtf8, self.inner.line, 0))
        })
    }

    pub fn to_vec(&self) -> Result<Vec<&str>, ReadError> {
        if let Some(ref e) = self.inner.error {
            return Err(e.clone());
        }
        self.inner
            .ranges
            .iter()
            .map(|r| {
                core::str::from_utf8(&self.inner.buf[r.start..r.end])
                    .map_err(|_| ReadError::new(ReadErrorKind::InvalidUtf8, self.inner.line, 0))
            })
            .collect()
    }

    pub fn iter(&self) -> Fields<'_> {
        Fields {
            buf: &self.inner.buf,
            iter: self.inner.ranges.iter(),
            error: self.inner.error.as_ref().map(|e| &e.kind),
            line: self.inner.line,
        }
    }
}

impl fmt::Debug for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner.error {
            Some(e) => write!(f, "Row(Err({e}))"),
            None => {
                f.debug_list()
                    .entries(
                        self.inner.ranges.iter().map(|r| {
                            core::str::from_utf8(&self.inner.buf[r.start..r.end]).unwrap_or("<invalid utf-8>")
                        }),
                    )
                    .finish()
            }
        }
    }
}

pub struct Fields<'a> {
    buf: &'a [u8],
    iter: core::slice::Iter<'a, FieldRange>,
    error: Option<&'a ReadErrorKind>,
    line: usize,
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<&'a str, ReadError>;
    fn next(&mut self) -> Option<Self::Item> {
        let r = self.iter.next()?;
        if let Some(kind) = self.error {
            return Some(Err(ReadError::new(kind.clone(), self.line, 0)));
        }
        Some(
            core::str::from_utf8(&self.buf[r.start..r.end])
                .map_err(|_| ReadError::new(ReadErrorKind::InvalidUtf8, self.line, 0)),
        )
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for Fields<'a> {}

// ── Iterators ─────────────────────────────────────────────────────────

pub struct BytesRows<'r, R: Read> {
    reader: &'r mut Reader<R>,
}

impl<'r, R: Read> Iterator for BytesRows<'r, R> {
    type Item = BytesRow;
    fn next(&mut self) -> Option<Self::Item> {
        self.reader.read_row().map(|r| r.inner)
    }
}

pub struct Rows<'r, R: Read> {
    reader: &'r mut Reader<R>,
}

impl<'r, R: Read> Iterator for Rows<'r, R> {
    type Item = Row;
    fn next(&mut self) -> Option<Self::Item> {
        self.reader.read_row()
    }
}
