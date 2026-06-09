#[cfg(feature = "serde")]
use alloc::collections::BTreeMap;
#[cfg(feature = "serde")]
use alloc::rc::Rc;
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

pub struct Reader<R> {
    buf: Vec<u8>,
    scratch: Vec<u8>,
    ranges: Vec<RawField>,
    start: usize,
    end: usize,
    line: usize,
    field_start: usize,
    scratch_field_start: usize,
    state: State,
    delimiter: u8,
    flexible: bool,
    num_fields: Option<usize>,
    row_size_hint: usize,
    headers_parsed: bool,
    pending_cr: bool,
    headers: Vec<String>,
    #[cfg(feature = "serde")]
    header_map: Option<Rc<BTreeMap<String, usize>>>,
    source: R,
    eof: bool,
}

// ── Common methods (always available) ─────────────────────────────────

impl<R> Reader<R> {
    pub fn set_delimiter(&mut self, byte: u8) -> &mut Self {
        self.delimiter = byte;
        self
    }

    pub fn set_flexible(&mut self, yes: bool) -> &mut Self {
        self.flexible = yes;
        self
    }

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
            self.header_map = Some(Rc::new(map));
        }
        self
    }

    pub fn headers(&self) -> Option<&[String]> {
        if self.headers_parsed { Some(&self.headers) } else { None }
    }

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

    fn consume_newline(&mut self) {
        if self.start < self.end && self.buf[self.start] == b'\r' {
            self.start += 1;
        }
        if self.start < self.end && self.buf[self.start] == b'\n' {
            self.start += 1;
        } else if self.start > 0 && self.start >= self.end && self.buf[self.start - 1] == b'\r' {
            self.pending_cr = true;
        }
        self.line += 1;
    }

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

    fn build_bytes_row(&mut self, error: Option<ReadError>) -> BytesRow {
        let mut total: usize = 0;
        for r in &self.ranges {
            total += r.end - r.start;
        }

        let cap = if total > 0 { total } else { self.row_size_hint.max(64) };
        let mut row_buf = Vec::with_capacity(cap);
        let mut row_ranges = Vec::with_capacity(self.ranges.len());

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
        }
    }

    fn build_row(&mut self, error: Option<ReadError>) -> Row {
        let bytes_row = self.build_bytes_row(error);
        Row {
            inner: bytes_row,
            #[cfg(feature = "serde")]
            header_map: self.header_map.clone(),
        }
    }
}

fn is_newline(b: u8) -> bool {
    b == b'\n' || b == b'\r'
}

// ── Generic Reader (any Read source) ──────────────────────

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

            if self.pending_cr && self.buf[self.start] == b'\n' {
                self.start += 1;
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
                            } else if self.fill_buf().ok().unwrap_or(false) && self.buf[after_quote] == b'"' {
                                self.scratch.push(b'"');
                                self.start = after_quote + 1;
                            } else {
                                self.ranges.push(RawField {
                                    start: self.scratch_field_start,
                                    end: self.scratch.len(),
                                    src: Src::Scratch,
                                });
                                self.start = after_quote;
                                self.state = State::AfterQuote;
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

    pub fn parse_headers(&mut self) -> Result<Vec<String>, ReadError> {
        self.headers_parsed = true;
        let row = match self.read_row() {
            Some(row) => row,
            None => return Ok(Vec::new()),
        };
        let h: Vec<String> = row.to_vec()?.iter().map(|s| s.to_string()).collect();
        self.headers = h.clone();
        #[cfg(feature = "serde")]
        {
            let map: BTreeMap<String, usize> = h.iter().enumerate().map(|(i, name)| (name.clone(), i)).collect();
            self.header_map = Some(Rc::new(map));
        }
        Ok(h)
    }

    pub fn rows(&mut self) -> Rows<'_, R> {
        Rows {
            reader: self,
        }
    }
    pub fn rows_bytes(&mut self) -> BytesRows<'_, R> {
        BytesRows {
            reader: self,
        }
    }
}

// ── BytesRow ──────────────────────────────────────────────────────────

pub struct BytesRow {
    buf: Vec<u8>,
    ranges: Vec<FieldRange>,
    error: Option<ReadError>,
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
    pub(crate) header_map: Option<Rc<BTreeMap<String, usize>>>,
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
        self.inner
            .get(index)
            .map(|bytes| core::str::from_utf8(bytes).map_err(|_| ReadError::new(ReadErrorKind::InvalidUtf8, 0, 0)))
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
                    .map_err(|_| ReadError::new(ReadErrorKind::InvalidUtf8, 0, 0))
            })
            .collect()
    }

    pub fn iter(&self) -> Fields<'_> {
        Fields {
            buf: &self.inner.buf,
            iter: self.inner.ranges.iter(),
            error: self.inner.error.is_some(),
        }
    }
}

impl fmt::Debug for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner.error {
            Some(e) => write!(f, "Row(Err({e}))"),
            None => f
                .debug_list()
                .entries(
                    self.inner
                        .ranges
                        .iter()
                        .map(|r| unsafe { core::str::from_utf8_unchecked(&self.inner.buf[r.start..r.end]) }),
                )
                .finish(),
        }
    }
}

pub struct Fields<'a> {
    buf: &'a [u8],
    iter: core::slice::Iter<'a, FieldRange>,
    error: bool,
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<&'a str, ReadError>;
    fn next(&mut self) -> Option<Self::Item> {
        let r = self.iter.next()?;
        if self.error {
            return Some(Err(ReadError::new(ReadErrorKind::Io, 0, 0)));
        }
        Some(
            core::str::from_utf8(&self.buf[r.start..r.end])
                .map_err(|_| ReadError::new(ReadErrorKind::InvalidUtf8, 0, 0)),
        )
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for Fields<'a> {}

// ── Iterators ─────────────────────────────────────────────────────────

pub struct BytesRows<'r, R> {
    reader: &'r mut Reader<R>,
}

impl<'r, R: Read> Iterator for BytesRows<'r, R> {
    type Item = BytesRow;
    fn next(&mut self) -> Option<Self::Item> {
        self.reader.read_row().map(|r| r.inner)
    }
}

pub struct Rows<'r, R> {
    reader: &'r mut Reader<R>,
}

impl<'r, R: Read> Iterator for Rows<'r, R> {
    type Item = Row;
    fn next(&mut self) -> Option<Self::Item> {
        self.reader.read_row()
    }
}
