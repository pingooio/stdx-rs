use alloc::vec::Vec;
use core::{fmt, marker::PhantomData, str};
#[cfg(feature = "serde")]
use std::collections::HashMap;

use crate::error::{ReadError, ReadErrorKind};

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    StartOfField,
    InUnquoted,
    InQuoted,
    AfterQuote,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Src {
    Buf,
    Scratch,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FieldRange {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) src: Src,
}

/// Reads CSV data from a `std::io::Read` source.
///
/// Rows are yielded by calling [`rows`], which returns an iterator
/// of `Row<'_>`. Errors are deferred to the [`Row`] methods.
///
/// # Example
///
/// ```no_run
/// use csv2::Reader;
/// use std::fs::File;
///
/// let mut reader = Reader::from_reader(File::open("data.csv")?);
/// for row in reader.rows() {
///     for field in row.fields()? {
///     }
/// }
/// # Ok::<_, csv2::ReadError>(())
/// ```
///
/// # Headers
///
/// Use [`parse_headers`] to read the first row as column headers.
///
/// [`rows`]: Reader::rows
/// [`parse_headers`]: Reader::parse_headers
pub struct Reader<R> {
    pub(crate) buf: Vec<u8>,
    pub(crate) scratch: Vec<u8>,
    pub(crate) ranges: Vec<FieldRange>,
    start: usize,
    end: usize,
    line: usize,
    field_start: usize,
    scratch_field_start: usize,
    state: State,
    delimiter: u8,
    headers_parsed: bool,
    pub(crate) headers: Vec<String>,
    #[cfg(feature = "serde")]
    pub(crate) header_map: Option<HashMap<String, usize>>,
    source: R,
    eof: bool,
}

impl<R> Reader<R> {
    /// Set the field delimiter byte (default is `,`).
    pub fn set_delimiter(&mut self, byte: u8) -> &mut Self {
        self.delimiter = byte;
        self
    }

    /// Return the column headers, if [`parse_headers`] was called.
    ///
    /// [`parse_headers`]: Reader::parse_headers
    pub fn headers(&self) -> Option<&[String]> {
        if self.headers_parsed { Some(&self.headers) } else { None }
    }
}

fn is_newline(b: u8) -> bool {
    b == b'\n' || b == b'\r'
}

impl<R: std::io::Read> Reader<R> {
    /// Create a reader from any `std::io::Read` source.
    ///
    /// Data is streamed in chunks as rows are parsed, without loading
    /// the entire input into memory.
    pub fn from_reader(source: R) -> Self {
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
            headers_parsed: false,
            headers: Vec::new(),
            #[cfg(feature = "serde")]
            header_map: None,
            source,
            eof: false,
        }
    }

    /// Read and return the first row as column headers.
    ///
    /// Must be called before iterating with [`rows`]. The parsed headers
    /// are stored internally and used by [`Row::deserialize`] for
    /// header-based field mapping.
    pub fn parse_headers(&mut self) -> Result<Vec<String>, ReadError> {
        self.headers_parsed = true;
        let row = match self.read_row() {
            Some(row) => row,
            None => return Ok(Vec::new()),
        };
        let h: Vec<String> = row.fields()?.map(|s| s.to_string()).collect();
        self.headers = h.clone();
        #[cfg(feature = "serde")]
        {
            self.header_map = Some(h.iter().enumerate().map(|(i, name)| (name.clone(), i)).collect());
        }
        Ok(h)
    }

    /// Return an iterator over the remaining rows.
    ///
    /// If [`parse_headers`] was called, iteration starts after the header
    /// row. Otherwise, it starts from the first row.
    ///
    /// ```no_run
    /// use csv2::Reader;
    /// let mut reader = Reader::from_reader(std::io::Cursor::new(b"a,b\n1,2\n"));
    /// for row in reader.rows() {
    ///     for field in row.fields()? {
    ///     }
    /// }
    /// # Ok::<_, csv2::ReadError>(())
    /// ```
    pub fn rows(&mut self) -> Rows<'_, R> {
        Rows {
            reader: self,
            _marker: PhantomData,
        }
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

    fn fill_buf(&mut self) -> Result<bool, ReadError> {
        if self.eof {
            return Ok(false);
        }
        let mut tmp = [0u8; 16384];
        let n = self.source.read(&mut tmp)?;
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        self.buf.extend_from_slice(&tmp[..n]);
        self.end = self.buf.len();
        Ok(true)
    }

    fn consume_newline(&mut self) {
        if self.start < self.end && self.buf[self.start] == b'\r' {
            self.start += 1;
        }
        if self.start < self.end && self.buf[self.start] == b'\n' {
            self.start += 1;
        }
        self.line += 1;
    }

    fn read_row<'s>(&'s mut self) -> Option<Row<'s>> {
        self.compact();
        self.ranges.clear();
        self.scratch.clear();
        self.state = State::StartOfField;

        loop {
            if self.start >= self.end && !self.fill_buf().ok()? {
                if self.ranges.is_empty() && self.state == State::StartOfField {
                    return None;
                }
                return match self.state {
                    State::InQuoted => {
                        Some(self.build_row_with(Some(ReadError::new(ReadErrorKind::UnterminatedQuote, self.line, 0))))
                    }
                    _ => {
                        self.finalize_current_field();
                        Some(self.build_row_with(None))
                    }
                };
            }

            let byte = self.buf[self.start];

            match self.state {
                State::StartOfField => {
                    if byte == b'\r' || byte == b'\n' {
                        if !self.ranges.is_empty() {
                            self.ranges.push(FieldRange {
                                start: self.start,
                                end: self.start,
                                src: Src::Buf,
                            });
                        }
                        self.consume_newline();
                        if self.ranges.is_empty() {
                            continue;
                        }
                        return Some(self.build_row_with(None));
                    }
                    self.field_start = self.start;
                    if byte == self.delimiter {
                        self.ranges.push(FieldRange {
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
                            self.ranges.push(FieldRange {
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
                                return Some(self.build_row_with(None));
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
                            } else {
                                self.ranges.push(FieldRange {
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
                        return Some(self.build_row_with(None));
                    } else {
                        return Some(self.build_row_with(Some(ReadError::new(
                            ReadErrorKind::TrailingContent,
                            self.line,
                            0,
                        ))));
                    }
                }
            }
        }
    }

    fn finalize_current_field(&mut self) {
        match self.state {
            State::InUnquoted => {
                self.ranges.push(FieldRange {
                    start: self.field_start,
                    end: self.start,
                    src: Src::Buf,
                });
            }
            State::AfterQuote => {}
            State::StartOfField => {
                if !self.ranges.is_empty() {
                    self.ranges.push(FieldRange {
                        start: self.start,
                        end: self.start,
                        src: Src::Buf,
                    });
                }
            }
            State::InQuoted => unreachable!(),
        }
    }

    fn build_row_with(&self, error: Option<ReadError>) -> Row<'_> {
        Row {
            buf: &self.buf[..self.end],
            scratch: &self.scratch,
            ranges: &self.ranges,
            error,
            #[cfg(feature = "serde")]
            header_map: self.header_map.as_ref(),
        }
    }
}

/// A single row of CSV data.
///
/// Borrows from the `Reader` that produced it and cannot outlive it.
/// Fields are already unescaped: surrounding quotes are stripped and
/// `""` escape sequences are resolved to `"`.
///
/// Errors from parsing are stored in the [`Row`] and returned when
/// accessing fields via [`fields`] or [`all`].
///
/// [`fields`]: Row::fields
/// [`all`]: Row::all
pub struct Row<'a> {
    buf: &'a [u8],
    scratch: &'a [u8],
    ranges: &'a [FieldRange],
    error: Option<ReadError>,
    #[cfg(feature = "serde")]
    pub(crate) header_map: Option<&'a HashMap<String, usize>>,
}

impl Row<'_> {
    /// Return the parse error, if any.
    pub fn error(&self) -> Option<&ReadError> {
        self.error.as_ref()
    }

    /// Number of fields in this row (0 on error).
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Returns `true` if the row has no fields.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Iterate over all fields as `&str`, zero allocation.
    ///
    /// Returns an error if this row was the result of a parse failure.
    ///
    /// ```no_run
    /// use csv2::Reader;
    /// let mut reader = Reader::from_reader(std::io::Cursor::new(b"\"hello\",world\n"));
    /// for row in reader.rows() {
    ///     for field in row.fields()? {
    ///     }
    /// }
    /// # Ok::<_, csv2::ReadError>(())
    /// ```
    pub fn fields(&self) -> Result<Fields<'_>, ReadError> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        Ok(Fields {
            buf: self.buf,
            scratch: self.scratch,
            iter: self.ranges.iter(),
        })
    }

    /// Collect all fields into owned `String`s.
    ///
    /// Returns an error if this row was the result of a parse failure.
    pub fn all(&self) -> Result<Vec<String>, ReadError> {
        Ok(self.fields()?.map(|f| f.to_string()).collect())
    }
}

impl<'a> fmt::Debug for Row<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error {
            Some(e) => write!(f, "Row(Err({e}))"),
            None => f
                .debug_list()
                .entries(self.ranges.iter().map(|r| {
                    let slice = match r.src {
                        Src::Buf => &self.buf[r.start..r.end],
                        Src::Scratch => &self.scratch[r.start..r.end],
                    };
                    unsafe { str::from_utf8_unchecked(slice) }
                }))
                .finish(),
        }
    }
}

/// A zero-allocation iterator over the fields of a [`Row`].
///
/// Yields `&str` for each field. Created by [`Row::fields`].
pub struct Fields<'a> {
    buf: &'a [u8],
    scratch: &'a [u8],
    iter: core::slice::Iter<'a, FieldRange>,
}

impl<'a> Iterator for Fields<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let r = self.iter.next()?;
        let slice = match r.src {
            Src::Buf => &self.buf[r.start..r.end],
            Src::Scratch => &self.scratch[r.start..r.end],
        };
        Some(unsafe { str::from_utf8_unchecked(slice) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for Fields<'a> {}

/// An iterator over the rows of a CSV source.
///
/// Created by [`Reader::rows`]. Each item is a [`Row<'_>`](Row) with
/// errors deferred to its methods.
///
/// ```no_run
/// use csv2::Reader;
/// let mut reader = Reader::from_reader(std::io::Cursor::new(b"a,b\n1,2\n"));
/// for row in reader.rows() {
///     let fields = row.all()?;
/// }
/// # Ok::<_, csv2::ReadError>(())
/// ```
pub struct Rows<'r, R> {
    reader: *mut Reader<R>,
    _marker: PhantomData<&'r mut Reader<R>>,
}

impl<'r, R: std::io::Read> Iterator for Rows<'r, R> {
    type Item = Row<'r>;

    fn next(&mut self) -> Option<Self::Item> {
        let reader = unsafe { &mut *self.reader };
        match reader.read_row() {
            Some(row) => Some(unsafe { core::mem::transmute::<Row<'_>, Row<'r>>(row) }),
            None => None,
        }
    }
}
