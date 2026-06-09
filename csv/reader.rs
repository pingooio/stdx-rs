use alloc::{
    borrow::Cow,
    string::{String, ToString},
    vec::Vec,
};
use core::{ops::Index, str};

use crate::error::{ReadError, ReadErrorKind};

#[derive(Copy, Clone, Debug)]
struct FieldRange {
    start: usize,
    end: usize,
    quoted: bool,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum State {
    StartOfField,
    InUnquoted,
    InQuoted,
    AfterQuote,
}

/// Parses CSV data from a byte slice or a `std::io::Read` source.
///
/// Create an iterator over rows with [`Reader::rows`]:
///
/// ```no_run
/// # use csv::Reader;
/// let data = b"name,age\nAlice,30\nBob,25\n";
/// for row in Reader::new(data).rows() {
///     let row = row?;
///     // ...
/// }
/// # Ok::<_, csv::ReadError>(())
/// ```
pub struct Reader {
    buf: Vec<u8>,
    pos: usize,
    field_ranges: Vec<FieldRange>,
    field_start: usize,
    field_start_column: usize,
    state: State,
    line: usize,
    column: usize,
    delimiter: u8,
    flexible: bool,
    eof: bool,

    #[cfg(feature = "std")]
    source: Option<Box<dyn std::io::Read>>,
}

impl Reader {
    /// Create a reader from a byte slice. The data is copied into
    /// an internal buffer. This constructor is available with or
    /// without the `std` feature.
    pub fn new(data: &[u8]) -> Self {
        Reader {
            buf: data.to_vec(),
            pos: 0,
            field_ranges: Vec::new(),
            field_start: 0,
            field_start_column: 1,
            state: State::StartOfField,
            line: 1,
            column: 1,
            delimiter: b',',
            flexible: false,
            eof: true,
            #[cfg(feature = "std")]
            source: None,
        }
    }

    /// Set the field delimiter byte (default is `,`).
    pub fn set_delimiter(&mut self, byte: u8) -> &mut Self {
        self.delimiter = byte;
        self
    }

    /// Allow variable numbers of fields per row (default `false`).
    pub fn set_flexible(&mut self, yes: bool) -> &mut Self {
        self.flexible = yes;
        self
    }

    /// Read all rows from this CSV source.
    ///
    /// Consumes the reader and returns an iterator yielding
    /// [`Result<Row, ReadError>`].
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use csv::Reader;
    /// let data = b"a,b,c\n1,2,3\n";
    /// let mut total = 0usize;
    /// for row in Reader::new(data).rows() {
    ///     total += row?.len();
    /// }
    /// assert_eq!(total, 6);
    /// # Ok::<_, csv::ReadError>(())
    /// ```
    pub fn rows(self) -> Rows {
        Rows {
            reader: self,
        }
    }

    fn read_row(&mut self) -> Result<Option<Row>, ReadError> {
        self.field_ranges.clear();
        self.state = State::StartOfField;

        loop {
            if self.pos >= self.buf.len() && !self.fill_buf()? {
                return if self.field_ranges.is_empty() && self.state == State::StartOfField {
                    Ok(None)
                } else {
                    if self.state == State::InQuoted {
                        return Err(ReadError::new(
                            ReadErrorKind::UnterminatedQuote,
                            self.line,
                            self.column_at(self.field_start),
                        ));
                    }
                    match self.state {
                        State::InUnquoted => {
                            self.field_ranges.push(FieldRange {
                                start: self.field_start,
                                end: self.pos,
                                quoted: false,
                            });
                        }
                        State::AfterQuote => {
                            self.field_ranges.push(FieldRange {
                                start: self.field_start,
                                end: self.pos,
                                quoted: true,
                            });
                        }
                        State::StartOfField => {
                            if !self.field_ranges.is_empty() {
                                self.field_ranges.push(FieldRange {
                                    start: self.pos,
                                    end: self.pos,
                                    quoted: false,
                                });
                            }
                        }
                        State::InQuoted => unreachable!(),
                    }
                    Ok(Some(self.make_row()?))
                };
            }

            if self.pos >= self.buf.len() {
                break;
            }

            let byte = self.buf[self.pos];

            match self.state {
                State::StartOfField => {
                    if byte == b'\r' || byte == b'\n' {
                        if !self.field_ranges.is_empty() {
                            self.field_ranges.push(FieldRange {
                                start: self.pos,
                                end: self.pos,
                                quoted: false,
                            });
                        }
                        self.consume_line_end();
                        if self.field_ranges.is_empty() {
                            continue;
                        }
                        return Ok(Some(self.make_row()?));
                    }
                    if byte == self.delimiter {
                        self.field_ranges.push(FieldRange {
                            start: self.pos,
                            end: self.pos,
                            quoted: false,
                        });
                        self.pos += 1;
                        self.column += 1;
                        continue;
                    }
                    if byte == b'"' {
                        self.field_start = self.pos;
                        self.field_start_column = self.column;
                        self.state = State::InQuoted;
                        self.pos += 1;
                        self.column += 1;
                    } else {
                        self.field_start = self.pos;
                        self.field_start_column = self.column;
                        self.state = State::InUnquoted;
                        self.pos += 1;
                        self.column += 1;
                    }
                }

                State::InUnquoted => {
                    if byte == self.delimiter {
                        self.field_ranges.push(FieldRange {
                            start: self.field_start,
                            end: self.pos,
                            quoted: false,
                        });
                        self.state = State::StartOfField;
                        self.pos += 1;
                        self.column = 1;
                    } else if byte == b'\r' || byte == b'\n' {
                        self.field_ranges.push(FieldRange {
                            start: self.field_start,
                            end: self.pos,
                            quoted: false,
                        });
                        self.consume_line_end();
                        return Ok(Some(self.make_row()?));
                    } else {
                        self.pos += 1;
                        self.column += 1;
                    }
                }

                State::InQuoted => {
                    if byte == b'"' {
                        self.state = State::AfterQuote;
                        self.pos += 1;
                        self.column += 1;
                    } else {
                        self.pos += 1;
                        self.column += 1;
                    }
                }

                State::AfterQuote => {
                    if byte == b'"' {
                        self.state = State::InQuoted;
                        self.pos += 1;
                        self.column += 1;
                    } else if byte == self.delimiter {
                        self.field_ranges.push(FieldRange {
                            start: self.field_start,
                            end: self.pos,
                            quoted: true,
                        });
                        self.state = State::StartOfField;
                        self.pos += 1;
                        self.column = 1;
                    } else if byte == b'\r' || byte == b'\n' {
                        self.field_ranges.push(FieldRange {
                            start: self.field_start,
                            end: self.pos,
                            quoted: true,
                        });
                        self.consume_line_end();
                        return Ok(Some(self.make_row()?));
                    } else {
                        return Err(ReadError::new(
                            ReadErrorKind::TrailingContent,
                            self.line,
                            self.column_at(self.field_start),
                        ));
                    }
                }
            }
        }

        Ok(None)
    }

    fn make_row(&mut self) -> Result<Row, ReadError> {
        let ranges = core::mem::take(&mut self.field_ranges);
        if ranges.is_empty() {
            return Ok(Row {
                input: String::new(),
                fields: Vec::new(),
            });
        }
        let buf_start = ranges[0].start;
        let buf_end = ranges.last().unwrap().end;
        let raw = self.buf[buf_start..buf_end].to_vec();
        let input = String::from_utf8(raw).map_err(|_| ReadError::new(ReadErrorKind::InvalidUtf8, self.line, 0))?;
        let fields: Vec<FieldRange> = ranges
            .iter()
            .map(|r| FieldRange {
                start: r.start - buf_start,
                end: r.end - buf_start,
                quoted: r.quoted,
            })
            .collect();
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        Ok(Row {
            input,
            fields,
        })
    }

    fn consume_line_end(&mut self) {
        if self.pos < self.buf.len() && self.buf[self.pos] == b'\r' {
            self.pos += 1;
        }
        if self.pos < self.buf.len() && self.buf[self.pos] == b'\n' {
            self.pos += 1;
        }
        self.line += 1;
        self.column = 1;
    }

    fn fill_buf(&mut self) -> Result<bool, ReadError> {
        if self.eof {
            return Ok(false);
        }
        #[cfg(feature = "std")]
        {
            if let Some(source) = &mut self.source {
                let mut tmp = [0u8; 8192];
                let n = source.read(&mut tmp)?;
                if n == 0 {
                    self.eof = true;
                    return Ok(false);
                }
                self.buf.extend_from_slice(&tmp[..n]);
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn column_at(&self, _pos: usize) -> usize {
        self.field_start_column
    }
}

#[cfg(feature = "std")]
impl Reader {
    /// Create a reader from any `std::io::Read` source. Data is streamed
    /// in chunks as rows are read, without loading the entire input.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use std::fs::File;
    /// # use csv::Reader;
    /// let file = File::open("data.csv").unwrap();
    /// for row in Reader::from_reader(file).rows() {
    ///     let row = row?;
    ///     // ...
    /// }
    /// # Ok::<_, csv::ReadError>(())
    /// ```
    pub fn from_reader(reader: impl std::io::Read + 'static) -> Self {
        Reader {
            buf: Vec::new(),
            pos: 0,
            field_ranges: Vec::new(),
            field_start: 0,
            field_start_column: 1,
            state: State::StartOfField,
            line: 1,
            column: 1,
            delimiter: b',',
            flexible: false,
            eof: false,
            source: Some(Box::new(reader)),
        }
    }
}

/// A single row of CSV data.
///
/// A `Row` owns its data, so it can outlive the reader used to create it.
/// Fields are validated as UTF-8 at parse time, so all access methods
/// return `&str`.
///
/// Raw fields (including surrounding quotes) are accessed via [`get_raw`].
/// Unescaped fields (quotes stripped, `""` resolved) are accessed via
/// [`fields`].
///
/// [`get_raw`]: Row::get_raw
/// [`fields`]: Row::fields
#[derive(Clone, Debug)]
pub struct Row {
    input: String,
    fields: Vec<FieldRange>,
}

impl Row {
    /// Number of fields in this row.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Returns `true` if the row has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Return the raw field at `index`, or `None` if out of bounds.
    /// Includes surrounding quotes for quoted fields.
    pub fn get_raw(&self, index: usize) -> Option<&str> {
        let range = self.fields.get(index)?;
        Some(&self.input[range.start..range.end])
    }

    /// Iterate over unescaped fields, yielding `Cow<str>`.
    ///
    /// For quoted fields, surrounding quotes are stripped and `""`
    /// escape sequences are resolved to a single `"`. Returns
    /// `Cow::Borrowed` when no escaping is needed.
    pub fn fields(&self) -> Fields<'_> {
        Fields {
            input: &self.input,
            ranges: self.fields.iter(),
        }
    }
}

impl Index<usize> for Row {
    type Output = str;

    fn index(&self, index: usize) -> &str {
        self.get_raw(index).expect("Row index out of bounds")
    }
}

/// An owning iterator over raw field strings in a [`Row`].
///
/// Created by iterating over a `Row` by value.
pub struct RowIntoIter {
    input: String,
    ranges: alloc::vec::IntoIter<FieldRange>,
}

impl Iterator for RowIntoIter {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        let range = self.ranges.next()?;
        Some(self.input[range.start..range.end].to_string())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ranges.size_hint()
    }
}

impl ExactSizeIterator for RowIntoIter {
    fn len(&self) -> usize {
        self.ranges.len()
    }
}

impl IntoIterator for Row {
    type Item = String;
    type IntoIter = RowIntoIter;

    fn into_iter(self) -> RowIntoIter {
        RowIntoIter {
            input: self.input,
            ranges: self.fields.into_iter(),
        }
    }
}

/// Iterator over unescaped fields in a [`Row`], yielding `Cow<str>`.
///
/// Created by [`Row::fields`]. Returns `Cow::Borrowed` when the field
/// requires no escaping (the common case), and `Cow::Owned` only when
/// `""` escape sequences in quoted fields need to be resolved.
pub struct Fields<'a> {
    input: &'a str,
    ranges: core::slice::Iter<'a, FieldRange>,
}

impl<'a> Iterator for Fields<'a> {
    type Item = Cow<'a, str>;

    fn next(&mut self) -> Option<Cow<'a, str>> {
        let range = self.ranges.next()?;
        let raw = &self.input[range.start..range.end];

        if range.quoted {
            if raw.len() < 2 {
                return Some(Cow::Borrowed(""));
            }
            let content = &raw[1..raw.len() - 1];
            if content.contains("\"\"") {
                Some(Cow::Owned(content.replace("\"\"", "\"")))
            } else {
                Some(Cow::Borrowed(content))
            }
        } else {
            Some(Cow::Borrowed(raw))
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.ranges.size_hint()
    }
}

impl<'a> ExactSizeIterator for Fields<'a> {
    fn len(&self) -> usize {
        self.ranges.len()
    }
}

/// An iterator over the rows of a CSV reader.
///
/// Created by [`Reader::rows`]. Each item is a [`Result<Row, ReadError>`]
/// so errors from malformed CSV data are surfaced per row.
///
/// # Example
///
/// ```no_run
/// # use csv::Reader;
/// let data = b"a,b,c\n1,2,3\n";
/// for result in Reader::new(data).rows() {
///     match result {
///         Ok(row) => println!("got {} fields", row.len()),
///         Err(e) => eprintln!("error at line {}: {e}", e.line),
///     }
/// }
/// ```
pub struct Rows {
    reader: Reader,
}

impl Iterator for Rows {
    type Item = Result<Row, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.read_row() {
            Ok(Some(row)) => Some(Ok(row)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
