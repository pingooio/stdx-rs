use std::io::{Cursor, Read};

use csv::*;

fn collect_rows(data: &[u8]) -> Vec<Vec<String>> {
    let mut reader = Reader::new(Cursor::new(data));
    let mut out = Vec::new();
    for row in reader.rows() {
        out.push(row.to_vec().unwrap().iter().map(|s| s.to_string()).collect());
    }
    out
}

/// Forces reads in small chunks to exercise buffer-boundary code paths.
struct ChunkReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl ChunkReader {
    fn new(data: &[u8], chunk: usize) -> Self {
        ChunkReader {
            data: data.to_vec(),
            pos: 0,
            chunk,
        }
    }
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let to_read = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
        buf[..to_read].copy_from_slice(&self.data[self.pos..self.pos + to_read]);
        self.pos += to_read;
        Ok(to_read)
    }
}

/// A reader that returns an error after yielding the given number of bytes.
struct ErrorAfterReader {
    data: Vec<u8>,
    pos: usize,
    limit: usize,
}

impl ErrorAfterReader {
    fn new(data: Vec<u8>, limit: usize) -> Self {
        ErrorAfterReader {
            data,
            pos: 0,
            limit,
        }
    }
}

impl Read for ErrorAfterReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.limit {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "simulated IO error"));
        }
        let to_read = self
            .limit
            .saturating_sub(self.pos)
            .min(buf.len())
            .min(self.data.len() - self.pos);
        buf[..to_read].copy_from_slice(&self.data[self.pos..self.pos + to_read]);
        self.pos += to_read;
        Ok(to_read)
    }
}

// ── Reader: Basic Parsing ──────────────────────────────────────────

#[test]
fn test_rfc4180_example_1() {
    let rows = collect_rows(b"aaa,bbb,ccc\r\nzzz,yyy,xxx\r\n");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["aaa", "bbb", "ccc"]);
    assert_eq!(rows[1], vec!["zzz", "yyy", "xxx"]);
}

#[test]
fn test_rfc4180_example_2() {
    let rows = collect_rows(b"aaa,bbb,ccc\r\nzzz,yyy,xxx");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 3);
    assert_eq!(rows[1].len(), 3);
}

#[test]
fn test_rfc4180_example_3() {
    let rows = collect_rows(b"field_name,field_name,field_name\r\naaa,bbb,ccc\r\nzzz,yyy,xxx\r\n");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0], vec!["field_name", "field_name", "field_name"]);
}

#[test]
fn test_rfc4180_example_5() {
    let rows = collect_rows(b"\"aaa\",\"bbb\",\"ccc\"\r\nzzz,yyy,xxx\r\n");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["aaa", "bbb", "ccc"]);
}

#[test]
fn test_rfc4180_example_6() {
    let rows = collect_rows(b"\"aaa\",\"b\r\nbb\",\"ccc\"\r\nzzz,yyy,xxx\r\n");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["aaa", "b\r\nbb", "ccc"]);
}

#[test]
fn test_rfc4180_example_7() {
    let rows = collect_rows(b"\"aaa\",\"b\"\"bb\",\"ccc\"\r\nzzz,yyy,xxx\r\n");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["aaa", "b\"bb", "ccc"]);
}

#[test]
fn test_single_line_no_trailing_newline() {
    let rows = collect_rows(b"a,b,c");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], vec!["a", "b", "c"]);
}

#[test]
fn test_empty_input() {
    let rows = collect_rows(b"");
    assert!(rows.is_empty());
}

#[test]
fn test_empty_fields() {
    let rows = collect_rows(b",,\r\n,,\r\n");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["", "", ""]);
    assert_eq!(rows[1], vec!["", "", ""]);
}

#[test]
fn test_blank_lines_skipped() {
    let rows = collect_rows(b"a,b,c\n\n\n1,2,3\n");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_escaped_quotes_in_quoted_field() {
    let rows = collect_rows(b"\"\"\"hello\"\"\",world\n");
    assert_eq!(rows[0], vec!["\"hello\"", "world"]);
}

#[test]
fn test_quoted_field_contains_commas() {
    let rows = collect_rows(b"\"hello, world\",foo\n");
    assert_eq!(rows[0], vec!["hello, world", "foo"]);
}

#[test]
fn test_quoted_field_contains_newline() {
    let rows = collect_rows(b"\"line1\nline2\",foo\n");
    assert_eq!(rows[0], vec!["line1\nline2", "foo"]);
}

#[test]
fn test_custom_delimiter() {
    let data = b"a|b|c\n1|2|3\n";
    let mut reader = Reader::new(Cursor::new(data));
    reader.set_delimiter(b'|');
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows[0], vec!["a", "b", "c"]);
    assert_eq!(rows[1], vec!["1", "2", "3"]);
}

#[test]
fn test_tab_delimiter() {
    let data = b"a\tb\tc\n1\t2\t3\n";
    let mut reader = Reader::new(Cursor::new(data));
    reader.set_delimiter(b'\t');
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows[0], vec!["a", "b", "c"]);
    assert_eq!(rows[1], vec!["1", "2", "3"]);
}

// ── Reader: Line endings ──────────────────────────────────────────────

#[test]
fn test_crlf_line_endings() {
    let rows = collect_rows(b"a,b,c\r\n1,2,3\r\n");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_lf_line_endings() {
    let rows = collect_rows(b"a,b,c\n1,2,3\n");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_cr_line_endings() {
    let rows = collect_rows(b"a,b,c\r1,2,3\r");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_mixed_line_endings() {
    let rows = collect_rows(b"a,b,c\r\n1,2,3\n4,5,6\r");
    assert_eq!(rows.len(), 3);
}

#[test]
fn test_no_trailing_newline() {
    let rows = collect_rows(b"a,b,c\n1,2,3");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_single_field_no_newline() {
    let rows = collect_rows(b"hello");
    assert_eq!(rows[0], vec!["hello"]);
}

// ── Reader: Headers ───────────────────────────────────────────────────

#[test]
fn test_parse_headers() {
    let mut reader = Reader::new(Cursor::new(b"name,age,city\nAlice,30,NYC\nBob,25,LA\n"));
    let headers = reader.parse_headers().unwrap();
    assert_eq!(headers, vec!["name", "age", "city"]);
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows[0], vec!["Alice", "30", "NYC"]);
}

#[test]
fn test_set_headers() {
    let mut reader = Reader::new(Cursor::new(b"Alice,30,NYC\nBob,25,LA\n"));
    reader.set_headers(vec!["name".into(), "age".into(), "city".into()]);
    assert_eq!(reader.headers().unwrap(), &["name", "age", "city"]);
}

#[test]
fn test_headers_empty_csv() {
    let mut reader = Reader::new(Cursor::new(b""));
    let headers = reader.parse_headers().unwrap();
    assert!(headers.is_empty());
}

#[test]
fn test_headers_accessor() {
    let mut reader = Reader::new(Cursor::new(b"a,b\n1,2\n"));
    assert!(reader.headers().is_none());
    reader.parse_headers().unwrap();
    assert_eq!(reader.headers().unwrap(), &["a", "b"]);
}

// ── Reader: UTF-8 validation ──────────────────────────────────────────

#[test]
fn test_invalid_utf8_in_unquoted_field() {
    let data = b"a,\xff,b\n";
    let mut reader = Reader::new(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    // csv defers UTF-8 validation: no error until to_vec() is called
    assert!(row.error().is_none());
    assert!(row.to_vec().is_err());
}

#[test]
fn test_invalid_utf8_in_quoted_field() {
    let data = b"a,\"\xff\",b\n";
    let mut reader = Reader::new(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.error().is_none());
    assert!(row.to_vec().is_err());
}

#[test]
fn test_null_bytes_in_field() {
    let rows = collect_rows(b"a,\0,c\n");
    assert_eq!(rows[0], vec!["a", "\0", "c"]);
}

#[test]
fn test_invalid_utf8_second_row_ok_first_row() {
    let data = b"a,b\nc,\xff\n";
    let mut reader = Reader::new(Cursor::new(data));
    let mut rows = reader.rows();
    let row1 = rows.next().unwrap();
    assert_eq!(row1.to_vec().unwrap(), vec!["a", "b"]);
    let row2 = rows.next().unwrap();
    assert!(row2.to_vec().is_err());
}

// ── Reader: Errors ────────────────────────────────────────────────────

#[test]
fn test_unterminated_quote() {
    let data = b"a,\"unterminated\n";
    let mut reader = Reader::new(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(matches!(row.error().unwrap().kind(), ReadErrorKind::UnterminatedQuote));
}

#[test]
fn test_trailing_content_after_quoted_field() {
    let data = b"\"hello\"garbage\n";
    let mut reader = Reader::new(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(matches!(row.error().unwrap().kind(), ReadErrorKind::TrailingContent));
}

#[test]
fn test_io_error_propagation() {
    let data = b"a,b,c\n1,2,3\n4,5,6\n";
    let mut reader = Reader::new(ErrorAfterReader::new(data.to_vec(), 10));
    let mut rows = reader.rows();
    assert!(rows.next().is_some()); // may succeed
    // If the IO error hasn't been hit yet, keep going
    for row in rows {
        if let Some(e) = row.error() {
            assert!(matches!(e.kind(), ReadErrorKind::Io));
            break;
        }
    }
}

#[test]
fn test_error_display_invalid_utf8() {
    let e = ReadError::new(ReadErrorKind::InvalidUtf8, 4, 0);
    let s = e.to_string();
    assert!(s.contains("invalid UTF-8"));
    assert!(s.contains("line 4"));
}

#[test]
fn test_error_display_inconsistent_field_count() {
    let e = ReadError::new(
        ReadErrorKind::InconsistentFieldCount {
            expected: 3,
            found: 2,
        },
        5,
        0,
    );
    let s = e.to_string();
    assert!(s.contains("expected 3"));
    assert!(s.contains("found 2"));
    assert!(s.contains("line 5"));
}

// ── Reader: Row API ───────────────────────────────────────────────────

#[test]
fn test_row_to_vec() {
    let mut reader = Reader::new(Cursor::new(b"a,b,c\n"));
    let row = reader.rows().next().unwrap();
    assert_eq!(row.to_vec().unwrap(), vec!["a", "b", "c"]);
}

#[test]
fn test_row_len() {
    let mut reader = Reader::new(Cursor::new(b"a,b,c\n1,2,3,4\n"));
    let mut rows = reader.rows();
    assert_eq!(rows.next().unwrap().len(), 3);
    assert_eq!(rows.next().unwrap().len(), 4);
}

#[test]
fn test_row_is_empty() {
    // Blank lines are skipped, so a single newline produces no rows
    let mut reader = Reader::new(b"\n".as_slice());
    assert!(reader.rows().next().is_none());
}

#[test]
fn test_row_get() {
    let mut reader = Reader::new(Cursor::new(b"a,b,c\n"));
    let row = reader.rows().next().unwrap();
    assert_eq!(row.get(0).unwrap().unwrap(), "a");
    assert_eq!(row.get(1).unwrap().unwrap(), "b");
    assert_eq!(row.get(2).unwrap().unwrap(), "c");
    assert!(row.get(3).is_none());
}

#[test]
fn test_row_iter() {
    let mut reader = Reader::new(Cursor::new(b"a,b,c\n"));
    let row = reader.rows().next().unwrap();
    let fields: Vec<&str> = row.iter().map(|r| r.unwrap()).collect();
    assert_eq!(fields, vec!["a", "b", "c"]);
}

#[test]
fn test_row_debug() {
    let mut reader = Reader::new(b"a,b,c\n".as_slice());
    let row = reader.rows().next().unwrap();
    let s = format!("{:?}", row);
    assert!(s.contains("a") && s.contains("b") && s.contains("c"));
}

#[test]
fn test_row_debug_error() {
    let data = b"\"unterminated\n";
    let mut reader = Reader::new(Cursor::new(data));
    let row = reader.rows().next().unwrap();
    let s = format!("{:?}", row);
    assert!(s.contains("Err("));
}

// ── BytesRow API ──────────────────────────────────────────────────────

#[test]
fn test_bytes_row_to_vec() {
    let mut reader = Reader::new(Cursor::new(b"a,b,c\n"));
    let bytes_row = reader.rows_bytes().next().unwrap();
    let fields = bytes_row.to_vec().unwrap();
    assert_eq!(fields, vec![&b"a"[..], &b"b"[..], &b"c"[..]]);
}

#[test]
fn test_bytes_row_get() {
    let mut reader = Reader::new(Cursor::new(b"a,b,c\n"));
    let bytes_row = reader.rows_bytes().next().unwrap();
    assert_eq!(bytes_row.get(0).unwrap(), &b"a"[..]);
    assert!(bytes_row.get(3).is_none());
}

#[test]
fn test_bytes_row_iter() {
    let mut reader = Reader::new(Cursor::new(b"a,b,c\n"));
    let bytes_row = reader.rows_bytes().next().unwrap();
    let fields: Vec<&[u8]> = bytes_row.iter().collect();
    assert_eq!(fields, vec![&b"a"[..], &b"b"[..], &b"c"[..]]);
}

#[test]
fn test_bytes_row_len() {
    let mut reader = Reader::new(Cursor::new(b"a,b,c\n"));
    let bytes_row = reader.rows_bytes().next().unwrap();
    assert_eq!(bytes_row.len(), 3);
}

#[test]
fn test_bytes_row_debug() {
    let mut reader = Reader::new(b"a,b,c\n".as_slice());
    let bytes_row = reader.rows_bytes().next().unwrap();
    let s = format!("{:?}", bytes_row);
    assert!(s.contains("97") || s.contains("BytesRow"));
}

#[test]
fn test_bytes_row_non_utf8_succeeds() {
    let data = b"a,\xff,b\n";
    let mut reader = Reader::new(Cursor::new(data));
    let bytes_row = reader.rows_bytes().next().unwrap();
    let fields = bytes_row.to_vec().unwrap();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[1], &b"\xff"[..]);
    // bytes row does NOT validate UTF-8
    assert!(bytes_row.error().is_none());
}

// ── Reader: Buffer boundary tests ─────────────────────────────────────

#[test]
fn test_chunked_reader_1byte() {
    let data = b"a,b,c\n1,2,3\n";
    let mut reader = Reader::new(ChunkReader::new(data, 1));
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["a", "b", "c"]);
}

#[test]
fn test_chunked_reader_4byte() {
    let data = b"a,b,c\n1,2,3\n";
    let mut reader = Reader::new(ChunkReader::new(data, 4));
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_quoted_field_across_chunks() {
    let data = b"\"hello, world\",foo\nbar,baz\n";
    let mut reader = Reader::new(ChunkReader::new(data, 4));
    let mut rows = reader.rows();
    let row1 = rows.next().unwrap();
    assert_eq!(row1.to_vec().unwrap(), vec!["hello, world", "foo"]);
    let row2 = rows.next().unwrap();
    assert_eq!(row2.to_vec().unwrap(), vec!["bar", "baz"]);
}

#[test]
fn test_large_quoted_field() {
    let inner = "x".repeat(40000);
    let data = format!("\"{inner}\",end\n");
    let mut reader = Reader::new(ChunkReader::new(data.as_bytes(), 4096));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert_eq!(row.len(), 2);
    assert_eq!(row.to_vec().unwrap()[0].len(), 40000);
    assert_eq!(row.to_vec().unwrap()[1], "end");
}

#[test]
fn test_crlf_split_chunk_boundary() {
    let before = "x".repeat(16380);
    let data = format!("aaa,{before}\r\n");
    let mut reader = Reader::new(ChunkReader::new(data.as_bytes(), 4096));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert_eq!(row.len(), 2);
    assert_eq!(row.to_vec().unwrap()[0], "aaa");
    assert_eq!(row.to_vec().unwrap()[1].len(), 16380);
}

// ── Reader: new convenience ───────────────────────────────────

#[test]
fn test_new_with_slice() {
    let mut reader = Reader::new(b"a,b,c\n1,2,3\n".as_slice());
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["a", "b", "c"]);
    assert_eq!(rows[1], vec!["1", "2", "3"]);
}

#[test]
fn test_new_with_quoted_slice() {
    let mut reader = Reader::new(b"\"hello\",\"world\"\n".as_slice());
    let row = reader.rows().next().unwrap();
    assert_eq!(row.to_vec().unwrap(), vec!["hello", "world"]);
}

// ── Reader: CR at EOF ─────────────────────────────────────────────────

#[test]
fn test_cr_at_eof() {
    let rows = collect_rows(b"a,b\r");
    assert_eq!(rows[0], vec!["a", "b"]);
}

// ── Reader: Edge cases ────────────────────────────────────────────────

#[test]
fn test_leading_delimiter() {
    let rows = collect_rows(b",a,b\n");
    assert_eq!(rows[0], vec!["", "a", "b"]);
}

#[test]
fn test_trailing_delimiter() {
    let rows = collect_rows(b"a,b,\n");
    assert_eq!(rows[0], vec!["a", "b", ""]);
}

#[test]
fn test_only_delimiter() {
    let rows = collect_rows(b",\n");
    assert_eq!(rows[0], vec!["", ""]);
}

#[test]
fn test_quoted_empty_field() {
    let rows = collect_rows(b"\"\"\n");
    assert_eq!(rows[0], vec![""]);
}

#[test]
fn test_escaped_quote_at_end_of_quoted_field() {
    let rows = collect_rows(b"\"\"\"\"\n");
    assert_eq!(rows[0], vec!["\""]);
}

#[test]
fn test_single_field_rows() {
    let rows = collect_rows(b"hello\nworld\n");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["hello"]);
    assert_eq!(rows[1], vec!["world"]);
}

#[test]
fn test_mixed_quoted_and_unquoted() {
    let rows = collect_rows(b"\"quoted\",unquoted,\"also quoted\"\n");
    assert_eq!(rows[0], vec!["quoted", "unquoted", "also quoted"]);
}

#[test]
fn test_multiple_consecutive_blank_lines() {
    let rows = collect_rows(b"a,b\n\n\n\n1,2\n");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["a", "b"]);
    assert_eq!(rows[1], vec!["1", "2"]);
}

#[test]
fn test_unicode_fields() {
    let rows = collect_rows("café,ñoño\n".as_bytes());
    assert_eq!(rows[0], vec!["café", "ñoño"]);
}

#[test]
fn test_bom_at_start_of_csv() {
    // BOM is treated as part of the first field
    let rows = collect_rows(b"\xef\xbb\xbfa,b\n");
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[0][0].as_bytes(), b"\xef\xbb\xbfa");
    assert_eq!(rows[0][1], "b");
}

#[test]
fn test_unterminated_quote_at_eof() {
    let data = b"a,\"unterminated";
    let mut reader = Reader::new(Cursor::new(data));
    let row = reader.rows().next().unwrap();
    assert!(matches!(row.error().unwrap().kind(), ReadErrorKind::UnterminatedQuote));
}

#[test]
fn test_strict_mode_inconsistent_field_count_error() {
    let data = b"a,b\n1,2,3\n";
    let mut reader = Reader::new(Cursor::new(data));
    let mut rows = reader.rows();
    let row1 = rows.next().unwrap();
    assert_eq!(row1.to_vec().unwrap(), vec!["a", "b"]);
    let row2 = rows.next().unwrap();
    assert!(matches!(
        row2.error().unwrap().kind(),
        ReadErrorKind::InconsistentFieldCount {
            expected: 2,
            found: 3
        }
    ));
}

#[test]
fn test_fields_iterator_preserves_error_kind() {
    let data = b"\"hello\"garbage\n";
    let mut reader = Reader::new(Cursor::new(data));
    let row = reader.rows().next().unwrap();
    let mut iter = row.iter();
    let err = iter.next().unwrap().unwrap_err();
    assert!(matches!(err.kind(), ReadErrorKind::TrailingContent));
}

// ── Reader: set_flexible ──────────────────────────────────────────────

#[test]
fn test_strict_mode_consistent_fields_ok() {
    let mut reader = Reader::new(Cursor::new(b"a,b\n1,2\n3,4\n"));
    reader.set_flexible(false);
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows.len(), 3);
}

#[test]
fn test_flexible_mode_variable_fields_ok() {
    let mut reader = Reader::new(Cursor::new(b"a,b\n1,2,3\n4\n"));
    reader.set_flexible(true);
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows.len(), 3);
}

// ── Writer ────────────────────────────────────────────────────────────

#[test]
fn test_writer_basic() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b", "c"]).unwrap();
    w.write_row(["1", "2", "3"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,b,c\r\n1,2,3\r\n");
}

#[test]
fn test_writer_empty_fields() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["", "b", ""]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"\",b,\"\"\r\n");
}

#[test]
fn test_writer_auto_quote_comma() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello, world", "foo"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"hello, world\",foo\r\n");
}

#[test]
fn test_writer_auto_quote_quote() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["he said \"hello\"", "foo"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"he said \"\"hello\"\"\",foo\r\n");
}

#[test]
fn test_writer_auto_quote_newline() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello\nworld", "foo"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"hello\nworld\",foo\r\n");
}

#[test]
fn test_writer_custom_delimiter() {
    let mut w = Writer::new(Vec::new());
    w.delimiter(b'\t');
    w.write_row(["a", "b", "c"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a\tb\tc\r\n");
}

#[test]
fn test_writer_strict_field_count() {
    let mut w = Writer::new(Vec::new());
    w.set_flexible(false);
    w.write_row(["a", "b"]).unwrap();
    let err = w.write_row(["1", "2", "3"]).unwrap_err();
    assert!(matches!(
        err,
        WriteError::InconsistentFieldCount {
            expected: 2,
            found: 3,
            ..
        }
    ));
}

#[test]
fn test_writer_flexible_field_count() {
    let mut w = Writer::new(Vec::new());
    w.set_flexible(true);
    w.write_row(["a", "b"]).unwrap();
    w.write_row(["1", "2", "3"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,b\r\n1,2,3\r\n");
}

#[test]
fn test_writer_flush() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b"]).unwrap();
    w.flush().unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,b\r\n");
}

#[test]
fn test_writer_into_inner() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b"]).unwrap();
    let inner: Vec<u8> = w.into_inner().unwrap();
    assert_eq!(String::from_utf8(inner).unwrap(), "a,b\r\n");
}

#[test]
fn test_writer_no_rows() {
    let w = Writer::new(Vec::new());
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "");
}

#[test]
fn test_writer_row_with_cr() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello\rworld", "foo"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"hello\rworld\",foo\r\n");
}

#[test]
fn test_writer_row_with_crlf() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["foo\r\nbar"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"foo\r\nbar\"\r\n");
}

#[test]
fn test_writer_no_fields_error_before_write() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b"]).unwrap();
    // This should error BEFORE the bad row is buffered
    let err = w.write_row(["1", "2", "3"]).unwrap_err();
    assert!(matches!(
        err,
        WriteError::InconsistentFieldCount {
            expected: 2,
            found: 3,
            ..
        }
    ));
    // The buffer should NOT contain the bad row — only the first row
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,b\r\n");
}

// ── Roundtrip ─────────────────────────────────────────────────────────

#[test]
fn test_roundtrip_basic() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b", "c"]).unwrap();
    w.write_row(["1", "2", "3"]).unwrap();
    let csv_data = w.into_inner().unwrap();
    let mut reader = Reader::new(Cursor::new(csv_data));
    let rows: Vec<Vec<String>> = reader
        .rows()
        .map(|r| r.to_vec().unwrap().iter().map(|s| s.to_string()).collect())
        .collect();
    assert_eq!(rows[0], vec!["a", "b", "c"]);
    assert_eq!(rows[1], vec!["1", "2", "3"]);
}

#[test]
fn test_roundtrip_with_commas() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello, world", "foo,bar"]).unwrap();
    let csv_data = w.into_inner().unwrap();
    let mut reader = Reader::new(Cursor::new(csv_data));
    let row = reader.rows().next().unwrap();
    assert_eq!(row.to_vec().unwrap(), vec!["hello, world", "foo,bar"]);
}

#[test]
fn test_roundtrip_with_quotes() {
    let mut w = Writer::new(Vec::new());
    w.write_row([r#"he said "hello""#, "foo"]).unwrap();
    let csv_data = w.into_inner().unwrap();
    let mut reader = Reader::new(Cursor::new(csv_data));
    let row = reader.rows().next().unwrap();
    assert_eq!(row.to_vec().unwrap(), vec![r#"he said "hello""#, "foo"]);
}

#[test]
fn test_roundtrip_with_newlines() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello\nworld", "foo\r\nbar"]).unwrap();
    let csv_data = w.into_inner().unwrap();
    let mut reader = Reader::new(Cursor::new(csv_data));
    let row = reader.rows().next().unwrap();
    assert_eq!(row.to_vec().unwrap(), vec!["hello\nworld", "foo\r\nbar"]);
}

// ── Serde ─────────────────────────────────────────────────────────────

#[cfg(feature = "serde")]
mod serde_tests {
    use std::io::Cursor;

    use csv::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Person {
        name: String,
        age: u32,
    }

    #[test]
    fn test_deserialize_positional() {
        let data = b"Alice,30\nBob,25\n";
        let mut reader = Reader::new(Cursor::new(data));
        let mut rows = reader.rows();
        let p1: Person = rows.next().unwrap().deserialize().unwrap();
        assert_eq!(p1.name, "Alice");
        assert_eq!(p1.age, 30);
        let p2: Person = rows.next().unwrap().deserialize().unwrap();
        assert_eq!(p2.name, "Bob");
        assert_eq!(p2.age, 25);
    }

    #[test]
    fn test_deserialize_with_headers() {
        let data = b"name,age\nAlice,30\nBob,25\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.parse_headers().unwrap();
        let mut rows = reader.rows();
        let p1: Person = rows.next().unwrap().deserialize().unwrap();
        assert_eq!(p1.name, "Alice");
        assert_eq!(p1.age, 30);
        let p2: Person = rows.next().unwrap().deserialize().unwrap();
        assert_eq!(p2.name, "Bob");
        assert_eq!(p2.age, 25);
    }

    #[test]
    fn test_deserialize_header_order_independent() {
        let data = b"age,name\n30,Alice\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.parse_headers().unwrap();
        let p: Person = reader.rows().next().unwrap().deserialize().unwrap();
        assert_eq!(p.name, "Alice");
        assert_eq!(p.age, 30);
    }

    #[test]
    fn test_deserialize_type_mismatch() {
        let data = b"name,age\nAlice,not_a_number\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.parse_headers().unwrap();
        let row = reader.rows().next().unwrap();
        let result: Result<Person, _> = row.deserialize();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.kind(), ReadErrorKind::Deserialize(_)));
        let display = err.to_string();
        assert!(display.contains("deserialization error"), "got: {display}");
    }

    #[test]
    fn test_deserialize_missing_column_defaults_to_empty() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Record {
            name: String,
            age: u32,
            city: String,
        }
        let data = b"name,age\nAlice,30\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.parse_headers().unwrap();
        let row = reader.rows().next().unwrap();
        let result: Result<Record, _> = row.deserialize();
        assert!(result.is_ok(), "should succeed, got: {:?}", result.err());
        let rec = result.unwrap();
        assert_eq!(rec.name, "Alice");
        assert_eq!(rec.age, 30);
        assert_eq!(rec.city, "");
    }

    #[test]
    fn test_deserialize_positional_to_tuple() {
        let data = b"Alice,30\nBob,25\n";
        let mut reader = Reader::new(Cursor::new(data));
        let mut rows = reader.rows();
        let t1: (String, u32) = rows.next().unwrap().deserialize().unwrap();
        assert_eq!(t1, ("Alice".to_string(), 30));
    }

    #[test]
    fn test_deserialize_set_headers() {
        let data = b"Alice,30\nBob,25\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.set_headers(vec!["name".into(), "age".into()]);
        let mut rows = reader.rows();
        let p1: Person = rows.next().unwrap().deserialize().unwrap();
        assert_eq!(p1.name, "Alice");
        assert_eq!(p1.age, 30);
    }

    #[test]
    fn test_deserialize_row_can_outlive_reader() {
        // Owned rows prove they can outlive the reader
        let row = {
            let mut reader = Reader::new(b"Alice,30\n".as_slice());
            reader.rows().next().unwrap()
        };
        // row is used after reader is dropped
        let p: Person = row.deserialize().unwrap();
        assert_eq!(p.name, "Alice");
    }

    #[test]
    fn test_deserialize_with_bytes_row_also_works() {
        // BytesRow doesn't have deserialize, but Row wrapping it does
        let data = b"Alice,30\n";
        let mut reader = Reader::new(Cursor::new(data));
        let row = reader.rows().next().unwrap();
        let p: Person = row.deserialize().unwrap();
        assert_eq!(p.name, "Alice");
        assert_eq!(p.age, 30);
    }

    #[test]
    fn test_deserialize_option_field() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct WithOption {
            name: String,
            age: Option<u32>,
            city: Option<String>,
        }
        // age present, city absent
        let data = b"name,age\nAlice,30\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.parse_headers().unwrap();
        let rec: WithOption = reader.rows().next().unwrap().deserialize().unwrap();
        assert_eq!(rec.name, "Alice");
        assert_eq!(rec.age, Some(30));
        assert_eq!(rec.city, None);
    }

    #[test]
    fn test_deserialize_bool() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct WithBool {
            name: String,
            active: bool,
        }
        let data = b"name,active\nAlice,true\nBob,false\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.parse_headers().unwrap();
        let rows: Vec<WithBool> = reader.rows().map(|r| r.deserialize().unwrap()).collect();
        assert_eq!(rows[0].name, "Alice");
        assert!(rows[0].active);
        assert_eq!(rows[1].name, "Bob");
        assert!(!rows[1].active);
    }

    #[test]
    fn test_deserialize_extra_columns_ignored() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct OnlyName {
            name: String,
        }
        let data = b"name,age,city\nAlice,30,NYC\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.parse_headers().unwrap();
        let rec: OnlyName = reader.rows().next().unwrap().deserialize().unwrap();
        assert_eq!(rec.name, "Alice");
    }

    #[test]
    fn test_deserialize_flexible_row_different_field_count() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Record {
            a: String,
            b: String,
        }
        let data = b"a,b\n1,2,3\n";
        let mut reader = Reader::new(Cursor::new(data));
        reader.set_flexible(true);
        reader.parse_headers().unwrap();
        let result: Result<Record, _> = reader.rows().next().unwrap().deserialize();
        assert!(result.is_ok());
        // Positional deserialization only uses first N fields
    }
}

// ── Row can outlive Reader (owned row test) ───────────────────────────

#[test]
fn test_row_outlives_reader() {
    let row = {
        let mut reader = Reader::new(b"a,b,c\n1,2,3\n".as_slice());
        reader.rows().nth(1).unwrap()
    };
    // row is used after reader would be dropped (owned)
    assert_eq!(row.len(), 3);
    assert_eq!(row.to_vec().unwrap(), vec!["1", "2", "3"]);
}

#[test]
fn test_rows_collected_outlive_reader() {
    let rows: Vec<Row> = {
        let mut reader = Reader::new(b"a,b\n1,2\n3,4\n".as_slice());
        reader.rows().collect()
    };
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].to_vec().unwrap(), vec!["a", "b"]);
    assert_eq!(rows[2].to_vec().unwrap(), vec!["3", "4"]);
}

#[test]
fn test_bytes_rows_collected_outlive_reader() {
    let rows: Vec<BytesRow> = {
        let mut reader = Reader::new(b"a,b\n1,2\n".as_slice());
        reader.rows_bytes().collect()
    };
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].to_vec().unwrap(), vec![&b"1"[..], &b"2"[..]]);
}

// ── ExactSizeIterator tests ──────────────────────────────────────────

#[test]
fn test_fields_exact_size() {
    let mut reader = Reader::new(b"a,b,c\n".as_slice());
    let row = reader.rows().next().unwrap();
    let mut iter = row.iter();
    assert_eq!(iter.size_hint(), (3, Some(3)));
    iter.next();
    assert_eq!(iter.size_hint(), (2, Some(2)));
}

#[test]
fn test_bytes_fields_exact_size() {
    let mut reader = Reader::new(b"a,b,c\n".as_slice());
    let bytes_row = reader.rows_bytes().next().unwrap();
    let mut iter = bytes_row.iter();
    assert_eq!(iter.size_hint(), (3, Some(3)));
    iter.next();
    assert_eq!(iter.size_hint(), (2, Some(2)));
}

// ── Large data tests ──────────────────────────────────────────────────

#[test]
fn test_large_fields() {
    let big = "x".repeat(10000);
    let data = format!("{big},{big},{big}\n");
    let mut reader = Reader::new(Cursor::new(data.as_bytes()));
    let row = reader.rows().next().unwrap();
    assert_eq!(row.len(), 3);
    assert_eq!(row.to_vec().unwrap()[0].len(), 10000);
}

#[test]
fn test_many_fields() {
    let fields: Vec<String> = (0..100).map(|i| format!("field{i}")).collect();
    let line = fields.join(",") + "\n";
    let mut reader = Reader::new(Cursor::new(line.as_bytes()));
    let row = reader.rows().next().unwrap();
    assert_eq!(row.len(), 100);
}

#[test]
fn test_large_streaming() {
    let mut csv = String::new();
    for i in 0..1000 {
        csv.push_str(&format!("a{}", i));
        for j in 1..20 {
            csv.push(',');
            csv.push_str(&format!("b{}", j));
        }
        csv.push('\n');
    }
    let mut reader = Reader::new(Cursor::new(csv.as_bytes()));
    let mut count = 0;
    for row in reader.rows() {
        assert_eq!(row.len(), 20);
        count += 1;
    }
    assert_eq!(count, 1000);
}
