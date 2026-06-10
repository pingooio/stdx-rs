use std::io::{Cursor, Read};

use csv_legacy2::*;

fn collect_rows(data: &[u8]) -> Vec<Vec<String>> {
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut out = Vec::new();
    for row in reader.rows() {
        out.push(row.all().unwrap());
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
    let rows = collect_rows(b"\"aaa\",\"b\"\"bb\",\"ccc\"");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], vec!["aaa", "b\"bb", "ccc"]);
}

// ── Reader: Line Endings ───────────────────────────────────────────

#[test]
fn test_crlf_endings() {
    let rows = collect_rows(b"a,b\r\nc,d\r\n");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_lf_endings() {
    let rows = collect_rows(b"a,b\nc,d\n");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_cr_endings() {
    let rows = collect_rows(b"a,b\rc,d\r");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_mixed_endings() {
    let rows = collect_rows(b"a,b\r\nc,d\ne,f\r");
    assert_eq!(rows.len(), 3);
}

#[test]
fn test_no_trailing_newline() {
    let rows = collect_rows(b"a,b\nc,d");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_single_line_no_newline() {
    let rows = collect_rows(b"hello,world");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], vec!["hello", "world"]);
}

// ── Reader: Edge Cases ─────────────────────────────────────────────

#[test]
fn test_empty_input() {
    let rows = collect_rows(b"");
    assert_eq!(rows.len(), 0);
}

#[test]
fn test_empty_field() {
    let rows = collect_rows(b"a,,c\n");
    assert_eq!(rows[0], vec!["a", "", "c"]);
}

#[test]
fn test_empty_quoted_field() {
    let rows = collect_rows(b"a,\"\",c\n");
    assert_eq!(rows[0], vec!["a", "", "c"]);
}

#[test]
fn test_all_empty_fields() {
    let rows = collect_rows(b",,\n");
    assert_eq!(rows[0], vec!["", "", ""]);
}

#[test]
fn test_blank_lines_skipped() {
    let rows = collect_rows(b"a,b\n\n\nc,d\n");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_escaped_quote_in_quoted_field() {
    let rows = collect_rows(b"\"Say \"\"Hello\"\"\",world\n");
    assert_eq!(rows[0], vec!["Say \"Hello\"", "world"]);
}

#[test]
fn test_quoted_field_with_comma() {
    let rows = collect_rows(b"a,\"b,c\",d\n");
    assert_eq!(rows[0], vec!["a", "b,c", "d"]);
}

#[test]
fn test_quoted_field_with_embedded_newline() {
    let rows = collect_rows(b"a,\"b\nc\",d\n");
    assert_eq!(rows[0], vec!["a", "b\nc", "d"]);
}

#[test]
fn test_quoted_field_with_embedded_crlf() {
    let rows = collect_rows(b"a,\"b\r\nc\",d\r\n");
    assert_eq!(rows[0], vec!["a", "b\r\nc", "d"]);
}

#[test]
fn test_unicode_fields() {
    let data = "名前,年齢\n田中,30\n";
    let rows = collect_rows(data.as_bytes());
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["名前", "年齢"]);
    assert_eq!(rows[1], vec!["田中", "30"]);
}

#[test]
fn test_custom_delimiter() {
    let data = b"a|b|c\n1|2|3\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    reader.set_delimiter(b'|');
    let mut rows = Vec::new();
    for row in reader.rows() {
        rows.push(row.all().unwrap());
    }
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["a", "b", "c"]);
    assert_eq!(rows[1], vec!["1", "2", "3"]);
}

#[test]
fn test_tab_delimiter() {
    let data = b"a\tb\tc\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    reader.set_delimiter(b'\t');
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert_eq!(row.all().unwrap(), vec!["a", "b", "c"]);
}

// ── Reader: Fields iterator (zero-alloc) ───────────────────────────

#[test]
fn test_fields_zero_alloc() {
    let data = b"hello,world\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    let fields: Vec<&str> = row.fields().unwrap().collect();
    assert_eq!(fields, vec!["hello", "world"]);
}

#[test]
fn test_fields_unescaped() {
    let data = b"\"hello\",\"foo\"\"bar\",\"b\"\"\"\"\"\"\"\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    let fields: Vec<&str> = row.fields().unwrap().collect();
    assert_eq!(fields, vec!["hello", "foo\"bar", "b\"\"\""]);
}

// ── Reader: Trailing content after quoted field ───────────────────

#[test]
fn test_trailing_content_after_quoted_field() {
    let data = b"\"hello\" garbage\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.fields().is_err());
    assert!(matches!(row.error(), Some(e) if matches!(e.kind(), ReadErrorKind::TrailingContent)));
}

#[test]
fn test_trailing_content_after_quoted_field_at_eof() {
    let data = b"\"hello\"garbage";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.fields().is_err());
    assert!(matches!(row.error(), Some(e) if matches!(e.kind(), ReadErrorKind::TrailingContent)));
}

// ── Reader: Headers ─────────────────────────────────────────────────

#[test]
fn test_with_headers() {
    let data = b"name,age,city\nAlice,30,NYC\nBob,25,LA\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let headers = reader.parse_headers().unwrap();
    assert_eq!(headers, vec!["name", "age", "city"]);
    let mut out = Vec::new();
    for row in reader.rows() {
        out.push(row.all().unwrap());
    }
    assert_eq!(out.len(), 2);
    assert_eq!(out[0], vec!["Alice", "30", "NYC"]);
    assert_eq!(out[1], vec!["Bob", "25", "LA"]);
}

#[test]
fn test_without_headers() {
    let data = b"Alice,30,NYC\nBob,25,LA\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    assert!(reader.headers().is_none());
    let mut out = Vec::new();
    for row in reader.rows() {
        out.push(row.all().unwrap());
    }
    assert_eq!(out.len(), 2);
}

// ── Reader: Trailing delimiter ─────────────────────────────────────

#[test]
fn test_trailing_delimiter_at_eof() {
    let rows = collect_rows(b"a,b,");
    assert_eq!(rows[0], vec!["a", "b", ""]);
}

#[test]
fn test_trailing_delimiter_only() {
    let rows = collect_rows(b",");
    assert_eq!(rows[0], vec!["", ""]);
}

#[test]
fn test_large_fields() {
    let large = "x".repeat(10000);
    let data = format!("{large},{large}\n");
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert_eq!(row.len(), 2);
    let fields: Vec<&str> = row.fields().unwrap().collect();
    assert_eq!(fields[0].len(), 10000);
    assert_eq!(fields[1].len(), 10000);
}

#[test]
fn test_many_fields() {
    let mut csv = String::new();
    for i in 0..100 {
        if i > 0 {
            csv.push(',');
        }
        csv.push_str(&format!("field{i}"));
    }
    csv.push('\n');
    let mut reader = Reader::from_reader(Cursor::new(csv));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert_eq!(row.len(), 100);
    let fields: Vec<&str> = row.fields().unwrap().collect();
    assert_eq!(fields[0], "field0");
    assert_eq!(fields[99], "field99");
}

#[test]
fn test_large_streaming() {
    let mut csv = Vec::new();
    for i in 0..1000 {
        if i > 0 {
            csv.push(b'\n');
        }
        for j in 0..20 {
            if j > 0 {
                csv.push(b',');
            }
            csv.extend_from_slice(format!("{i}-{j}").as_bytes());
        }
    }
    let mut reader = Reader::from_reader(Cursor::new(csv));
    let mut count = 0;
    for row in reader.rows() {
        assert_eq!(row.len(), 20);
        count += 1;
    }
    assert_eq!(count, 1000);
}

// ── Reader: Error handling ─────────────────────────────────────────

#[test]
fn test_unterminated_quote() {
    let data = b"a,\"unterminated\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.fields().is_err());
    assert!(matches!(row.error(), Some(e) if e.to_string().contains("unterminated quote")));
}

// ── Writer ──────────────────────────────────────────────────────────

#[test]
fn test_writer_basic() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b", "c"]).unwrap();
    w.write_row(["1", "2", "3"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,b,c\r\n1,2,3\r\n");
}

#[test]
fn test_writer_empty_field() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "", "c"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,\"\",c\r\n");
}

#[test]
fn test_writer_auto_quote_comma() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello, world"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"hello, world\"\r\n");
}

#[test]
fn test_writer_auto_quote_double_quote() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["say \"hello\""]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"say \"\"hello\"\"\"\r\n");
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
fn test_writer_field_count_consistent() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b", "c"]).unwrap();
    let err = w.write_row(["1", "2"]).unwrap_err();
    match err {
        WriteError::InconsistentFieldCount {
            expected,
            found,
            row,
        } => {
            assert_eq!(expected, 3);
            assert_eq!(found, 2);
            assert_eq!(row, 2);
        }
        _ => panic!("wrong error variant"),
    }
}

#[test]
fn test_writer_flexible() {
    let mut w = Writer::new(Vec::new());
    w.flexible(true);
    w.write_row(["a", "b", "c"]).unwrap();
    w.write_row(["1", "2"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,b,c\r\n1,2\r\n");
}

#[test]
fn test_writer_flush() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b"]).unwrap();
    w.flush().unwrap();
    assert_eq!(w.into_inner().unwrap(), b"a,b\r\n");
}

// ── Roundtrip ───────────────────────────────────────────────────────

#[test]
fn test_roundtrip_simple() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b", "c"]).unwrap();
    w.write_row(["1", "2", "3"]).unwrap();
    let csv_data = w.into_inner().unwrap();
    let mut out = Vec::new();
    for row in Reader::from_reader(Cursor::new(csv_data)).rows() {
        out.push(row.all().unwrap());
    }
    assert_eq!(
        out,
        vec![
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            vec!["1".to_string(), "2".to_string(), "3".to_string()],
        ]
    );
}

#[test]
fn test_roundtrip_quotes_commas() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello, world", "foo\"bar"]).unwrap();
    let csv_data = w.into_inner().unwrap();
    let mut out = Vec::new();
    for row in Reader::from_reader(Cursor::new(csv_data)).rows() {
        out.push(row.all().unwrap());
    }
    assert_eq!(out[0], vec!["hello, world", "foo\"bar"]);
}

// ── Reader: Buffer boundary tests ──────────────────────────────────

#[test]
fn test_chunked_escaped_quote_at_buffer_boundary() {
    let data = b"\"hello\"\"world\",second\n";
    let mut reader = Reader::from_reader(ChunkReader::new(data, 1));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert_eq!(row.len(), 2);
    let fields: Vec<&str> = row.fields().unwrap().collect();
    assert_eq!(fields[0], "hello\"world");
    assert_eq!(fields[1], "second");
}

#[test]
fn test_chunked_escaped_quote_pair_at_boundary() {
    let before = "x".repeat(100);
    let data = format!("\"{before}\"\"more\",rest\n");
    let mut reader = Reader::from_reader(ChunkReader::new(data.as_bytes(), 16));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    let fields: Vec<&str> = row.fields().unwrap().collect();
    let expected = format!("{before}\"more");
    assert_eq!(fields[0], expected);
}

#[test]
fn test_chunked_crlf_at_boundary() {
    let before = "x".repeat(16380);
    let data = format!("first,{before}\r\nsecond,line\n");
    let mut reader = Reader::from_reader(ChunkReader::new(data.as_bytes(), 16));
    let mut rows = reader.rows();
    let row1 = rows.next().unwrap();
    assert_eq!(row1.len(), 2);
    assert_eq!(row1.fields().unwrap().collect::<Vec<&str>>()[1].len(), 16380);
    let row2 = rows.next().unwrap();
    assert_eq!(row2.len(), 2);
    let fields: Vec<&str> = row2.fields().unwrap().collect();
    assert_eq!(fields[0], "second");
    assert_eq!(fields[1], "line");
}

#[test]
fn test_chunked_delimiter_at_boundary() {
    let data = b"abc,def,ghi\n123,456,789\n";
    let mut reader = Reader::from_reader(ChunkReader::new(data, 4));
    let rows: Vec<Vec<String>> = reader.rows().map(|r| r.all().unwrap()).collect();
    assert_eq!(rows[0], vec!["abc", "def", "ghi"]);
    assert_eq!(rows[1], vec!["123", "456", "789"]);
}

#[test]
fn test_chunked_quoted_field_spanning_multiple_reads() {
    let inner = "x".repeat(50000);
    let data = format!("a,\"{inner}\",b\nc,d,e\n");
    let mut reader = Reader::from_reader(ChunkReader::new(data.as_bytes(), 4096));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert_eq!(row.len(), 3);
    let fields: Vec<&str> = row.fields().unwrap().collect();
    assert_eq!(fields[0], "a");
    assert_eq!(fields[1], inner);
    assert_eq!(fields[2], "b");
}

// ── Reader: IO error propagation ────────────────────────────────────

#[test]
fn test_io_error_reported() {
    let data = b"a,b\n1,2\n3,4\n";
    let reader = ErrorAfterReader::new(data.to_vec(), 5);
    let mut reader = Reader::from_reader(reader);
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.error().is_none());
    assert_eq!(row.all().unwrap(), vec!["a", "b"]);
    let row = rows.next().unwrap();
    assert!(row.error().is_some());
    assert!(matches!(row.error().unwrap().kind(), ReadErrorKind::Io));
    assert!(rows.next().is_none());
}

#[test]
fn test_io_error_while_in_quoted() {
    let data = b"a,\"unterminated data that never closes\n";
    let reader = ErrorAfterReader::new(data.to_vec(), 10);
    let mut reader = Reader::from_reader(reader);
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.error().is_some());
}

// ── Reader: More edge cases ────────────────────────────────────────

#[test]
fn test_only_blank_lines() {
    let rows = collect_rows(b"\n\n\n\r\n\r\n");
    assert_eq!(rows.len(), 0);
}

#[test]
fn test_single_quoted_field_only() {
    let rows = collect_rows(b"\"hello\"\n");
    assert_eq!(rows[0], vec!["hello"]);
}

#[test]
fn test_all_quoted_fields() {
    let rows = collect_rows(b"\"a\",\"b\",\"c\"\n\"1\",\"2\",\"3\"\n");
    assert_eq!(rows[0], vec!["a", "b", "c"]);
    assert_eq!(rows[1], vec!["1", "2", "3"]);
}

#[test]
fn test_quote_in_middle_of_unquoted_field() {
    let rows = collect_rows(b"hello\"world,foo\n");
    assert_eq!(rows[0], vec!["hello\"world", "foo"]);
}

#[test]
fn test_trailing_delimiter_with_newline() {
    let rows = collect_rows(b"a,b,\n");
    assert_eq!(rows[0], vec!["a", "b", ""]);
}

#[test]
fn test_blank_line_between_data() {
    let rows = collect_rows(b"a,b\n\nc,d\n");
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_row_with_single_field_no_newline() {
    let rows = collect_rows(b"hello");
    assert_eq!(rows[0], vec!["hello"]);
}

#[test]
fn test_three_delimiters_empty_fields() {
    let rows = collect_rows(b",,,\n");
    assert_eq!(rows[0], vec!["", "", "", ""]);
}

#[test]
fn test_leading_trailing_blank_lines() {
    let rows = collect_rows(b"\n\na,b\nc,d\n\n\n");
    assert_eq!(rows.len(), 2);
}

// ── Reader: Row method tests ───────────────────────────────────────

#[test]
fn test_row_debug() {
    let mut reader = Reader::from_reader(Cursor::new(b"hello,world\n"));
    let row = reader.rows().next().unwrap();
    let debug = format!("{:?}", row);
    assert!(debug.starts_with("["), "debug starts with '[', got: {debug}");
    assert!(debug.contains("hello"), "debug contains 'hello', got: {debug}");
}

#[test]
fn test_row_len_and_is_empty() {
    let mut reader = Reader::from_reader(Cursor::new(b"a,b,c\nhello\n"));
    let mut rows = reader.rows();
    let r = rows.next().unwrap();
    assert_eq!(r.len(), 3);
    assert!(!r.is_empty());
    // blank lines are skipped — next row is "hello"
    let r = rows.next().unwrap();
    assert_eq!(r.len(), 1);
    assert!(!r.is_empty());
}

#[test]
fn test_fields_exact_size_iterator() {
    use std::iter::ExactSizeIterator;
    let mut reader = Reader::from_reader(Cursor::new(b"a,b,c\n"));
    let row = reader.rows().next().unwrap();
    let fields = row.fields().unwrap();
    assert_eq!(fields.len(), 3);
}

#[test]
fn test_row_all_error_propagation() {
    let mut reader = Reader::from_reader(Cursor::new(b"\"hello\" garbage\n"));
    let row = reader.rows().next().unwrap();
    assert!(row.all().is_err());
}

// ── Reader: Headers ─────────────────────────────────────────────────

#[test]
fn test_headers_empty_csv() {
    let mut reader = Reader::from_reader(Cursor::new(b""));
    let headers = reader.parse_headers().unwrap();
    assert!(headers.is_empty());
    assert!(reader.rows().next().is_none());
}

#[test]
fn test_headers_none_before_parse() {
    let reader = Reader::from_reader(Cursor::new(b"a,b\n1,2\n"));
    assert!(reader.headers().is_none());
}

#[test]
fn test_headers_after_parse() {
    let mut reader = Reader::from_reader(Cursor::new(b"name,age\nAlice,30\n"));
    reader.parse_headers().unwrap();
    assert_eq!(reader.headers().unwrap(), &["name", "age"]);
}

// ── Reader: Error display ──────────────────────────────────────────

#[test]
fn test_error_display_unterminated_quote() {
    let e = ReadError::new(ReadErrorKind::UnterminatedQuote, 5, 10);
    let s = e.to_string();
    assert!(s.contains("unterminated quote"));
    assert!(s.contains("line 5"));
}

#[test]
fn test_error_display_trailing_content() {
    let e = ReadError::new(ReadErrorKind::TrailingContent, 3, 0);
    let s = e.to_string();
    assert!(s.contains("trailing content"));
}

#[test]
fn test_error_display_io() {
    let e = ReadError::new(ReadErrorKind::Io, 1, 0);
    let s = e.to_string();
    assert!(s.contains("I/O error"));
}

// ── Writer: additional edge cases ──────────────────────────────────

#[test]
fn test_writer_empty_row() {
    let mut w = Writer::new(Vec::new());
    let empty: &[&str] = &[];
    w.write_row(empty).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\r\n");
}

#[test]
fn test_writer_newline_in_field() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello\nworld"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"hello\nworld\"\r\n");
}

#[test]
fn test_writer_cr_in_field() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello\rworld"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"hello\rworld\"\r\n");
}

#[test]
fn test_writer_no_rows() {
    let w = Writer::new(Vec::new());
    let result = w.into_inner().unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_writer_flush_twice() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a"]).unwrap();
    w.flush().unwrap();
    w.flush().unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a\r\n");
}

// ── Reader: set_delimiter builder pattern ──────────────────────────

#[test]
fn test_set_delimiter_chaining() {
    let data = b"a:b:c\n1:2:3\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    reader.set_delimiter(b':').set_delimiter(b':');
    let rows: Vec<Vec<String>> = reader.rows().map(|r| r.all().unwrap()).collect();
    assert_eq!(rows[0], vec!["a", "b", "c"]);
}

// ── Writer: Auto-quote with special chars combined ──────────────────

#[test]
fn test_writer_field_with_delimiter_and_quote() {
    let mut w = Writer::new(Vec::new());
    w.write_row([r#"hello, "world""#]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"hello, \"\"world\"\"\"\r\n");
}

// ── Roundtrip: additional ──────────────────────────────────────────

#[test]
fn test_roundtrip_with_newlines_in_fields() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello\nworld", "foo\r\nbar"]).unwrap();
    let csv_data = w.into_inner().unwrap();
    let mut out = Vec::new();
    for row in Reader::from_reader(Cursor::new(csv_data)).rows() {
        out.push(row.all().unwrap());
    }
    assert_eq!(out[0], vec!["hello\nworld", "foo\r\nbar"]);
}

// ── Reader: UTF-8 validation ─────────────────────────────────────────

#[test]
fn test_invalid_utf8_in_unquoted_field() {
    let data = b"a,\xff,b\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.error().is_some());
    assert!(matches!(row.error().unwrap().kind(), ReadErrorKind::InvalidUtf8));
}

#[test]
fn test_invalid_utf8_in_quoted_field() {
    let data = b"a,\"\xff\",b\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.error().is_some());
    assert!(matches!(row.error().unwrap().kind(), ReadErrorKind::InvalidUtf8));
}

#[test]
fn test_invalid_utf8_sets_error_not_panic() {
    let data = b"\xff,bar\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(row.fields().is_err());
    assert!(matches!(row.error().unwrap().kind(), ReadErrorKind::InvalidUtf8));
}

#[test]
fn test_null_bytes_in_field() {
    let rows = collect_rows(b"a,\0,c\n");
    assert_eq!(rows[0], vec!["a", "\0", "c"]);
}

// ── Reader: from_bytes convenience ────────────────────────────────────

#[test]
fn test_from_bytes_convenience() {
    let mut reader = Reader::from_bytes(b"a,b,c\n1,2,3\n");
    let rows: Vec<Vec<String>> = reader.rows().map(|r| r.all().unwrap()).collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], vec!["a", "b", "c"]);
    assert_eq!(rows[1], vec!["1", "2", "3"]);
}

// ── Reader: CR at EOF edge cases ──────────────────────────────────────

#[test]
fn test_cr_at_eof() {
    let rows = collect_rows(b"a,b\r");
    assert_eq!(rows[0], vec!["a", "b"]);
}

#[test]
fn test_crlf_split_chunk_boundary() {
    let before = "x".repeat(16380);
    let data = format!("aaa,{before}\r\n");
    let mut reader = Reader::from_reader(ChunkReader::new(data.as_bytes(), 4096));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert_eq!(row.len(), 2);
    let fields: Vec<&str> = row.fields().unwrap().collect();
    assert_eq!(fields[0], "aaa");
    assert_eq!(fields[1].len(), 16380);
}

// ── Reader: Error display for new variants ────────────────────────────

#[test]
fn test_error_display_invalid_utf8() {
    let e = ReadError::new(ReadErrorKind::InvalidUtf8, 4, 0);
    let s = e.to_string();
    assert!(s.contains("invalid UTF-8"));
    assert!(s.contains("line 4"));
}

// ── Reader: Trailing content after closing quote across boundary ──────

#[test]
fn test_trailing_content_after_quote_at_boundary() {
    let data = b"\"hello\"garbage\n";
    let mut reader = Reader::from_reader(ChunkReader::new(data, 1));
    let mut rows = reader.rows();
    let row = rows.next().unwrap();
    assert!(matches!(row.error().unwrap().kind(), ReadErrorKind::TrailingContent));
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
        let mut reader = Reader::from_reader(Cursor::new(data));
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
        let mut reader = Reader::from_reader(Cursor::new(data));
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
        let mut reader = Reader::from_reader(Cursor::new(data));
        reader.parse_headers().unwrap();
        let p: Person = reader.rows().next().unwrap().deserialize().unwrap();
        assert_eq!(p.name, "Alice");
        assert_eq!(p.age, 30);
    }

    #[test]
    fn test_deserialize_type_mismatch() {
        let data = b"name,age\nAlice,not_a_number\n";
        let mut reader = Reader::from_reader(Cursor::new(data));
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
        let mut reader = Reader::from_reader(Cursor::new(data));
        reader.parse_headers().unwrap();
        let row = reader.rows().next().unwrap();
        // city is not in headers -> defaults to ""
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
        let mut reader = Reader::from_reader(Cursor::new(data));
        let mut rows = reader.rows();
        let t1: (String, u32) = rows.next().unwrap().deserialize().unwrap();
        assert_eq!(t1, ("Alice".to_string(), 30));
    }
}

// ── Reader: field_bytes for non-UTF-8 data ────────────────────────────

#[test]
fn test_invalid_utf8_second_row_ok_first_row() {
    let data = b"a,b\nc,\xff\n";
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut rows = reader.rows();
    // First row is valid
    let row1 = rows.next().unwrap();
    assert_eq!(row1.all().unwrap(), vec!["a", "b"]);
    // Second row has invalid UTF-8 in second field
    let row2 = rows.next().unwrap();
    assert!(row2.error().is_some());
    assert!(matches!(row2.error().unwrap().kind(), ReadErrorKind::InvalidUtf8));
}
