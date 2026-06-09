use std::io::Cursor;

use csv2::*;

fn collect_rows(data: &[u8]) -> Vec<Vec<String>> {
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut out = Vec::new();
    for row in reader.rows() {
        out.push(row.all().unwrap());
    }
    out
}

fn collect_rows_result(data: &[u8]) -> Result<Vec<Vec<String>>, ReadError> {
    let mut reader = Reader::from_reader(Cursor::new(data));
    let mut out = Vec::new();
    for row in reader.rows() {
        out.push(row.all()?);
    }
    Ok(out)
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
