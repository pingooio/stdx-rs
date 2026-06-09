use std::borrow::Cow;

use csv_legacy::*;

// ── Reader: Basic Parsing ──────────────────────────────────────────

#[test]
fn test_rfc4180_example_1() {
    let data = b"aaa,bbb,ccc\r\nzzz,yyy,xxx\r\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 3);
    assert_eq!(rows[0].get_raw(0), Some("aaa"));
    assert_eq!(rows[0].get_raw(1), Some("bbb"));
    assert_eq!(rows[0].get_raw(2), Some("ccc"));
    assert_eq!(rows[1].get_raw(0), Some("zzz"));
    assert_eq!(rows[1].get_raw(1), Some("yyy"));
    assert_eq!(rows[1].get_raw(2), Some("xxx"));
}

#[test]
fn test_rfc4180_example_2() {
    let data = b"aaa,bbb,ccc\r\nzzz,yyy,xxx";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 3);
    assert_eq!(rows[1].len(), 3);
}

#[test]
fn test_rfc4180_example_3() {
    let data = b"field_name,field_name,field_name\r\naaa,bbb,ccc\r\nzzz,yyy,xxx\r\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].get_raw(0), Some("field_name"));
    assert_eq!(rows[1].get_raw(0), Some("aaa"));
}

#[test]
fn test_rfc4180_example_4() {
    let data = b"aaa,bbb,ccc";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 3);
    assert_eq!(rows[0].get_raw(0), Some("aaa"));
    assert_eq!(rows[0].get_raw(1), Some("bbb"));
    assert_eq!(rows[0].get_raw(2), Some("ccc"));
}

#[test]
fn test_rfc4180_example_5() {
    let data = b"\"aaa\",\"bbb\",\"ccc\"\r\nzzz,yyy,xxx\r\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows[0].get_raw(0), Some("\"aaa\""));
    assert_eq!(rows[0].get_raw(1), Some("\"bbb\""));
    assert_eq!(rows[0].get_raw(2), Some("\"ccc\""));
}

#[test]
fn test_rfc4180_example_6() {
    let data = b"\"aaa\",\"b\r\nbb\",\"ccc\"\r\nzzz,yyy,xxx\r\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get_raw(0), Some("\"aaa\""));
    assert_eq!(rows[0].get_raw(1), Some("\"b\r\nbb\""));
    assert_eq!(rows[0].get_raw(2), Some("\"ccc\""));
    assert_eq!(rows[1].get_raw(0), Some("zzz"));
    assert_eq!(rows[1].get_raw(1), Some("yyy"));
    assert_eq!(rows[1].get_raw(2), Some("xxx"));
}

#[test]
fn test_rfc4180_example_7() {
    let data = b"\"aaa\",\"b\"\"bb\",\"ccc\"";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_raw(0), Some("\"aaa\""));
    assert_eq!(rows[0].get_raw(1), Some("\"b\"\"bb\""));
    assert_eq!(rows[0].get_raw(2), Some("\"ccc\""));
}

// ── Reader: Line Endings ───────────────────────────────────────────

#[test]
fn test_crlf_endings() {
    let data = b"a,b\r\nc,d\r\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[1].len(), 2);
}

#[test]
fn test_lf_endings() {
    let data = b"a,b\nc,d\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[1].len(), 2);
}

#[test]
fn test_cr_endings() {
    let data = b"a,b\rc,d\r";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[1].len(), 2);
}

#[test]
fn test_mixed_endings() {
    let data = b"a,b\r\nc,d\ne,f\r";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 3);
    for row in &rows {
        assert_eq!(row.len(), 2);
    }
}

#[test]
fn test_no_trailing_newline() {
    let data = b"a,b\nc,d";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[1].len(), 2);
}

#[test]
fn test_single_line_no_newline() {
    let data = b"hello,world";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_raw(0), Some("hello"));
    assert_eq!(rows[0].get_raw(1), Some("world"));
}

// ── Reader: Edge Cases ─────────────────────────────────────────────

#[test]
fn test_empty_input() {
    let mut rows = Reader::new(b"").rows();
    assert!(rows.next().is_none());
}

#[test]
fn test_empty_field() {
    let data = b"a,,c\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.len(), 3);
    assert_eq!(row.get_raw(0), Some("a"));
    assert_eq!(row.get_raw(1), Some(""));
    assert_eq!(row.get_raw(2), Some("c"));
}

#[test]
fn test_empty_quoted_field() {
    let data = b"a,\"\",c\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.get_raw(0), Some("a"));
    assert_eq!(row.get_raw(1), Some("\"\""));
    assert_eq!(row.get_raw(2), Some("c"));
}

#[test]
fn test_all_empty_fields() {
    let data = b",,\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.len(), 3);
    for i in 0..3 {
        assert_eq!(row.get_raw(i), Some(""));
    }
}

#[test]
fn test_single_empty_line_is_skipped() {
    let mut rows = Reader::new(b"\n").rows();
    assert!(rows.next().is_none());
}

#[test]
fn test_blank_lines_skipped() {
    let data = b"a,b\n\n\nc,d\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.len(), 2);
    }
}

#[test]
fn test_leading_blank_lines() {
    let data = b"\n\na,b\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 2);
}

#[test]
fn test_escaped_quote_in_quoted_field() {
    let data = b"\"Say \"\"Hello\"\"\",world\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.len(), 2);
    assert_eq!(row.get_raw(0), Some("\"Say \"\"Hello\"\"\""));
    assert_eq!(row.get_raw(1), Some("world"));
}

#[test]
fn test_quoted_field_with_comma() {
    let data = b"a,\"b,c\",d\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.len(), 3);
    assert_eq!(row.get_raw(0), Some("a"));
    assert_eq!(row.get_raw(1), Some("\"b,c\""));
    assert_eq!(row.get_raw(2), Some("d"));
}

#[test]
fn test_quoted_field_with_embedded_newline() {
    let data = b"a,\"b\nc\",d\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_raw(1), Some("\"b\nc\""));
}

#[test]
fn test_quoted_field_with_embedded_crlf() {
    let data = b"a,\"b\r\nc\",d\r\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_raw(1), Some("\"b\r\nc\""));
}

#[test]
fn test_unicode_fields() {
    let data = "名前,年齢\n田中,30\n";
    let rows: Vec<_> = Reader::new(data.as_bytes())
        .rows()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get_raw(0), Some("名前"));
    assert_eq!(rows[0].get_raw(1), Some("年齢"));
    assert_eq!(rows[1].get_raw(0), Some("田中"));
    assert_eq!(rows[1].get_raw(1), Some("30"));
}

#[test]
fn test_unterminated_quote() {
    let data = b"a,\"unterminated\n";
    let result: Result<Vec<_>, _> = Reader::new(data).rows().collect();
    let err = result.unwrap_err();
    assert!(err.to_string().contains("unterminated quote"));
}

#[test]
fn test_row_into_iter_owned() {
    let data = b"a,b,c\n";
    let row = Reader::new(data).rows().next().unwrap().unwrap();
    let fields: Vec<String> = row.into_iter().collect();
    assert_eq!(fields, vec!["a", "b", "c"]);
}

#[test]
fn test_row_len_is_empty() {
    let data = b"a,b\n";
    let row = Reader::new(data).rows().next().unwrap().unwrap();
    assert_eq!(row.len(), 2);
    assert!(!row.is_empty());
}

#[test]
fn test_row_get_out_of_bounds() {
    let data = b"a,b\n";
    let row = Reader::new(data).rows().next().unwrap().unwrap();
    assert!(row.get_raw(2).is_none());
}

#[test]
fn test_custom_delimiter() {
    let data = b"a|b|c\n1|2|3\n";
    let mut reader = Reader::new(data);
    reader.set_delimiter(b'|');
    let rows: Vec<_> = reader.rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get_raw(0), Some("a"));
    assert_eq!(rows[0].get_raw(1), Some("b"));
    assert_eq!(rows[0].get_raw(2), Some("c"));
    assert_eq!(rows[1].get_raw(0), Some("1"));
    assert_eq!(rows[1].get_raw(1), Some("2"));
    assert_eq!(rows[1].get_raw(2), Some("3"));
}

#[test]
fn test_tab_delimiter() {
    let data = b"a\tb\tc\n";
    let mut reader = Reader::new(data);
    reader.set_delimiter(b'\t');
    let rows: Vec<_> = reader.rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get_raw(0), Some("a"));
    assert_eq!(rows[0].get_raw(1), Some("b"));
    assert_eq!(rows[0].get_raw(2), Some("c"));
}

// ── Reader: Unescaped fields ───────────────────────────────────────

#[test]
fn test_fields_basic() {
    let data = b"\"hello\",world,\"foo\"\"bar\"\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    let fields: Vec<Cow<'_, str>> = rows[0].fields().collect();
    assert_eq!(fields[0], "hello");
    assert_eq!(fields[1], "world");
    assert_eq!(fields[2], "foo\"bar");
}

#[test]
fn test_fields_empty() {
    let data = b"\"\",\" \"\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    let fields: Vec<Cow<'_, str>> = rows[0].fields().collect();
    assert_eq!(fields[0], "");
    assert_eq!(fields[1], " ");
}

#[test]
fn test_fields_borrowed() {
    let data = b"hello,world\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    for field in rows[0].fields() {
        assert!(matches!(field, Cow::Borrowed(_)));
    }
}

#[test]
fn test_fields_collect_string() {
    let data = b"\"hello\",\"foo\"\"bar\"\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    let fields: Vec<String> = rows[0].fields().map(|f| f.into_owned()).collect();
    assert_eq!(fields, vec!["hello", "foo\"bar"]);
}

// ── Writer: Basic ──────────────────────────────────────────────────

#[cfg(feature = "std")]
#[test]
fn test_writer_basic() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b", "c"]).unwrap();
    w.write_row(["1", "2", "3"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,b,c\r\n1,2,3\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_single_field() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "hello\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_empty_field() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "", "c"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,\"\",c\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_all_empty() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["", ""]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"\",\"\"\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_single_empty_field() {
    let mut w = Writer::new(Vec::new());
    w.write_row([""]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"\"\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_auto_quote_comma() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello, world"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"hello, world\"\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_auto_quote_newline() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["line1\nline2"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"line1\nline2\"\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_auto_quote_crlf() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["line1\r\nline2"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"line1\r\nline2\"\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_auto_quote_double_quote() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["say \"hello\""]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"say \"\"hello\"\"\"\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_no_quote_needed() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["hello world"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "hello world\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_custom_delimiter() {
    let mut w = Writer::new(Vec::new());
    w.delimiter(b'\t');
    w.write_row(["a", "b", "c"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a\tb\tc\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_auto_quote_custom_delimiter() {
    let mut w = Writer::new(Vec::new());
    w.delimiter(b'|');
    w.write_row(["a|b", "c"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "\"a|b\"|c\r\n");
}

// ── Writer: Field Count Validation ────────────────────────────────

#[cfg(feature = "std")]
#[test]
fn test_writer_field_count_consistent() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b", "c"]).unwrap();
    w.write_row(["1", "2", "3"]).unwrap();
    assert!(w.into_inner().is_ok());
}

#[cfg(feature = "std")]
#[test]
fn test_writer_field_count_mismatch() {
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
        _ => panic!("expected InconsistentFieldCount error"),
    }
}

#[cfg(feature = "std")]
#[test]
fn test_writer_field_count_mismatch_flexible() {
    let mut w = Writer::new(Vec::new());
    w.flexible(true);
    w.write_row(["a", "b", "c"]).unwrap();
    w.write_row(["1", "2"]).unwrap();
    let result = String::from_utf8(w.into_inner().unwrap()).unwrap();
    assert_eq!(result, "a,b,c\r\n1,2\r\n");
}

#[cfg(feature = "std")]
#[test]
fn test_writer_flush() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["a", "b"]).unwrap();
    w.flush().unwrap();
    assert_eq!(w.into_inner().unwrap(), b"a,b\r\n");
}

// ── Writer: Roundtrip ──────────────────────────────────────────────

#[cfg(feature = "std")]
fn roundtrip(records: &[&[&[u8]]]) {
    let mut w = Writer::new(Vec::new());
    for record in records {
        w.write_row(*record).unwrap();
    }
    let csv_data = w.into_inner().unwrap();

    let rows: Vec<_> = Reader::new(&csv_data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), records.len(), "roundtrip row count");

    for (i, expected) in records.iter().enumerate() {
        let actual: Vec<String> = rows[i].fields().map(|f| f.into_owned()).collect();
        let expected_str: Vec<String> = expected
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect();
        assert_eq!(actual.len(), expected_str.len(), "roundtrip row {i}: field count");
        for (j, (a, e)) in actual.iter().zip(expected_str.iter()).enumerate() {
            assert_eq!(a, e, "roundtrip row {i}, field {j}");
        }
    }
}

#[cfg(feature = "std")]
#[test]
fn test_roundtrip_simple() {
    roundtrip(&[&[b"a", b"b", b"c"], &[b"1", b"2", b"3"]]);
}

#[cfg(feature = "std")]
#[test]
fn test_roundtrip_with_commas() {
    roundtrip(&[&[b"hello, world", b"foo"]]);
}

#[cfg(feature = "std")]
#[test]
fn test_roundtrip_with_quotes() {
    roundtrip(&[&[b"say \"hi\"", b"bar"]]);
}

#[cfg(feature = "std")]
#[test]
fn test_roundtrip_with_newlines() {
    roundtrip(&[&[b"line1\nline2", b"foo"]]);
}

#[cfg(feature = "std")]
#[test]
fn test_roundtrip_empty_fields() {
    roundtrip(&[&[b"a", b"", b"c"], &[b"", b"b", b""]]);
}

#[cfg(feature = "std")]
#[test]
fn test_roundtrip_mixed() {
    roundtrip(&[&[b"plain", b"with, comma", b"with \" quote", b"with\nnewline"]]);
}

// ── Reader: from_reader streaming ──────────────────────────────────

#[cfg(feature = "std")]
#[test]
fn test_from_reader() {
    let data = b"a,b,c\n1,2,3\n";
    let reader = std::io::Cursor::new(data);
    let rows: Vec<_> = Reader::from_reader(reader)
        .rows()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get_raw(0), Some("a"));
    assert_eq!(rows[0].get_raw(1), Some("b"));
    assert_eq!(rows[0].get_raw(2), Some("c"));
    assert_eq!(rows[1].get_raw(0), Some("1"));
    assert_eq!(rows[1].get_raw(1), Some("2"));
    assert_eq!(rows[1].get_raw(2), Some("3"));
}

#[cfg(feature = "std")]
#[test]
fn test_from_reader_streaming_across_chunks() {
    let data = b"a,b,c,d,e,f,g,h,i,j\n1,2,3,4,5,6,7,8,9,10\n";
    let reader = std::io::Cursor::new(data);
    let rows: Vec<_> = Reader::from_reader(reader)
        .rows()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 10);
    assert_eq!(rows[1].len(), 10);
}

#[cfg(feature = "std")]
#[test]
fn test_from_reader_large_data() {
    let mut rows_out: Vec<String> = Vec::new();
    for i in 0..1000 {
        let fields: Vec<String> = (0..10).map(|j| format!("{i}-{j}")).collect();
        rows_out.push(fields.join(","));
    }
    let data = rows_out.join("\n").into_bytes();

    let reader = std::io::Cursor::new(data);
    let rows: Vec<_> = Reader::from_reader(reader)
        .rows()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), 1000);
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.len(), 10);
        let expected0 = format!("{i}-0");
        let expected9 = format!("{i}-9");
        assert_eq!(row.get_raw(0), Some(expected0.as_str()));
        assert_eq!(row.get_raw(9), Some(expected9.as_str()));
    }
}

// ── Writer: Roundtrip with streaming reader ────────────────────────

#[cfg(feature = "std")]
#[test]
fn test_write_then_read_streaming() {
    let mut w = Writer::new(Vec::new());
    w.write_row(["name", "age", "city"]).unwrap();
    w.write_row(["Alice", "30", "New York, NY"]).unwrap();
    w.write_row(["Bob", "25", "\"Hello\" said Bob"]).unwrap();
    let csv_data = w.into_inner().unwrap();

    let reader = std::io::Cursor::new(csv_data);
    let rows: Vec<_> = Reader::from_reader(reader)
        .rows()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows.len(), 3);
    let parsed: Vec<Vec<String>> = rows
        .iter()
        .map(|row| row.fields().map(|f| f.into_owned()).collect())
        .collect();
    assert_eq!(parsed[0], vec!["name", "age", "city"]);
    assert_eq!(parsed[1], vec!["Alice", "30", "New York, NY"]);
    assert_eq!(parsed[2], vec!["Bob", "25", "\"Hello\" said Bob"]);
}

// ── Reader: Trailing delimiter at EOF ─────────────────────────────

#[test]
fn test_trailing_delimiter_at_eof() {
    let data = b"a,b,";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 3);
    assert_eq!(rows[0].get_raw(0), Some("a"));
    assert_eq!(rows[0].get_raw(1), Some("b"));
    assert_eq!(rows[0].get_raw(2), Some(""));
}

#[test]
fn test_trailing_delimiter_only() {
    let data = b",";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[0].get_raw(0), Some(""));
    assert_eq!(rows[0].get_raw(1), Some(""));
}

#[test]
fn test_trailing_delimiter_with_newline() {
    let data = b"a,b,\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 3);
    assert_eq!(rows[0].get_raw(0), Some("a"));
    assert_eq!(rows[0].get_raw(1), Some("b"));
    assert_eq!(rows[0].get_raw(2), Some(""));
}

// ── Reader: Trailing content after quoted field ───────────────────

#[test]
fn test_trailing_content_after_quoted_field() {
    let data = b"\"hello\" garbage\n";
    let result: Result<Vec<_>, _> = Reader::new(data).rows().collect();
    let err = result.unwrap_err();
    assert_eq!(err.line, 1);
    assert!(matches!(err.kind(), ReadErrorKind::TrailingContent));
}

#[test]
fn test_trailing_content_after_quoted_field_at_eof() {
    let data = b"\"hello\"garbage";
    let result: Result<Vec<_>, _> = Reader::new(data).rows().collect();
    let err = result.unwrap_err();
    assert!(matches!(err.kind(), ReadErrorKind::TrailingContent));
}

#[test]
fn test_trailing_content_after_quoted_field_with_comma() {
    let data = b"\"hello\"x,world\n";
    let result: Result<Vec<_>, _> = Reader::new(data).rows().collect();
    let err = result.unwrap_err();
    assert!(matches!(err.kind(), ReadErrorKind::TrailingContent));
}

// ── Reader: Row::get_raw() and Index ──────────────────────────────

#[test]
fn test_row_get_valid() {
    let data = b"a,b,c\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows[0].get_raw(0), Some("a"));
    assert_eq!(rows[0].get_raw(1), Some("b"));
    assert_eq!(rows[0].get_raw(2), Some("c"));
}

#[test]
fn test_row_get_out_of_bounds_range() {
    let data = b"a,b\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows[0].get_raw(2), None);
    assert_eq!(rows[0].get_raw(usize::MAX), None);
}

#[test]
fn test_row_index() {
    let data = b"hello,world\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(&rows[0][0], "hello");
    assert_eq!(&rows[0][1], "world");
}

#[test]
#[should_panic(expected = "index out of bounds")]
fn test_row_index_panics() {
    let data = b"a,b\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    let _ = &rows[0][5];
}

// ── Reader: Fields ExactSizeIterator ──────────────────────────────

#[test]
fn test_fields_exact_size() {
    let data = b"\"hello\",world,\"foo\"\"bar\"\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    let iter = rows[0].fields();
    assert_eq!(iter.len(), 3);
    assert!(iter.size_hint() == (3, Some(3)));
    let fields: Vec<_> = iter.collect();
    assert_eq!(fields.len(), 3);
}

#[test]
fn test_fields_exact_size_empty() {
    let mut rows = Reader::new(b"\n").rows();
    assert!(rows.next().is_none());
}

// ── Reader: Invalid UTF-8 ─────────────────────────────────────────

#[test]
fn test_invalid_utf8_returns_error() {
    let data = b"hello,\xff\xffworld\n";
    let result: Result<Vec<_>, _> = Reader::new(data).rows().collect();
    let err = result.unwrap_err();
    assert!(matches!(err.kind(), ReadErrorKind::InvalidUtf8));
}

// ── Reader: ReadError::kind() accessor ────────────────────────────

#[test]
fn test_read_error_kind_unterminated_quote() {
    let data = b"\"unterminated";
    let result: Result<Vec<_>, _> = Reader::new(data).rows().collect();
    let err = result.unwrap_err();
    assert!(matches!(err.kind(), ReadErrorKind::UnterminatedQuote));
    assert_eq!(err.line, 1);
}

#[test]
fn test_read_error_kind_trailing_content() {
    let data = b"\"ok\"xyz\n";
    let result: Result<Vec<_>, _> = Reader::new(data).rows().collect();
    let err = result.unwrap_err();
    assert!(matches!(err.kind(), ReadErrorKind::TrailingContent));
}

// ── Reader: Additional edge cases ─────────────────────────────────

#[test]
fn test_only_delimiter_and_newline() {
    let data = b",\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[0].get_raw(0), Some(""));
    assert_eq!(rows[0].get_raw(1), Some(""));
}

#[test]
fn test_multiple_blank_lines_then_data() {
    let data = b"\n\n\na,b\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[0].get_raw(0), Some("a"));
    assert_eq!(rows[0].get_raw(1), Some("b"));
}

#[test]
fn test_leading_trailing_blank_lines() {
    let data = b"\n\na,b\n\nc,d\n\n";
    let rows: Vec<_> = Reader::new(data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[0].get_raw(0), Some("a"));
    assert_eq!(rows[1].len(), 2);
    assert_eq!(rows[1].get_raw(0), Some("c"));
}

// ── Potential Clippy checks ───────────────────────────────────────

#[test]
fn test_large_fields() {
    let large = "x".repeat(10000);
    let data = format!("{large},{large}\n");
    let rows: Vec<_> = Reader::new(data.as_bytes())
        .rows()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(rows[0].len(), 2);
    assert_eq!(rows[0].get_raw(0).unwrap().len(), 10000);
}

#[test]
fn test_many_fields() {
    let mut data: Vec<u8> = (0..100)
        .map(|i| {
            if i == 0 {
                format!("field{i}")
            } else {
                format!(",field{i}")
            }
        })
        .collect::<String>()
        .into_bytes();
    data.push(b'\n');
    let rows: Vec<_> = Reader::new(&data).rows().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(rows[0].len(), 100);
    assert_eq!(rows[0].get_raw(0), Some("field0"));
    assert_eq!(rows[0].get_raw(99), Some("field99"));
}

// ── Rows: iterator API tests ──────────────────────────────────────

#[test]
fn test_rows_for_loop() {
    let data = b"a,b\nc,d\n";
    let mut count = 0;
    for result in Reader::new(data).rows() {
        let row = result.unwrap();
        count += row.len();
    }
    assert_eq!(count, 4);
}

#[test]
fn test_rows_for_loop_with_error() {
    let data = b"a,b\n\"bad";
    let mut errors = 0usize;
    for result in Reader::new(data).rows() {
        if result.is_err() {
            errors += 1;
        }
    }
    assert_eq!(errors, 1);
}

#[test]
fn test_rows_collect_ok() {
    let data = b"x,y\n1,2\n";
    let rows: Vec<Row> = Reader::new(data).rows().collect::<Result<_, _>>().unwrap();
    assert_eq!(rows.len(), 2);
}

#[test]
fn test_rows_collect_err_stops_early() {
    let data = b"a,b\n\"bad\nc,d\n";
    let mut iter = Reader::new(data).rows();
    assert!(iter.next().unwrap().is_ok());
    assert!(iter.next().unwrap().is_err());
}

#[test]
fn test_rows_size_hint() {
    let rows = Reader::new(b"a,b\n").rows();
    let hint = rows.size_hint();
    assert_eq!(hint, (0, None));
}
