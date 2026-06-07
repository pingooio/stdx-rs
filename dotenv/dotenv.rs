#![cfg_attr(docsrs, feature(doc_cfg))]

//! Loads environment variables from `.env` files.
//!
//! # Quick start
//!
//! ```rust,ignore
//! dotenv::load();
//! ```
//!
//! Call [`load`] near the start of your program to load a `.env` file
//! from the current working directory.
//!
//! # Precedence
//!
//! - **Existing environment variables are never overwritten.** A variable
//!   already set in the environment takes priority over anything in `.env`.
//! - **First declaration wins in `.env`.** If the same key appears multiple
//!   times, only the first is used.
//!
//! # Supported syntax
//!
//! ```env
//! HELLO=world
//! HELLO="world"
//! HELLO='world'
//! HELLO='"nested"'
//! HELLO=world  # inline comment
//! # full-line comment
//! ```
//!
//! ## Key names
//!
//! Keys may only contain ASCII letters, digits, `_`, `.`, and `-`.
//!
//! ## Limitations
//!
//! - Multi-line values are not supported.
//! - Variable substitution (e.g. `${FOO}`) is not supported.
//! - Export syntax (`export KEY=value`) is not supported.

use std::{collections::HashSet, env, fmt, fs, io};

/// Errors that can occur when loading a `.env` file.
#[derive(Debug)]
pub enum Error {
    /// An I/O error (file not found, permissions, etc.).
    Io(io::Error),
    /// A parse error on a specific line.
    Parse(ParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "dotenv I/O error: {e}"),
            Error::Parse(e) => write!(f, "dotenv parse error at line {}: {}", e.line, e.kind),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            Error::Parse(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// A parse error with the line number and kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The 1-indexed line number where the error occurred.
    pub line: usize,
    /// The kind of parse error.
    pub kind: ParseErrorKind,
}

/// The specific kind of parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A line without an `=` sign.
    MissingEquals,
    /// A quoted value (`"..."` or `'...'`) without a closing quote.
    UnmatchedQuote,
    /// A line with an empty key before the `=` sign.
    EmptyKey,
    /// A key containing characters outside the allowed set
    /// (alphanumeric, `_`, `.`, `-`).
    InvalidKey,
    /// Extra content found after a closing quote.
    TrailingContent,
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseErrorKind::MissingEquals => f.write_str("missing equals sign"),
            ParseErrorKind::UnmatchedQuote => f.write_str("unmatched quote"),
            ParseErrorKind::EmptyKey => f.write_str("empty key"),
            ParseErrorKind::InvalidKey => f.write_str("invalid key character"),
            ParseErrorKind::TrailingContent => f.write_str("trailing content after closing quote"),
        }
    }
}

/// Loads the `.env` file from the current working directory.
///
/// Each key-value pair found in the file is set as an environment variable
/// for the current process, subject to these rules:
///
/// 1. A variable already present in the environment is not overwritten.
/// 2. When the same key appears multiple times in `.env`, the first
///    declaration takes effect.
///
/// # Errors
///
/// Returns [`Error`] if the file cannot be read (missing, permissions,
/// etc.) or if the `.env` file is malformed.
///
/// # Example
///
/// ```rust,ignore
/// fn main() {
///     if let Err(e) = dotenv::load() {
///         eprintln!("Failed to load .env: {e}");
///     }
/// }
/// ```
pub fn load() -> Result<(), Error> {
    let mut path = env::current_dir()?;
    path.push(".env");
    let content = fs::read_to_string(&path)?;
    let pairs = parse(&content)?;

    let existing: HashSet<String> = env::vars().map(|(k, _)| k).collect();

    let mut seen = HashSet::new();
    for (key, value) in &pairs {
        if seen.insert(key.clone()) && !existing.contains(key.as_str()) {
            // SAFETY: single-threaded at startup, no concurrent access to env
            unsafe { env::set_var(key, value) };
        }
    }
    Ok(())
}

/// Parse a `.env` file string into a list of `(key, value)` pairs.
fn parse(input: &str) -> Result<Vec<(String, String)>, Error> {
    let mut pairs = Vec::new();

    for (line_idx, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim_start();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let eq_pos = line.find('=').ok_or_else(|| {
            Error::Parse(ParseError {
                line: line_idx + 1,
                kind: ParseErrorKind::MissingEquals,
            })
        })?;

        let key = line[..eq_pos].trim_end();
        let value_str = &line[eq_pos + 1..];

        if key.is_empty() {
            return Err(Error::Parse(ParseError {
                line: line_idx + 1,
                kind: ParseErrorKind::EmptyKey,
            }));
        }

        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            return Err(Error::Parse(ParseError {
                line: line_idx + 1,
                kind: ParseErrorKind::InvalidKey,
            }));
        }

        let value = parse_value(value_str, line_idx + 1)?;
        pairs.push((key.to_string(), value));
    }

    Ok(pairs)
}

/// Parse a single value string (everything after `=`).
fn parse_value(s: &str, line: usize) -> Result<String, Error> {
    let trimmed = s.trim();

    if trimmed.is_empty() {
        return Ok(String::new());
    }

    match trimmed.as_bytes()[0] {
        b'"' => {
            let rest = &trimmed[1..];
            let close = rest.find('"').ok_or_else(|| {
                Error::Parse(ParseError {
                    line,
                    kind: ParseErrorKind::UnmatchedQuote,
                })
            })?;
            let after = rest[close + 1..].trim();
            if !after.is_empty() && !after.starts_with('#') {
                return Err(Error::Parse(ParseError {
                    line,
                    kind: ParseErrorKind::TrailingContent,
                }));
            }
            Ok(rest[..close].to_string())
        }
        b'\'' => {
            let rest = &trimmed[1..];
            let close = rest.find('\'').ok_or_else(|| {
                Error::Parse(ParseError {
                    line,
                    kind: ParseErrorKind::UnmatchedQuote,
                })
            })?;
            let after = rest[close + 1..].trim();
            if !after.is_empty() && !after.starts_with('#') {
                return Err(Error::Parse(ParseError {
                    line,
                    kind: ParseErrorKind::TrailingContent,
                }));
            }
            Ok(rest[..close].to_string())
        }
        _ => {
            let comment_start = s
                .as_bytes()
                .windows(2)
                .position(|w| w[0].is_ascii_whitespace() && w[1] == b'#')
                .map(|i| i + 1);
            let val = match comment_start {
                Some(pos) => &s[..pos],
                None => s,
            };
            Ok(val.trim().to_string())
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(input: &str) -> Vec<(String, String)> {
        parse(input).unwrap()
    }

    fn parse_kind(input: &str) -> ParseErrorKind {
        match parse(input).unwrap_err() {
            Error::Parse(e) => e.kind,
            _ => panic!("expected Parse error"),
        }
    }

    fn parse_line(input: &str) -> usize {
        match parse(input).unwrap_err() {
            Error::Parse(e) => e.line,
            _ => panic!("expected Parse error"),
        }
    }

    // Unsafe helper for tests — tests are single-threaded
    unsafe fn set_env(k: &str, v: &str) {
        unsafe { env::set_var(k, v) };
    }

    unsafe fn remove_env(k: &str) {
        unsafe { env::remove_var(k) };
    }

    // ── Basic parsing ──────────────────────────────────────────────────────

    #[test]
    fn simple_key_value() {
        assert_eq!(parse_ok("K=v"), vec![("K".into(), "v".into())]);
    }

    #[test]
    fn multiple_pairs() {
        let pairs = parse_ok("A=1\nB=2\nC=3");
        assert_eq!(
            pairs,
            vec![
                ("A".into(), "1".into()),
                ("B".into(), "2".into()),
                ("C".into(), "3".into()),
            ]
        );
    }

    #[test]
    fn value_with_equals() {
        assert_eq!(parse_ok("K=a=b=c"), vec![("K".into(), "a=b=c".into())]);
    }

    #[test]
    fn key_with_underscore() {
        assert_eq!(parse_ok("MY_KEY=val"), vec![("MY_KEY".into(), "val".into())]);
    }

    #[test]
    fn key_with_dot() {
        assert_eq!(parse_ok("my.key=val"), vec![("my.key".into(), "val".into())]);
    }

    #[test]
    fn key_with_hyphen() {
        assert_eq!(parse_ok("my-key=val"), vec![("my-key".into(), "val".into())]);
    }

    #[test]
    fn key_with_digits() {
        assert_eq!(parse_ok("KEY123=val"), vec![("KEY123".into(), "val".into())]);
    }

    #[test]
    fn key_mixed() {
        assert_eq!(parse_ok("A1.b-C_2=val"), vec![("A1.b-C_2".into(), "val".into())]);
    }

    #[test]
    fn key_starting_with_hyphen() {
        assert_eq!(parse_ok("-KEY=v"), vec![("-KEY".into(), "v".into())]);
    }

    #[test]
    fn key_starting_with_dot() {
        assert_eq!(parse_ok(".KEY=v"), vec![(".KEY".into(), "v".into())]);
    }

    #[test]
    fn key_starting_with_underscore() {
        assert_eq!(parse_ok("_KEY=v"), vec![("_KEY".into(), "v".into())]);
    }

    // ── Double-quoted values ───────────────────────────────────────────────

    #[test]
    fn double_quoted_value() {
        assert_eq!(parse_ok("K=\"hello\""), vec![("K".into(), "hello".into())]);
    }

    #[test]
    fn double_quoted_with_spaces() {
        assert_eq!(parse_ok("K=\"hello world\""), vec![("K".into(), "hello world".into())]);
    }

    #[test]
    fn double_quoted_empty() {
        assert_eq!(parse_ok("K=\"\""), vec![("K".into(), "".into())]);
    }

    #[test]
    fn double_quoted_hash_preserved() {
        assert_eq!(parse_ok("K=\"a#b\""), vec![("K".into(), "a#b".into())]);
    }

    #[test]
    fn double_quoted_equals_inside() {
        assert_eq!(parse_ok("K=\"a=b\""), vec![("K".into(), "a=b".into())]);
    }

    #[test]
    fn double_quoted_single_quotes_inside() {
        assert_eq!(parse_ok("K=\"it's ok\""), vec![("K".into(), "it's ok".into())]);
    }

    #[test]
    fn double_quoted_whitespace_preserved() {
        assert_eq!(parse_ok("K=\" hello \""), vec![("K".into(), " hello ".into())]);
    }

    #[test]
    fn double_quoted_trailing_content_error() {
        assert_eq!(parse_kind("K=\"hello\"extra"), ParseErrorKind::TrailingContent);
    }

    #[test]
    fn double_quoted_trailing_comment_allowed() {
        assert_eq!(parse_ok("K=\"hello\" # comment"), vec![("K".into(), "hello".into())]);
    }

    // ── Single-quoted values ───────────────────────────────────────────────

    #[test]
    fn single_quoted_value() {
        assert_eq!(parse_ok("K='hello'"), vec![("K".into(), "hello".into())]);
    }

    #[test]
    fn single_quoted_with_spaces() {
        assert_eq!(parse_ok("K='hello world'"), vec![("K".into(), "hello world".into())]);
    }

    #[test]
    fn single_quoted_empty() {
        assert_eq!(parse_ok("K=''"), vec![("K".into(), "".into())]);
    }

    #[test]
    fn single_quoted_hash_preserved() {
        assert_eq!(parse_ok("K='a#b'"), vec![("K".into(), "a#b".into())]);
    }

    #[test]
    fn single_quoted_double_quotes_inside() {
        assert_eq!(parse_ok(r#"K='"hello"'"#), vec![("K".into(), r#""hello""#.into())]);
    }

    #[test]
    fn single_quoted_whitespace_preserved() {
        assert_eq!(parse_ok("K=' hello '"), vec![("K".into(), " hello ".into())]);
    }

    #[test]
    fn single_quoted_trailing_content_error() {
        assert_eq!(parse_kind("K='hello'extra"), ParseErrorKind::TrailingContent);
    }

    // ── Quoted example from the spec ────────────────────────────────────────

    #[test]
    fn quoted_nested_example() {
        assert_eq!(parse_ok("HELLO='\"hello\"'"), vec![("HELLO".into(), "\"hello\"".into())]);
    }

    // ── Unquoted values ────────────────────────────────────────────────────

    #[test]
    fn unquoted_hash_is_comment() {
        assert_eq!(parse_ok("K=val # comment"), vec![("K".into(), "val".into())]);
    }

    #[test]
    fn unquoted_hash_no_space_not_comment() {
        assert_eq!(parse_ok("K=val#comment"), vec![("K".into(), "val#comment".into())]);
    }

    #[test]
    fn unquoted_trimmed() {
        assert_eq!(parse_ok("K=  val  "), vec![("K".into(), "val".into())]);
    }

    #[test]
    fn unquoted_trailing_spaces_before_comment() {
        assert_eq!(parse_ok("K=val   # comment"), vec![("K".into(), "val".into())]);
    }

    #[test]
    fn unquoted_value_with_numbers() {
        assert_eq!(parse_ok("PORT=8080"), vec![("PORT".into(), "8080".into())]);
    }

    #[test]
    fn unquoted_value_with_dots() {
        assert_eq!(parse_ok("HOST=192.168.1.1"), vec![("HOST".into(), "192.168.1.1".into())]);
    }

    #[test]
    fn unquoted_value_containing_quote() {
        assert_eq!(parse_ok("K=hello\"there"), vec![("K".into(), "hello\"there".into())]);
    }

    #[test]
    fn unquoted_value_containing_only_hash() {
        assert_eq!(parse_ok("K=#"), vec![("K".into(), "#".into())]);
    }

    #[test]
    fn unquoted_value_hash_without_preceding_space() {
        assert_eq!(parse_ok("K=val#ue"), vec![("K".into(), "val#ue".into())]);
    }

    #[test]
    fn unquoted_hash_with_preceding_space_is_comment() {
        assert_eq!(parse_ok("K=val #ue"), vec![("K".into(), "val".into())]);
    }

    // ── Empty values ───────────────────────────────────────────────────────

    #[test]
    fn empty_value_no_quotes() {
        assert_eq!(parse_ok("K="), vec![("K".into(), "".into())]);
    }

    #[test]
    fn empty_value_trailing_spaces() {
        assert_eq!(parse_ok("K=   "), vec![("K".into(), "".into())]);
    }

    #[test]
    fn empty_value_spaces_before_comment() {
        assert_eq!(parse_ok("K=   # comment"), vec![("K".into(), "".into())]);
    }

    // ── Whitespace handling ────────────────────────────────────────────────

    #[test]
    fn leading_whitespace_on_line() {
        assert_eq!(parse_ok("  K=v"), vec![("K".into(), "v".into())]);
    }

    #[test]
    fn trailing_whitespace_before_equals() {
        assert_eq!(parse_ok("K  =v"), vec![("K".into(), "v".into())]);
    }

    #[test]
    fn whitespace_around_equals() {
        assert_eq!(parse_ok("K = v"), vec![("K".into(), "v".into())]);
    }

    #[test]
    fn tabs_as_whitespace() {
        assert_eq!(parse_ok("\tK\t=\tv"), vec![("K".into(), "v".into())]);
    }

    // ── Comments ───────────────────────────────────────────────────────────

    #[test]
    fn full_line_comment() {
        assert!(parse_ok("# this is a comment").is_empty());
    }

    #[test]
    fn comment_with_leading_spaces() {
        assert!(parse_ok("  # indented comment").is_empty());
    }

    #[test]
    fn empty_lines_skipped() {
        assert!(parse_ok("\n\n\n").is_empty());
    }

    #[test]
    fn mixed_comments_and_values() {
        let pairs = parse_ok("# header\nA=1\n\nB=2 # inline\n");
        assert_eq!(pairs, vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
    }

    // ── Line endings ───────────────────────────────────────────────────────

    #[test]
    fn unix_line_endings() {
        assert_eq!(parse_ok("A=1\nB=2"), vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
    }

    #[test]
    fn windows_line_endings() {
        assert_eq!(parse_ok("A=1\r\nB=2"), vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
    }

    #[test]
    fn no_trailing_newline() {
        assert_eq!(parse_ok("A=1"), vec![("A".into(), "1".into())]);
    }

    #[test]
    fn single_line_no_newline() {
        assert_eq!(parse_ok("K=v"), vec![("K".into(), "v".into())]);
    }

    // ── Edge cases: empty / comment-only files ─────────────────────────────

    #[test]
    fn empty_file() {
        assert!(parse_ok("").is_empty());
    }

    #[test]
    fn only_comments() {
        assert!(parse_ok("# a\n# b\n# c").is_empty());
    }

    #[test]
    fn only_blank_lines() {
        assert!(parse_ok("\n\n \n\t\n").is_empty());
    }

    // ── Error cases ────────────────────────────────────────────────────────

    #[test]
    fn error_missing_equals() {
        assert_eq!(parse_kind("INVALID"), ParseErrorKind::MissingEquals);
    }

    #[test]
    fn error_missing_equals_with_comment() {
        assert_eq!(parse_kind("K # comment"), ParseErrorKind::MissingEquals);
    }

    #[test]
    fn error_empty_key() {
        assert_eq!(parse_kind("=value"), ParseErrorKind::EmptyKey);
    }

    #[test]
    fn error_empty_key_with_spaces() {
        assert_eq!(parse_kind("   =value"), ParseErrorKind::EmptyKey);
    }

    #[test]
    fn error_unmatched_double_quote() {
        assert_eq!(parse_kind("K=\"hello"), ParseErrorKind::UnmatchedQuote);
    }

    #[test]
    fn error_unmatched_single_quote() {
        assert_eq!(parse_kind("K='hello"), ParseErrorKind::UnmatchedQuote);
    }

    #[test]
    fn error_unmatched_double_quote_with_hash() {
        assert_eq!(parse_kind("K=\"hello#more"), ParseErrorKind::UnmatchedQuote);
    }

    #[test]
    fn error_trailing_content_double_quote() {
        assert_eq!(parse_kind("K=\"hello\"extra"), ParseErrorKind::TrailingContent);
    }

    #[test]
    fn error_trailing_content_single_quote() {
        assert_eq!(parse_kind("K='hello'extra"), ParseErrorKind::TrailingContent);
    }

    #[test]
    fn error_trailing_content_line_number() {
        assert_eq!(parse_line("A=1\nK=\"v\"x\nB=2"), 2);
    }

    #[test]
    fn error_invalid_key_exclamation() {
        assert_eq!(parse_kind("K!EY=v"), ParseErrorKind::InvalidKey);
    }

    #[test]
    fn error_invalid_key_dollar() {
        assert_eq!(parse_kind("\u{0024}KEY=v"), ParseErrorKind::InvalidKey);
    }

    #[test]
    fn error_invalid_key_at() {
        assert_eq!(parse_kind("KEY@=v"), ParseErrorKind::InvalidKey);
    }

    #[test]
    fn error_invalid_key_space() {
        assert_eq!(parse_kind("K EY=v"), ParseErrorKind::InvalidKey);
    }

    #[test]
    fn error_invalid_key_slash() {
        assert_eq!(parse_kind("KEY/VAL=v"), ParseErrorKind::InvalidKey);
    }

    #[test]
    fn error_invalid_key_unicode() {
        assert_eq!(parse_kind("K\u{00C9}Y=v"), ParseErrorKind::InvalidKey);
    }

    #[test]
    fn error_line_number_missing_equals() {
        assert_eq!(parse_line("A=1\nINVALID\nB=2"), 2);
    }

    #[test]
    fn error_line_number_invalid_key() {
        assert_eq!(parse_line("A=1\n\"$\"BAD=v\nB=2"), 2);
    }

    #[test]
    fn error_line_number_unmatched_quote() {
        assert_eq!(parse_line("A=1\nK=\"unclosed\nB=2"), 2);
    }

    // ── Unicode values ─────────────────────────────────────────────────────

    #[test]
    fn unicode_value_unquoted() {
        assert_eq!(parse_ok("K=h\u{00E9}llo"), vec![("K".into(), "h\u{00E9}llo".into())]);
    }

    #[test]
    fn unicode_value_double_quoted() {
        assert_eq!(parse_ok("K=\"h\u{00E9}llo\""), vec![("K".into(), "h\u{00E9}llo".into())]);
    }

    #[test]
    fn unicode_value_single_quoted() {
        assert_eq!(parse_ok("K='h\u{00E9}llo'"), vec![("K".into(), "h\u{00E9}llo".into())]);
    }

    // ── `load()` integration tests ─────────────────────────────────────────

    #[test]
    fn load_sets_vars() {
        let dir = env::temp_dir().join(format!("dotenv_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let env_path = dir.join(".env");
        fs::write(&env_path, "DOTENV_TEST_FOO=bar\nDOTENV_TEST_BAZ=qux").unwrap();

        let old = env::current_dir().ok();
        env::set_current_dir(&dir).unwrap();

        let result = load();

        if let Some(p) = old {
            let _ = env::set_current_dir(p);
        }
        let _ = fs::remove_file(&env_path);
        let _ = fs::remove_dir(&dir);

        assert!(result.is_ok());
        assert_eq!(env::var("DOTENV_TEST_FOO").unwrap(), "bar");
        assert_eq!(env::var("DOTENV_TEST_BAZ").unwrap(), "qux");

        unsafe { remove_env("DOTENV_TEST_FOO") };
        unsafe { remove_env("DOTENV_TEST_BAZ") };
    }

    #[test]
    fn load_preserves_existing_env_vars() {
        unsafe { set_env("DOTENV_EXISTING", "original") };

        let dir = env::temp_dir().join(format!("dotenv_test_existing_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let env_path = dir.join(".env");
        fs::write(&env_path, "DOTENV_EXISTING=from_file").unwrap();

        let old = env::current_dir().ok();
        env::set_current_dir(&dir).unwrap();

        let result = load();

        if let Some(p) = old {
            let _ = env::set_current_dir(p);
        }
        let _ = fs::remove_file(&env_path);
        let _ = fs::remove_dir(&dir);

        assert!(result.is_ok());
        assert_eq!(env::var("DOTENV_EXISTING").unwrap(), "original");

        unsafe { remove_env("DOTENV_EXISTING") };
    }

    #[test]
    fn load_first_declaration_wins() {
        let dir = env::temp_dir().join(format!("dotenv_test_first_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let env_path = dir.join(".env");
        fs::write(&env_path, "DOTENV_DUP=first\nDOTENV_DUP=second").unwrap();

        let old = env::current_dir().ok();
        env::set_current_dir(&dir).unwrap();

        let result = load();

        if let Some(p) = old {
            let _ = env::set_current_dir(p);
        }
        let _ = fs::remove_file(&env_path);
        let _ = fs::remove_dir(&dir);

        assert!(result.is_ok());
        assert_eq!(env::var("DOTENV_DUP").unwrap(), "first");

        unsafe { remove_env("DOTENV_DUP") };
    }

    #[test]
    fn load_file_not_found() {
        let dir = env::temp_dir().join(format!("dotenv_test_missing_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);

        let old = env::current_dir().ok();
        env::set_current_dir(&dir).unwrap();

        let result = load();

        if let Some(p) = old {
            let _ = env::set_current_dir(p);
        }
        let _ = fs::remove_dir(&dir);

        match result.unwrap_err() {
            Error::Io(_) => {}
            _ => panic!("expected Io error"),
        }
    }

    #[test]
    fn load_parse_error() {
        let dir = env::temp_dir().join(format!("dotenv_test_parse_err_{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let env_path = dir.join(".env");
        fs::write(&env_path, "A=1\nMALFORMED\nB=2").unwrap();

        let old = env::current_dir().ok();
        env::set_current_dir(&dir).unwrap();

        let result = load();

        if let Some(p) = old {
            let _ = env::set_current_dir(p);
        }
        let _ = fs::remove_file(&env_path);
        let _ = fs::remove_dir(&dir);

        match result.unwrap_err() {
            Error::Parse(e) => assert_eq!(e.line, 2),
            _ => panic!("expected Parse error"),
        }
    }
}
