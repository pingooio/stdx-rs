//! HTML escaping functions for auto-escaping mode and the `escape` filter.

use crate::error::Error;

pub type EscaperFn = fn(&str, &mut String) -> Result<(), Error>;

/// HTML escaper (HTML mode)
pub fn html_escape(input: &str, output: &mut String) -> Result<(), Error> {
    output.reserve(input.len());
    for c in input.chars() {
        match c {
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            '&' => output.push_str("&amp;"),
            _ => output.push(c),
        }
    }
    Ok(())
}

/// Convenience wrapper that returns a new `String`.
pub fn html_escape_to_string(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            '&' => output.push_str("&amp;"),
            _ => output.push(c),
        }
    }
    output
}
