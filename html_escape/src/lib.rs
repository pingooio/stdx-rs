use std::cmp::max;

pub fn escape(src: &str) -> String {
    let mut ret_val = String::with_capacity(max(4, src.len()));
    for c in src.chars() {
        let replacement = match c {
            // this character, when confronted, will start a tag
            '<' => "&lt;",
            // in an unquoted attribute, will end the attribute value
            '>' => "&gt;",
            // in an attribute surrounded by double quotes, this character will end the attribute value
            '\"' => "&quot;",
            // in an attribute surrounded by single quotes, this character will end the attribute value
            '\'' => "&apos;",
            // in HTML5, returns a bogus parse error in an unquoted attribute, while in SGML/HTML, it will end an attribute value surrounded by backquotes
            '`' => "&grave;",
            // in an unquoted attribute, this character will end the attribute
            '/' => "&#47;",
            // starts an entity reference
            '&' => "&amp;",
            // if at the beginning of an unquoted attribute, will get ignored
            '=' => "&#61;",
            // will end an unquoted attribute
            ' ' => "&#32;",
            '\t' => "&#9;",
            '\n' => "&#10;",
            '\x0c' => "&#12;",
            '\r' => "&#13;",
            // a spec-compliant browser will perform this replacement anyway, but the middleware might not
            '\0' => "&#65533;",
            // ALL OTHER CHARACTERS ARE PASSED THROUGH VERBATIM
            _ => {
                ret_val.push(c);
                continue;
            }
        };
        ret_val.push_str(replacement);
    }
    ret_val
}
