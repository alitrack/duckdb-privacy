//! Minimal JSON — ported from privacy.lua's inline encoder/decoder
//! (object/array/string/number/boolean/null, nested). Objects preserve
//! insertion order (matches the Lua outputs' key order for stable diffs).

use std::collections::HashMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    // Vec<(key, value)> — order-preserving object
    Obj(Vec<(String, Value)>),
    Arr(Vec<Value>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(p) => p.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn get_s(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| match v {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        })
    }
    pub fn get_f(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| match v {
            Value::Num(n) => Some(*n),
            _ => None,
        })
    }
    pub fn get_arr(&self, key: &str) -> Option<&Vec<Value>> {
        self.get(key).and_then(|v| match v {
            Value::Arr(a) => Some(a),
            _ => None,
        })
    }
    pub fn is_obj(&self) -> bool {
        matches!(self, Value::Obj(_))
    }
}

// ── encode ─────────────────────────────────────────────────────────

pub fn encode(v: &Value) -> String {
    let mut out = String::with_capacity(64);
    enc(v, &mut out);
    out
}

fn enc(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Num(n) => {
            if n.is_nan() {
                out.push_str("null");
            } else {
                // Lua json_encode uses string.format('%g', v)
                let _ = write!(out, "{}", fmt_g(*n));
            }
        }
        Value::Str(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        let _ = write!(out, "\\u{:04x}", c as u32);
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        Value::Arr(a) => {
            out.push('[');
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                enc(item, out);
            }
            out.push(']');
        }
        Value::Obj(p) => {
            out.push('{');
            for (i, (k, val)) in p.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                enc(&Value::Str(k.clone()), out);
                out.push(':');
                enc(val, out);
            }
            out.push('}');
        }
    }
}

/// Lua `string.format('%g', x)` equivalent: 6 significant digits,
/// exponent form when the fixed form would be too long.
pub fn fmt_g(x: f64) -> String {
    if x == 0.0 {
        return "0".into();
    }
    if !x.is_finite() {
        return "null".into();
    }
    // %.5e → 6 significant digits
    let sci = format!("{:.5e}", x);
    let (mant, exp) = sci.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    if (-4..6).contains(&exp) {
        // fixed form
        let digits = mant.replace('.', "");
        let sign_neg = digits.starts_with('-');
        let digits = digits.trim_start_matches('-');
        let dot_at = if exp >= 0 {
            exp as usize + 1
        } else {
            0
        };
        let mut s = String::new();
        if sign_neg {
            s.push('-');
        }
        if dot_at == 0 {
            s.push_str("0.");
            // digits[0] is the leading significant digit, so a value with
            // exponent -1 needs zero padding zeros, -2 needs one, etc.
            for _ in 0..(-exp - 1).max(0) {
                s.push('0');
            }
            s.push_str(digits);
        } else if dot_at >= digits.len() {
            s.push_str(digits);
            for _ in 0..(dot_at - digits.len()) {
                s.push('0');
            }
        } else {
            s.push_str(&digits[..dot_at]);
            s.push('.');
            s.push_str(&digits[dot_at..]);
        }
        // strip trailing zeros after '.'
        if let Some(dot) = s.find('.') {
            let trimmed = s[dot + 1..].trim_end_matches('0');
            if trimmed.is_empty() {
                s.truncate(dot);
            } else {
                s.truncate(dot + 1 + trimmed.len());
            }
        }
        s
    } else {
        let mant_trimmed = trim_zeros(mant);
        let mant_trimmed = mant_trimmed.strip_suffix('.').unwrap_or(&mant_trimmed);
        format!("{}e{}{:02}", mant_trimmed, if exp >= 0 { '+' } else { '-' }, exp.abs())
    }
}

fn trim_zeros(mant: &str) -> String {
    let m = mant.trim_end_matches('0');
    if m.ends_with('.') {
        m.to_string()
    } else {
        m.to_string()
    }
}

// ── decode ─────────────────────────────────────────────────────────

pub fn decode(s: &str) -> Result<Value, String> {
    let bytes = s.as_bytes();
    let mut pos = 0usize;
    let v = parse_value(s, bytes, &mut pos).map_err(|e| e)?;
    skip_ws(s, bytes, &mut pos);
    if pos != s.len() {
        return Err(format!("trailing data at pos {}", pos));
    }
    Ok(v)
}

fn skip_ws(s: &str, bytes: &[u8], pos: &mut usize) {
    while *pos < s.len() {
        match bytes[*pos] {
            b' ' | b'\t' | b'\n' | b'\r' => *pos += 1,
            _ => break,
        }
    }
}

fn parse_value(s: &str, bytes: &[u8], pos: &mut usize) -> Result<Value, String> {
    skip_ws(s, bytes, pos);
    if *pos >= s.len() {
        return Err(format!("unexpected end at pos {}", pos));
    }
    let c = bytes[*pos];
    match c {
        b'{' => {
            *pos += 1;
            let mut p = Vec::new();
            skip_ws(s, bytes, pos);
            if *pos < s.len() && bytes[*pos] == b'}' {
                *pos += 1;
                return Ok(Value::Obj(p));
            }
            loop {
                skip_ws(s, bytes, pos);
                let k = parse_string(s, bytes, pos)?;
                skip_ws(s, bytes, pos);
                if *pos >= s.len() || bytes[*pos] != b':' {
                    return Err(format!("expected : at pos {}", pos));
                }
                *pos += 1;
                let v = parse_value(s, bytes, pos)?;
                p.push((k, v));
                skip_ws(s, bytes, pos);
                if *pos >= s.len() {
                    return Err(format!("unterminated object at pos {}", pos));
                }
                match bytes[*pos] {
                    b',' => *pos += 1,
                    b'}' => {
                        *pos += 1;
                        return Ok(Value::Obj(p));
                    }
                    _ => return Err(format!("expected , or }} at pos {}", pos)),
                }
            }
        }
        b'[' => {
            *pos += 1;
            let mut a = Vec::new();
            skip_ws(s, bytes, pos);
            if *pos < s.len() && bytes[*pos] == b']' {
                *pos += 1;
                return Ok(Value::Arr(a));
            }
            loop {
                a.push(parse_value(s, bytes, pos)?);
                skip_ws(s, bytes, pos);
                if *pos >= s.len() {
                    return Err(format!("unterminated array at pos {}", pos));
                }
                match bytes[*pos] {
                    b',' => *pos += 1,
                    b']' => {
                        *pos += 1;
                        return Ok(Value::Arr(a));
                    }
                    _ => return Err(format!("expected , or ] at pos {}", pos)),
                }
            }
        }
        b'"' => Ok(Value::Str(parse_string(s, bytes, pos)?)),
        _ => {
            // number: optional '-', digits, optional '.', optional exponent
            let rest = &s[*pos..];
            if !rest.is_empty() && (rest.starts_with('-') || rest.starts_with(|c: char| c.is_ascii_digit())) {
                let mut i = 0usize;
                let rb = rest.as_bytes();
                if i < rb.len() && rb[i] == b'-' {
                    i += 1;
                }
                let mut saw_digit = false;
                while i < rb.len() && rb[i].is_ascii_digit() {
                    i += 1;
                    saw_digit = true;
                }
                if i < rb.len() && rb[i] == b'.' {
                    i += 1;
                    while i < rb.len() && rb[i].is_ascii_digit() {
                        i += 1;
                        saw_digit = true;
                    }
                }
                if i < rb.len() && (rb[i] == b'e' || rb[i] == b'E') {
                    i += 1;
                    if i < rb.len() && (rb[i] == b'+' || rb[i] == b'-') {
                        i += 1;
                    }
                    while i < rb.len() && rb[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                if saw_digit && i > 0 {
                    if let Ok(v) = rest[..i].parse::<f64>() {
                        *pos += i;
                        return Ok(Value::Num(v));
                    }
                }
            }
            if rest.starts_with("true") {
                *pos += 4;
                Ok(Value::Bool(true))
            } else if s[*pos..].starts_with("false") {
                *pos += 5;
                Ok(Value::Bool(false))
            } else if s[*pos..].starts_with("null") {
                *pos += 4;
                Ok(Value::Null)
            } else {
                Err(format!("unexpected value at pos {}", pos))
            }
        }
    }
}

fn parse_string(s: &str, bytes: &[u8], pos: &mut usize) -> Result<String, String> {
    if bytes[*pos] != b'"' {
        return Err(format!("expected string at pos {}", pos));
    }
    *pos += 1;
    let mut out = String::new();
    while *pos < s.len() {
        let c = bytes[*pos];
        if c == b'"' {
            *pos += 1;
            return Ok(out);
        }
        if c == b'\\' {
            // truncated escape: `*pos+1` runs past the buffer when the string
            // ends right on a backslash (was an unchecked OOB -> process abort).
            if *pos + 1 >= bytes.len() {
                return Err(format!("truncated escape at pos {}", pos));
            }
            let n = bytes[*pos + 1];
            match n {
                b'u' => {
                    // truncated \uXXXX: need 4 hex digits after \u
                    if *pos + 6 > s.len() {
                        return Err(format!("truncated \\u at pos {}", pos));
                    }
                    let hex = &s[*pos + 2..*pos + 6];
                    let cp = u32::from_str_radix(hex, 16).map_err(|_| format!("bad \\u at pos {}", pos))?;
                    push_char(&mut out, cp);
                    // \uXXXX is 6 chars; advance past all of it and skip the
                    // shared `*pos += 2` at the end of the match (the 2-char
                    // escapes fall through to that one). Without `continue` the
                    // escape consumed 8 bytes and a valid \uXXXX became an
                    // "unterminated string" error.
                    *pos += 6;
                    continue;
                }
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                _ => {
                    *pos += 2;
                    continue;
                }
            }
            *pos += 2;
        } else if c < 0x80 {
            out.push(c as char);
            *pos += 1;
        } else {
            // multi-byte UTF-8 char: copy the full char, advance by its byte len
            let ch_len = utf8_char_len(c);
            if *pos + ch_len > s.len() {
                return Err(format!("truncated utf8 char at pos {}", pos));
            }
            out.push_str(&s[*pos..*pos + ch_len]);
            *pos += ch_len;
        }
    }
    Err(format!("unterminated string at pos {}", pos))
}

/// Push a unicode codepoint (validates ≤ 0x10FFFF; the Lua reference only
/// produced < 0x800 via 1-3 byte UTF-8, but we accept the full range).
fn push_char(out: &mut String, cp: u32) {
    if let Some(ch) = char::from_u32(cp) {
        out.push(ch);
    }
}

/// Byte length of a UTF-8 char given its leading byte.
fn utf8_char_len(lead: u8) -> usize {
    if lead < 0x80 {
        1
    } else if lead >= 0xF0 {
        4
    } else if lead >= 0xE0 {
        3
    } else if lead >= 0xC0 {
        2
    } else {
        1 // stray continuation byte — treat as 1 to avoid infinite loop
    }
}

// ── helpers for op handlers ────────────────────────────────────────

/// Build an order-preserving object quickly.
pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
    Value::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

/// Ordered object from string keys.
pub fn obj_owned(pairs: Vec<(String, Value)>) -> Value {
    Value::Obj(pairs)
}

pub fn arr(items: Vec<Value>) -> Value {
    Value::Arr(items)
}

/// Look up a key in an ordered object, returning a mutable ref.
pub fn get_mut<'a>(p: &'a mut Vec<(String, Value)>, key: &str) -> Option<&'a mut Value> {
    p.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// Convert a Value into a string if it is a string, number (as %g), or bool.
pub fn to_str_lossy(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Num(n) => fmt_g(*n),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => String::new(),
    }
}

/// Parse f64 from a Value (numbers pass through; numeric strings parse).
pub fn to_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Num(n) => Some(*n),
        Value::Str(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

/// Flatten an object into a lookup map (helper for callers that want
/// hashmap ergonomics on top of the ordered form).
pub fn to_map(v: &Value) -> HashMap<String, &Value> {
    let mut m = HashMap::new();
    if let Value::Obj(p) = v {
        for (k, val) in p {
            m.insert(k.clone(), val);
        }
    }
    m
}

#[cfg(test)]
mod fmt_g_tests {
    use super::fmt_g;

    /// Regression: the negative-exponent branch used to emit one zero too many,
    /// which divided every value in (0, 1) by ten (0.9 → "0.09"). Epsilon
    /// budgets, p-values and ratios all flow through this formatter.
    #[test]
    fn sub_one_values_keep_their_scale() {
        assert_eq!(fmt_g(0.9), "0.9");
        assert_eq!(fmt_g(0.5), "0.5");
        assert_eq!(fmt_g(0.55), "0.55");
        assert_eq!(fmt_g(0.01), "0.01");
        assert_eq!(fmt_g(0.001), "0.001");
        assert_eq!(fmt_g(0.0001), "0.0001");
        assert_eq!(fmt_g(-0.9), "-0.9");
        assert_eq!(fmt_g(-0.001), "-0.001");
    }

    #[test]
    fn integral_and_large_values() {
        assert_eq!(fmt_g(0.0), "0");
        assert_eq!(fmt_g(1.0), "1");
        assert_eq!(fmt_g(2.0), "2");
        assert_eq!(fmt_g(1234.5), "1234.5");
        assert_eq!(fmt_g(100000.0), "100000");
    }

    #[test]
    fn tiny_values_switch_to_exponent() {
        assert_eq!(fmt_g(0.00001), "1e-05");
        assert_eq!(fmt_g(0.000001), "1e-06");
    }
}

#[cfg(test)]
mod truncated_escape_tests {
    use super::decode;

    /// Regression (P1): parse_string read `*pos+1` / `*pos+2..*pos+6` with no
    /// bounds check, so a string whose value ends right on a backslash (or a
    /// \u with fewer than 4 hex digits) indexed past the buffer and panicked
    /// -> SIGABRT the whole DuckDB process. These must return Err (→ NULL via
    /// dispatch), never panic. Inputs below are the raw JSON text to decode.
    #[test]
    fn backslash_at_eof_is_error_not_panic() {
        // value `abc\` with the backslash as the final byte of the buffer
        assert!(decode("{\"v\":\"abc\\").is_err());
    }

    #[test]
    fn truncated_unicode_escape_is_error_not_panic() {
        // `a\u0` leaves only 1 hex digit before the closing quote: *pos+6 runs
        // past the buffer (pre-fix: slice OOB -> panic). r## keeps `\u` literal.
        assert!(decode(r##"{"v":"a\u0"}"##).is_err());
        // zero hex digits after \u
        assert!(decode(r##"{"v":"a\u"}"##).is_err());
    }

    #[test]
    fn valid_escapes_still_parse() {
        let v = decode(r##"{"v":"a\nb\tc"}"##).unwrap();
        assert_eq!(v.get_s("v").unwrap(), "a\nb\tc");
        let v = decode(r##"{"v":"\u00e9"}"##).unwrap();
        assert_eq!(v.get_s("v").unwrap(), "\u{e9}");
    }
}
