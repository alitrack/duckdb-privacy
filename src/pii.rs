//! Kind-based PII masking for the `mask` op.
//!
//! The Lua reference `mask` is *mode*-based only (star / hash / bin / suppress /
//! rand) and has no notion of "this is a phone number". `mask_cn` is the op that
//! classifies by kind. That split leaves `mask('13812345678','phone')` — the
//! form the README documents and the test suite uses — with nothing behind it.
//!
//! This module fills that hole with an explicit, auditable rule table. Rules are
//! data, not prose:
//!
//! | kind               | rule                                                     |
//! |--------------------|----------------------------------------------------------|
//! | phone / mobile     | 11 digits → first 3 + `****` + last 4                     |
//! | email              | keep first char of local part + `**` (per char) + domain  |
//! | name               | keep first and last char, `*` in between                  |
//! | id / idcard        | 18 or 15 chars → first 6 + `********`/`*****` + last 4    |
//! | bankcard / card    | 16..=19 digits → first 6 + `*` … + last 4                 |
//! | ip                 | first two octets kept, rest → `***`                       |
//! | address            | first 6 chars kept, rest → `***`                          |
//! | general / other    | star with head/tail from args (defaults 1 and 1)          |
//!
//! Anything that does not match its kind's shape falls back to `general`, so a
//! wrong `kind` degrades to plain starring instead of leaking the value.

use crate::json::Value;

use crate::mask::{f_opt, generic_star, is_compound_surname, s};

fn base(v: &str, head: usize, tail: usize) -> String {
    let chars: Vec<char> = v.chars().collect();
    // Clamp: head/tail come from a client f64 `as usize` and can be
    // usize::MAX (1e300), which would break the guard and OOB the slices.
    let n = chars.len();
    let head = head.min(n);
    let tail = tail.min(n);
    if n <= head + tail {
        return "*".repeat(n);
    }
    let h: String = chars[..head].iter().collect();
    let t: String = chars[n - tail..].iter().collect();
    format!("{}{}{}", h, "*".repeat(n - head - tail), t)
}

fn is_digits(v: &str) -> bool {
    !v.is_empty() && v.chars().all(|c| c.is_ascii_digit())
}

/// Digits/dashes/spaces preserved as separators, only digits starred.
fn mask_keep_separators(v: &str, head: usize, tail: usize) -> String {
    let digits: Vec<usize> = v
        .char_indices()
        .filter(|(_, c)| c.is_ascii_digit())
        .map(|(i, _)| i)
        .collect();
    let n = digits.len();
    if n <= head + tail {
        return "*".repeat(v.chars().count());
    }
    let mut out = String::with_capacity(v.len());
    for (pos, ch) in v.char_indices() {
        if ch.is_ascii_digit() {
            let idx = digits.iter().position(|&d| d == pos).unwrap_or(0);
            if idx < head || idx >= n - tail {
                out.push(ch);
            } else {
                out.push('*');
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Star the local part of an email, keep the first character and the domain.
fn mask_email(v: &str) -> String {
    match v.find('@') {
        Some(at) if at > 0 => {
            let local: Vec<char> = v[..at].chars().collect();
            let first: String = local.iter().take(1).collect();
            let stars = "*".repeat(local.len().saturating_sub(1));
            format!("{}{}{}", first, stars, &v[at..])
        }
        _ => generic_star(v, None, None),
    }
}

fn mask_name(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() <= 2 {
        // Two-character names: keep the surname only (same as mask_cn).
        let first2: String = chars.iter().take(2).collect();
        let keep = if chars.len() >= 2 && is_compound_surname(&first2) {
            2
        } else {
            1
        };
        if chars.len() <= keep {
            return "*".repeat(chars.len());
        }
        let h: String = chars[..keep].iter().collect();
        return format!("{}{}", h, "*".repeat(chars.len() - keep));
    }
    base(v, 1, 1)
}

fn mask_id(v: &str) -> String {
    if is_digits(v) && v.len() == 18 {
        return format!("{}{}{}", &v[..6], "*".repeat(8), &v[14..]);
    }
    if is_digits(v) && v.len() == 15 {
        return format!("{}{}{}", &v[..6], "*".repeat(5), &v[11..]);
    }
    generic_star(v, None, None)
}

fn mask_bankcard(v: &str) -> String {
    if is_digits(v) && (16..=19).contains(&v.len()) {
        return format!(
            "{}{}{}",
            &v[..6],
            "*".repeat(v.len() - 10),
            &v[v.len() - 4..]
        );
    }
    generic_star(v, None, None)
}

fn mask_phone(v: &str) -> String {
    let digits: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 11 && digits.starts_with('1') {
        // Preserve any separator layout the caller had, but star the middle.
        if digits.len() == v.chars().count() {
            return format!("{}{}{}", &v[..3], "****", &v[7..]);
        }
        return mask_keep_separators(v, 3, 4);
    }
    generic_star(v, None, None)
}

fn mask_ip(v: &str) -> String {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| is_digits(p) && p.len() <= 3) {
        return format!("{}.{}.{}.{}", parts[0], parts[1], "***", "***");
    }
    generic_star(v, None, None)
}

fn mask_address(v: &str) -> String {
    let chars: Vec<char> = v.chars().collect();
    if chars.len() <= 6 {
        return base(v, 1, 1);
    }
    let head: String = chars[..6].iter().collect();
    format!("{}***", head)
}

/// Canonicalise the many spellings callers use for the same kind.
pub fn canon_kind(kind: &str) -> &str {
    match kind.trim().to_ascii_lowercase().as_str() {
        "phone" | "mobile" | "cell" | "tel" | "手机" | "手机号" => "phone",
        "email" | "mail" | "邮箱" => "email",
        "name" | "person" | "姓名" => "name",
        "id" | "idcard" | "id_card" | "national_id" | "身份证" => "id",
        "bankcard" | "card" | "creditcard" | "银行卡" | "信用卡" => "bankcard",
        "ip" | "ipv4" => "ip",
        "address" | "addr" | "地址" => "address",
        _ => "general",
    }
}

/// `mask(value, kind)` — kind-aware PII masking with a safe general fallback.
pub fn mask_kind(p: &Value) -> String {
    let v = s(p, "v");
    if v.is_empty() {
        return String::new();
    }
    let kind = p.get_s("kind").unwrap_or("general").to_string();
    let head = f_opt(p, "head").map(|x| x.max(0.0) as usize).unwrap_or(1);
    let tail = f_opt(p, "tail").map(|x| x.max(0.0) as usize).unwrap_or(1);
    match canon_kind(&kind) {
        "phone" => mask_phone(&v),
        "email" => mask_email(&v),
        "name" => mask_name(&v),
        "id" => mask_id(&v),
        "bankcard" => mask_bankcard(&v),
        "ip" => mask_ip(&v),
        "address" => mask_address(&v),
        _ => base(&v, head, tail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn p(pairs: Vec<(&str, Value)>) -> Value {
        json::obj(pairs)
    }

    #[test]
    fn phone_keeps_prefix_and_suffix() {
        let v = p(vec![
            ("v", Value::Str("13812345678".into())),
            ("kind", Value::Str("phone".into())),
        ]);
        assert_eq!(mask_kind(&v), "138****5678");
        // "mobile" and Chinese spellings are aliases
        let v2 = p(vec![
            ("v", Value::Str("13812345678".into())),
            ("kind", Value::Str("手机".into())),
        ]);
        assert_eq!(mask_kind(&v2), "138****5678");
    }

    #[test]
    fn email_keeps_first_char_and_domain() {
        let v = p(vec![
            ("v", Value::Str("abc@example.com".into())),
            ("kind", Value::Str("email".into())),
        ]);
        assert_eq!(mask_kind(&v), "a**@example.com");
    }

    #[test]
    fn name_keeps_first_and_last() {
        let v = p(vec![
            ("v", Value::Str("张三丰".into())),
            ("kind", Value::Str("name".into())),
        ]);
        assert_eq!(mask_kind(&v), "张*丰");
        let two = p(vec![
            ("v", Value::Str("张三".into())),
            ("kind", Value::Str("name".into())),
        ]);
        assert_eq!(mask_kind(&two), "张*");
    }

    #[test]
    fn idcard_keeps_region_and_tail() {
        let v = p(vec![
            ("v", Value::Str("110101199003078515".into())),
            ("kind", Value::Str("id".into())),
        ]);
        assert_eq!(mask_kind(&v), "110101********8515");
    }

    #[test]
    fn unknown_kind_falls_back_to_starring() {
        let v = p(vec![
            ("v", Value::Str("whatever".into())),
            ("kind", Value::Str("nonsense".into())),
        ]);
        assert_eq!(mask_kind(&v), "w******r");
    }

    #[test]
    fn wrong_shape_degrades_to_general() {
        // "phone" kind on a non-phone value must not mangle or leak it.
        let v = p(vec![
            ("v", Value::Str("not-a-phone".into())),
            ("kind", Value::Str("phone".into())),
        ]);
        let out = mask_kind(&v);
        assert!(out.starts_with('n') && out.ends_with('e'), "{out}");
        assert!(out.contains('*'));
    }
}
