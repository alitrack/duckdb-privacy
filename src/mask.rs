//! PII masking: generic mask modes + CN-compliant rules (GB/T 37964) +
//! MIMIC-style date shifting. Ported from privacy.lua ops:
//! mask / mask_cn / dateshift / dateoffset.

use crate::json::{self, Value};
use crate::rng::{fnv1a, Rng};

pub(crate) fn s(v: &Value, k: &str) -> String {
    v.get(k).map(json::to_str_lossy).unwrap_or_default()
}
fn f(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(json::to_f64).unwrap_or(f64::NAN)
}
pub(crate) fn f_opt(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(json::to_f64)
}

// ── generic mask (op='mask') ───────────────────────────────────────

pub fn mask(p: &Value) -> String {
    let v = s(p, "v");
    let mode = p.get_s("mode").unwrap_or("star").to_string();
    match mode.as_str() {
        "hash" => {
            let keep = f_opt(p, "keep").unwrap_or(2.0) as usize;
            let fp = format!("{:08x}", fnv1a(&v, &s(p, "salt")));
            let head: String = v.chars().take(keep).collect();
            format!("{}#{}", head, fp)
        }
        "star" => {
            let head = f_opt(p, "head").unwrap_or(1.0) as usize;
            let tail = f_opt(p, "tail").unwrap_or(1.0) as usize;
            let chars: Vec<char> = v.chars().collect();
            if chars.len() <= head + tail {
                "*".repeat(chars.len())
            } else {
                let head_s: String = chars[..head].iter().collect();
                let tail_s: String = chars[chars.len() - tail..].iter().collect();
                format!("{}{}{}", head_s, "*".repeat(chars.len() - head - tail), tail_s)
            }
        }
        "bin" => {
            let x = v.parse::<f64>().ok();
            let Some(x) = x else {
                return "null".into();
            };
            let lo = f_opt(p, "lo").unwrap_or(0.0);
            let mut hi = f_opt(p, "hi").unwrap_or(100.0);
            let bins = f_opt(p, "bins").unwrap_or(5.0) as usize;
            if hi <= lo {
                hi = lo + 1.0;
            }
            let w = (hi - lo) / bins as f64;
            let mut b = ((x - lo) / w).floor() as i64;
            if b < 0 {
                b = 0;
            }
            if b >= bins as i64 {
                b = (bins - 1) as i64;
            }
            format!(
                "[{},{})",
                json::fmt_g(lo + b as f64 * w),
                json::fmt_g(lo + (b as f64 + 1.0) * w)
            )
        }
        "suppress" => crate::dp::SUPPRESS.to_string(),
        "rand" => {
            let salt = if s(p, "salt").is_empty() { "anon".to_string() } else { s(p, "salt") };
            let mut rng = Rng::new(i64::from(fnv1a(&v, &salt)));
            // Lua: make_rng(fnv1a(v, p.salt or 'anon')) — seed is the u32 hash
            format!("{}", (rng.next_f64() * 10000.0).floor() as i64)
        }
        _ => String::new(),
    }
}

// ── CN compliance (op='mask_cn') ───────────────────────────────────

/// Compound (复) surnames — keep 2 chars when the name starts with one.
pub(crate) fn is_compound_surname(first2: &str) -> bool {
    const S: &[&str] = &[
        "欧阳", "司马", "上官", "诸葛", "东方", "皇甫", "尉迟", "公孙", "慕容", "司徒",
        "令狐", "宇文", "长孙", "独孤", "南宫", "西门", "夏侯", "端木", "呼延", "澹台",
    ];
    S.contains(&first2)
}

/// Fail-closed generic star over UTF-8 chars (head/tail default 1/1).
pub(crate) fn generic_star(v: &str, head: Option<usize>, tail: Option<usize>) -> String {
    let head = head.unwrap_or(1);
    let tail = tail.unwrap_or(1);
    let chars: Vec<char> = v.chars().collect();
    if chars.len() <= head + tail {
        return "*".repeat(chars.len());
    }
    let head_s: String = chars[..head].iter().collect();
    let tail_s: String = chars[chars.len() - tail..].iter().collect();
    format!("{}{}{}", head_s, "*".repeat(chars.len() - head - tail), tail_s)
}

/// Value auto-detection (kind='auto').
fn cn_detect(v: &str) -> Option<String> {
    if v.chars().all(|c| c.is_ascii_digit()) {
        return match v.len() {
            18 | 15 => Some("idcard".into()),
            11 if v.starts_with('1') && matches!(v.chars().nth(1), Some(c) if ('3'..='9').contains(&c)) => {
                Some("mobile".into())
            }
            n if (16..=19).contains(&n) => Some("bankcard".into()),
            _ => None,
        };
    }
    if v.contains('@') {
        if let Some(at) = v.find('@') {
            let local = &v[..at];
            let domain = &v[at + 1..];
            if !local.is_empty()
                && !domain.is_empty()
                && local.bytes().all(|b| !b.is_ascii_whitespace())
                && domain.bytes().all(|b| !b.is_ascii_whitespace())
                && domain.contains('.')
            {
                return Some("email".into());
            }
        }
    }
    // CJK name: 2..6 chars, every char a 3-byte CJK unified ideograph
    let chars: Vec<char> = v.chars().collect();
    if (2..=6).contains(&chars.len())
        && chars.iter().all(|&c| ('\u{4e00}'..='\u{9fff}').contains(&c))
    {
        return Some("name".into());
    }
    None
}

pub fn mask_cn(p: &Value) -> String {
    let v = s(p, "v");
    if v.is_empty() {
        return String::new();
    }
    let mut kind = p.get_s("kind").unwrap_or("auto").to_string();
    if kind == "auto" {
        kind = cn_detect(&v).unwrap_or_else(|| "generic".into());
    }
    let mode = p.get_s("mode").unwrap_or("star").to_string();
    let fp = format!("{:08x}", fnv1a(&v, &s(p, "salt")));

    // hash mode: rule prefix + fingerprint (deterministic → join key)
    if mode == "hash" {
        return match kind.as_str() {
            "idcard" if v.len() == 18 || v.len() == 15 => {
                format!("{}#{}", &v[..6], fp)
            }
            "bankcard" if (16..=19).contains(&v.len()) => format!("{}#{}", &v[..6], fp),
            "mobile" if v.len() == 11 => format!("{}#{}", &v[..3], fp),
            "name" => {
                let chars: Vec<char> = v.chars().collect();
                let first2: String = chars.iter().take(2).collect();
                let keep = if chars.len() >= 2 && is_compound_surname(&first2) {
                    2
                } else {
                    1
                };
                if chars.len() <= keep {
                    return "*".repeat(chars.len());
                }
                let head: String = chars[..keep].iter().collect();
                format!("{}#{}", head, fp)
            }
            "email" => {
                if let Some(at) = v.find('@') {
                    if at > 0 {
                        return format!("{}#{}{}", &v[..1], fp, &v[at..]);
                    }
                }
                format!("{}#{}", generic_star(&v, None, None), fp)
            }
            _ => format!("{}#{}", generic_star(&v, None, None), fp),
        };
    }

    // star / birth
    match kind.as_str() {
        "idcard" => {
                // birth mode: generalize birth date to year (length preserved)
                if mode == "birth" && v.len() == 18 && v.chars().all(|c| c.is_ascii_digit()) {
                    // 18-digit: [0..6]region [6..10]YYYY [10..12]MM [12..14]DD [14..]seq
                    if let Some((m, d)) = birth_ok(&v[6..10], &v[10..12], &v[12..14]) {
                    if m && d {
                        return format!("{}{}0101{}", &v[..6], &v[6..10], &v[14..]);
                    }
                }
            }
            if mode == "birth" && v.len() == 15 && v.chars().all(|c| c.is_ascii_digit()) {
                if let Some((m, d)) = birth_ok(&v[6..8], &v[8..10], &v[10..12]) {
                    if m && d {
                        return format!("{}{}0101{}", &v[..6], &v[6..8], &v[12..]);
                    }
                }
            }
            if v.len() == 18 {
                return format!("{}{}{}", &v[..6], "*".repeat(8), &v[14..]);
            }
            if v.len() == 15 {
                return format!("{}{}{}", &v[..6], "*".repeat(5), &v[11..]);
            }
            generic_star(&v, None, None)
        }
        "mobile" => {
            if v.len() == 11 {
                return format!("{}{}{}", &v[..3], "*".repeat(4), &v[7..]);
            }
            generic_star(&v, None, None)
        }
        "bankcard" => {
            if (16..=19).contains(&v.len()) {
                return format!("{}{}{}", &v[..6], "*".repeat(v.len() - 10), &v[v.len() - 4..]);
            }
            generic_star(&v, None, None)
        }
        "name" => {
            let chars: Vec<char> = v.chars().collect();
            let first2: String = chars.iter().take(2).collect();
            let keep = if chars.len() >= 2 && is_compound_surname(&first2) {
                2
            } else {
                1
            };
            if chars.len() <= keep {
                return "*".repeat(chars.len());
            }
            let head: String = chars[..keep].iter().collect();
            format!("{}{}", head, "*".repeat(chars.len() - keep))
        }
        "email" => {
            if let Some(at) = v.find('@') {
                if at > 0 {
                    return format!("{}***{}", &v[..1], &v[at..]);
                }
            }
            generic_star(&v, None, None)
        }
        _ => generic_star(&v, f_opt(p, "head").map(|x| x as usize), f_opt(p, "tail").map(|x| x as usize)),
    }
}

fn birth_ok(_y: &str, m: &str, d: &str) -> Option<(bool, bool)> {
    let (mm, dd) = (m.parse::<u32>().ok()?, d.parse::<u32>().ok()?);
    Some((mm >= 1 && mm <= 12, dd >= 1 && dd <= 31))
}

// ── date shifting (dateshift / dateoffset) ─────────────────────────

/// Howard Hinnant civil-days (proleptic Gregorian, pure integer).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719_468
}

pub fn civil_from_days(z0: i64) -> (i64, i64, i64) {
    let z = z0 + 719_468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Auto-detect the date separator and parse, trying '-' / '/' / '.' / 'cn'
/// (the CJK form) in turn. Lets `dateshift`/`date_plus_days` handle
/// "2020-03-05", "2020/03/05", "2020.03.05" and "2020年03月05日" without the
/// caller having to know which form it is.
fn parse_ymd_any(v: &str) -> Option<(i64, i64, i64, String, &'static str)> {
    for sep in ["-", "/", ".", "cn"] {
        if let Some(r) = parse_ymd_ts(v, sep) {
            return Some((r.0, r.1, r.2, r.3, sep));
        }
    }
    None
}

/// Parse 'YYYY-MM-DD[ HH:MM:SS]' (sep '-', '/', '.' or 'cn').
/// Returns (y, m, d, tsuffix) where tsuffix keeps its leading space.
fn parse_ymd_ts(v: &str, sep: &str) -> Option<(i64, i64, i64, String)> {
    // split at the separator occurrences
    let parts = match sep {
        "-" => v.splitn(4, '-').collect::<Vec<_>>(),
        "/" => v.splitn(4, '/').collect::<Vec<_>>(),
        "." => v.splitn(4, '.').collect::<Vec<_>>(),
        "cn" => {
            // YYYY年MM月DD日rest — split on the three CJK separators. The
            // digit-ness and 4-digit-year checks are done by the shared
            // validation below, so the previous `strip_prefix(...)` (which
            // measured the *remainder*, never the year) is gone: it made this
            // branch return None for every real date.
            let (year, after) = v.split_once('年')?;
            let (month, after2) = after.split_once('月')?;
            let (day, after3) = after2.split_once('日')?;
            vec![year, month, day, after3]
        }
        _ => return None,
    };
    if parts.len() < 3 {
        return None;
    }
    let (y_s, m_s, d_s) = (parts[0], parts[1], parts[2]);
    let rest = if parts.len() >= 4 { parts[3] } else { "" };
    if !y_s.chars().all(|c| c.is_ascii_digit())
        || !m_s.chars().all(|c| c.is_ascii_digit())
        || !d_s.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    if m_s.len() > 2 || d_s.len() > 2 || y_s.len() != 4 {
        return None;
    }
    let mut ts = rest.to_string();
    // Lua: keep leading space; reject non-space start; single trailing space = none
    if ts.starts_with(' ') {
        ts = ts.trim_end().to_string();
        if ts.len() <= 1 {
            ts = String::new();
        }
        // only pure time suffixes (HH:MM:SS / HH:MM)
        let body = ts.strip_prefix(' ').unwrap_or(&ts);
        if !(is_hms(body) || is_hm(body)) {
            return None;
        }
    } else {
        ts = String::new();
    }
    let (y, m, d) = (y_s.parse::<i64>().ok()?, m_s.parse::<i64>().ok()?, d_s.parse::<i64>().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // round-trip validation (rejects 2020-02-31 etc.)
    let (y2, m2, d2) = civil_from_days(days_from_civil(y, m, d));
    if y2 != y || m2 != m || d2 != d {
        return None;
    }
    Some((y, m, d, ts))
}

fn is_hms(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.len() <= 2 && p.chars().all(|c| c.is_ascii_digit()))
}
fn is_hm(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return false;
    }
    parts.iter().all(|p| !p.is_empty() && p.len() <= 2 && p.chars().all(|c| c.is_ascii_digit()))
}

fn fmt_dt(y: i64, m: i64, d: i64, sep: &str, tsuffix: &str) -> String {
    let t = if tsuffix.is_empty() {
        String::new()
    } else {
        format!(" {}", tsuffix)
    };
    if sep == "cn" {
        format!("{:04}年{:02}月{:02}日{}", y, m, d, t)
    } else {
        format!("{:04}{}{:02}{}{:02}{}", y, sep, m, sep, d, t)
    }
}

/// key → offset days in [-days, days]
pub fn key_offset(key: &str, salt: &str, days: i64) -> i64 {
    if days == 0 {
        return 0;
    }
    let h = fnv1a(key, salt);
    ((h as i64) % (2 * days + 1)) - days
}

/// op='dateshift' → "YYYY-MM-DD" or "YYYY-MM-DD|delta" (with_delta) or "null"
pub fn dateshift(p: &Value) -> String {
    let v = s(p, "v");
    if v.is_empty() {
        return "null".into();
    }
    let Some((y, m, d, ts, sep)) = parse_ymd_any(&v) else {
        return "null".into();
    };
    let days = f_opt(p, "days").map(|x| x.abs() as i64).unwrap_or(180);
    let salt = if s(p, "salt").is_empty() { "dateshift".to_string() } else { s(p, "salt") };
    let off = key_offset(&s(p, "key"), &salt, days);
    let (ny, nm, nd) = civil_from_days(days_from_civil(y, m, d) + off);
    // Re-emit the same separator the input used, so a "2020-03-05" stays
    // "YYYY-MM-DD" and "2020年03月05日" stays "YYYY年MM月DD日".
    let out = fmt_dt(ny, nm, nd, sep, &ts);
    if p.get("with_delta").is_some()
        && matches!(p.get("with_delta"), Some(Value::Bool(true)))
    {
        return format!("{}|{}", out, off);
    }
    out
}

/// Shift a date by `delta` days (negative = earlier). Auto-detects the
/// separator (like `dateshift`) so a `YYYY年MM月DD日` input re-emits in that
/// form; returns `"null"` when the input does not parse, matching `dateshift`.
pub fn date_plus_days(v: &str, delta: i64) -> String {
    match parse_ymd_any(v) {
        Some((y, m, d, ts, sep)) => {
            let (ny, nm, nd) = civil_from_days(days_from_civil(y, m, d) + delta);
            fmt_dt(ny, nm, nd, sep, &ts)
        }
        None => "null".into(),
    }
}

/// op='dateoffset' → the integer offset (in days) a key maps to.
pub fn dateoffset(p: &Value) -> String {
    let days = f_opt(p, "days").map(|x| x.abs() as i64).unwrap_or(180);
    if days == 0 {
        return "0".into();
    }
    let salt = if s(p, "salt").is_empty() { "dateshift".to_string() } else { s(p, "salt") };
    format!("{}", key_offset(&s(p, "key"), &salt, days))
}

// ── unit tests: Hinnant algorithm + shift invariants ───────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hinnant_anchor() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 1, 1), 10_957);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
    }

    #[test]
    fn leap_roundtrip() {
        assert!(parse_ymd_ts("2020-02-29", "-").is_some());
        assert!(parse_ymd_ts("2020-02-30", "-").is_none());
        assert!(parse_ymd_ts("2021-02-29", "-").is_none());
    }

    #[test]
    fn offset_bounds() {
        let mut mx = 0;
        for i in 0..10_000 {
            let k = format!("key{}", i);
            let o = key_offset(&k, "dateshift", 180);
            assert!((-180..=180).contains(&o));
            mx = mx.max(o.abs());
        }
        assert!(mx > 0);
    }

    #[test]
    fn shift_preserves_relative() {
        // same key → constant offset → (b - a) invariant
        let a = Value::Obj(vec![
            ("v".into(), Value::Str("2020-03-15".into())),
            ("key".into(), Value::Str("10001".into())),
            ("days".into(), Value::Num(180.0)),
        ]);
        let b = Value::Obj(vec![
            ("v".into(), Value::Str("2020-04-15".into())),
            ("key".into(), Value::Str("10001".into())),
            ("days".into(), Value::Num(180.0)),
        ]);
        let oa = dateshift(&a);
        let ob = dateshift(&b);
        let (ya, ma, da) = oa.parse::<i64>().map(|_| (0, 0, 0)).unwrap_or_else(|_| (0, 0, 0));
        let _ = (ya, ma, da);
        let p = |s: &str| -> i64 {
            let (y, m, d, _ts) = parse_ymd_ts(s, "-").unwrap();
            days_from_civil(y, m, d)
        };
        assert_eq!(p(&oa), days_from_civil(2020, 3, 15) + (p(&ob) - days_from_civil(2020, 4, 15)));
        assert_eq!(p(&ob) - p(&oa), days_from_civil(2020, 4, 15) - days_from_civil(2020, 3, 15));
    }

    /// Regression (P3): the 'cn' branch was dead — `strip_prefix` measured the
    /// *remainder* after dropping digit-leading chars, so `len()==4` was never
    /// true for a real `2020年03月05日` and the branch always returned None.
    /// After the fix, a Chinese date must parse and `dateshift` must move it,
    /// re-emitting the 年月日 form.
    #[test]
    fn cn_date_shifts() {
        // parse_ymd_ts('cn') now parses (was always None before)
        let (y, m, d, _) = parse_ymd_ts("2020年03月05日", "cn").expect("cn date must parse");
        assert_eq!((y, m, d), (2020, 3, 5));

        // dateshift auto-detects the separator and shifts, keeping the 年月日 form
        let p = Value::Obj(vec![
            ("v".into(), Value::Str("2020年03月05日".into())),
            ("key".into(), Value::Str("k1".into())),
            ("days".into(), Value::Num(180.0)),
        ]);
        let out = dateshift(&p);
        assert_ne!(out, "null", "cn date must not be null: {out}");
        assert!(out.contains('年'), "output keeps 年: {out}");
        assert!(out.contains('月'), "output keeps 月: {out}");
        assert!(out.contains('日'), "output keeps 日: {out}");
        // and it actually moved (different from the input date)
        assert_ne!(out, "2020年03月05日");

        // the relative-spacing invariant holds across two cn dates sharing a key
        let a = Value::Obj(vec![
            ("v".into(), Value::Str("2020年03月01日".into())),
            ("key".into(), Value::Str("k1".into())),
            ("days".into(), Value::Num(180.0)),
        ]);
        let b = Value::Obj(vec![
            ("v".into(), Value::Str("2020年04月01日".into())),
            ("key".into(), Value::Str("k1".into())),
            ("days".into(), Value::Num(180.0)),
        ]);
        let day = |s: &str| {
            let (y, m, d, _, _) = parse_ymd_any(s).expect("shifted cn date must re-parse");
            days_from_civil(y, m, d)
        };
        assert_eq!(
            day(&dateshift(&b)) - day(&dateshift(&a)),
            days_from_civil(2020, 4, 1) - days_from_civil(2020, 3, 1),
            "cn shift preserves relative day spacing"
        );
    }

    #[test]
    fn cn_rules() {
        let p = Value::Obj(vec![
            ("v".into(), Value::Str("13800138000".into())),
            ("op".into(), Value::Str("mask_cn".into())),
        ]);
        assert_eq!(mask_cn(&p), "138****8000");

        let p = Value::Obj(vec![("v".into(), Value::Str("110101199003071234".into()))]);
        assert_eq!(mask_cn(&p), "110101********1234");

        let p = Value::Obj(vec![
            ("v".into(), Value::Str("欧阳锋".into())),
            ("kind".into(), Value::Str("name".into())),
        ]);
        assert_eq!(mask_cn(&p), "欧阳*");

        let p = Value::Obj(vec![
            ("v".into(), Value::Str("110101199003071234".into())),
            ("kind".into(), Value::Str("idcard".into())),
            ("mode".into(), Value::Str("birth".into())),
        ]);
        assert_eq!(mask_cn(&p), "110101199001011234");
    }
}
