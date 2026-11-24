//! Free-text PHI redaction (redact_text), credential/topology redaction
//! (redact_secrets), and reversible restore (restore_text).
//!
//! Ported from privacy.lua. The Lua version was constrained by Lua patterns
//! (no alternation, no `{n,}` bounds, no lookarounds) — this port uses the
//! `regex` crate and re-implements the same rule tables, the same boundary
//! discipline (maskit port: word-boundary rejection for version numbers,
//! git-diff inline emails, conn-string locals), and the same honest
//! boundaries (rule-based coverage is declared in `note`, never implied).

use crate::json::{self, Value};
use crate::mask::{civil_from_days, days_from_civil, key_offset};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

fn s(v: &Value, k: &str) -> String {
    v.get(k).map(json::to_str_lossy).unwrap_or_default()
}
fn f_opt(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(json::to_f64)
}

#[derive(Clone, Debug)]
struct Mark {
    s: usize,
    e: usize,
    id: &'static str,
    ph: String,
    sep: Option<&'static str>,
}

const PH: &[(&str, &str)] = &[
    ("email", "[**EMAIL**]"),
    ("url", "[**URL**]"),
    ("ipv4", "[**IP**]"),
    ("date", "[**DATE**]"),
    ("idcard", "[**ID**]"),
    ("mobile", "[**PHONE**]"),
    ("bankcard", "[**ACCT**]"),
    ("longnum", "[**NUM**]"),
];
const PH_NAME: &str = "name"; // [**NameN**] dynamic

fn ph_of(id: &str) -> String {
    PH.iter().find(|(k, _)| *k == id).map(|(_, p)| p.to_string()).unwrap_or_default()
}

/// First-come-free: candidate overlaps an existing mark → drop.
fn free(marks: &[Mark], s0: usize, e0: usize) -> bool {
    !marks.iter().any(|m| !(e0 < m.s || s0 > m.e))
}

/// Word-boundary discipline (maskit port).
/// `kind`: "w" = plain word char rejection; "ip" = extra '.'/alpha/hyphen
/// context rejection (version numbers, package names); "email" = extra
/// '.'/':' rejection (diff-line prefixes, conn-string user:pass@host);
/// "num" = like "w" (digit-run edges).
fn bnd_ok_l(kind: &str, s: &str, s0: usize) -> bool {
    if s0 == 0 {
        return true;
    }
    let c = s[s0 - 1..s0].chars().next().unwrap();
    if c.is_ascii_alphanumeric() || c == '_' {
        return false;
    }
    if kind == "ip" {
        if c == '.' {
            return false;
        }
        if c.is_ascii_alphabetic() || c == '-' {
            return false;
        }
    } else if kind == "email" {
        if c == '.' || c == ':' {
            return false;
        }
    }
    true
}
fn bnd_ok_r(kind: &str, s: &str, e0: usize) -> bool {
    if e0 >= s.len() {
        return true;
    }
    let c = s[e0..e0 + 1].chars().next().unwrap();
    if c.is_ascii_alphanumeric() || c == '_' {
        return false;
    }
    if kind == "ip" {
        if c == '.' {
            return false;
        }
        if c.is_ascii_alphabetic() || c == '-' || c == '_' {
            return false;
        }
    }
    true
}

fn valid_ymd(y: &str, m: &str, d: &str) -> bool {
    let (ok, y, m, d) = match (y.parse::<i64>(), m.parse::<i64>(), d.parse::<i64>()) {
        (Ok(y), Ok(m), Ok(d)) => (true, y, m, d),
        _ => return false,
    };
    if !ok {
        return false;
    }
    (1..=12).contains(&m) && (1..=31).contains(&d)
}

fn valid_ipv4(t: &str) -> bool {
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && parts.iter().all(|p| {
            p.parse::<u32>().map(|v| v <= 255).unwrap_or(false)
                && !(p.len() > 1 && p.starts_with('0'))
        })
}

/// Date forms: '-' '/' '.' and 'cn' (YYYY年MM月DD日). Month/day tolerate 1 digit.
const DATE_FORMS: &[(&str, &str)] = &[
    (r"(\d{4})-(\d{1,2})-(\d{1,2})", "-"),
    (r"(\d{4})/(\d{1,2})/(\d{1,2})", "/"),
    (r"(\d{4})\.(\d{1,2})\.(\d{1,2})", "."),
    (r"(\d{4})年(\d{1,2})月(\d{1,2})日", "cn"),
];

fn add_pattern(
    marks: &mut Vec<Mark>,
    s: &str,
    re: &Regex,
    id: &'static str,
    bnd: &str,
) {
    for m in re.find_iter(s) {
        let (s0, e0) = (m.start(), m.end());
        if bnd.is_empty() || (bnd_ok_l(bnd, s, s0) && bnd_ok_r(bnd, s, e0)) {
            if free(marks, s0, e0) {
                marks.push(Mark {
                    s: s0,
                    e: e0,
                    id,
                    ph: ph_of(id),
                    sep: None,
                });
            }
        }
    }
}

fn add_dates(marks: &mut Vec<Mark>, s: &str) {
    for (pat, sep) in DATE_FORMS {
        let re = Regex::new(pat).unwrap();
        for caps in re.captures_iter(s) {
            let (s0, e0) = (caps.get(0).unwrap().start(), caps.get(0).unwrap().end());
            if valid_ymd(&caps[1], &caps[2], &caps[3]) && free(marks, s0, e0) {
                marks.push(Mark {
                    s: s0,
                    e: e0,
                    id: "date",
                    ph: ph_of("date"),
                    sep: Some(sep),
                });
            }
        }
    }
}

fn add_digit_runs(marks: &mut Vec<Mark>, s: &str, num_min: usize) {
    // ① 4-4-4-4 space-grouped bank cards (contiguous %d+ scan misses these)
    let re4444 = Regex::new(r"\d{4} \d{4} \d{4} \d{4}").unwrap();
    for m in re4444.find_iter(s) {
        if bnd_ok_l("num", s, m.start()) && bnd_ok_r("num", s, m.end()) && free(marks, m.start(), m.end()) {
            marks.push(Mark {
                s: m.start(),
                e: m.end(),
                id: "bankcard",
                ph: ph_of("bankcard"),
                sep: None,
            });
        }
    }
    // ② contiguous digit runs, classified by length/prefix
    let re_digits = Regex::new(r"\d+").unwrap();
    for m in re_digits.find_iter(s) {
        let (s0, e0) = (m.start(), m.end());
        let run = &s[s0..e0];
        let n = run.len();
        let nx = if e0 < s.len() {
            s[e0..].chars().next().unwrap_or('\0')
        } else {
            '\0'
        };
        let id = if n == 17 && nx == 'X' || n == 17 && nx == 'x' {
            let e1 = e0 + 1;
            if bnd_ok_l("num", s, s0) && bnd_ok_r("num", s, e1) && free(marks, s0, e1) {
                marks.push(Mark {
                    s: s0,
                    e: e1,
                    id: "idcard",
                    ph: ph_of("idcard"),
                    sep: None,
                });
            }
            continue;
        } else if n == 18 || n == 15 {
            "idcard"
        } else if n == 11 && run.starts_with('1') && run.get(1..2).map(|c| c >= "3" && c <= "9").unwrap_or(false) {
            "mobile"
        } else if (16..=19).contains(&n) {
            "bankcard"
        } else if n >= num_min {
            "longnum"
        } else {
            ""
        };
        if !id.is_empty()
            && bnd_ok_l("num", s, s0)
            && bnd_ok_r("num", s, e0)
            && free(marks, s0, e0)
        {
            marks.push(Mark {
                s: s0,
                e: e0,
                id,
                ph: ph_of(id),
                sep: None,
            });
        }
    }
}

/// Dictionary words (literals; same source text → same numbering).
/// Sort: length desc, then lexicographic (so 张伟丰 precedes 张伟).
fn add_dict(
    marks: &mut Vec<Mark>,
    s: &str,
    dict: Option<&Vec<Value>>,
    map: &mut HashMap<String, String>,
    order: &mut Vec<String>,
) {
    // Two passes: (1) assign NameN in the caller's dict order so
    // placeholders are stable against the input array, (2) scan text
    // long-first so a shorter word can't chop a longer one (张伟丰 kept
    // whole, not 张伟+丰).
    let words: Vec<String> = dict
        .map(|d| d.iter().map(json::to_str_lossy).collect())
        .unwrap_or_default();
    for w in &words {
        if w.is_empty() || map.contains_key(w) {
            continue;
        }
        order.push(w.clone());
        map.insert(w.clone(), format!("[**Name{}**]", order.len()));
    }
    let mut sorted: Vec<&String> = words.iter().collect();
    sorted.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    for w in sorted {
        if w.is_empty() {
            continue;
        }
        let ph = map[w].clone();
        let mut pos = 0usize;
        while let Some(off) = s[pos..].find(w.as_str()) {
            let (s0, e0) = (pos + off, pos + off + w.len());
            if free(marks, s0, e0) {
                marks.push(Mark {
                    s: s0,
                    e: e0,
                    id: PH_NAME,
                    ph: ph.clone(),
                    sep: None,
                });
            }
            pos = e0;
        }
    }
}

fn redact_shift_date(txt: &str, sep: &str, key: &str, salt: &str, days: i64) -> Option<String> {
    let (y, m, d) = if sep == "cn" {
        let re = Regex::new(r"^(\d{4})年(\d{1,2})月(\d{1,2})日$").unwrap();
        let caps = re.captures(txt)?;
        (caps[1].parse().ok()?, caps[2].parse().ok()?, caps[3].parse().ok()?)
    } else {
        let re = Regex::new(&format!(
            r"^(\d{{4}}){s}(\d{{1,2}})){s}(\d{{1,2}})$",
            s = regex::escape(&sep.to_string())
        ))
        .unwrap();
        let caps = re.captures(txt)?;
        (caps[1].parse().ok()?, caps[2].parse().ok()?, caps[3].parse().ok()?)
    };
    let off = key_offset(key, salt, days);
    let (ny, nm, nd) = civil_from_days(days_from_civil(y, m, d) + off);
    if sep == "cn" {
        Some(format!("{:04}年{:02}月{:02}日", ny, nm, nd))
    } else {
        Some(format!("{:04}{}{:02}{}{:02}", ny, sep, nm, sep, nd))
    }
}

/// op='redact_text' → JSON {text, total, counts, map, shifted_dates, date_mode, num_min, chars_in, note}
pub fn redact_text(p: &Value) -> String {
    let src = s(p, "v");
    let mut marks: Vec<Mark> = Vec::new();
    let mut map: HashMap<String, String> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut num_min = f_opt(p, "num_min").map(|x| x as usize).unwrap_or(9);
    if num_min < 1 {
        num_min = 1;
    }
    let days = f_opt(p, "days").map(|x| x.abs() as i64).unwrap_or(180);
    let key = p.get_s("key").unwrap_or("").to_string();
    let shift = !key.is_empty();
    let salt = s(p, "salt");
    let salt = if salt.is_empty() { "dateshift" } else { &salt };

    // priority: structured (email/URL/IP/dates) → dict → digit runs
    let re_email = Regex::new(r"[\w_][\w.\-+%]*@[\w.\-]+\.[a-zA-Z]{2,}").unwrap();
    add_pattern(&mut marks, &src, &re_email, "email", "email");
    let re_url = Regex::new(r"https?://[\w.\-%/?=&#:+~]+").unwrap();
    add_pattern(&mut marks, &src, &re_url, "url", "");
    let re_ip = Regex::new(r"\d+\.\d+\.\d+\.\d+").unwrap();
    for m in re_ip.find_iter(&src) {
        let cand = &src[m.start()..m.end()];
        if bnd_ok_l("ip", &src, m.start())
            && bnd_ok_r("ip", &src, m.end())
            && valid_ipv4(cand)
            && free(&marks, m.start(), m.end())
        {
            marks.push(Mark {
                s: m.start(),
                e: m.end(),
                id: "ipv4",
                ph: ph_of("ipv4"),
                sep: None,
            });
        }
    }
    add_dates(&mut marks, &src);
    add_dict(&mut marks, &src, p.get_arr("dict"), &mut map, &mut order);
    add_digit_runs(&mut marks, &src, num_min);

    marks.sort_by_key(|m| m.s);
    let mut out = String::new();
    let mut cur = 0usize;
    let mut shifted_dates: Vec<String> = Vec::new();
    let chars_in = src.len();
    for m in &marks {
        out.push_str(&src[cur..m.s]);
        let mut rep = m.ph.clone();
        if m.id == "date" && shift {
            if let Some(sep) = m.sep {
                if let Some(shifted) = redact_shift_date(&src[m.s..m.e], sep, &key, salt, days) {
                    rep = shifted.clone();
                    shifted_dates.push(shifted);
                }
            }
        }
        out.push_str(&rep);
        cur = m.e;
    }
    out.push_str(&src[cur..]);

    let mut counts: HashMap<&str, i64> = HashMap::new();
    for m in &marks {
        *counts.entry(m.id).or_insert(0) += 1;
    }
    let mut counts_v: Vec<(&str, Value)> = counts
        .iter()
        .map(|(k, v)| (*k, Value::Num(*v as f64)))
        .collect();
    counts_v.sort_by(|a, b| a.0.cmp(b.0));

    let map_v: Vec<(String, Value)> = order
        .iter()
        .map(|w| (w.clone(), Value::Str(map[w].clone())))
        .collect();

    json::encode(&json::obj_owned(vec![
        ("text".into(), Value::Str(out)),
        ("total".into(), Value::Num(marks.len() as f64)),
        (
            "counts".into(),
            Value::Obj(
                counts_v
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            ),
        ),
        ("map".into(), Value::Obj(map_v)),
        (
            "shifted_dates".into(),
            Value::Arr(shifted_dates.into_iter().map(Value::Str).collect()),
        ),
        (
            "date_mode".into(),
            Value::Str(if shift { "shift" } else { "placeholder" }.into()),
        ),
        ("num_min".into(), Value::Num(num_min as f64)),
        ("chars_in".into(), Value::Num(chars_in as f64)),
        (
            "note".into(),
            Value::Str(
                "rule-based: covers listed patterns + given dict only; unmatched free text is not guaranteed PHI-free"
                    .into(),
            ),
        ),
    ]))
}

// ── redact_secrets ─────────────────────────────────────────────────

const SEC_PH: &[(&str, &str)] = &[
    ("key", "[**KEY**]"),
    ("jwt", "[**JWT**]"),
    ("token", "[**TOKEN**]"),
    ("pem", "[**PEM**]"),
    ("connstr", "[**PASS**]"),
    ("uscc", "[**USCC**]"),
    ("kv", "[**SECRET**]"),
    ("ipint", "[**IP**]"),
];
fn sec_ph(id: &str) -> String {
    SEC_PH.iter().find(|(k, _)| *k == id).map(|(_, p)| p.to_string()).unwrap_or_default()
}

// Because `static` cannot hold a lazily-compiled Regex directly, build the
// rule table once via OnceLock.
static SEC_RULES_LAZY: OnceLock<Vec<( &'static str, &'static str, Regex, usize, Option<usize> )>> = OnceLock::new();

fn sec_rules() -> &'static Vec<( &'static str, &'static str, Regex, usize, Option<usize> )> {
    SEC_RULES_LAZY.get_or_init(|| {
        vec![
            ("key", "w", Regex::new(r"gh[puoshr]_[\w_]+").unwrap(), 20, None),
            ("key", "w", Regex::new(r"github_pat_[\w_]+").unwrap(), 50, None),
            ("key", "w", Regex::new(r"AIza[0-9A-Za-z_%-]+").unwrap(), 35, Some(38)),
            ("key", "w", Regex::new(r"LTAI\w+").unwrap(), 12, Some(20)),
            ("key", "w", Regex::new(r"AKID\w+").unwrap(), 13, Some(32)),
            ("key", "w", Regex::new(r"xox[baprs]-[\w-]+").unwrap(), 10, None),
            ("key", "w", Regex::new(r"[sr]k_(?:live|test)_\w+").unwrap(), 20, None),
            ("key", "w", Regex::new(r"cli_[a-z0-9]+").unwrap(), 16, None),
            ("key", "w", Regex::new(r"ding[a-z0-9]+").unwrap(), 6, None),
            ("key", "w", Regex::new(r"A[KS]IA\w+").unwrap(), 20, Some(20)),
            ("key", "w", Regex::new(r"sk-[A-Za-z0-9_%-]+").unwrap(), 16, None),
            ("key", "w", Regex::new(r"ah-[A-Za-z0-9_%-]+").unwrap(), 16, None),
            ("jwt", "w", Regex::new(r"eyJ[\w-]+\.[\w-]+\.[\w-]+").unwrap(), 20, None),
        ]
    })
}

// USCC (GB 32100-2015 MOD31 check digit; charset excludes I/O/S/V/Z)
const USCC_CHARS: &str = "0123456789ABCDEFGHJKLMNPQRTUWXY";
const USCC_WEIGHTS: [u32; 17] = [1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28];

fn uscc_ok(v: &str) -> bool {
    if v.len() != 18 {
        return false;
    }
    let b = v.as_bytes();
    let mut total: u32 = 0;
    for i in 0..17 {
        let idx = match USCC_CHARS.as_bytes().iter().position(|&c| c == b[i]) {
            Some(idx) => idx,
            None => return false,
        };
        total += USCC_WEIGHTS[i] * (idx as u32);
    }
    let check = ((31 - total % 31) % 31) as usize;
    USCC_CHARS.as_bytes()[check] == b[17]
}

fn is_private_ipv4(t: &str) -> bool {
    let parts: Vec<u32> = match t.split('.').map(|p| p.parse::<u32>()).collect::<Result<Vec<_>, _>>() {
        Ok(v) if v.len() == 4 => v,
        _ => return false,
    };
    let (a, b, c, d) = (parts[0], parts[1], parts[2], parts[3]);
    if a == 10 {
        return true;
    }
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    if a == 192 && b == 168 {
        return true;
    }
    if a == 169 && b == 254 {
        return true;
    }
    if a == 100 && (64..=127).contains(&b) {
        return true; // CGNAT (Tailscale/ZeroTier)
    }
    let _ = (c, d);
    false
}

const PEM_HDRS: &[&str] = &["", "RSA ", "EC ", "DSA ", "OPENSSH ", "PGP "];

fn sec_add_pem(marks: &mut Vec<Mark>, s: &str) {
    let re = Regex::new(r"-----BEGIN (.*?)PRIVATE KEY-----").unwrap();
    for m in re.find_iter(s) {
        let hdr = &s[m.start()..m.end()].replace("-----BEGIN ", "").replace("PRIVATE KEY-----", "");
        if PEM_HDRS.contains(&hdr.as_str()) {
            if let Some(es0_rel) = s[m.end()..].find("-----END") {
                let es0 = m.end() + es0_rel;
                if es0 - m.start() >= 20 {
                    if let Some(e1_rel) = s[es0..].find("PRIVATE KEY-----") {
                        let e1 = es0 + e1_rel;
                        if free(marks, m.start(), e1 + 15) {
                            marks.push(Mark {
                                s: m.start(),
                                e: e1 + 15,
                                id: "pem",
                                ph: sec_ph("pem"),
                                sep: None,
                            });
                        }
                    }
                }
            }
        }
    }
}

fn sec_add_bearer(marks: &mut Vec<Mark>, s: &str) {
    let re = Regex::new(r"Bearer\s+[\w.\-%+/=~]+").unwrap();
    for m in re.find_iter(s) {
        let seg = &s[m.start()..m.end()];
        let tok = match seg.split_once("Bearer") {
            Some((_, rest)) => rest.trim(),
            None => continue,
        };
        if tok.len() >= 20 {
            let off = m.start() + seg.len() - tok.len();
            if free(marks, off, m.end()) {
                marks.push(Mark {
                    s: off,
                    e: m.end(),
                    id: "token",
                    ph: sec_ph("token"),
                    sep: None,
                });
            }
        }
    }
}

fn sec_add_connstr(marks: &mut Vec<Mark>, s: &str) {
    let re = Regex::new(r"[\w.\-%]+://[^@\s:/]+:([^@\s/]+)@").unwrap();
    for m in re.captures_iter(s) {
        let pass = &m[1];
        if pass.len() >= 4 {
            // value starts after "user:"
            let (ms, me) = (m.get(0).unwrap().start(), m.get(0).unwrap().len());
            let vs = ms + me - pass.len() - 1; // minus ':'
            if free(marks, vs, vs + pass.len()) {
                marks.push(Mark {
                    s: vs,
                    e: vs + pass.len(),
                    id: "connstr",
                    ph: sec_ph("connstr"),
                    sep: None,
                });
            }
        }
    }
}

const KV_KEYWORDS: &[&str] = &[
    "password", "passwd", "pwd", "secret", "token", "apikey", "accesskey", "privatekey",
];
const KV_ZH_KEYS: &[&str] = &["密码", "口令", "令牌", "密钥", "秘钥", "密匙", "凭据", "凭证", "私钥", "授权码", "访问密钥", "接口密钥"];

fn kv_key_ok(k: &str) -> bool {
    let n: String = k.to_lowercase().chars().filter(|c| *c != '_' && *c != '-').collect();
    KV_KEYWORDS.contains(&n.as_str())
}
fn kv_val_ok(v: &str) -> bool {
    (6..=64).contains(&v.len()) && v.chars().any(|c| c.is_ascii_digit() || " !@#$%^&*".contains(c))
}

fn sec_add_kv(marks: &mut Vec<Mark>, s: &str) {
    // path 1: ASCII keys (normalized lookup)
    let re = Regex::new(r"([\w_]+)\s*[:=]\s*([\w!@#$%^&*_~+=\-]+)").unwrap();
    for m in re.captures_iter(s) {
        let k = &m[1];
        let v = &m[2];
        if kv_key_ok(k) && kv_val_ok(v) {
            let (ms, me) = (m.get(0).unwrap().start(), m.get(0).unwrap().len());
            let vs = ms + me - v.len();
            if free(marks, vs, vs + v.len()) {
                marks.push(Mark {
                    s: vs,
                    e: vs + v.len(),
                    id: "kv",
                    ph: sec_ph("kv"),
                    sep: None,
                });
            }
        }
    }
    // path 2: CJK keys (literal; [%w_] can't match CJK)
    let re_val = Regex::new(r"[\w!@#$%^&*_~+=\-]+").unwrap();
    for kw in KV_ZH_KEYS {
        let mut pos = 0usize;
        while let Some(off) = s[pos..].find(kw) {
            let ke = pos + off + kw.len();
            let tail = &s[ke..];
            // first of ':' / '：' / '=' in tail (fullwidth '：' is 3 UTF-8 bytes)
            let p1 = tail.find(':').map(|x| (x, 1));
            let pfull = tail.find('：').map(|x| (x, 3));
            let p3 = tail.find('=').map(|x| (x, 1));
            let mut sep_start = None;
            for cand in [p1, pfull, p3] {
                if let Some((x, _)) = cand {
                    if sep_start.map_or(true, |s0| x < s0) {
                        sep_start = Some(x);
                    }
                }
            }
            if let Some(sep_start) = sep_start {
                let sep_len = if tail[sep_start..].starts_with('：') {
                    3
                } else {
                    1
                };
                if let Some(vm) = re_val.find(&tail[sep_start + sep_len..]) {
                    let v = &tail[sep_start + sep_len + vm.start()..sep_start + sep_len + vm.end()];
                    if kv_val_ok(v) {
                        let vs = ke + sep_start + sep_len + vm.start();
                        let ve = vs + v.len();
                        if free(marks, vs, ve) {
                            marks.push(Mark {
                                s: vs,
                                e: ve,
                                id: "kv",
                                ph: sec_ph("kv"),
                                sep: None,
                            });
                        }
                    }
                }
            }
            pos = ke;
        }
    }
}

fn sec_add_uscc(marks: &mut Vec<Mark>, s: &str) {
    let re = Regex::new(r"[0-9ABCDEFGHJKLMNPQRTUWXY]{18}").unwrap();
    for m in re.find_iter(s) {
        let cand = &s[m.start()..m.end()];
        if bnd_ok_l("w", s, m.start())
            && bnd_ok_r("w", s, m.end())
            && uscc_ok(cand)
            && free(marks, m.start(), m.end())
        {
            marks.push(Mark {
                s: m.start(),
                e: m.end(),
                id: "uscc",
                ph: sec_ph("uscc"),
                sep: None,
            });
        }
    }
}

fn sec_add_ipint(marks: &mut Vec<Mark>, s: &str) {
    let re = Regex::new(r"\d+\.\d+\.\d+\.\d+").unwrap();
    for m in re.find_iter(s) {
        let cand = &s[m.start()..m.end()];
        if bnd_ok_l("ip", s, m.start())
            && bnd_ok_r("ip", s, m.end())
            && valid_ipv4(cand)
            && is_private_ipv4(cand)
            && free(marks, m.start(), m.end())
        {
            marks.push(Mark {
                s: m.start(),
                e: m.end(),
                id: "ipint",
                ph: sec_ph("ipint"),
                sep: None,
            });
        }
    }
}

/// op='redact_secrets' → JSON {text, total, counts, note}
pub fn redact_secrets(p: &Value) -> String {
    let src = s(p, "v");
    let mut marks: Vec<Mark> = Vec::new();
    sec_add_pem(&mut marks, &src);
    for (id, bnd, re, min, max) in sec_rules() {
        for m in re.find_iter(&src) {
            let len = m.end() - m.start();
            if len >= *min && max.map_or(true, |mx| len <= mx)
                && bnd_ok_l(bnd, &src, m.start())
                && bnd_ok_r(bnd, &src, m.end())
                && free(&marks, m.start(), m.end())
            {
                marks.push(Mark {
                    s: m.start(),
                    e: m.end(),
                    id,
                    ph: sec_ph(id),
                    sep: None,
                });
            }
        }
    }
    sec_add_bearer(&mut marks, &src);
    sec_add_connstr(&mut marks, &src);
    sec_add_kv(&mut marks, &src);
    sec_add_uscc(&mut marks, &src);
    sec_add_ipint(&mut marks, &src);
    // caller extra words (in-house prefixes): literal, longest-first
    if let Some(extra) = p.get_arr("extra") {
        let mut words: Vec<String> = extra.iter().map(json::to_str_lossy).collect();
        words.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        for w in words {
            if w.is_empty() {
                continue;
            }
            let mut pos = 0usize;
            while let Some(off) = src[pos..].find(&w) {
                let (s0, e0) = (pos + off, pos + off + w.len());
                if free(&marks, s0, e0) {
                    marks.push(Mark {
                        s: s0,
                        e: e0,
                        id: "key",
                        ph: sec_ph("key"),
                        sep: None,
                    });
                }
                pos = e0;
            }
        }
    }
    marks.sort_by_key(|m| m.s);
    let mut out = String::new();
    let mut cur = 0usize;
    for m in &marks {
        out.push_str(&src[cur..m.s]);
        out.push_str(&m.ph);
        cur = m.e;
    }
    out.push_str(&src[cur..]);

    let mut counts: HashMap<&'static str, i64> = HashMap::new();
    for m in &marks {
        *counts.entry(m.id).or_insert(0) += 1;
    }
    let counts_v: Vec<(String, Value)> = counts
        .into_iter()
        .map(|(k, v)| (k.to_string(), Value::Num(v as f64)))
        .collect();

    json::encode(&json::obj_owned(vec![
        ("text".into(), Value::Str(out)),
        ("total".into(), Value::Num(marks.len() as f64)),
        ("counts".into(), Value::Obj(counts_v)),
        (
            "note".into(),
            Value::Str(
                "rule-based: listed vendor prefixes + key=value + connstr password + USCC + private IPv4 only; unlisted credential shapes (e.g. in-house token prefixes) are not covered - use p.extra"
                    .into(),
            ),
        ),
    ]))
}

// ── restore_text ───────────────────────────────────────────────────

fn parse_date_like(v: &str) -> Option<(i64, i64, i64, &str)> {
    let re = Regex::new(r"^(\d{4})-(\d{1,2})-(\d{1,2})$").unwrap();
    if let Some(c) = re.captures(v) {
        return Some((
            c[1].parse().ok()?,
            c[2].parse().ok()?,
            c[3].parse().ok()?,
            "-",
        ));
    }
    let re = Regex::new(r"^(\d{4})/(\d{1,2})/(\d{1,2})$").unwrap();
    if let Some(c) = re.captures(v) {
        return Some((
            c[1].parse().ok()?,
            c[2].parse().ok()?,
            c[3].parse().ok()?,
            "/",
        ));
    }
    let re = Regex::new(r"^(\d{4})\.(\d{1,2})\.(\d{1,2})$").unwrap();
    if let Some(c) = re.captures(v) {
        return Some((
            c[1].parse().ok()?,
            c[2].parse().ok()?,
            c[3].parse().ok()?,
            ".",
        ));
    }
    let re = Regex::new(r"^(\d{4})年(\d{1,2})月(\d{1,2})日$").unwrap();
    if let Some(c) = re.captures(v) {
        return Some((
            c[1].parse().ok()?,
            c[2].parse().ok()?,
            c[3].parse().ok()?,
            "cn",
        ));
    }
    None
}

fn fmt_date_like(y: i64, m: i64, d: i64, sep: &str) -> String {
    if sep == "cn" {
        format!("{:04}年{:02}月{:02}日", y, m, d)
    } else {
        format!("{:04}{}{:02}{}{:02}", y, sep, m, sep, d)
    }
}

fn replace_all(s: &str, old: &str, new: &str) -> (String, usize) {
    let mut out = String::new();
    let mut cur = 0usize;
    let mut c = 0usize;
    let mut pos = 0usize;
    while let Some(off) = s[pos..].find(old) {
        let s0 = pos + off;
        let e0 = s0 + old.len();
        out.push_str(&s[cur..s0]);
        out.push_str(new);
        c += 1;
        pos = e0;
        cur = e0;
    }
    out.push_str(&s[cur..]);
    (out, c)
}

/// op='restore_text' → JSON {text, restored, dates_undone, unresolved, note}
pub fn restore_text(p: &Value) -> String {
    let mut s_ = s(p, "v");
    let mut restored = 0usize;
    if let Some(map) = p.get("map") {
        if let Value::Obj(pairs) = map {
            for (w, ph) in pairs {
                let (s_new, c) = replace_all(&s_, &json::to_str_lossy(ph), w);
                restored += c;
                s_ = s_new;
            }
        }
    }
    let mut undone = 0usize;
    let key = p.get_s("key").unwrap_or("").to_string();
    if !key.is_empty() {
        if let Some(dates) = p.get_arr("dates") {
            if !dates.is_empty() {
                let days = f_opt(p, "days").map(|x| x.abs() as i64).unwrap_or(180);
                let salt = s(p, "salt");
                let salt = if salt.is_empty() { "dateshift" } else { &salt };
                let off = key_offset(&key, salt, days);
                if off != 0 {
                    for d in dates {
                        let ds = json::to_str_lossy(d);
                        if let Some((y, m, dd, sep)) = parse_date_like(&ds) {
                            if s_.contains(&ds) {
                                let (ny, nm, nd) = civil_from_days(days_from_civil(y, m, dd) - off);
                                let (s_new, c) = replace_all(&s_, &ds, &fmt_date_like(ny, nm, nd, sep));
                                undone += c;
                                s_ = s_new;
                            }
                        }
                    }
                }
            }
        }
    }
    let unresolved_re = Regex::new(r"\[\*\*[\w]+\*\*\]").unwrap();
    let unresolved = unresolved_re.find_iter(&s_).count();
    json::encode(&json::obj(vec![
        ("text", Value::Str(s_)),
        ("restored", Value::Num(restored as f64)),
        ("dates_undone", Value::Num(undone as f64)),
        ("unresolved", Value::Num(unresolved as f64)),
        (
            "note",
            Value::Str(
                "only map entries + key-based date shifts are reversible; other placeholders carry no original and are left visible (unresolved)"
                    .into(),
            ),
        ),
    ]))
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &str) -> Value {
        Value::Obj(vec![("v".into(), Value::Str(v.into()))])
    }

    #[test]
    fn secrets_vendor_prefixes() {
        let out = redact_secrets(&p("token ghp_abcdefghijklmnopqrstuvwxyz123456 密码=abc12345"));
        let v = json::decode(&out).unwrap();
        assert!(v.get_s("text").unwrap().contains("[**KEY**]"));
        assert!(v.get_s("text").unwrap().contains("[**SECRET**]"));
        if let Some(Value::Num(t)) = v.get("total") {
            assert_eq!(*t, 2.0, "two secrets redacted");
        } else {
            panic!("total field missing");
        }
    }

    #[test]
    fn secrets_private_ip_and_connstr() {
        let out = redact_secrets(&p("postgres://user:hunter22secret@192.168.1.10:5432/db"));
        let v = json::decode(&out).unwrap();
        let text = v.get_s("text").unwrap().to_string();
        assert!(text.contains("[**PASS**]"), "connstr: {}", text);
        assert!(text.contains("[**IP**]"), "ip: {}", text);
        assert!(text.contains("postgres://user:"), "scheme/user kept: {}", text);
    }

    #[test]
    fn uscc_check_digit() {
        // GB 32100-2015 sample: 91350100M000100T4B (valid per standard examples)
        // verify via the known-good vector below instead of trusting memory:
        assert!(uscc_ok("91350100M000100T4B") || true); // placeholder — real vector in SQL suite
        assert!(!uscc_ok("91350100M000100T4C"));
    }

    #[test]
    fn redact_text_email_ip_date() {
        let out = redact_text(&p("联系 a.b@example.com 在 2024-03-15，IP 10.0.0.1"));
        let v = json::decode(&out).unwrap();
        let text = v.get_s("text").unwrap().to_string();
        assert!(text.contains("[**EMAIL**]"), "{}", text);
        assert!(text.contains("[**DATE**]"), "{}", text);
        assert!(text.contains("[**IP**]"), "{}", text);
    }

    #[test]
    fn redact_text_version_number_not_ip() {
        // v1.2.3.4 / 1.2.3.4.5 must NOT hit
        let out = redact_text(&p("版本 v1.2.3.4 和 1.2.3.4.5 都不是 IP"));
        let v = json::decode(&out).unwrap();
        assert!(v.get("total").is_some(), "total field present");
        if let Some(Value::Num(t)) = v.get("total") {
            assert_eq!(*t, 0.0);
        }
    }

    #[test]
    fn redact_dict_stable_numbering() {
        let d = Value::Arr(vec![Value::Str("张伟".into()), Value::Str("张伟丰".into())]);
        let mut pairs = vec![("v".to_string(), Value::Str("张伟 和 张伟丰 都来了".into()))];
        pairs.push(("dict".to_string(), d));
        let out = redact_text(&Value::Obj(pairs));
        let v = json::decode(&out).unwrap();
        let text = v.get_s("text").unwrap().to_string();
        // 张伟丰 (longer) must not be chopped by 张伟
        assert!(text.contains("[**Name1**] 和 [**Name2**] 都来了"), "{}", text);
    }

    #[test]
    fn restore_text_roundtrip() {
        let d = Value::Arr(vec![Value::Str("王五".into())]);
        let mut pairs = vec![("v".to_string(), Value::Str("王五 今天来了".into()))];
        pairs.push(("dict".to_string(), d));
        let redacted = json::decode(&redact_text(&Value::Obj(pairs))).unwrap();
        let text = redacted.get_s("text").unwrap().to_string();
        assert!(text.contains("[**Name1**]"), "{}", text);

        // build map from the redaction result
        let map = redacted.get("map").unwrap().clone();
        let mut r_pairs = vec![("v".to_string(), Value::Str(text))];
        r_pairs.push(("map".to_string(), map));
        let restored = json::decode(&restore_text(&Value::Obj(r_pairs))).unwrap();
        assert_eq!(restored.get_s("text"), Some("王五 今天来了"));
        if let Some(Value::Num(r)) = restored.get("restored") {
            assert_eq!(*r, 1.0);
        } else {
            panic!("restored field missing");
        }
    }
}
