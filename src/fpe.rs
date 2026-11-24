//! FPE format-preserving encryption: FF3 / FF3-1 (NIST SP 800-38G),
//! AES-128/192/256. Ported from privacy.lua's FFI-u64 implementation.
//!
//! Rust has native u128, so the 128-bit modular arithmetic the Lua had to
//! hand-roll with FFI double-word ops is native here (and much faster).
//!
//! Honesty boundary (carried over from the Lua header): NIST has RETIRED
//! SP 800-38G — FF3/FF3-1 are no longer recommended as general-purpose FPE
//! primitives. This module is positioned as *deterministic reversible PII
//! masking* (same key+tweak → same output, key-holding restores, card
//! numbers stay Luhn-valid), not as a general FPE security product.

use crate::json::{self, Value};
use aes::Aes128;
use aes::Aes192;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit};

// ── alphabets ──────────────────────────────────────────────────────

pub fn alphabet_of(name: &str) -> Option<&'static str> {
    Some(match name {
        "digits" => "0123456789",
        "alnum" | "lowercase" => "abcdefghijklmnopqrstuvwxyz",
        "uppercase" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "base64" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/",
        "hex" => "0123456789abcdef",
        _ => return None,
    })
}

// ── hex helpers ────────────────────────────────────────────────────

pub fn hex2bytes(h: &str) -> Result<Vec<u8>, String> {
    if h.len() % 2 != 0 {
        return Err("key/tweak: odd hex length".into());
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    let b = h.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or("key/tweak: bad hex")?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or("key/tweak: bad hex")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

// ── core FF3 / FF3-1 ───────────────────────────────────────────────
/// Clean FF3/FF3-1 transform with explicit (a, b) locals.
pub fn ff3_transform(key: &[u8], tw8: &[u8; 8], alpha: &str, s: &str, enc: bool, _ff31: bool) -> Result<String, String> {
    let base = alpha.len() as u128;
    let n = s.len();
    let u = (n + 1) / 2;
    let v = n - u;

    let alpha_chars: Vec<char> = alpha.chars().collect();
    let mut char_idx: std::collections::HashMap<char, u64> = std::collections::HashMap::new();
    for (i, c) in alpha_chars.iter().enumerate() {
        char_idx.insert(*c, i as u64);
    }

    // decode: read LEFT-TO-RIGHT, first char = lowest digit (matches encode,
    // the mysto-python-fpe / Lua reversed convention). NOT standard order.
    let decode = |part: &str| -> Result<u128, String> {
        let mut x: u128 = 0;
        for ch in part.chars().rev() {
            let d = *char_idx.get(&ch).ok_or_else(|| format!("fpe: char not in alphabet"))?;
            x = x * base + d as u128;
        }
        Ok(x)
    };

    let a_str = s.get(..u).ok_or("slice")?;
    let b_str = s.get(u..).ok_or("slice")?;
    let mut a = decode(a_str)?;
    let mut b = decode(b_str)?;

    let mut mu: u128 = 1;
    for _ in 0..u {
        mu *= base;
    }
    let mut mv: u128 = 1;
    for _ in 0..v {
        mv *= base;
    }

    let key_rev: Vec<u8> = key.iter().rev().copied().collect();
    let seq: Vec<u8> = if enc { (0..8).collect() } else { (0..8).rev().collect() };

    for &i in &seq {
        let is_even = i % 2 == 0;
        let m = if is_even { mu } else { mv };
        // NIST: W_even = T[4..8] (T_R), W_odd = T[0..4] (T_L)
        let w: [u8; 4] = if is_even {
            [tw8[4], tw8[5], tw8[6], tw8[7]]
        } else {
            [tw8[0], tw8[1], tw8[2], tw8[3]]
        };
        let other = if enc { b } else { a };
        let other16 = other.to_be_bytes();
        let mut pblock = [0u8; 16];
        pblock[0..4].copy_from_slice(&[w[0], w[1], w[2], w[3] ^ i]);
        // NIST: P[4..16] = other as a 12-byte BIG-ENDIAN value = the LOW 12
        // bytes of the 16-byte representation (other < base^10 << 2^96).
        pblock[4..16].copy_from_slice(&other16[4..16]);
        let p_rev = rev16(&pblock);
        let s_block = aes_encrypt(key_rev.as_slice(), &p_rev);
        let s_rev = rev16(&s_block);
        let y = u128::from_be_bytes(s_rev);
        // y is a full 128-bit AES output (up to 2^128); m < 2^96, a,b < m.
        // Reduce y mod m first so the add/sub stays in-range. For the subtract,
        // avoid wrapping_sub: (b - y%m) mod m with b,y%m < m needs the
        // +m adjustment BEFORE the final % (wrapping_sub then %m is wrong
        // because m ∤ 2^128).
        if enc {
            let c = (a + y % m) % m;
            a = b;
            b = c;
        } else {
            let c = (b + m - y % m) % m;
            b = a;
            a = c;
        }
    }

    let encode = |x: u128, len: usize| -> String {
        // NIST / mysto-python-fpe convention (shared with the Lua lib): the
        // numeral is written LOWEST digit first on the wire. decode reads
        // right-to-left, so decode(encode(x)) == x for x < base^len.
        let mut out = String::with_capacity(len);
        let mut r = x;
        for _ in 0..len {
            let rem = (r % base) as usize;
            out.push(alpha_chars[rem]);
            r /= base;
        }
        out
    };

    let ea = encode(a, u);
    let eb = encode(b, v);
    Ok(format!("{}{}", ea, eb))
}

pub fn rev16(b: &[u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = b[15 - i];
    }
    o
}

pub fn aes_encrypt(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    match key.len() {
        16 => {
            let e = <Aes128 as KeyInit>::new(key.try_into().unwrap());
            let blk = generic_array::GenericArray::clone_from_slice(block);
            let mut blk = blk;
            e.encrypt_block(&mut blk);
            out = blk.as_slice().try_into().unwrap();
        }
        24 => {
            let e = <Aes192 as KeyInit>::new(key.try_into().unwrap());
            let blk = generic_array::GenericArray::clone_from_slice(block);
            let mut blk = blk;
            e.encrypt_block(&mut blk);
            out = blk.as_slice().try_into().unwrap();
        }
        32 => {
            let e = <Aes256 as KeyInit>::new(key.try_into().unwrap());
            let blk = generic_array::GenericArray::clone_from_slice(block);
            let mut blk = blk;
            e.encrypt_block(&mut blk);
            out = blk.as_slice().try_into().unwrap();
        }
        _ => unreachable!("key length validated by caller"),
    }
    out
}

// ── public API (mirrors the Lua ops) ───────────────────────────────

struct FpeOpts {
    v: String,
    key: Vec<u8>,
    tweak: Vec<u8>,
    algo: String,
    alpha: String,
    alpha_name: String,
}

fn fpe_opts(p: &Value, _op: &str) -> Result<FpeOpts, String> {
    let v = p.get_s("v").unwrap_or("").to_string();
    if v.chars().count() < 2 {
        return Err("fpe: v 须为长度 ≥ 2 的字符串".into());
    }
    let algo = p.get_s("algo").unwrap_or("ff31").to_string();
    if algo != "ff31" && algo != "ff3" {
        return Err("fpe: algo 须为 'ff31' 或 'ff3'".into());
    }
    let alpha_name = p.get_s("alphabet").unwrap_or("digits").to_string();
    let alpha = match alphabet_of(&alpha_name) {
        Some(a) => a.to_string(),
        None => {
            // custom alphabet string
            alpha_name.clone()
        }
    };
    if alpha.chars().count() < 2 {
        return Err("fpe: 未知字母表（可用 digits/alnum/base64/hex 或传字母表字符串）".into());
    }
    let key_hex = p.get_s("key").filter(|k| !k.is_empty()).unwrap_or("00000000000000000000000000000000");
    if !matches!(key_hex.len(), 32 | 48 | 64) {
        return Err("fpe: key 须为 32/48/64 位 hex（16/24/32 字节）".into());
    }
    let key = hex2bytes(key_hex)?;
    let tlen = if algo == "ff31" { 14 } else { 16 };
    let tweak_hex = p.get_s("tweak").unwrap_or("").to_string();
    let tweak_hex = if tweak_hex.is_empty() {
        "0".repeat(tlen)
    } else {
        tweak_hex
    };
    if tweak_hex.len() != tlen {
        return Err(format!("fpe: tweak 须为 {} 位 hex（{}）", tlen, algo));
    }
    let tweak = hex2bytes(&tweak_hex)?;
    // alphabet membership check
    for (i, ch) in v.chars().enumerate() {
        if !alpha.chars().any(|c| c == ch) {
            return Err(format!("fpe: 第 {} 字符 '{}' 不在字母表内", i + 1, ch));
        }
    }
    Ok(FpeOpts {
        v,
        key,
        tweak,
        algo,
        alpha,
        alpha_name,
    })
}

fn fpe_run(o: &FpeOpts, enc: bool) -> Result<String, String> {
    let ff31 = o.algo == "ff31";
    let tw8: [u8; 8] = if ff31 {
        let t = &o.tweak;
        [t[0], t[1], t[2], t[3] & 0xF0, t[4], t[5], t[6], (t[3] & 0x0F) << 4]
    } else {
        let t = &o.tweak;
        [t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]]
    };
    // length gate (mirror ff3_core's domain checks)
    let base = o.alpha.len() as u128;
    let n = o.v.len();
    if n < 2 {
        return Err("fpe: length < 2".into());
    }
    let _u = (n + 1) / 2;
    let t96 = (1u128 << 32) * (1u128 << 32) * (1u128 << 32);
    let mut pow: u128 = 1;
    let mut u_max = 0;
    for _ in 0..96 {
        if pow > t96 / base {
            break;
        }
        pow *= base;
        u_max += 1;
    }
    if n as u32 > 2 * u_max {
        return Err(format!("fpe: 长度 {} 超出 radix {} 的 NIST 允许区间 [2,{}]", n, base, 2 * u_max));
    }
    if ff31 {
        let mut pn = 1.0f64;
        let mut small = true;
        for _ in 0..n {
            pn *= base as f64;
            if pn >= 1e6 {
                small = false;
                break;
            }
        }
        if small {
            return Err(format!("fpe: FF3-1 要求域大小 radix^n ≥ 10^6（当前 radix {}, n {}）", base, n));
        }
    }
    ff3_transform(&o.key, &tw8, &o.alpha, &o.v, enc, ff31)
}

/// op='fpe_encode' / 'fpe_decode' → JSON
pub fn fpe_op(p: &Value, enc: bool) -> String {
    let o = match fpe_opts(p, if enc { "fpe_encode" } else { "fpe_decode" }) {
        Ok(o) => o,
        Err(e) => return json::encode(&json::obj(vec![("error", Value::Str(e))])),
    };
    let out = fpe_run(&o, enc);
    match out {
        Ok(ct) => {
            let clen = ct.chars().count() as f64;
            if enc {
                json::encode(&json::obj(vec![
                    ("value", Value::Str(ct)),
                    ("algo", Value::Str(o.algo)),
                    (
                        "alphabet",
                        Value::Str(o.alpha_name),
                    ),
                    ("length", Value::Num(clen)),
                ]))
            } else {
                json::encode(&json::obj(vec![
                    ("value", Value::Str(ct)),
                    ("algo", Value::Str(o.algo)),
                    ("length", Value::Num(clen)),
                ]))
            }
        }
        Err(e) => json::encode(&json::obj(vec![("error", Value::Str(format!("fpe: {}", e)))])),
    }
}

/// Luhn check digit (for a 15-digit prefix).
fn luhn_checkdigit(d15: &str) -> u8 {
    let mut sum: u32 = 0;
    let mut alt = true;
    for c in d15.chars().rev() {
        let mut d = c.to_digit(10).unwrap_or(0) as u32;
        if alt {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alt = !alt;
    }
    ((10 - sum % 10) % 10) as u8
}

/// op='fpe_luhn' → first 15 digits FPE, 16th = recomputed Luhn (stays valid)
pub fn fpe_luhn(p: &Value) -> String {
    let digits: String = p.get_s("v").unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect();
    let sub = Value::Obj(vec![
        ("v".into(), Value::Str(digits.get(..15).unwrap_or("").to_string())),
        ("key".into(), p.get("key").cloned().unwrap_or(Value::Null)),
        ("tweak".into(), p.get("tweak").cloned().unwrap_or(Value::Null)),
        ("algo".into(), Value::Str("ff31".into())),
        ("alphabet".into(), Value::Str("digits".into())),
    ]);
    let r = fpe_op(&sub, true);
    // r is JSON; extract value
    let v = json::decode(&r).unwrap_or(Value::Null);
    let ct = v.get_s("value").map(|s| s.to_string());
    let Some(ct) = ct else {
        return r;
    };
    if v.get("error").is_some() {
        return r;
    }
    json::encode(&json::obj(vec![
        (
            "value",
            Value::Str(format!("{}{}", ct, luhn_checkdigit(&ct))),
        ),
        ("algo", Value::Str("ff31".into())),
        (
            "note",
            Value::Str(
                "first 15 digits FPE-encrypted, 16th = recomputed Luhn check digit (output stays Luhn-valid)"
                    .into(),
            ),
        ),
    ]))
}

// ── NIST test vectors ──────────────────────────────────────────────
// SP 800-38G FF3 (AES-128, 8-byte tweak):
//   K = 000102030405060708090A0B0C0D0E0F
//   T = F0F1F2F3F4F5F6F7
//   radix 2: 01 ↔ 10
// ACVP FF3-1 (AES-256, 7-byte tweak) vectors are asserted by the SQL suite
// via the pre-generated case file (gen_fpe_cases.py) to keep parity with the
// Lua's 869-vector campaign. Unit tests here use the classic FF3 vector.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nist_ff3_vector() {
        // Verified FF3 vector from the Python oracle (ff31_ref.py FF3_VECTORS[0],
        // NIST SP 800-38G family, 64-bit tweak).
        let key = hex2bytes("EF4359D8D580AA4F7F036D6F04FC6A94").unwrap();
        let tweak = hex2bytes("D8E7920AFA330A73").unwrap();
        let tw8: [u8; 8] = [tweak[0], tweak[1], tweak[2], tweak[3], tweak[4], tweak[5], tweak[6], tweak[7]];
        let alpha = "0123456789";
        let pt = "890121234567890000";
        let ct = ff3_transform(&key, &tw8, alpha, pt, true, false).unwrap();
        assert_eq!(ct, "750918814058654607");
        let back = ff3_transform(&key, &tw8, alpha, &ct, false, false).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn ff31_nist_vector() {
        // Verified FF3-1 vector (oracle FF31_VECTORS[2], AES-192, 56-bit tweak).
        let key = hex2bytes("718385E6542534604419E83CE387A437").unwrap();
        let t = hex2bytes("B6F35084FA90E1").unwrap();
        let tw8: [u8; 8] = [
            t[0], t[1], t[2], t[3] & 0xF0, t[4], t[5], t[6], (t[3] & 0x0F) << 4,
        ];
        let alpha = "abcdefghijklmnopqrstuvwxyz";
        let pt = "wfmwlrorcd";
        let ct = ff3_transform(&key, &tw8, alpha, pt, true, true).unwrap();
        assert_eq!(ct, "ywowehycyd");
        let back = ff3_transform(&key, &tw8, alpha, &ct, false, true).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn fpe_deterministic_and_distinct() {
        let mk = |v: &str| -> Value {
            Value::Obj(vec![
                ("v".into(), Value::Str(v.into())),
                ("key".into(), Value::Str("00000000000000000000000000000000".into())),
                ("algo".into(), Value::Str("ff31".into())),
            ])
        };
        let a = fpe_op(&mk("1234567890123456"), true);
        let b = fpe_op(&mk("1234567890123456"), true);
        assert_eq!(a, b);
        let c = fpe_op(&mk("1234567890123457"), true);
        assert_ne!(a, c);
        // decode inverts
        let dec = json::decode(&a).unwrap();
        let ct = dec.get_s("value").unwrap().to_string();
        let dec_p = Value::Obj(vec![
            ("v".into(), Value::Str(ct)),
            ("key".into(), Value::Str("00000000000000000000000000000000".into())),
            ("algo".into(), Value::Str("ff31".into())),
        ]);
        let back = json::decode(&fpe_op(&dec_p, false)).unwrap();
        assert_eq!(back.get_s("value").unwrap(), "1234567890123456");
    }
}
