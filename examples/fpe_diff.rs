//! Differential test: verify Rust ff3_transform against the Python oracle's
//! NIST vectors (15 FF3 SP 800-38G + 18 FF3-1 ACVP), enc AND dec.
//! Input: JSON lines {kind, alphabet, key, tweak, pt, ct} from
//! scripts/emit_vectors.py (read from env FPE_VECTORS path).
use privacy::fpe::{ff3_transform, hex2bytes};
use std::env;

fn main() {
    let path = env::var("FPE_VECTORS").expect("set FPE_VECTORS=/path/vectors.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut pass = 0;
    let mut fail = 0;
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let kind = jstr(line, "kind");
        let alpha = jstr(line, "alphabet");
        let key_h = jstr(line, "key");
        let t_h = jstr(line, "tweak");
        let pt = jstr(line, "pt");
        let ct = jstr(line, "ct");
        let key = hex2bytes(&key_h).unwrap();
        let t = hex2bytes(&t_h).unwrap();
        let tw8: [u8; 8] = if kind == "ff31" {
            [
                t[0],
                t[1],
                t[2],
                t[3] & 0xF0,
                t[4],
                t[5],
                t[6],
                (t[3] & 0x0F) << 4,
            ]
        } else {
            [t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]]
        };
        let ff31 = kind == "ff31";
        let got = ff3_transform(&key, &tw8, &alpha, &pt, true, ff31).unwrap();
        let ok1 = got == ct;
        if !ok1 {
            fail += 1;
            println!("FAIL enc  #{} {} pt={} got={} expect={}", n, kind, pt, got, ct);
        }
        let back = ff3_transform(&key, &tw8, &alpha, &ct, false, ff31).unwrap();
        let ok2 = back == pt;
        if !ok2 {
            fail += 1;
            println!("FAIL dec  #{} {} ct={} got={} expect={}", n, kind, ct, back, pt);
        }
        if ok1 && ok2 {
            pass += 1;
        }
    }
    println!("differential: {pass} pass, {fail} fail (each pass = enc+dec)");
    std::process::exit(if fail == 0 { 0 } else { 1 });
}

fn jstr(line: &str, key: &str) -> String {
    let k = format!("\"{}\":", key);
    let i = line.find(&k).unwrap() + k.len();
    let rest = &line[i..];
    let s = rest.find('"').unwrap() + 1;
    let e = rest[s..].find('"').unwrap() + s;
    rest[s..e].to_string()
}
