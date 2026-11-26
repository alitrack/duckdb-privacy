//! k-anonymity (simplified Mondrian: equal-weight range split +
//! interval/prefix generalization) + kanon_report (l-diversity,
//! t-closeness, suppression rate, generalization loss — GB/T 42460
//! de-identification effect elements).
//!
//! Ported from privacy.lua ops: kanon / kanon_report.
//!
//! Honest boundaries (carried over): equal-weight splits only (not strict
//! Mondrian IL minimization); l-diversity = distinct-l + entropy-l (no
//! recursive-(c,l)); t-closeness = TV (categorical) or normalized 1-D EMD
//! (ordered), not full EMD; generalization loss is a simplified ILA.

use crate::json::{self, Value};
use std::collections::HashMap;

#[derive(Clone)]
struct Rec {
    id: f64,
    id_set: bool,
    qi: Vec<(String, Value)>,
    sens: Option<String>,
}

impl Rec {
    fn qi_get(&self, f: &str) -> Option<&Value> {
        self.qi.iter().find(|(k, _)| k == f).map(|(_, v)| v)
    }
    fn qi_num(&self, f: &str) -> Option<f64> {
        self.qi_get(f).and_then(json::to_f64)
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).map(json::to_str_lossy).unwrap_or_default()
}
fn f(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(json::to_f64).unwrap_or(f64::NAN)
}
fn f_opt(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(json::to_f64)
}

/// Parse records from either the `records` array form or the parallel-array
/// form ({age:[...], city:[...], id:[...], sens:[...]}).
fn parse_records(p: &Value) -> Result<Vec<Rec>, String> {
    if let Some(recs) = p.get_arr("records") {
        if recs.is_empty() {
            return Err("records required".into());
        }
        let mut out = Vec::with_capacity(recs.len());
        for r in recs {
            let mut rec = Rec {
                id: 0.0,
                id_set: false,
                qi: Vec::new(),
                sens: None,
            };
            if let Value::Obj(_) = r {
                if let Some(id) = r.get("id") {
                    rec.id = json::to_f64(id).unwrap_or(0.0);
                    rec.id_set = true;
                }
                if let Some(sens) = r.get("sens") {
                    rec.sens = Some(json::to_str_lossy(sens));
                }
                if let Some(qi) = r.get("qi") {
                    if let Value::Obj(pairs) = qi {
                        rec.qi = pairs
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                    }
                }
            }
            out.push(rec);
        }
        return Ok(out);
    }
    // parallel-array form
    let control: &[&str] = &["op", "records", "k"];
    let mut arrs: Vec<(String, Vec<Value>)> = Vec::new();
    if let Value::Obj(pairs) = p {
        for (k, v) in pairs {
            if control.contains(&k.as_str()) {
                continue;
            }
            if let Value::Arr(a) = v {
                if !a.is_empty() {
                    arrs.push((k.clone(), a.clone()));
                }
            }
        }
    }
    let n = arrs.iter().map(|(_, a)| a.len()).max().unwrap_or(0);
    if n == 0 {
        return Err("records required".into());
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut rec = Rec {
            id: 0.0,
            id_set: false,
            qi: Vec::new(),
            sens: None,
        };
        for (k, a) in &arrs {
            if let Some(v) = a.get(i) {
                match k.as_str() {
                    "sens" => rec.sens = Some(json::to_str_lossy(v)),
                    "id" => {
                        rec.id = json::to_f64(v).unwrap_or(0.0);
                        rec.id_set = true;
                    }
                    _ => rec.qi.push((k.clone(), v.clone())),
                }
            }
        }
        out.push(rec);
    }
    Ok(out)
}

fn qi_min(rows: &[Rec], field: &str) -> f64 {
    rows.iter()
        .filter_map(|r| r.qi_num(field))
        .fold(f64::INFINITY, f64::min)
}
fn qi_max(rows: &[Rec], field: &str) -> f64 {
    rows.iter()
        .filter_map(|r| r.qi_num(field))
        .fold(f64::NEG_INFINITY, f64::max)
}

fn common_prefix(strs: &[String]) -> String {
    if strs.is_empty() {
        return String::new();
    }
    if strs.len() == 1 {
        return strs[0].clone();
    }
    let mut p = strs[0].clone();
    for s in &strs[1..] {
        let k = p
            .chars()
            .zip(s.chars())
            .take_while(|(a, b)| a == b)
            .count();
        p = p.chars().take(k).collect();
        if p.is_empty() {
            break;
        }
    }
    p
}

/// Split core: find the widest numeric dimension, median-split.
fn split(rows: &[Rec], k: i64) -> Option<(Vec<Rec>, Vec<Rec>)> {
    if rows.len() <= (2 * k - 1) as usize {
        return None;
    }
    // fields come from the first record (all records share the qi schema)
    let fields: Vec<&str> = rows[0]
        .qi
        .iter()
        .filter(|(_, v)| matches!(v, Value::Num(_)))
        .map(|(k, _)| k.as_str())
        .collect();
    let mut best: Option<(&str, f64)> = None;
    for f in fields {
        let span = qi_max(rows, f) - qi_min(rows, f);
        if best.map_or(true, |(_, bs)| span > bs) {
            best = Some((f, span));
        }
    }
    let (bf, _) = best?;
    let mut sorted: Vec<&Rec> = rows.iter().collect();
    sorted.sort_by(|a, b| a.qi_num(bf).unwrap_or(0.0).partial_cmp(&b.qi_num(bf).unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));
    let mid = sorted.len() / 2;
    let left: Vec<Rec> = sorted[..mid].iter().map(|r| (*r).clone()).collect();
    let right: Vec<Rec> = sorted[mid..].iter().map(|r| (*r).clone()).collect();
    Some((left, right))
}

fn kanon_core(records: &mut [Rec], k: i64) -> Vec<Vec<Rec>> {
    let mut groups: Vec<Vec<Rec>> = vec![records.to_vec()];
    let mut stable = false;
    while !stable {
        stable = true;
        let mut next = Vec::new();
        for g in groups {
            if g.len() >= (2 * k) as usize {
                if let Some((l, r)) = split(&g, k) {
                    if l.len() >= k as usize && r.len() >= k as usize {
                        stable = false;
                        next.push(l);
                        next.push(r);
                        continue;
                    }
                }
            }
            next.push(g);
        }
        groups = next;
    }
    groups
}

/// Generalize one group's qi into the output form (numeric → "[min,max]",
/// string → common prefix or '*').
fn generalize_group(g: &[Rec]) -> Vec<(String, String)> {
    let sample_fields: Vec<String> = g[0]
        .qi
        .iter()
        .filter(|(_, v)| !matches!(v, Value::Null))
        .map(|(k, _)| k.clone())
        .collect();
    let mut out = Vec::new();
    for f in sample_fields {
        let is_num = g[0].qi_get(&f).map(|v| matches!(v, Value::Num(_))).unwrap_or(false);
        if is_num {
            let lo = qi_min(g, &f);
            let hi = qi_max(g, &f);
            out.push((f, format!("[{},{}]", json::fmt_g(lo), json::fmt_g(hi))));
        } else {
            // A ragged qi (parallel arrays of different lengths, or records with
            // different keys) can leave a record missing a field that g[0] has; map
            // the absent value to the empty string rather than unwrapping (which
            // panicked and aborted the whole process).
            let strs: Vec<String> = g.iter().map(|r| r.qi_get(&f).map(json::to_str_lossy).unwrap_or_default()).collect();
            let pref = common_prefix(&strs);
            out.push((f, if pref.is_empty() { "*".into() } else { pref }));
        }
    }
    out
}

fn group_ids(g: &[Rec]) -> Value {
    Value::Arr(g.iter().map(|r| Value::Num(if r.id_set { r.id } else { 0.0 })).collect())
}

/// op='kanon' → {"groups":[...],"suppressed":N,"k":K}
pub fn kanon(p: &Value) -> String {
    let mut records = match parse_records(p) {
        Ok(r) => r,
        Err(e) => return json::encode(&json::obj(vec![("error", Value::Str(e))])),
    };
    // k is clamped to [1, 1e6]: 1e30 saturates `as i64` to i64::MAX, and the
    // `2 * k` arithmetic in kanon_core would overflow (debug: panic).
    let k = f_opt(p, "k").map(|x| x as i64).unwrap_or(2).clamp(1, 1_000_000);
    let groups = kanon_core(&mut records, k);
    let mut suppressed = 0i64;
    let mut out_groups = Vec::new();
    for g in &groups {
        if g.len() < k as usize {
            suppressed += g.len() as i64;
        }
        let qi_out = generalize_group(g);
        let pairs: Vec<(&str, Value)> = vec![
            ("size", Value::Num(g.len() as f64)),
            (
                "qi",
                Value::Obj(
                    qi_out
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::Str(v.clone())))
                        .collect(),
                ),
            ),
            ("ids", group_ids(g)),
        ];
        out_groups.push(json::obj(pairs));
    }
    format!(
        "{{\"groups\":{},\"suppressed\":{},\"k\":{}}}",
        json::encode(&Value::Arr(out_groups)),
        suppressed,
        k
    )
}

// ── kanon_report ───────────────────────────────────────────────────

fn sens_value(r: &Rec, p: &Value) -> Option<String> {
    if let Some(sf) = p.get_s("sensitive_field") {
        return r.qi_get(sf).map(json::to_str_lossy);
    }
    r.sens.clone()
}

fn build_dist(rows: &[Rec], p: &Value) -> (HashMap<String, i64>, i64, i64) {
    let mut d: HashMap<String, i64> = HashMap::new();
    let mut n = 0i64;
    let mut miss = 0i64;
    for r in rows {
        match sens_value(r, p) {
            Some(v) => {
                *d.entry(v).or_insert(0) += 1;
                n += 1;
            }
            None => miss += 1,
        }
    }
    (d, n, miss)
}

fn entropy_bits(d: &HashMap<String, i64>, n: i64) -> f64 {
    if n <= 0 {
        return 0.0;
    }
    let mut h = 0.0;
    let ln2 = 2f64.ln();
    for &c in d.values() {
        let pr = c as f64 / n as f64;
        h -= pr * (pr.ln() / ln2);
    }
    h
}

fn tv_distance(dg: &HashMap<String, i64>, ng: i64, dq: &HashMap<String, i64>, nq: i64) -> f64 {
    if ng <= 0 || nq <= 0 {
        return 0.0;
    }
    let mut keys: std::collections::HashSet<&String> = dg.keys().collect();
    for k in dq.keys() {
        keys.insert(k);
    }
    let mut s = 0.0;
    for k in keys {
        let pg = *dg.get(k).unwrap_or(&0) as f64 / ng as f64;
        let pq = *dq.get(k).unwrap_or(&0) as f64 / nq as f64;
        s += (pg - pq).abs();
    }
    s / 2.0
}

/// Normalized 1-D EMD (Wasserstein-1) over the union of support points.
/// Returns None when the distributions are not numeric (caller falls back
/// to TV).
fn emd_1d(dg: &HashMap<String, i64>, ng: i64, dq: &HashMap<String, i64>, nq: i64) -> Option<f64> {
    if ng <= 0 || nq <= 0 {
        return None;
    }
    let mut u: Vec<f64> = Vec::new();
    let mut numeric = true;
    for k in dg.keys() {
        match k.parse::<f64>() {
            // f64 parsing accepts "NaN"/"inf"; reject non-finite so the
            // support set (and the EMD) stays finite.
            Ok(x) if x.is_finite() => u.push(x),
            _ => {
                numeric = false;
                break;
            }
        }
    }
    if numeric {
        for k in dq.keys() {
            match k.parse::<f64>() {
                Ok(x) if x.is_finite() => u.push(x),
                _ => {
                    numeric = false;
                    break;
                }
            }
        }
    }
    if !numeric || u.len() < 2 {
        return None;
    }
    // Re-key each distribution by its parsed numeric value instead of by the
    // fmt_g string. A sensitive field stored as a non-canonical numeric string
    // ("1e5", "100.0", "75000.00") is keyed by its original text in
    // build_dist, so the old `fmt_g(u[i])` lookup silently returned 0 for it
    // and the cumulative mass (hence t-closeness / EMD) was wrong. Keying by
    // f64 also collapses equivalent forms ("100"/"100.0") onto one point.
    //
    // A HashMap can't be keyed by f64 (no Hash/Eq for floats), so accumulate
    // into a Vec, sort, and merge near-equal values. Each u[i] is one of the
    // accumulated keys, so the binary search below always lands.
    let mut num_g: Vec<(f64, i64)> = dg
        .iter()
        .filter_map(|(k, c)| k.parse::<f64>().ok().filter(|x| x.is_finite()).map(|x| (x, *c)))
        .collect();
    let mut num_q: Vec<(f64, i64)> = dq
        .iter()
        .filter_map(|(k, c)| k.parse::<f64>().ok().filter(|x| x.is_finite()).map(|x| (x, *c)))
        .collect();
    num_g.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    num_q.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let merge = |v: &mut Vec<(f64, i64)>| {
        v.dedup_by(|a, b| (a.0 - b.0).abs() < 1e-15);
        let mut out: Vec<(f64, i64)> = Vec::with_capacity(v.len());
        for (x, c) in v.iter() {
            match out.last_mut() {
                Some(last) if (last.0 - *x).abs() < 1e-15 => last.1 += *c,
                _ => out.push((*x, *c)),
            }
        }
        *v = out;
    };
    merge(&mut num_g);
    merge(&mut num_q);
    let count_at = |v: &[(f64, i64)], x: f64| -> i64 {
        match v.binary_search_by(|e| e.0.partial_cmp(&x).unwrap_or(std::cmp::Ordering::Equal)) {
            Ok(i) => v[i].1,
            Err(_) => 0,
        }
    };
    u.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    u.dedup_by(|a, b| (*a - *b).abs() < 1e-15);
    let span = u[u.len() - 1] - u[0];
    if span <= 0.0 {
        return Some(0.0);
    }
    let mut cum_g = 0.0;
    let mut cum_q = 0.0;
    let mut s = 0.0;
    for i in 0..u.len() - 1 {
        cum_g += count_at(&num_g, u[i]) as f64 / ng as f64;
        cum_q += count_at(&num_q, u[i]) as f64 / nq as f64;
        s += (cum_g - cum_q).abs() * (u[i + 1] - u[i]);
    }
    Some(s / span)
}

fn field_spans(rows: &[Rec]) -> HashMap<String, (f64, f64)> {
    let mut sp: HashMap<String, (f64, f64)> = HashMap::new();
    for r in rows {
        for (f, v) in &r.qi {
            if let Some(x) = json::to_f64(v) {
                let e = sp.entry(f.clone()).or_insert((x, x));
                e.0 = e.0.min(x);
                e.1 = e.1.max(x);
            }
        }
    }
    sp
}

fn group_ila(g: &[Rec], spans: &HashMap<String, (f64, f64)>) -> f64 {
    let fields: Vec<&str> = g[0]
        .qi
        .iter()
        .filter(|(_, v)| !matches!(v, Value::Null))
        .map(|(k, _)| k.as_str())
        .collect();
    if fields.is_empty() {
        return 0.0;
    }
    let nf = fields.len();
    let mut sum = 0.0;
    for f in &fields {
        let is_num = g[0].qi_get(f).map(|v| matches!(v, Value::Num(_))).unwrap_or(false);
        if is_num {
            let span = qi_max(g, f) - qi_min(g, f);
            let gs = spans.get(&f[..]).map(|(lo, hi)| hi - lo).unwrap_or(0.0);
            sum += if gs > 0.0 { span / gs } else { 0.0 };
        } else {
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for r in g {
                // same ragged-qi guard as generalize_group: missing field -> ""
                seen.insert(r.qi_get(f).map(json::to_str_lossy).unwrap_or_default());
            }
            let cnt = seen.len();
            sum += if cnt > 0 { 1.0 - 1.0 / cnt as f64 } else { 0.0 };
        }
    }
    sum / nf as f64
}

/// op='kanon_report' → {"report":{...},"groups":[...]}
pub fn kanon_report(p: &Value) -> String {
    let mut records = match parse_records(p) {
        Ok(r) => r,
        Err(e) => return json::encode(&json::obj(vec![("error", Value::Str(e))])),
    };
    let k = f_opt(p, "k").map(|x| x as i64).unwrap_or(2).clamp(1, 1_000_000);
    let groups = kanon_core(&mut records, k);
    let n = records.len() as i64;
    let l_req = f_opt(p, "l").unwrap_or(2.0);
    let t_req = f_opt(p, "t").unwrap_or(0.2);
    let (gl_d, gl_n, gl_miss) = build_dist(&records, p);
    let have_sens = gl_n > 0;
    let spans = field_spans(&records);

    let mut suppressed = 0i64;
    let mut min_size = i64::MAX;
    let mut min_distinct_l = i64::MAX;
    let mut min_entropy_l = f64::INFINITY;
    let mut max_t = 0.0;
    let mut t_metric = "tv".to_string();
    let mut weighted_ila = 0.0;
    let mut pub_n = 0i64;
    let mut n_pub_groups = 0i64;
    let mut out_groups = Vec::new();

    for g in &groups {
        let qi_out = generalize_group(g);
        let mut ent: Vec<(&str, Value)> = vec![
            ("size", Value::Num(g.len() as f64)),
            (
                "qi",
                Value::Obj(
                    qi_out
                        .iter()
                        .map(|(kk, v)| (kk.clone(), Value::Str(v.clone())))
                        .collect(),
                ),
            ),
            ("ids", group_ids(g)),
        ];
        let (dg, ng, _gl_miss_g) = build_dist(g, p);
        let ila = group_ila(g, &spans);
        ent.push(("ila", Value::Num(ila)));
        if g.len() < k as usize {
            suppressed += g.len() as i64;
        } else {
            n_pub_groups += 1;
            if (g.len() as i64) < min_size {
                min_size = g.len() as i64;
            }
            pub_n += g.len() as i64;
            weighted_ila += ila * g.len() as f64;
            if have_sens && ng > 0 {
                let dl = dg.len() as i64;
                let el = entropy_bits(&dg, ng);
                ent.push(("distinct_l", Value::Num(dl as f64)));
                ent.push(("entropy_l", Value::Num(el)));
                if dl < min_distinct_l {
                    min_distinct_l = dl;
                }
                if el < min_entropy_l {
                    min_entropy_l = el;
                }
                let tv = tv_distance(&dg, ng, &gl_d, gl_n);
                let mut t = tv;
                if p.get("ordered").is_some()
                    && matches!(p.get("ordered"), Some(Value::Bool(true)))
                {
                    if let Some(e) = emd_1d(&dg, ng, &gl_d, gl_n) {
                        t = e;
                        t_metric = "emd".to_string();
                    }
                }
                ent.push(("t", Value::Num(t)));
                if t > max_t {
                    max_t = t;
                }
            }
        }
        out_groups.push(json::obj(ent));
    }
    if min_size == i64::MAX {
        min_size = 0;
    }
    let k_ok = suppressed == 0;
    let mut l_ok: Option<bool> = None;
    let mut t_ok: Option<bool> = None;
    let mut violations: Vec<String> = Vec::new();
    if have_sens {
        let l_ok_val = min_distinct_l != i64::MAX && min_distinct_l >= l_req as i64;
        let h_need = l_req.ln() / 2f64.ln();
        l_ok = Some(l_ok_val && min_entropy_l != f64::INFINITY && min_entropy_l + 1e-9 >= h_need);
        t_ok = Some(max_t <= t_req + 1e-12);
        if !l_ok.unwrap() {
            violations.push("l".into());
        }
        if !t_ok.unwrap() {
            violations.push("t".into());
        }
    }
    if !k_ok {
        violations.push("k".into());
    }
    let pass = k_ok && (!have_sens || (l_ok.unwrap_or(true) && t_ok.unwrap_or(true)));

    let mut rep: Vec<(&str, Value)> = vec![
        ("k", Value::Num(k as f64)),
        ("k_ok", Value::Bool(k_ok)),
        ("n", Value::Num(n as f64)),
        ("groups", Value::Num(n_pub_groups as f64)),
        ("suppressed", Value::Num(suppressed as f64)),
        (
            "suppression_rate",
            Value::Num(if n > 0 { suppressed as f64 / n as f64 } else { 0.0 }),
        ),
        ("min_class_size", Value::Num(min_size as f64)),
        (
            "generalization_loss",
            Value::Num(if pub_n > 0 { weighted_ila / pub_n as f64 } else { 0.0 }),
        ),
        (
            "total_generalization_loss",
            Value::Num(if n > 0 { weighted_ila / n as f64 } else { 0.0 }),
        ),
        ("verdict", Value::Str(if pass { "pass" } else { "fail" }.into())),
        (
            "violations",
            Value::Arr(violations.into_iter().map(Value::Str).collect()),
        ),
    ];
    if have_sens {
        rep.push(("l", Value::Num(l_req)));
        rep.push(("l_ok", Value::Bool(l_ok.unwrap_or(false))));
        rep.push((
            "min_distinct_l",
            Value::Num(if min_distinct_l == i64::MAX { 0 } else { min_distinct_l } as f64),
        ));
        rep.push((
            "min_entropy_l",
            Value::Num(if min_entropy_l == f64::INFINITY { 0.0 } else { min_entropy_l }),
        ));
        rep.push(("t", Value::Num(t_req)));
        rep.push(("t_ok", Value::Bool(t_ok.unwrap_or(false))));
        rep.push(("max_t", Value::Num(max_t)));
        rep.push(("t_metric", Value::Str(t_metric)));
        rep.push(("sensitive_missing", Value::Num(gl_miss as f64)));
    }
    format!(
        "{{\"report\":{},\"groups\":{}}}",
        json::encode(&json::obj(rep)),
        json::encode(&Value::Arr(out_groups))
    )
}

// ── tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn recs_json() -> Value {
        json::decode(
            r#"[{"id":1,"qi":{"age":25,"city":"hz"}},
                {"id":2,"qi":{"age":26,"city":"hz"}},
                {"id":3,"qi":{"age":60,"city":"sh"}},
                {"id":4,"qi":{"age":61,"city":"sh"}}]"#,
        )
        .unwrap()
    }

    #[test]
    fn kanon_splits_two() {
        let recs = recs_json();
        let p = Value::Obj(vec![
            ("records".into(), recs),
            ("k".into(), Value::Num(2.0)),
        ]);
        let out = kanon(&p);
        let v = json::decode(&out).unwrap();
        let groups = v.get_arr("groups").unwrap();
        assert_eq!(groups.len(), 2);
        assert!(v.get("suppressed").is_some(), "suppressed field present");
    }

    #[test]
    fn kanon_suppress_small() {
        let p = Value::Obj(vec![
            (
                "records".into(),
                json::decode(
                    r#"[{"id":1,"qi":{"age":25}},{"id":2,"qi":{"age":26}},{"id":3,"qi":{"age":90}}]"#,
                )
                .unwrap(),
            ),
            ("k".into(), Value::Num(5.0)),
        ]);
        let out = kanon(&p);
        assert!(out.contains("\"suppressed\":3"));
    }

    /// Regression (P2): `emd_1d` used to look each support point up as
    /// `fmt_g(parsed_value)` in the *string-keyed* distribution. A sensitive
    /// field stored as a non-canonical numeric string ("1e5") parses to
    /// 100000.0, but `fmt_g(100000.0)` is "100000", so the lookup silently
    /// returned 0 and the cumulative mass (→ t-closeness / EMD) was wrong.
    ///
    /// Two distributions that are *identical in value* — one record at each of
    /// 1.0, 100000.0, 999999.0 — differ only in spelling one of them "1e5"
    /// vs "100000". The (non-canonical) 100000.0 sits in the interior, so the
    /// old fmt_g keying dropped its mass and reported a spurious EMD (~0.30);
    /// re-keying by the parsed f64 correctly collapses both spellings onto one
    /// point, so the EMD must be exactly 0.
    #[test]
    fn emd_ignores_noncanonical_spelling() {
        let dg: HashMap<String, i64> = [("1".into(), 1), ("1e5".into(), 1), ("999999".into(), 1)]
            .into_iter().collect();
        let dq: HashMap<String, i64> = [("1".into(), 1), ("100000".into(), 1), ("999999".into(), 1)]
            .into_iter().collect();
        let e = emd_1d(&dg, 3, &dq, 3).expect("numeric distributions must yield an EMD");
        assert!((e - 0.0).abs() < 1e-9, "identical distributions have EMD 0, got {e}");
    }

    #[test]
    fn report_verdict() {
        let p = Value::Obj(vec![
            (
                "records".into(),
                json::decode(
                    r#"[{"id":1,"qi":{"age":25},"sens":"a"},{"id":2,"qi":{"age":26},"sens":"b"},
                        {"id":3,"qi":{"age":60},"sens":"c"},{"id":4,"qi":{"age":61},"sens":"d"}]"#,
                )
                .unwrap(),
            ),
            ("k".into(), Value::Num(2.0)),
            ("l".into(), Value::Num(2.0)),
            ("t".into(), Value::Num(0.2)),
        ]);
        let out = kanon_report(&p);
        let v = json::decode(&out).unwrap();
        let rep = v.get("report").unwrap();
        assert!(out.contains("\"verdict\":\"pass\"") || out.contains("\"verdict\":\"fail\""));
        assert!(rep.get("k_ok").is_some(), "k_ok field present in report");
    }

    /// Regression (MUST-FIX-1, 4th re-review): the parallel-array form builds
    /// `n = max array length` records, so shorter arrays leave later records
    /// missing a field that g[0] has. generalize_group used to `qi_get(f)
    /// .unwrap()` on the missing field and panic (SIGABRT). It must now treat
    /// the missing field as the empty string and return a valid report.
    #[test]
    fn kanon_ragged_parallel_arrays() {
        // age has 4 values, city has 2 -> records 2 and 3 have no city.
        let p = json::decode(r#"{"k":5,"age":[25,26,90,91],"city":["hz","sh"]}"#).unwrap();
        let out = kanon(&p);
        let v = json::decode(&out).unwrap();
        assert!(v.get("groups").is_some(), "groups present: {out}");
        assert!(!out.contains("\"error\""), "no error for ragged input: {out}");
    }

    /// Records form with differing qi keys (record 3 has no city) is the same
    /// class of ragged input; must also not panic.
    #[test]
    fn kanon_ragged_records_keys() {
        let p = json::decode(r#"{"k":5,"records":[
            {"id":1,"qi":{"age":25,"city":"hz"}},
            {"id":2,"qi":{"age":26,"city":"sh"}},
            {"id":3,"qi":{"age":90}},
            {"id":4,"qi":{"age":91}}]}"#).unwrap();
        let out = kanon(&p);
        let v = json::decode(&out).unwrap();
        assert!(v.get("groups").is_some(), "groups present: {out}");
    }
}
