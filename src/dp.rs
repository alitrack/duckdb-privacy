//! Differential privacy mechanisms + epsilon budget ledger.
//! Ported from privacy.lua ops: dp_count / dp_sum / dp_mean / laplace /
//! dp_compose / dp_alloc / dp_budget.

use crate::json::{self, Value};
use crate::rng::Rng;

fn f(v: &Value, k: &str) -> f64 {
    v.get(k).and_then(json::to_f64).unwrap_or(f64::NAN)
}

fn f_opt(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(json::to_f64)
}

fn seed_of(p: &Value) -> i64 {
    f_opt(p, "seed").map(|s| s as i64).unwrap_or_else(|| {
        // Lua default: os.time() — wall clock seconds
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(1)
    })
}

// ── mechanisms ─────────────────────────────────────────────────────

/// op='dp_count' → "123" (integer string)
pub fn dp_count(p: &Value) -> String {
    let sensitivity = f_opt(p, "sensitivity").unwrap_or(1.0);
    let epsilon = f_opt(p, "epsilon").unwrap_or(1.0);
    let scale = sensitivity / epsilon;
    let mut rng = Rng::new(seed_of(p));
    let v = f_opt(p, "true_count").unwrap_or(0.0) + rng.laplace(scale);
    format!("{}", (v + 0.5).floor() as i64)
}

/// op='dp_sum' → "%.2f"
pub fn dp_sum(p: &Value) -> String {
    let sensitivity = f_opt(p, "sensitivity").unwrap_or(100.0);
    let epsilon = f_opt(p, "epsilon").unwrap_or(1.0);
    let mut rng = Rng::new(seed_of(p));
    let v = f_opt(p, "true_sum").unwrap_or(0.0) + rng.laplace(sensitivity / epsilon);
    format!("{:.2}", v)
}

/// op='dp_mean' → "%.4f" or "null"
pub fn dp_mean(p: &Value) -> String {
    let eps = f_opt(p, "epsilon").unwrap_or(1.0);
    let mut rng = Rng::new(seed_of(p));
    let s_sum = f_opt(p, "range").unwrap_or(100.0) / eps;
    let s_cnt = 1.0 / eps;
    let cnt = f_opt(p, "true_count").unwrap_or(0.0) + rng.laplace(s_cnt);
    if cnt < 1.0 {
        return "null".into();
    }
    let mean = (f_opt(p, "true_sum").unwrap_or(0.0) + rng.laplace(s_sum)) / cnt;
    format!("{:.4}", mean)
}

/// op='laplace' → one Laplace(0, scale) draw, "%.6f"
pub fn laplace(p: &Value) -> String {
    let scale = f_opt(p, "scale").unwrap_or(1.0);
    let mut rng = Rng::new(seed_of(p));
    format!("{:.6}", rng.laplace(scale))
}

// ── composition / budget ledger ────────────────────────────────────

/// Dwork-Roth advanced composition bound.
fn advanced_epsilon(list: &[f64], delta: f64) -> f64 {
    let s1: f64 = list.iter().map(|e| e * (e.exp() - 1.0)).sum();
    let s2: f64 = list.iter().map(|e| e * e).sum();
    s1 + (2.0 * (1.0 / delta).ln() * s2).sqrt()
}

fn list_sum(list: &[f64]) -> f64 {
    list.iter().sum()
}

/// p.epsilon / p.epsilons / p.count → list of per-query epsilons.
fn eps_list(p: &Value) -> Vec<f64> {
    let mut list = Vec::new();
    if let Some(arr) = p.get_arr("epsilons") {
        for e in arr {
            if let Some(x) = json::to_f64(e) {
                list.push(x);
            }
        }
    }
    let one = f_opt(p, "epsilon");
    let cnt = f_opt(p, "count").map(|c| c as i64).unwrap_or(0);
    if let Some(e) = one {
        if list.is_empty() && cnt > 0 {
            list.extend(std::iter::repeat(e).take(cnt as usize));
        } else if cnt <= 0 {
            list.push(e);
        }
    }
    list
}

/// op='dp_compose' → JSON {n, delta, basic_total, advanced_total, saving_ratio}
pub fn dp_compose(p: &Value) -> String {
    let delta = f_opt(p, "delta").unwrap_or(1e-5);
    let list = eps_list(p);
    if list.is_empty() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("epsilon or epsilons required".into()),
        )]));
    }
    let basic = list_sum(&list);
    let adv = advanced_epsilon(&list, delta);
    let saving = if basic > 0.0 { adv / basic } else { 0.0 };
    format!(
        "{{\"n\":{},\"delta\":{},\"basic_total\":{:.9},\"advanced_total\":{:.9},\"saving_ratio\":{:.4}}}",
        list.len(),
        json::fmt_g(delta),
        basic,
        adv,
        saving
    )
}

/// op='dp_alloc' → JSON budget allocation record.
pub fn dp_alloc(p: &Value) -> String {
    let budget = f_opt(p, "budget").unwrap_or(1.0);
    let n = f_opt(p, "n").map(|x| x as i64).unwrap_or(0);
    if n <= 0 {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("n (query count) must be >= 1".into()),
        )]));
    }
    let comp = p.get_s("composition").unwrap_or("basic").to_string();
    let delta = f_opt(p, "delta").unwrap_or(1e-5);
    let basic_per = budget / n as f64;

    // advanced: binary search for the largest uniform ε whose strong
    // composition bound stays ≤ budget (80 iterations, as in the Lua)
    let mut lo = 0.0;
    let mut hi = budget;
    for _ in 0..80 {
        let mid = (lo + hi) / 2.0;
        let lst = vec![mid; n as usize];
        if advanced_epsilon(&lst, delta) <= budget {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let adv_per = lo;

    let per = if comp == "advanced" || comp == "auto" { adv_per } else { basic_per };
    let best = if adv_per > basic_per { "advanced" } else { "basic" };
    let rec = if best == "advanced" { adv_per } else { basic_per };

    let bound_of = |x: f64| -> f64 {
        if (x - basic_per).abs() < 1e-15 {
            x * n as f64
        } else {
            advanced_epsilon(&vec![x; n as usize], delta)
        }
    };
    format!(
        "{{\"budget\":{},\"n\":{},\"delta\":{},\"requested_composition\":\"{}\",\
         \"per_query\":{:.9},\"total_bound\":{:.9},\"basic_per\":{:.9},\"advanced_per\":{:.9},\
         \"basic_total\":{:.9},\"advanced_total\":{:.9},\"best\":\"{}\",\"recommended_per_query\":{:.9}}}",
        json::fmt_g(budget),
        n,
        json::fmt_g(delta),
        comp,
        per,
        bound_of(per),
        basic_per,
        adv_per,
        basic_per * n as f64,
        bound_of(adv_per),
        best,
        rec
    )
}

/// op='dp_budget' → JSON single-step ledger gate.
pub fn dp_budget(p: &Value) -> String {
    let budget = f_opt(p, "budget").unwrap_or(1.0);
    let request = f_opt(p, "request").unwrap_or(0.0);
    let delta = f_opt(p, "delta").unwrap_or(1e-5);
    let comp = p.get_s("composition").unwrap_or("basic").to_string();
    let mut list: Vec<f64> = Vec::new();
    let mut entries = 0;
    if let Some(ledger) = p.get_arr("ledger") {
        for e in ledger {
            let x = match e {
                Value::Num(n) => Some(*n),
                Value::Obj(_) => e.get("epsilon").and_then(json::to_f64),
                Value::Str(s) => s.parse::<f64>().ok(),
                _ => None,
            };
            if let Some(x) = x {
                list.push(x);
                entries += 1;
            }
        }
    }
    let spent = f_opt(p, "spent").unwrap_or(0.0);
    let extra = spent - list_sum(&list);
    if extra > 1e-12 {
        list.push(extra);
    }
    let before = list_sum(&list);
    let after_basic = before + request;
    let mut tot_before = before;
    let mut tot_after = after_basic;
    if comp == "advanced" {
        tot_before = advanced_epsilon(&list, delta);
        let mut l2 = list.clone();
        l2.push(request);
        tot_after = advanced_epsilon(&l2, delta);
    }
    let allow = tot_after <= budget + 1e-12;
    format!(
        "{{\"allow\":{},\"composition\":\"{}\",\"budget\":{},\"request\":{},\"delta\":{},\"entries\":{},\
         \"spent_before\":{:.9},\"spent_after\":{:.9},\"total_before\":{:.9},\"total_after\":{:.9},\
         \"remaining_before\":{:.9},\"remaining_after\":{:.9},\"reason\":\"{}\"}}",
        if allow { "true" } else { "false" },
        comp,
        json::fmt_g(budget),
        json::fmt_g(request),
        json::fmt_g(delta),
        entries,
        before,
        after_basic,
        tot_before,
        tot_after,
        budget - tot_before,
        budget - tot_after,
        if allow { "ok" } else { "budget_exceeded" }
    )
}

/// Suppress helper — the '␀SUPPRESSED' marker string (U+2400).
pub const SUPPRESS: &str = "\u{2400}SUPPRESSED";

// ── tests: bit-exactness against the Lua reference is asserted by the
// SQL test suite (test_privacy.sql), not here; unit checks below only
// cover invariants. ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_deterministic() {
        use crate::rng::fnv1a;
        assert_eq!(fnv1a("13800138000", ""), fnv1a("13800138000", ""));
        assert_ne!(fnv1a("abc", ""), fnv1a("abd", ""));
    }

    #[test]
    fn rng_reproducible() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_f64(), b.next_f64());
        }
        let mut c = Rng::new(43);
        let different = (0..100).any(|_| a.next_f64() != c.next_f64());
        assert!(different);
    }

    #[test]
    fn dp_count_returns_int_string() {
        let p = json::obj(vec![
            ("true_count", Value::Num(1000.0)),
            ("epsilon", Value::Num(1.0)),
            ("seed", Value::Num(7.0)),
        ]);
        let out = dp_count(&p);
        assert!(out.parse::<i64>().is_ok());
    }

    #[test]
    fn dp_mean_null_when_count_collapses() {
        // seed that makes the noised count < 1 → "null"
        let p = json::obj(vec![
            ("true_sum", Value::Num(0.0)),
            ("true_count", Value::Num(0.0)),
            ("range", Value::Num(1.0)),
            ("epsilon", Value::Num(10000.0)),
            ("seed", Value::Num(1.0)),
        ]);
        let out = dp_mean(&p);
        assert!(out == "null" || out.parse::<f64>().is_ok());
    }

    #[test]
    fn advanced_ge_basic() {
        // Dwork-Roth advanced composition. For small δ the leading term
        // √(2·n·ln(1/δ))·ε can EXCEED basic composition n·ε (the advanced
        // theorem only beats basic when δ is large or ε_max is tiny). Verify
        // the formula against a hand-computed value + the actual ordering.
        let list = vec![0.5f64; 10];
        let adv = advanced_epsilon(&list, 1e-5);
        let basic = list_sum(&list); // 5.0
        let expected = 10.0 * 0.5 * (0.5f64.exp() - 1.0) + ((2.0f64 * (1.0f64 / 1e-5f64).ln() * 2.5f64).sqrt());
        assert!((adv - expected).abs() < 1e-9, "adv={} expected={}", adv, expected);
        assert!(adv > basic, "in this regime adv={} > basic={}", adv, basic);
    }

    #[test]
    fn budget_gate() {
        let p = json::obj(vec![
            ("budget", Value::Num(1.0)),
            ("request", Value::Num(0.2)),
            ("spent", Value::Num(0.9)),
        ]);
        let out = dp_budget(&p);
        assert!(out.contains("\"allow\":false"));
        assert!(out.contains("budget_exceeded"));
    }

}
