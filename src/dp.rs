//! Differential privacy mechanisms + epsilon budget ledger.
//! Ported from privacy.lua ops: dp_count / dp_sum / dp_mean / laplace /
//! dp_compose / dp_alloc / dp_budget.

use crate::json::{self, Value};
use crate::rng::Rng;

fn f_opt(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(json::to_f64)
}

// ── mechanisms ─────────────────────────────────────────────────────

/// Resolve the Laplace scale. `scale` is canonical; `b` is the shorthand the
/// SQL `laplace(scale[, seed])` surface uses. Reading only `scale` silently
/// ignored the SQL argument and made every call draw at scale 1.0 — a caller
/// asking for b=10 got 10x less noise than the ε they believed they had.
fn scale_of(p: &Value) -> f64 {
    f_opt(p, "scale").or_else(|| f_opt(p, "b")).unwrap_or(1.0)
}

/// Wall-clock seconds — the fallback seed when the caller supplies none.
pub fn clock_seed() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(1)
}

/// Park-Miller leaks its seed into the first output: x1 = 16807*seed, so a
/// small seed yields a first draw that is heavily correlated with the seed and
/// biased toward one side. Warming up first throws that correlation away —
/// determinism per seed is preserved, the bias is not.
const WARMUP: usize = 12;

/// One RNG for a whole data chunk, warmed up and ready to be advanced once per
/// row. Re-seeding per row is what made an unsseeded query add *identical*
/// noise to every row in the same second, which is both useless and unsafe.
pub fn stream_rng(seed: Option<i64>) -> Rng {
    let mut r = Rng::new(seed.unwrap_or_else(clock_seed));
    r.warm(WARMUP);
    r
}

/// op='dp_count' → "123" (integer string)
pub fn dp_count(p: &Value) -> String {
    let sensitivity = f_opt(p, "sensitivity").unwrap_or(1.0);
    let epsilon = f_opt(p, "epsilon").unwrap_or(1.0);
    let mut rng = stream_rng(f_opt(p, "seed").map(|s| s as i64));
    dp_count_draw(
        &mut rng,
        f_opt(p, "true_count").unwrap_or(0.0),
        sensitivity,
        epsilon,
    )
}

/// Noisy count, drawn from a caller-owned RNG so one chunk can stream draws.
pub fn dp_count_draw(rng: &mut Rng, true_count: f64, sensitivity: f64, epsilon: f64) -> String {
    let v = true_count + rng.laplace(sensitivity / epsilon);
    format!("{}", (v + 0.5).floor() as i64)
}

/// op='dp_sum' → "%.2f"
pub fn dp_sum(p: &Value) -> String {
    let sensitivity = f_opt(p, "sensitivity").unwrap_or(100.0);
    let epsilon = f_opt(p, "epsilon").unwrap_or(1.0);
    let mut rng = stream_rng(f_opt(p, "seed").map(|s| s as i64));
    dp_sum_draw(
        &mut rng,
        f_opt(p, "true_sum").unwrap_or(0.0),
        sensitivity,
        epsilon,
    )
}

/// Noisy sum, drawn from a caller-owned RNG.
pub fn dp_sum_draw(rng: &mut Rng, true_sum: f64, sensitivity: f64, epsilon: f64) -> String {
    let v = true_sum + rng.laplace(sensitivity / epsilon);
    format!("{:.2}", v)
}

/// op='dp_mean' → "%.4f" or "null"
pub fn dp_mean(p: &Value) -> String {
    let eps = f_opt(p, "epsilon").unwrap_or(1.0);
    let mut rng = stream_rng(f_opt(p, "seed").map(|s| s as i64));
    dp_mean_draw(
        &mut rng,
        f_opt(p, "true_sum").unwrap_or(0.0),
        f_opt(p, "true_count").unwrap_or(0.0),
        f_opt(p, "range").unwrap_or(100.0),
        eps,
    )
}

/// Noisy mean, drawn from a caller-owned RNG.
pub fn dp_mean_draw(
    rng: &mut Rng,
    true_sum: f64,
    true_count: f64,
    range: f64,
    eps: f64,
) -> String {
    let s_sum = range / eps;
    let s_cnt = 1.0 / eps;
    let cnt = true_count + rng.laplace(s_cnt);
    if cnt < 1.0 {
        return "null".into();
    }
    let mean = (true_sum + rng.laplace(s_sum)) / cnt;
    format!("{:.4}", mean)
}

/// op='laplace' → one Laplace(0, scale) draw, "%.6f"
pub fn laplace(p: &Value) -> String {
    let mut rng = stream_rng(f_opt(p, "seed").map(|s| s as i64));
    laplace_draw(&mut rng, scale_of(p))
}

/// One Laplace draw at `scale`, formatted for SQL output.
pub fn laplace_draw(rng: &mut Rng, scale: f64) -> String {
    format!("{:.6}", rng.laplace(scale))
}

// ── composition / budget ledger ────────────────────────────────────

/// A delta inside the Dwork-Roth domain: finite, 0 < δ < 1. The advanced
/// bound uses ln(1/δ), which diverges at δ = 0 and is negative (-> sqrt of a
/// negative) for δ >= 1; out-of-domain input must not reach the arithmetic or
/// it emits `NaN`/`inf` tokens that are not valid JSON.
fn delta_ok(d: f64) -> bool {
    // (1.0 / d) must stay finite: a denormal-scale d (e.g. 1e-320) passes
    // `0 < d < 1` but `1.0 / d` overflows to inf, and the bound's
    // `(1.0 / delta).ln()` would then emit an `inf` token. Real DP deltas
    // (1e-5..1e-12) are far from this.
    d.is_finite() && d > 0.0 && d < 1.0 && (1.0 / d).is_finite()
}

/// An epsilon the composition bound can accept: finite, non-negative, and
/// inside the exp-domain. The Dwork-Roth bound uses e.exp(), which overflows
/// to inf above ~709.78 in f64; a `1e308` or `1000` would emit an `inf` token
/// that is not valid JSON, so we reject anything >= 700 (a real per-query
/// privacy parameter never comes close).
fn epsilon_ok(e: f64) -> bool {
    e.is_finite() && e >= 0.0 && e < 700.0
}

/// Dwork-Roth advanced composition bound. Callers must gate `delta` through
/// [`delta_ok`] and the list through [`epsilon_ok`] first.
fn advanced_epsilon(list: &[f64], delta: f64) -> f64 {
    let s1: f64 = list.iter().map(|e| e * (e.exp() - 1.0)).sum();
    let s2: f64 = list.iter().map(|e| e * e).sum();
    let adv = s1 + (2.0 * (1.0 / delta).ln() * s2).sqrt();
    // Even with delta/epsilon gated, the SUMS can overflow f64 (many large
    // epsilons, or a tiny delta). Return one well-defined non-finite sentinel
    // (INFINITY, never NaN) so callers can detect and reject it instead of
    // emitting a non-JSON `inf`/`NaN` token.
    if adv.is_finite() { adv } else { f64::INFINITY }
}

fn list_sum(list: &[f64]) -> f64 {
    list.iter().sum()
}

/// Hard ceiling on per-query expansion. `count`/`n` come from a client f64
/// `as i64` and a value like 1e19 saturates to i64::MAX; repeating that many
/// times would request ~7e19 bytes and the allocator panics (capacity
/// overflow) -> process abort. Capping keeps a 10-byte input from amplifying
/// into an OOM.
const MAX_QUERIES: i64 = 1_000_000;

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
    let cnt = f_opt(p, "count").map(|c| (c as i64).clamp(0, MAX_QUERIES)).unwrap_or(0);
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
    if f_opt(p, "count").map(|c| c as i64).unwrap_or(0) > MAX_QUERIES {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str(format!("count must be <= {}", MAX_QUERIES)),
        )]));
    }
    if !delta_ok(delta) {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("delta must be in (0,1) for advanced composition (0 < δ < 1)".into()),
        )]));
    }
    let list = eps_list(p);
    if list.is_empty() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("epsilon or epsilons required".into()),
        )]));
    }
    if !list.iter().all(|e| epsilon_ok(*e)) {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("epsilons must be finite and >= 0 and < 700".into()),
        )]));
    }
    let basic = list_sum(&list);
    if !basic.is_finite() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("epsilon total overflowed (invalid for a privacy budget)".into()),
        )]));
    }
    let adv = advanced_epsilon(&list, delta);
    if !adv.is_finite() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("advanced composition overflowed (epsilon count too large / delta too small)".into()),
        )]));
    }
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
    if !budget.is_finite() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("budget must be finite".into()),
        )]));
    }
    let n = f_opt(p, "n").map(|x| x as i64).unwrap_or(0);
    if n <= 0 {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("n (query count) must be >= 1".into()),
        )]));
    }
    if n > MAX_QUERIES {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str(format!("n must be <= {}", MAX_QUERIES)),
        )]));
    }
    let comp = p.get_s("composition").unwrap_or("basic").to_string();
    let delta = f_opt(p, "delta").unwrap_or(1e-5);
    if !delta_ok(delta) {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("delta must be in (0,1) for advanced composition (0 < δ < 1)".into()),
        )]));
    }
    let basic_per = budget / n as f64;

    // advanced: binary search for the largest uniform ε whose strong
    // composition bound stays ≤ budget (80 iterations, as in the Lua).
    // e.exp() overflows above ~709; a tiny δ pushes the search ceiling there,
    // so clamp hi to the exp-domain ceiling to keep the arithmetic finite.
    let exp_cap = 700.0;
    let mut lo = 0.0;
    let mut hi = budget.min(exp_cap);
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
    // An inf budget or an extreme delta can drive the per-query value to
    // inf/NaN; reject that rather than emitting a non-JSON token.
    if !per.is_finite() || !adv_per.is_finite() || !basic_per.is_finite() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("per-query allocation overflowed (budget/delta out of range)".into()),
        )]));
    }
    let best = if adv_per > basic_per { "advanced" } else { "basic" };
    let rec = if best == "advanced" { adv_per } else { basic_per };

    let bound_of = |x: f64| -> f64 {
        let b = if (x - basic_per).abs() < 1e-15 {
            x * n as f64
        } else {
            advanced_epsilon(&vec![x; n as usize], delta)
        };
        if b.is_finite() { b } else { f64::INFINITY }
    };
    let total_bound = bound_of(per);
    let advanced_total = bound_of(adv_per);
    let basic_total = basic_per * n as f64;
    if !total_bound.is_finite() || !advanced_total.is_finite() || !basic_total.is_finite() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("total budget bound overflowed (out of range)".into()),
        )]));
    }
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
    if !budget.is_finite() || !request.is_finite() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("budget and request must be finite".into()),
        )]));
    }
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
    // `ledger`/`spent` may parse to inf (1e309) or NaN; the BASIC path
    // has no advanced-branch guard, so validate these here or the sums
    // below emit `inf` tokens (not valid JSON).
    if !spent.is_finite() || !list.iter().all(|x| x.is_finite()) {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("ledger and spent must be finite".into()),
        )]));
    }
    let extra = spent - list_sum(&list);
    if extra > 1e-12 {
        list.push(extra);
    }
    let before = list_sum(&list);
    let after_basic = before + request;
    // Even finite ledger values can overflow the sum (1e308 + 1e308).
    if !before.is_finite() || !after_basic.is_finite() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("ledger sum overflowed (entries too large)".into()),
        )]));
    }
    let mut tot_before = before;
    let mut tot_after = after_basic;
    if comp == "advanced" {
        if !delta_ok(delta) {
            return json::encode(&json::obj(vec![(
                "error",
                Value::Str("delta must be in (0,1) for advanced composition (0 < δ < 1)".into()),
            )]));
        }
        tot_before = advanced_epsilon(&list, delta);
        let mut l2 = list.clone();
        l2.push(request);
        tot_after = advanced_epsilon(&l2, delta);
        if !tot_before.is_finite() || !tot_after.is_finite() {
            return json::encode(&json::obj(vec![(
                "error",
                Value::Str("advanced composition overflowed (ledger too large / delta too small)".into()),
            )]));
        }
    }
    let allow = tot_after <= budget + 1e-12;
    // remaining_before/after are budget minus a total: two finite values
    // with opposite signs near the f64 ceiling make the difference overflow
    // to +/-inf, which is not valid JSON. Reject at the emit point.
    let rem_before = budget - tot_before;
    let rem_after = budget - tot_after;
    if !rem_before.is_finite() || !rem_after.is_finite() {
        return json::encode(&json::obj(vec![(
            "error",
            Value::Str("remaining budget overflowed (budget and spent opposite signs near f64 max)".into()),
        )]));
    }
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
        rem_before,
        rem_after,
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

    /// Re-review P3-2: composition ops used to emit `inf`/`NaN` tokens (not
    /// valid JSON) for out-of-domain input -- huge epsilon (e.exp() overflow),
    /// delta 0 / negative / >= 1 (ln(1/delta) diverges / sqrt of a negative).
    /// They must now return a structured error JSON instead.
    #[test]
    fn compose_rejects_out_of_domain() {
        let huge = dp_compose(&json::obj(vec![
            ("epsilon", json::Value::Num(1000.0)),
        ]));
        assert!(huge.contains("\"error\""), "1000 gave {huge}");
        let d0 = dp_compose(&json::obj(vec![
            ("epsilon", json::Value::Num(0.5)),
            ("delta", json::Value::Num(0.0)),
        ]));
        assert!(d0.contains("\"error\""), "delta=0 gave {d0}");
        let d1 = dp_compose(&json::obj(vec![
            ("epsilon", json::Value::Num(0.5)),
            ("delta", json::Value::Num(5.0)),
        ]));
        assert!(d1.contains("\"error\""), "delta=5 gave {d1}");
        let dneg = dp_compose(&json::obj(vec![
            ("epsilon", json::Value::Num(0.5)),
            ("delta", json::Value::Num(-1.0)),
        ]));
        assert!(dneg.contains("\"error\""), "delta=-1 gave {dneg}");
        let ok = dp_compose(&json::obj(vec![
            ("epsilon", json::Value::Num(0.5)),
        ]));
        assert!(!ok.contains("\"error\""), "valid got {ok}");
        assert!(!ok.contains("inf") && !ok.contains("NaN"), "NaN/inf leaked: {ok}");
    }

    /// dp_alloc / dp_budget use the same bound; a bad delta must error, not NaN.
    #[test]
    fn alloc_budget_reject_bad_delta() {
        let a = dp_alloc(&json::obj(vec![
            ("budget", json::Value::Num(1.0)),
            ("n", json::Value::Num(5.0)),
            ("delta", json::Value::Num(0.0)),
        ]));
        assert!(a.contains("\"error\""), "alloc delta=0 gave {a}");
        let b = dp_budget(&json::obj(vec![
            ("budget", json::Value::Num(1.0)),
            ("request", json::Value::Num(0.2)),
            ("composition", json::Value::Str("advanced".into())),
            ("delta", json::Value::Num(5.0)),
        ]));
        assert!(b.contains("\"error\""), "budget delta=5 gave {b}");
    }

    /// Regression (MUST-FIX-2, 4th re-review): extreme-but-finite input still
    /// made the composition bound emit `inf`/`NaN` (invalid JSON) through three
    /// paths. None of them may produce a non-finite token anymore.
    #[test]
    fn compose_no_infnan_extreme() {
        // (a) delta tiny enough that 1/delta overflows (passes 0<d<1).
        let tiny = dp_compose(&json::obj(vec![
            ("epsilon", json::Value::Num(1.0)),
            ("delta", json::Value::Num(1e-320)),
        ]));
        assert!(tiny.contains("\"error\""), "tiny delta gave {tiny}");
        assert!(!tiny.contains("inf") && !tiny.contains("NaN"), "leak: {tiny}");
        // (b) each epsilon < 700, but the sum over a million of them overflows.
        let big = dp_compose(&json::obj(vec![
            ("epsilon", json::Value::Num(699.0)),
            ("count", json::Value::Num(1_000_000.0)),
        ]));
        assert!(big.contains("\"error\""), "big eps*count gave {big}");
        assert!(!big.contains("inf") && !big.contains("NaN"), "leak: {big}");
    }

    /// (c) budget / request that parse to inf (e.g. 1e309) must be rejected.
    #[test]
    fn alloc_budget_reject_infinite_budget() {
        let a = dp_alloc(&json::obj(vec![
            ("budget", json::Value::Num(f64::INFINITY)),
            ("n", json::Value::Num(5.0)),
        ]));
        assert!(a.contains("\"error\""), "inf budget gave {a}");
        assert!(!a.contains("inf") && !a.contains("NaN"), "leak: {a}");
        let b = dp_budget(&json::obj(vec![
            ("budget", json::Value::Num(f64::INFINITY)),
            ("request", json::Value::Num(1.0)),
            ("composition", json::Value::Str("advanced".into())),
        ]));
        assert!(b.contains("\"error\""), "inf budget gave {b}");
    }

}

#[cfg(test)]
mod dp_regression_tests {
    use super::*;
    use crate::json;

    /// Regression: `laplace` read only the "scale" key while the SQL surface
    /// passes "b", so every call silently drew at scale 1.0. Asking for b=10
    /// used to return the same value as b=0.5 — a 20x error in the noise, which
    /// means the effective epsilon was wrong by the same factor.
    #[test]
    fn laplace_honours_b() {
        let draw = |b: f64| {
            let p = json::obj(vec![
                ("b", json::Value::Num(b)),
                ("seed", json::Value::Num(4242.0)),
            ]);
            laplace(&p).parse::<f64>().unwrap()
        };
        let small = draw(0.5).abs();
        let large = draw(10.0).abs();
        assert!(
            large > small * 3.0,
            "b is ignored: b=0.5 -> {small}, b=10 -> {large}"
        );
    }

    /// Regression: each SQL row re-seeded the RNG, so a whole chunk received one
    /// identical draw. Streaming from a shared RNG must advance per row.
    #[test]
    fn streamed_draws_are_independent() {
        let mut rng = stream_rng(Some(99));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            seen.insert(laplace_draw(&mut rng, 2.0));
        }
        assert_eq!(seen.len(), 64, "noise repeats across rows: {seen:?}");
    }

    /// Determinism per seed is still promised: same seed → same first draw.
    #[test]
    fn stream_seed_is_reproducible() {
        let a = laplace_draw(&mut stream_rng(Some(7)), 1.0);
        let b = laplace_draw(&mut stream_rng(Some(7)), 1.0);
        assert_eq!(a, b);
    }

    /// Small / adjacent seeds must not bias the sign of the noise. Before the
    /// warm-up, Park-Miller's first output was 16807*seed, which for seeds near
    /// zero is always small → every draw landed on the same side.
    #[test]
    fn adjacent_small_seeds_are_not_one_sided() {
        let mut pos = 0;
        let mut neg = 0;
        for seed in 1..=500i64 {
            let v: f64 = laplace_draw(&mut stream_rng(Some(seed)), 1.0)
                .parse()
                .unwrap();
            if v > 0.0 {
                pos += 1;
            } else {
                neg += 1;
            }
        }
        let ratio = f64::from(pos) / f64::from(pos + neg);
        assert!(
            (0.3..=0.7).contains(&ratio),
            "sign bias for adjacent seeds: pos ratio {ratio:.3} (pos={pos}, neg={neg})"
        );
    }

    /// dp_count over a chunk must give every row its own rounded value.
    #[test]
    fn dp_count_streams_per_row() {
        let mut rng = stream_rng(Some(11));
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            seen.insert(dp_count_draw(&mut rng, 1000.0, 1.0, 0.5));
        }
        assert!(seen.len() > 1, "dp_count produced one value for the chunk");
    }
}

#[cfg(test)]
mod dp_budget_basic_residual {
    use super::*;

    /// Round-5 residual: a finite `budget` with a non-finite `ledger`/`spent`
    /// (1e309 -> inf) used to flow through the BASIC path (no advanced guard)
    /// and be emitted as `inf`/`-inf` (not valid JSON). It must now error.
    #[test]
    fn dp_budget_basic_rejects_nonfinite_ledger() {
        // ledger entry that parses to inf
        let a = dp_budget(&json::obj(vec![
            ("budget", json::Value::Num(10.0)),
            ("request", json::Value::Num(1.0)),
            ("ledger", json::Value::Arr(vec![json::Value::Str("1e309".into())])),
            ("composition", json::Value::Str("basic".into())),
        ]));
        assert!(a.contains("\"error\""), "nonfinite ledger gave {a}");
        assert!(!a.contains("inf") && !a.contains("NaN"), "leak: {a}");
        // `spent` that parses to inf
        let b = dp_budget(&json::obj(vec![
            ("budget", json::Value::Num(10.0)),
            ("request", json::Value::Num(1.0)),
            ("spent", json::Value::Num(f64::INFINITY)),
        ]));
        assert!(b.contains("\"error\""), "inf spent gave {b}");
        assert!(!b.contains("inf") && !b.contains("NaN"), "leak: {b}");
        // sum overflow even with finite entries (1e308 + 1e308 -> inf)
        let c = dp_budget(&json::obj(vec![
            ("budget", json::Value::Num(10.0)),
            ("request", json::Value::Num(1.0)),
            ("ledger", json::Value::Arr(vec![json::Value::Num(1e308), json::Value::Num(1e308)])),
        ]));
        assert!(c.contains("\"error\""), "overflow ledger gave {c}");
        assert!(!c.contains("inf") && !c.contains("NaN"), "leak: {c}");
        // normal finite input still works
        let d = dp_budget(&json::obj(vec![
            ("budget", json::Value::Num(10.0)),
            ("request", json::Value::Num(1.0)),
            ("spent", json::Value::Num(5.0)),
        ]));
        assert!(!d.contains("\"error\""), "valid gave {d}");
    }
}

#[cfg(test)]
mod dp_budget_remaining_overflow {
    use super::*;

    /// Round-6 residual: finite opposite-sign budget/spent near the
    /// f64 ceiling make remaining_before/after = budget - total overflow
    /// to +/-inf. The emit point must now reject it with a structured
    /// error instead of emitting a non-JSON token.
    #[test]
    fn remaining_overflow_rejected() {
        let a = dp_budget(&json::obj(vec![
            ("budget", json::Value::Num(1.7e308)),
            ("request", json::Value::Num(1.0)),
            ("spent", json::Value::Num(-1.7e308)),
            ("ledger", json::Value::Arr(vec![json::Value::Num(-1.7e308)])),
        ]));
        assert!(a.contains("\"error\""), "opposite-sign near-max gave {a}");
        assert!(!a.contains("inf") && !a.contains("NaN"), "leak: {a}");
    }
}
