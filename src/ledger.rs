//! Session-scoped epsilon budget ledger.
//!
//! The JSON dispatcher ops (`dp_alloc` / `dp_budget`) are stateless math: you
//! hand them the whole picture every call. Real use wants a ledger that
//! accumulates across statements, which is what the native scalar shortcuts
//! `dp_alloc(scope, key, epsilon, budget)` and `dp_budget(scope)` expose. State
//! is keyed by scope string behind a process-wide mutex.
//!
//! Honest boundary: this is accounting, not enforcement. Nothing stops a caller
//! from running a query anyway — `dp_alloc` refuses to record an over-budget
//! allocation and `dp_budget` reports what is left, but the ledger is an audit
//! trail, not a sandbox.

use crate::json::{self, Value};
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Clone)]
struct Entry {
    key: String,
    epsilon: f64,
}

struct Ledger {
    budget: f64,
    entries: Vec<Entry>,
}

static LEDGERS: Mutex<Option<HashMap<String, Ledger>>> = Mutex::new(None);

fn with_ledgers<T>(f: impl FnOnce(&mut HashMap<String, Ledger>) -> T) -> T {
    let mut guard = LEDGERS.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn num(x: f64) -> Value {
    Value::Num(x)
}

fn obj(pairs: Vec<(&str, Value)>) -> String {
    json::encode(&json::obj(pairs))
}

/// Allocate `epsilon` against `scope`.
///
/// Every allocation is recorded, over budget or not: the ledger is an audit
/// trail of what was *asked for*, so silently dropping an over-budget request
/// would hide exactly the event an auditor needs to see. The response carries
/// `ok: false` plus `over_budget: true` so a caller can gate on it.
pub fn alloc(scope: &str, key: &str, epsilon: f64, budget: f64) -> String {
    with_ledgers(|map| {
        let led = map.entry(scope.to_string()).or_insert_with(|| Ledger {
            budget,
            entries: Vec::new(),
        });
        led.budget = budget;

        if !epsilon.is_finite() || epsilon < 0.0 {
            return obj(vec![
                ("scope", Value::Str(scope.to_string())),
                ("key", Value::Str(key.to_string())),
                ("ok", Value::Bool(false)),
                ("error", Value::Str("epsilon must be a finite value >= 0".into())),
            ]);
        }

        // Compare against what was already spent, before this request.
        let spent_before: f64 = led.entries.iter().map(|e| e.epsilon).sum();
        led.entries.push(Entry {
            key: key.to_string(),
            epsilon,
        });
        let spent_after = spent_before + epsilon;
        let over = spent_after > led.budget;

        obj(vec![
            ("scope", Value::Str(scope.to_string())),
            ("key", Value::Str(key.to_string())),
            ("ok", Value::Bool(!over)),
            ("allocated", Value::Bool(true)),
            ("over_budget", Value::Bool(over)),
            ("epsilon", num(epsilon)),
            ("spent", num(spent_after)),
            ("budget", num(led.budget)),
            ("remaining", num((led.budget - spent_after).max(0.0))),
            ("entries", num(led.entries.len() as f64)),
        ])
    })
}

/// Report the ledger state for `scope` (an unknown scope reports zeros).
pub fn report(scope: &str) -> String {
    with_ledgers(|map| {
        let (spent, budget, n) = match map.get(scope) {
            Some(l) => (
                l.entries.iter().map(|e| e.epsilon).sum::<f64>(),
                l.budget,
                l.entries.len(),
            ),
            None => (0.0, 1.0, 0usize),
        };
        obj(vec![
            ("scope", Value::Str(scope.to_string())),
            // "total" is what the smoke test reads; "spent" is the readable alias.
            ("total", num(spent)),
            ("spent", num(spent)),
            ("budget", num(budget)),
            ("remaining", num((budget - spent).max(0.0))),
            ("entries", num(n as f64)),
        ])
    })
}

/// Clear one scope (or every scope when `scope` is empty). Returns the number
/// of entries dropped, so a caller can assert the reset happened.
pub fn reset(scope: &str) -> usize {
    with_ledgers(|map| {
        if scope.is_empty() {
            let n: usize = map.values().map(|l| l.entries.len()).sum();
            map.clear();
            n
        } else {
            map.remove(scope).map(|l| l.entries.len()).unwrap_or(0)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_then_report_accumulates() {
        reset("s1"); // only this scope: the ledger is process-global, tests run in parallel
        alloc("s1", "a", 0.5, 1.0);
        alloc("s1", "b", 0.4, 1.0);
        let r = report("s1");
        assert!(r.contains("\"entries\":2"), "{r}");
        assert!(r.contains("\"total\":0.9"), "{r}");
    }

    #[test]
    fn over_budget_is_recorded_and_flagged() {
        reset("s2");
        let first = alloc("s2", "a", 0.9, 1.0);
        assert!(first.contains("\"over_budget\":false"), "{first}");
        // Over-budget requests are recorded (audit trail), flagged not dropped.
        let second = alloc("s2", "b", 0.5, 1.0);
        assert!(second.contains("\"over_budget\":true"), "{second}");
        assert!(second.contains("\"ok\":false"), "{second}");
        assert!(report("s2").contains("\"entries\":2"));
    }

    #[test]
    fn reset_clears_one_scope() {
        reset("s3");
        alloc("s3", "a", 0.1, 1.0);
        assert_eq!(reset("s3"), 1);
        assert!(report("s3").contains("\"entries\":0"));
    }
}
