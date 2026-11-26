//! duckdb-privacy — privacy engineering primitives as a native DuckDB
//! extension.
//!
//! Ported 1:1 from the `duckdb-luajit-libs` privacy lib (2,360 lines of Lua,
//! 18 ops). The Lua version ran inside the duckdb-luajit extension; this is
//! the standalone Rust product form: `install privacy;` and go — no luajit
//! runtime dependency, native u128 FPE, `regex`-crate redaction.
//!
//! API surface (VARCHAR unless noted):
//!   privacy(json_args)  — master dispatcher, JSON args with an "op" field.
//!                         Unknown op / bad JSON → NULL, not empty string:
//!                         a typo must not look like a legitimately empty mask.
//!   named shortcuts     — one overload per arity, so the documented call forms
//!                         work directly:
//!                           dp_count(true_count[, epsilon])
//!                           dp_sum(true_sum[, epsilon])
//!                           laplace(scale[, seed])
//!                           mask(value[, kind])
//!                           mask_cn(value[, kind[, mode]])
//!                           dateshift(value[, days])
//!                           dateoffset(date, delta_days)
//!                           redact_text(value) / redact_secrets(value)
//!                           fpe_encode(value, key, tweak)
//!                           fpe_decode(value, key, tweak)
//!                           dp_alloc(scope, key, epsilon, budget)
//!                           dp_budget(scope)
//!
//! JSON args keep the Lua table field names verbatim (true_count, epsilon,
//! sensitivity, v, kind, mode, salt, key, days, ...), so existing luajit call
//! sites convert by wrapping the table as JSON.

pub mod dp;
pub mod fpe;
pub mod json;
pub mod kanon;
pub mod ledger;
pub mod mask;
pub mod pii;
pub mod redact;
pub mod rng;

use quack_rs::{
    entry_point::init_extension_v2,
    prelude::*,
    vector::{VectorReader, VectorWriter},
};
use libduckdb_sys::{
    duckdb_data_chunk, duckdb_data_chunk_get_size, duckdb_extension_access,
    duckdb_extension_info, duckdb_function_info, duckdb_vector,
};

// ── helpers ────────────────────────────────────────────────────────

fn rows(input: duckdb_data_chunk) -> usize {
    usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0)
}

fn objs(pairs: Vec<(&str, json::Value)>) -> json::Value {
    json::obj(pairs)
}

fn vs(s: &str) -> json::Value {
    json::Value::Str(s.to_string())
}

fn vn(x: f64) -> json::Value {
    json::Value::Num(x)
}

/// Read column `col` of the chunk as an owned string; None means SQL NULL.
fn col_str(input: duckdb_data_chunk, col: usize, i: usize) -> Option<String> {
    let r = unsafe { VectorReader::new(input, col) };
    if !unsafe { r.is_valid(i) } {
        return None;
    }
    Some(unsafe { r.read_str(i) }.to_string())
}

/// Pull the `value` field out of an FPE JSON envelope. The shortcuts return the
/// ciphertext itself so `fpe_decode(fpe_encode(x, k, t), k, t)` composes.
fn fpe_value(out: &str) -> String {
    match json::decode(out) {
        Ok(v) => match v.get("value") {
            Some(json::Value::Str(s)) => s.clone(),
            Some(other) => json::to_str_lossy(other),
            None => out.to_string(),
        },
        Err(_) => out.to_string(),
    }
}

/// mask_cn uses its own kind vocabulary; map the common spellings onto it so
/// `phone` behaves like `mobile` instead of falling through to generic star.
fn cn_kind(kind: &str) -> String {
    match kind.trim().to_ascii_lowercase().as_str() {
        "phone" | "mobile" | "cell" | "tel" | "手机" | "手机号" => "mobile".into(),
        "id" | "idcard" | "id_card" | "身份证" => "idcard".into(),
        "card" | "bankcard" | "银行卡" | "信用卡" => "bankcard".into(),
        "mail" | "邮箱" => "email".into(),
        "姓名" | "person" => "name".into(),
        other => other.to_string(),
    }
}

// ── master dispatcher ──────────────────────────────────────────────

fn dispatch(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let v = json::decode(trimmed).ok()?;
    if !v.is_obj() {
        return None;
    }
    let op = v
        .get("op")
        .map(json::to_str_lossy)
        .unwrap_or_else(|| "mask".to_string());
    let out = match op.as_str() {
        "dp_count" => dp::dp_count(&v),
        "dp_sum" => dp::dp_sum(&v),
        "dp_mean" => dp::dp_mean(&v),
        "laplace" => dp::laplace(&v),
        "dp_compose" => dp::dp_compose(&v),
        "dp_alloc" => dp::dp_alloc(&v),
        "dp_budget" => dp::dp_budget(&v),
        "mask" => {
            // With a `kind` field the caller means PII masking (phone/email/
            // name/id...), which is a different rule set from the Lua-compatible
            // star/hash modes. Route on the presence of `kind`.
            if v.get("kind").is_some() {
                pii::mask_kind(&v)
            } else {
                mask::mask(&v)
            }
        }
        "mask_kind" => pii::mask_kind(&v),
        "mask_cn" => mask::mask_cn(&v),
        "dateshift" => mask::dateshift(&v),
        "dateoffset" => mask::dateoffset(&v),
        "redact_text" => redact::redact_text(&v),
        "redact_secrets" => redact::redact_secrets(&v),
        "restore_text" => redact::restore_text(&v),
        "kanon" => kanon::kanon(&v),
        "kanon_report" => kanon::kanon_report(&v),
        "fpe_encode" => fpe::fpe_op(&v, true),
        "fpe_decode" => fpe::fpe_op(&v, false),
        "fpe_luhn" => fpe::fpe_luhn(&v),
        _ => return None,
    };
    Some(out)
}

// ── scalar callbacks ───────────────────────────────────────────────

/// privacy(json) — NULL-preserving on both the input and the unknown-op path.
unsafe extern "C" fn fn_privacy(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        match col_str(input, 0, i).as_deref().and_then(dispatch) {
            Some(res) => unsafe { out.write_str(i, &res) },
            None => unsafe { out.set_null(i) },
        }
    }
}

/// dp_compose — dedicated callback. The named function previously reused the
/// generic dispatcher (`fn_privacy`), which routes on the JSON `op` field and
/// defaults to `"mask"` when it is absent — so `dp_compose('{"epsilon":…}')`
/// silently ran `mask` and returned empty, contradicting the README's named-
/// function contract. This decodes the JSON and calls `dp::dp_compose` directly
/// (it reads `delta`/`epsilon`/`epsilons`, not `op`), so the natural call shape
/// works; bad JSON / non-object → NULL, matching the dispatcher's contract.
unsafe extern "C" fn fn_dp_compose(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        let Some(raw) = col_str(input, 0, i) else {
            unsafe { out.set_null(i) };
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            unsafe { out.set_null(i) };
            continue;
        }
        match json::decode(trimmed) {
            Ok(v) if v.is_obj() => {
                let res = dp::dp_compose(&v);
                unsafe { out.write_str(i, &res) }
            }
            _ => unsafe { out.set_null(i) },
        }
    }
}

/// One string in, one string out, wrapped as `{"v": value}`.
fn unary(input: duckdb_data_chunk, output: duckdb_vector, f: fn(&json::Value) -> String) {
    let n = rows(input);
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        match col_str(input, 0, i) {
            Some(raw) => {
                let res = f(&objs(vec![("v", vs(&raw))]));
                unsafe { out.write_str(i, &res) }
            }
            None => unsafe { out.set_null(i) },
        }
    }
}

unsafe extern "C" fn fn_dp_count1(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rc = unsafe { VectorReader::new(input, 0) };
    let mut out = unsafe { VectorWriter::new(output) };
    // One RNG per chunk, advanced once per row. Re-seeding inside the loop made
    // every row land on the same wall-clock seed, so a whole table received the
    // *identical* noise draw — no independence, no protection.
    let mut rng = dp::stream_rng(None);
    for i in 0..n {
        if !unsafe { rc.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let c = unsafe { rc.read_i64(i) } as f64;
        let res = dp::dp_count_draw(&mut rng, c, 1.0, 1.0);
        unsafe { out.write_str(i, &res) }
    }
}

unsafe extern "C" fn fn_dp_count2(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rc = unsafe { VectorReader::new(input, 0) };
    let re = unsafe { VectorReader::new(input, 1) };
    let mut out = unsafe { VectorWriter::new(output) };
    let mut rng = dp::stream_rng(None);
    for i in 0..n {
        if !unsafe { rc.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let c = unsafe { rc.read_i64(i) } as f64;
        let eps = unsafe { re.is_valid(i) }
            .then(|| unsafe { re.read_f64(i) })
            .unwrap_or(1.0);
        let res = dp::dp_count_draw(&mut rng, c, 1.0, eps);
        unsafe { out.write_str(i, &res) }
    }
}

unsafe extern "C" fn fn_dp_sum1(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rs = unsafe { VectorReader::new(input, 0) };
    let mut out = unsafe { VectorWriter::new(output) };
    let mut rng = dp::stream_rng(None);
    for i in 0..n {
        if !unsafe { rs.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let s = unsafe { rs.read_f64(i) };
        let res = dp::dp_sum_draw(&mut rng, s, 100.0, 1.0);
        unsafe { out.write_str(i, &res) }
    }
}

unsafe extern "C" fn fn_dp_sum2(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rs = unsafe { VectorReader::new(input, 0) };
    let re = unsafe { VectorReader::new(input, 1) };
    let mut out = unsafe { VectorWriter::new(output) };
    let mut rng = dp::stream_rng(None);
    for i in 0..n {
        if !unsafe { rs.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let s = unsafe { rs.read_f64(i) };
        let eps = unsafe { re.is_valid(i) }
            .then(|| unsafe { re.read_f64(i) })
            .unwrap_or(1.0);
        let res = dp::dp_sum_draw(&mut rng, s, 100.0, eps);
        unsafe { out.write_str(i, &res) }
    }
}

unsafe extern "C" fn fn_laplace1(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rs = unsafe { VectorReader::new(input, 0) };
    let mut out = unsafe { VectorWriter::new(output) };
    let mut rng = dp::stream_rng(None);
    for i in 0..n {
        if !unsafe { rs.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let b = unsafe { rs.read_f64(i) };
        let res = dp::laplace_draw(&mut rng, b);
        unsafe { out.write_str(i, &res) }
    }
}

unsafe extern "C" fn fn_laplace2(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rs = unsafe { VectorReader::new(input, 0) };
    let re = unsafe { VectorReader::new(input, 1) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rs.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let b = unsafe { rs.read_f64(i) };
        // A per-row seed is honoured (same seed → same draw), but the stream is
        // warmed first: Park-Miller leaks the seed into its first output
        // (x1 = 16807*seed), which biased the noise toward one sign for small
        // or near-equal seeds.
        let seed = unsafe { re.is_valid(i) }.then(|| unsafe { re.read_f64(i) } as i64);
        let mut rng = dp::stream_rng(seed);
        let res = dp::laplace_draw(&mut rng, b);
        unsafe { out.write_str(i, &res) }
    }
}

// mask(value) — Lua-compatible, mode-based
unsafe extern "C" fn fn_mask1(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    unary(input, output, mask::mask);
}

// mask(value, kind) — kind-aware PII masking
unsafe extern "C" fn fn_mask2(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        match (col_str(input, 0, i), col_str(input, 1, i)) {
            (Some(v), Some(kind)) => {
                let res = pii::mask_kind(&objs(vec![("v", vs(&v)), ("kind", vs(&kind))]));
                unsafe { out.write_str(i, &res) }
            }
            _ => unsafe { out.set_null(i) },
        }
    }
}

// mask_cn(value[, kind[, mode]])
unsafe extern "C" fn fn_mask_cn1(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    unary(input, output, mask::mask_cn);
}

unsafe extern "C" fn fn_mask_cn2(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        match (col_str(input, 0, i), col_str(input, 1, i)) {
            (Some(v), Some(kind)) => {
                let res = mask::mask_cn(&objs(vec![("v", vs(&v)), ("kind", vs(&cn_kind(&kind)))]));
                unsafe { out.write_str(i, &res) }
            }
            _ => unsafe { out.set_null(i) },
        }
    }
}

unsafe extern "C" fn fn_mask_cn3(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        match (
            col_str(input, 0, i),
            col_str(input, 1, i),
            col_str(input, 2, i),
        ) {
            (Some(v), Some(kind), Some(mode)) => {
                let res = mask::mask_cn(&objs(vec![
                    ("v", vs(&v)),
                    ("kind", vs(&cn_kind(&kind))),
                    ("mode", vs(&mode)),
                ]));
                unsafe { out.write_str(i, &res) }
            }
            _ => unsafe { out.set_null(i) },
        }
    }
}

// dateshift(value[, days])
unsafe extern "C" fn fn_dateshift1(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    unary(input, output, mask::dateshift);
}

unsafe extern "C" fn fn_dateshift2(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rd = unsafe { VectorReader::new(input, 1) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        let Some(v) = col_str(input, 0, i) else {
            unsafe { out.set_null(i) };
            continue;
        };
        let days = unsafe { rd.is_valid(i) }.then(|| unsafe { rd.read_f64(i) });
        let mut o = vec![("v", vs(&v))];
        if let Some(d) = days {
            o.push(("days", vn(d)));
        }
        let res = mask::dateshift(&objs(o));
        unsafe { out.write_str(i, &res) };
    }
}

// dateoffset(date, delta_days) — undo a shift: date minus delta.
// Three overloads so the natural call shapes bind: (VARCHAR, DOUBLE) plus
// native (DATE, DOUBLE) / (DATE, BIGINT), which is what `date - orig`
// produces. Without the DATE overloads DuckDB reports "no function matches"
// because DATE does not implicitly cast to VARCHAR.
unsafe fn dateoffset_row(input: duckdb_data_chunk, out: &mut VectorWriter, i: usize, days: i64) {
    let Some(v) = col_str(input, 0, i) else {
        unsafe { out.set_null(i) };
        return;
    };
    let res = mask::date_plus_days(&v, -days);
    unsafe { out.write_str(i, &res) }
}

unsafe extern "C" fn fn_dateoffset2(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rd = unsafe { VectorReader::new(input, 1) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rd.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let delta = unsafe { rd.read_f64(i) } as i64;
        unsafe { dateoffset_row(input, &mut out, i, delta) }
    }
}

unsafe extern "C" fn fn_dateoffset_date(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rdate = unsafe { VectorReader::new(input, 0) };
    let rd = unsafe { VectorReader::new(input, 1) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        // DATE is stored as days since 1970-01-01 (i32).
        if !unsafe { rdate.is_valid(i) } || !unsafe { rd.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let days = i64::from(unsafe { rdate.read_i32(i) });
        let delta = unsafe { rd.read_f64(i) } as i64;
        let (y, m, d) = mask::civil_from_days(days - delta);
        unsafe { out.write_str(i, &format!("{y:04}-{m:02}-{d:02}")) }
    }
}

unsafe extern "C" fn fn_dateoffset_date_i64(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let rdate = unsafe { VectorReader::new(input, 0) };
    let rd = unsafe { VectorReader::new(input, 1) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rdate.is_valid(i) } || !unsafe { rd.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let days = i64::from(unsafe { rdate.read_i32(i) });
        let delta = unsafe { rd.read_i64(i) };
        let (y, m, d) = mask::civil_from_days(days - delta);
        unsafe { out.write_str(i, &format!("{y:04}-{m:02}-{d:02}")) }
    }
}

// redact_text(value) / redact_secrets(value)
unsafe extern "C" fn fn_redact_text(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    unary(input, output, redact::redact_text);
}

unsafe extern "C" fn fn_redact_secrets(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    unary(input, output, redact::redact_secrets);
}

// fpe_encode(value, key, tweak) / fpe_decode(value, key, tweak)
fn fpe3(input: duckdb_data_chunk, output: duckdb_vector, enc: bool) {
    let n = rows(input);
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        let (Some(v), Some(key)) = (col_str(input, 0, i), col_str(input, 1, i)) else {
            unsafe { out.set_null(i) };
            continue;
        };
        let tweak = col_str(input, 2, i).unwrap_or_default();
        let mut o = vec![
            ("v", vs(&v)),
            ("key", vs(&key)),
            (
                "op",
                vs(if enc { "fpe_encode" } else { "fpe_decode" }),
            ),
        ];
        if !tweak.is_empty() {
            o.push(("tweak", vs(&tweak)));
        }
        let res = fpe_value(&fpe::fpe_op(&objs(o), enc));
        unsafe { out.write_str(i, &res) };
    }
}

unsafe extern "C" fn fn_fpe_encode(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    fpe3(input, output, true);
}

unsafe extern "C" fn fn_fpe_decode(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    fpe3(input, output, false);
}

// dp_alloc(scope, key, epsilon, budget) — session ledger
unsafe extern "C" fn fn_dp_alloc4(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let re = unsafe { VectorReader::new(input, 2) };
    let rb = unsafe { VectorReader::new(input, 3) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        let (Some(scope), Some(key)) = (col_str(input, 0, i), col_str(input, 1, i)) else {
            unsafe { out.set_null(i) };
            continue;
        };
        let eps = unsafe { re.is_valid(i) }
            .then(|| unsafe { re.read_f64(i) })
            .unwrap_or(0.0);
        let budget = unsafe { rb.is_valid(i) }
            .then(|| unsafe { rb.read_f64(i) })
            .unwrap_or(1.0);
        let res = ledger::alloc(&scope, &key, eps, budget);
        unsafe { out.write_str(i, &res) };
    }
}

// dp_budget(scope) — session ledger report
unsafe extern "C" fn fn_dp_budget1(
    _i: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = rows(input);
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        match col_str(input, 0, i) {
            Some(scope) => {
                let res = ledger::report(&scope);
                unsafe { out.write_str(i, &res) }
            }
            None => unsafe { out.set_null(i) },
        }
    }
}

// ── registration ───────────────────────────────────────────────────

/// Every privacy function returns VARCHAR; only the parameter list varies.
macro_rules! varchar_overload {
    ($($param:expr),*) => {
        ScalarOverloadBuilder::new()
            $(.param($param))*
            .returns(TypeId::Varchar)
    };
}

fn register_all(reg: &impl Registrar) -> Result<(), ExtensionError> {
    unsafe {
        // dispatcher
        reg.register_scalar(
            ScalarFunctionBuilder::new("privacy")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_privacy),
        )?;

        // ── differential privacy ──
        // Volatile for the same reason as laplace: a folded constant argument
                // would reuse one noisy count for every row.
                reg.register_scalar(
                    ScalarFunctionBuilder::new("dp_count")
                        .param(TypeId::BigInt)
                        .returns(TypeId::Varchar)
                        .volatile()
                        .function(fn_dp_count1),
                )?;
                reg.register_scalar(
                    ScalarFunctionBuilder::new("dp_count")
                        .param(TypeId::BigInt)
                        .param(TypeId::Double)
                        .returns(TypeId::Varchar)
                        .volatile()
                        .function(fn_dp_count2),
                )?;
                reg.register_scalar(
                    ScalarFunctionBuilder::new("dp_sum")
                        .param(TypeId::Double)
                        .returns(TypeId::Varchar)
                        .volatile()
                        .function(fn_dp_sum1),
                )?;
                reg.register_scalar(
                    ScalarFunctionBuilder::new("dp_sum")
                        .param(TypeId::Double)
                        .param(TypeId::Double)
                        .returns(TypeId::Varchar)
                        .volatile()
                        .function(fn_dp_sum2),
                )?;
        // Both overloads must be volatile: DuckDB folds constant-argument
                // expressions, so a non-volatile noise function evaluated against a
                // constant returns the *same* draw for every row of the result.
                // ScalarFunctionSetBuilder (quack-rs 0.14) has no volatile flag, so the
                // overloads are registered individually — DuckDB appends them to the
                // same function set.
                reg.register_scalar(
                    ScalarFunctionBuilder::new("laplace")
                        .param(TypeId::Double)
                        .returns(TypeId::Varchar)
                        .volatile()
                        .function(fn_laplace1),
                )?;
                reg.register_scalar(
                    ScalarFunctionBuilder::new("laplace")
                        .param(TypeId::Double)
                        .param(TypeId::Double)
                        .returns(TypeId::Varchar)
                        .volatile()
                        .function(fn_laplace2),
                )?;
        // dp_compose has a dedicated callback so the natural call shape
        // dp_compose('{"epsilon":…}') works without an explicit "op" field —
        // the dispatcher (fn_privacy) would otherwise default to "mask".
        reg.register_scalar(
            ScalarFunctionBuilder::new("dp_compose")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_dp_compose),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("dp_alloc")
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .param(TypeId::Double)
                .param(TypeId::Double)
                .returns(TypeId::Varchar)
                .function(fn_dp_alloc4),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("dp_budget")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_dp_budget1),
        )?;

        // ── masking ──
        reg.register_scalar_set(
            ScalarFunctionSetBuilder::new("mask")
                .overload(varchar_overload!(TypeId::Varchar).function(fn_mask1))
                .overload(
                    varchar_overload!(TypeId::Varchar, TypeId::Varchar).function(fn_mask2),
                ),
        )?;
        reg.register_scalar_set(
            ScalarFunctionSetBuilder::new("mask_cn")
                .overload(varchar_overload!(TypeId::Varchar).function(fn_mask_cn1))
                .overload(
                    varchar_overload!(TypeId::Varchar, TypeId::Varchar).function(fn_mask_cn2),
                )
                .overload(
                    varchar_overload!(TypeId::Varchar, TypeId::Varchar, TypeId::Varchar)
                        .function(fn_mask_cn3),
                ),
        )?;

        // ── date shifting ──
        reg.register_scalar_set(
            ScalarFunctionSetBuilder::new("dateshift")
                .overload(varchar_overload!(TypeId::Varchar).function(fn_dateshift1))
                .overload(
                    varchar_overload!(TypeId::Varchar, TypeId::Double).function(fn_dateshift2),
                ),
        )?;
        reg.register_scalar_set(
            ScalarFunctionSetBuilder::new("dateoffset")
                .overload(
                    varchar_overload!(TypeId::Varchar, TypeId::Double).function(fn_dateoffset2),
                )
                .overload(
                    varchar_overload!(TypeId::Date, TypeId::Double).function(fn_dateoffset_date),
                )
                .overload(
                    varchar_overload!(TypeId::Date, TypeId::BigInt)
                        .function(fn_dateoffset_date_i64),
                ),
        )?;

        // ── free-text redaction ──
        reg.register_scalar(
            ScalarFunctionBuilder::new("redact_text")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_redact_text),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("redact_secrets")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_redact_secrets),
        )?;

        // ── format-preserving encryption ──
        reg.register_scalar(
            ScalarFunctionBuilder::new("fpe_encode")
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_fpe_encode),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fpe_decode")
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_fpe_decode),
        )?;
    }
    Ok(())
}

// Entry point — DuckDB expects the symbol `privacy_init_c_api`
// (EXTENSION_NAME = privacy per Makefile / Cargo [lib]).
#[no_mangle]
pub unsafe extern "C" fn privacy_init_c_api(
    info: duckdb_extension_info,
    access: *const duckdb_extension_access,
) -> bool {
    unsafe {
        init_extension_v2(info, access, quack_rs::DUCKDB_API_VERSION, |con| register_all(con))
    }
}
