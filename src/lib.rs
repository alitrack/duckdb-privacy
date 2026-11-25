//! duckdb-privacy — privacy engineering primitives as a native DuckDB
//! extension.
//!
//! Ported 1:1 from the `duckdb-luajit-libs` privacy lib (2,360 lines of Lua,
//! 18 ops). The Lua version ran inside the duckdb-luajit extension; this is
//! the standalone Rust product form: `install privacy;` and go — no luajit
//! runtime dependency, native u128 FPE, `regex`-crate redaction.
//!
//! API surface (all return VARCHAR):
//!   privacy(json_args)     — master dispatcher, JSON args with "op" field,
//!                            output byte-compatible with the Lua lib
//!   plus named shortcuts for the hot paths (dp_count, dp_sum, laplace,
//!   mask, mask_cn, dateshift, redact_secrets, fpe_encode, fpe_decode).
//!
//! JSON args keep the Lua table field names verbatim (true_count, epsilon,
//! sensitivity, v, kind, mode, salt, key, days, ...), so existing luajit
//! call sites convert by wrapping the table as JSON.

pub mod dp;
pub mod fake;
pub mod fpe;
pub mod json;
pub mod kanon;
pub mod mask;
pub mod redact;
pub mod rng;

use quack_rs::{
    table::{BindInfo, TableFunctionBuilder},
    data_chunk::DataChunk,
    entry_point::init_extension_v2,
    prelude::*,
    vector::{VectorReader, VectorWriter},
};
use libduckdb_sys::{
    duckdb_data_chunk, duckdb_data_chunk_get_size, duckdb_extension_access,
    duckdb_extension_info, duckdb_function_info, duckdb_vector,
};

/// Master dispatcher: privacy(json) → VARCHAR
/// Parses the JSON args (object with "op" or legacy op-less = mask) and
/// routes to the matching op. Unknown op / bad JSON → '' (empty, same
/// contract as the Lua `run()` falling through).
fn dispatch(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let v = match json::decode(trimmed) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    if !v.is_obj() {
        return String::new();
    }
    let op = v
        .get("op")
        .map(json::to_str_lossy)
        .unwrap_or_else(|| "mask".to_string());
    match op.as_str() {
        "dp_count" => dp::dp_count(&v),
        "dp_sum" => dp::dp_sum(&v),
        "dp_mean" => dp::dp_mean(&v),
        "laplace" => dp::laplace(&v),
        "dp_compose" => dp::dp_compose(&v),
        "dp_alloc" => dp::dp_alloc(&v),
        "dp_budget" => dp::dp_budget(&v),
        "mask" => mask::mask(&v),
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
        // fake generator: "fake" (module op, defaults to gen) + sub-ops
        "fake" | "gen" | "rows" | "table" | "template" | "kinds" => fake::fake(&v),
        _ => String::new(),
    }
}

// ── scalar function callbacks ──────────────────────────────────────

/// One VARCHAR in → dispatch(json) out.
unsafe extern "C" fn privacy_dispatch_fn(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rin = unsafe { VectorReader::new(input, 0) }; // VARCHAR json
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rin.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let res = dispatch(unsafe { rin.read_str(i) });
        unsafe { out.write_str(i, &res) };
    }
}


fn vchar_op(input: duckdb_data_chunk, output: duckdb_vector, f: fn(&json::Value) -> String) {
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rin = unsafe { VectorReader::new(input, 0) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rin.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let raw = unsafe { rin.read_str(i) };
        let res = f(&json::obj(vec![("v", json::Value::Str(raw.to_string()))]));
        unsafe { out.write_str(i, &res) };
    }
}

fn vchar_op_op(input: duckdb_data_chunk, output: duckdb_vector, f: fn(&json::Value) -> String) {
    // ops that read other fields beyond "v" (dateshift: days/salt/key)
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rin = unsafe { VectorReader::new(input, 0) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rin.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let raw = unsafe { rin.read_str(i) };
        let res = f(&json::obj(vec![("v", json::Value::Str(raw.to_string()))]));
        unsafe { out.write_str(i, &res) };
    }
}

unsafe extern "C" fn fn_mask(_info: duckdb_function_info, input: duckdb_data_chunk, output: duckdb_vector) {
    vchar_op(input, output, mask::mask);
}
unsafe extern "C" fn fn_mask_cn(_info: duckdb_function_info, input: duckdb_data_chunk, output: duckdb_vector) {
    vchar_op(input, output, mask::mask_cn);
}
unsafe extern "C" fn fn_dateshift(_info: duckdb_function_info, input: duckdb_data_chunk, output: duckdb_vector) {
    vchar_op_op(input, output, mask::dateshift);
}
unsafe extern "C" fn fn_redact_secrets(_info: duckdb_function_info, input: duckdb_data_chunk, output: duckdb_vector) {
    vchar_op(input, output, redact::redact_secrets);
}
unsafe extern "C" fn fn_fpe_encode(_info: duckdb_function_info, input: duckdb_data_chunk, output: duckdb_vector) {
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rin = unsafe { VectorReader::new(input, 0) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rin.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let raw = unsafe { rin.read_str(i) };
        // vchar with op hint
        let v = json::obj(vec![
            ("v", json::Value::Str(raw.to_string())),
            ("op", json::Value::Str("fpe_encode".to_string())),
        ]);
        unsafe { out.write_str(i, &fpe::fpe_op(&v, true)) };
    }
}
unsafe extern "C" fn fn_fpe_decode(_info: duckdb_function_info, input: duckdb_data_chunk, output: duckdb_vector) {
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rin = unsafe { VectorReader::new(input, 0) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rin.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let raw = unsafe { rin.read_str(i) };
        let v = json::obj(vec![
            ("v", json::Value::Str(raw.to_string())),
            ("op", json::Value::Str("fpe_decode".to_string())),
        ]);
        unsafe { out.write_str(i, &fpe::fpe_op(&v, false)) };
    }
}

unsafe fn fake_scalar(
    info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
    kind: &'static str,
) {
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rin = unsafe { VectorReader::new(input, 0) };
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        let seed: i64 = if unsafe { rin.is_valid(i) } {
            unsafe { rin.read_str(i) }.parse().unwrap_or(0)
        } else {
            0
        };
        let v = json::obj(vec![
            ("op", json::Value::Str("fake".into())),
            ("kind", json::Value::Str(kind.into())),
            ("seed", json::Value::Num(seed as f64)),
        ]);
        let res = fake::fake(&v);
        unsafe { out.write_str(i, &res) };
    }
}

// per-kind static dispatchers (DuckDB scalar fns take a fixed signature)
unsafe extern "C" fn fake_scalar_name(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "person.full")
}
unsafe extern "C" fn fake_scalar_email(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "contact.email")
}
unsafe extern "C" fn fake_scalar_phone(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "contact.phone")
}
unsafe extern "C" fn fake_scalar_company(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "company.name")
}
unsafe extern "C" fn fake_scalar_address(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "address.full")
}
unsafe extern "C" fn fake_scalar_uuid(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "uuid")
}
unsafe extern "C" fn fake_scalar_int(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "number.int")
}
unsafe extern "C" fn fake_scalar_float(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "number.float")
}
unsafe extern "C" fn fake_scalar_bool(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "bool.b")
}
unsafe extern "C" fn fake_scalar_color(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "color.name")
}
unsafe extern "C" fn fake_scalar_date(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "date.iso")
}
unsafe extern "C" fn fake_scalar_words(info: duckdb_function_info, i: duckdb_data_chunk, o: duckdb_vector) {
    fake_scalar(info, i, o, "text.words")
}

// Two-arg shortcut: dp_count(true_count, epsilon)
unsafe extern "C" fn fn_dp_count2(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rc = unsafe { VectorReader::new(input, 0) }; // BIGINT true_count
    let re = unsafe { VectorReader::new(input, 1) }; // DOUBLE epsilon
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rc.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let count = unsafe { rc.read_i64(i) } as f64;
        let eps = unsafe { re.is_valid(i) }.then(|| unsafe { re.read_f64(i) }).unwrap_or(1.0);
        let v = json::obj(vec![
            ("true_count", json::Value::Num(count)),
            ("epsilon", json::Value::Num(eps)),
        ]);
        unsafe { out.write_str(i, &dp::dp_count(&v)) };
    }
}

unsafe extern "C" fn fn_dp_sum2(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rs = unsafe { VectorReader::new(input, 0) }; // DOUBLE true_sum
    let re = unsafe { VectorReader::new(input, 1) }; // DOUBLE epsilon
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rs.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let sum = unsafe { rs.read_f64(i) };
        let eps = unsafe { re.is_valid(i) }.then(|| unsafe { re.read_f64(i) }).unwrap_or(1.0);
        let v = json::obj(vec![
            ("true_sum", json::Value::Num(sum)),
            ("epsilon", json::Value::Num(eps)),
        ]);
        unsafe { out.write_str(i, &dp::dp_sum(&v)) };
    }
}

unsafe extern "C" fn fn_laplace2(
    _info: duckdb_function_info,
    input: duckdb_data_chunk,
    output: duckdb_vector,
) {
    let n = usize::try_from(unsafe { duckdb_data_chunk_get_size(input) }).unwrap_or(0);
    let rs = unsafe { VectorReader::new(input, 0) }; // DOUBLE scale
    let mut out = unsafe { VectorWriter::new(output) };
    for i in 0..n {
        if !unsafe { rs.is_valid(i) } {
            unsafe { out.set_null(i) };
            continue;
        }
        let scale = unsafe { rs.read_f64(i) };
        let v = json::obj(vec![("b", json::Value::Num(scale))]);
        unsafe { out.write_str(i, &dp::laplace(&v)) };
    }
}

// ── registration ───────────────────────────────────────────────────

fn register_all(reg: &impl Registrar) -> Result<(), ExtensionError> {
    unsafe {
        reg.register_scalar(
            ScalarFunctionBuilder::new("privacy")
                .param(TypeId::Varchar) // json_args
                .returns(TypeId::Varchar)
                .function(privacy_dispatch_fn),
        )?;

        reg.register_scalar(
            ScalarFunctionBuilder::new("dp_count")
                .param(TypeId::BigInt) // true_count
                .param(TypeId::Double) // epsilon
                .returns(TypeId::Varchar)
                .function(fn_dp_count2),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("dp_sum")
                .param(TypeId::Double) // true_sum
                .param(TypeId::Double) // epsilon
                .returns(TypeId::Varchar)
                .function(fn_dp_sum2),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("laplace")
                .param(TypeId::Double) // scale b
                .returns(TypeId::Varchar)
                .function(fn_laplace2),
        )?;

        reg.register_scalar(
            ScalarFunctionBuilder::new("mask")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_mask),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("mask_cn")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_mask_cn),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("dateshift")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_dateshift),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("redact_secrets")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_redact_secrets),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fpe_encode")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_fpe_encode),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fpe_decode")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fn_fpe_decode),
        )?;

        // fake scalar shortcuts (one per common kind)
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_name")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_name),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_email")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_email),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_phone")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_phone),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_company")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_company),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_address")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_address),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_uuid")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_uuid),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_int")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_int),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_float")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_float),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_bool")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_bool),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_color")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_color),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_date")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_date),
        )?;
        reg.register_scalar(
            ScalarFunctionBuilder::new("fake_words")
                .param(TypeId::Varchar)
                .returns(TypeId::Varchar)
                .function(fake_scalar_words),
        )?;
    }

    // native table function: SELECT * FROM fake(list := '<spec JSON>')
    let tb = TableFunctionBuilder::new("fake")
        .named_param("list", TypeId::Varchar)
        .with_state::<FakeTableState, _>(|bind: &BindInfo| -> Result<FakeTableState, ExtensionError> {
            bind.add_result_column("row_idx", TypeId::BigInt);
            bind.add_result_column("val", TypeId::Varchar);
            let list = unsafe { bind.get_named_parameter_value("list") }
                .as_str_or_default();
            if list.is_empty() {
                return Err(ExtensionError::new("fake: 'list' is required"));
            }
            let spec = match crate::json::decode(&list) {
                Ok(v) => v,
                Err(_) => return Err(ExtensionError::new("fake: 'list' must be valid JSON")),
            };
            let rows = fake::build_rows(&spec)
                .map_err(|e| ExtensionError::new(e))?;
            Ok(FakeTableState { rows, next: 0 })
        })
        .scan(|st: &mut FakeTableState, chunk: &DataChunk| -> Result<(), ExtensionError> {
            let total = st.rows.len();
            if st.next >= total {
                unsafe { chunk.set_size(0) };
                return Ok(());
            }
            let mut w = 0usize;
            while st.next < total && w < 256 {
                unsafe { chunk.writer(0).write_i64(w, st.next as i64) };
                unsafe { chunk.writer(1).write_str(w, &st.rows[st.next]) };
                st.next += 1;
                w += 1;
            }
            unsafe { chunk.set_size(w) };
            Ok(())
        })
        .build()?;
    unsafe { reg.register_table(tb)? };

    Ok(())
}

#[derive(Default)]
struct FakeTableState {
    rows: Vec<String>,
    next: usize,
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
