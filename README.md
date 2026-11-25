# duckdb-privacy

Native DuckDB extension for privacy engineering primitives. Ported 1:1 from the
`duckdb-luajit-libs` privacy lib (2,360 lines of Lua, 18 ops) to Rust, with the
API surface preserved so existing `luajit_module(...)`-style SQL keeps working.

## What it does

- **Differential privacy** — `dp_count` / `dp_sum` / `dp_mean` / `laplace`, plus
  an in-session **epsilon budget ledger** (`dp_alloc` / `dp_budget` / `dp_compose`)
  with basic/advanced composition.
- **PII/PHI masking** — `mask` (phone / email / name / id / address / ip / card /
  bankcard / general) and CN-compliant `mask_cn` (GB/T 37964 keep-first-keep-last
  rules).
- **MIMIC-style date shifting** — `dateshift` / `dateoffset` (deterministic,
  order-preserving, reversible by delta).
- **Free-text PHI redaction** — `redact_text` (phone / SSN / DOB / MRN / hospital /
  drug / dose …) and `redact_secrets` (API keys / tokens / connection strings / IPs).
- **Reversible restore** — `restore_text` reverses a `redact_text` output given the
  original, so masked corpora can be un-mapped for authorized re-identification.
- **FPE format-preserving encryption** — `fpe_encode` / `fpe_decode` (FF3 / FF3-1,
  NIST SP 800-38G, AES-128/192/256). Format, length, and checksum positions
  preserved; deterministic per (key, tweak); wrong key → garbage, never plaintext.
- **k-anonymity** — `kanon` (simplified Mondrian range/prefix generalization)
  and `kanon_report` (l-diversity, t-closeness, suppression rate, generalization
  loss per GB/T 42460).

## The single entry point

Everything is reachable through one dispatcher that mirrors the Lua API exactly:

```sql
SELECT privacy('{
  "op": "mask_cn",
  "v": "110101199003071234",
  "kind": "idcard",
  "mode": "birth"
}');
```

…so any `luajit_module(source:='privacy.lua', args:='{"op":...}')` call migrates by
swapping the call, with the JSON payload unchanged. The op names are:
`dp_count` `dp_sum` `dp_mean` `laplace` `dp_compose` `dp_alloc` `dp_budget`
`mask` `mask_cn` `dateshift` `dateoffset` `redact_text` `redact_secrets`
`restore_text` `kanon` `kanon_report` `fpe_encode` `fpe_decode` `fpe_luhn`.

For the hot paths, a handful of native scalar shortcuts are also registered — these
take the bare value (wrapped to `{"v": ...}` internally) so the common case needs no
JSON: `mask(v)`, `mask_cn(v)`, `dateshift(v)`, `redact_secrets(v)`, `fpe_encode(v)`,
`fpe_decode(v)`, plus two-arg DP `dp_count(true_count, epsilon)`,
`dp_sum(true_sum, epsilon)`, and `laplace(scale)`. Anything that needs the extra
parameters (e.g. `dateshift` days/key, `redact_text` dict, `mask_cn` kind/mode, the
budget ledger, kanon) goes through the `privacy(json)` dispatcher above.

## Why a native extension (not the Lua lib)

The Lua version is a great reference implementation, but it pays three costs this
port removes:

1. **No 128-bit integer arithmetic in Lua.** FF3's 128-bit modular
   add/multiply was hand-rolled over a FFI u64 pair. Rust has native `u128`, so the
   FPE core is both shorter and correct-by-construction, and the whole FPE path is
   an order of magnitude faster on large tables.
2. **Deterministic, auditable crypto.** The FPE core is a self-contained module with
   NIST SP 800-38G test vectors; no FFI boundary, no Lua GC pressure on the hot loop.
3. **No JIT warmup.** First-row cost is constant; no VM startup per connection.

## Build

```bash
make            # via extension-ci-tools (libduckdb 1.2.0, quack-rs 0.14)
# or directly:
cargo build --release
# → target/release/libprivacy.so   (make release wraps it into build/release/privacy.duckdb_extension)
```

## Test

```bash
# unit tests (24) incl. AES-128 FIPS-197 + Hinnant date anchors + DP/kanon invariants
cargo test --release

# FPE differential check vs the Python oracle (15 NIST FF3 + 18 FF3-1 vectors, enc+dec)
python3 scripts/emit_vectors.py > /tmp/vectors.jsonl
FPE_VECTORS=/tmp/vectors.jsonl cargo run --release --example fpe_diff

# SQL smoke (all ops) once a signed build is loadable:
duckdb -c "LOAD 'build/release/privacy.duckdb_extension';" < test/smoke.sql
```

`test/smoke.sql` exercises every op with structural invariants and
round-trip checks. FPE determinism, format preservation, and key-bounding are
asserted directly; DP symmetry is checked over 10k Laplace draws drawn from a
single advancing stream (the shape a real query has, so a per-row re-seed
regression shows up here). `cargo test` carries the statistical regression for
the noise generator itself: centring, scale, symmetry, LCG domain, uniformity,
known Park-Miller values, and per-seed determinism.

## Noise semantics (read this before using `laplace` / `dp_*`)

- **A draw is fresh per row.** The noise functions are registered as volatile, so
  DuckDB cannot constant-fold them: `SELECT laplace(2) FROM t` produces a
  different draw for every row even though the argument never changes. (Without
  the volatile flag DuckDB evaluates the function once and repeats that single
  draw for the whole result set, which silently collapses any per-row noise.)
- **Rows in one query draw from one advancing stream**, not from a per-row
  re-seed. Re-seeding per row used to make every row in the same wall-clock
  second receive the *identical* value.
- **An explicit seed makes the draw reproducible** — `laplace(2, 42)` is the same
  value every time, on every row. Use a seed for tests, not for production noise;
  when you need per-row noise, omit it.
- **The stream is warmed up before the first draw.** The Park-Miller LCG emits
  `x1 = 16807*seed` as its first output, which correlated the first draw so
  strongly with the seed that small or adjacent seeds produced one-sided noise
  (an empirical check over seeds 0..20000 returned *zero* positive draws, bias
  ≈ -2.16·scale). That bug voids the ε-DP guarantee, since Laplace noise must be
  centred on zero. Values are therefore deterministic per seed but **not**
  numerically identical to the Lua reference.

## Honest boundaries (carried over from the Lua lib)

- `dp_*` mechanisms are **Laplace-based** (sensitivity 1 for count/mean, max|value|
  for sum). They are not calibrated for Gaussian or RDP composition.
- The PRNG is a 31-bit Park-Miller LCG: empirically the Laplace draw over 10^6
  samples lands at std ≈ 2.87 for a nominal `2√2 = 2.828` and P(x>0) ≈ 0.50, i.e.
  ~1–2% lattice deviation. Fine for reportable aggregates; do not treat the
  stream as cryptographic randomness.
- `kanon` is **simplified Mondrian** (equal-weight range/prefix split), not a
  full recursive partitioner; `kanon_report` measures the result, it does not
  guarantee feasibility.
- `redact_text` is **regex-based PHI detection** — high recall on the covered types,
  but not a substitute for NLP-level de-identification; review the output for
  regulated datasets.
- FPE is **format-preserving, not format-preserving *and* order-preserving**; do not
  use the ciphertext as a sortable surrogate unless you accept that the order is
  pseudo-random per (key, tweak).

## License

MIT (see `LICENSE`).
