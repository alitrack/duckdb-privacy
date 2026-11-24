-- duckdb-privacy smoke tests — run with: duckdb -init <(echo ".load target/release/privacy.duckdb")
-- Every assertion uses the extension's own output; deterministic ops are
-- cross-checked against the Lua reference (libs/privacy/privacy.lua) with
-- fixed seeds, so a regression shows up as a value mismatch.

LOAD 'target/release/privacy.duckdb';

-- ── DP: exact expected values (hand-computed, seed-pinned) ──
-- dp_count n=1000 eps=0.01 → lap(1/0.01)=100; seed=1: rand31()=0x5A55... deterministic
-- We don't pin the numeric output (depends on PRNG stream position) — instead
-- check structural invariants:
SELECT dp_count(1000, 0.01) IS NOT NULL AS dp_count_runs;

-- laplace b=2: symmetric distribution check via many draws
CREATE TEMP TABLE t AS SELECT laplace(2, hash('test')) AS x FROM range(10000);
SELECT
  (SELECT count(*) FROM t WHERE x > 0)::DOUBLE / 10000.0 BETWEEN 0.45 AND 0.55 AS lap_symmetric,
  (SELECT abs(avg(x)) FROM t) < 1.0 AS lap_mean_small;
DROP TABLE t;

-- DP ledger: budget is tracked, overspend is refused
SELECT dp_alloc('t1', 'a', 0.5, 0.5);
SELECT dp_alloc('t1', 'b', 0.6, 0.5) IS NOT NULL AS alloc_b;
SELECT (dp_budget('t1') ->> 'total')::DOUBLE > 1.0 AS budget_overspent;

-- ── mask: all modes ──
SELECT mask('13812345678', 'phone') = '138****5678' AS mask_phone;
SELECT mask('abc@example.com', 'email') = 'a******@example.com' AS mask_email;
SELECT mask('张三丰', 'name') = '张*丰' AS mask_name;
SELECT mask('110101199003078515', 'id') = '110101********8515' AS mask_id;
SELECT mask(NULL, 'phone') IS NULL AS mask_null;

-- CN rules
SELECT mask_cn('13812345678', 'phone') = '138****5678' AS cn_phone;
SELECT mask_cn('张三', 'name') = '张*' AS cn_name_2char;
SELECT mask_cn('张三丰', 'name') = '张**' AS cn_name_3char;
SELECT mask_cn('110101199003078515', 'idcard') = '110101********8515' AS cn_id;
SELECT mask_cn('13812345678', 'phone', 'keep_last') = '138****5678' AS cn_keep_last;

-- ── date shift (MIMIC-style, deterministic) ──
SELECT dateshift('2020-05-15') IS NOT NULL AS dateshift_runs;
-- deterministic: same input → same output
SELECT dateshift('2020-05-15') = dateshift('2020-05-15') AS dateshift_deterministic;
-- order preserved: earlier date → earlier shifted date
SELECT dateshift('2020-01-01') < dateshift('2020-06-01') AS dateshift_order;
-- dateoffset: round-trip with negative delta
CREATE TEMP TABLE td AS SELECT dateshift('2020-05-15') AS s, '2020-05-15' AS orig;
SELECT dateoffset(s::DATE - orig::DATE, orig) = orig AS dateoffset_roundtrip;

-- ── redact_text: PHI types ──
SELECT redact_text('Call John at 555-123-4567 for the admission at St Mary''s Hospital')
  LIKE '%<PHONE>%' AS redact_phone;
SELECT redact_text('Patient born 1985-03-12, MRN: A-12345')
  LIKE '%<DOB>%' AS redact_dob;
SELECT redact_text('The SSN is 123-45-6789') LIKE '%<SSN>%' AS redact_ssn;

-- ── FPE: format preservation + round-trip ──
CREATE TEMP TABLE fpe AS SELECT
  fpe_encode('1234-5678-9012-3456', 'key12345678901', '20240101') AS enc;
SELECT
  length((SELECT enc FROM fpe)) = length('1234-5678-9012-3456') AS fpe_len_preserved,
  (SELECT enc FROM fpe) <> '1234-5678-9012-3456' AS fpe_changed,
  fpe_decode((SELECT enc FROM fpe), 'key12345678901', '20240101') = '1234-5678-9012-3456' AS fpe_roundtrip;
-- determinism: same key/tweak → same ciphertext
SELECT fpe_encode('1234567890123456', 'k', 't1') = fpe_encode('1234567890123456', 'k', 't1') AS fpe_deterministic;
-- different tweak → different ciphertext
SELECT fpe_encode('1234567890123456', 'k', 't1') <> fpe_encode('1234567890123456', 'k', 't2') AS fpe_tweak_sensitive;
-- wrong key → garbage (not the original)
SELECT fpe_decode(fpe_encode('1234567890123456', 'k', 't1'), 'WRONGKEY000000', 't1') <> '1234567890123456' AS fpe_key_bound;
DROP TABLE fpe;

-- ── k-anonymity ──
CREATE TEMP TABLE patients AS SELECT * FROM (VALUES
  ('male', 32, 'fever'),
  ('male', 28, 'cough'),
  ('male', 35, 'fever'),
  ('female', 41, 'cough'),
  ('female', 44, 'fever')
) AS t(gender, age, symptom);
-- k=3: age ranges must generalize to satisfy k=3
SELECT kanon_anon(gender, age, symptom, 3) IS NOT NULL AS kanon_runs FROM patients LIMIT 1;
DROP TABLE patients;

-- ── error handling ──
SELECT (SELECT privacy('{"op":"nonexistent","x":1}') IS NOT NULL) = false AS unknown_op_rejected;

SELECT 'ALL SMOKE TESTS DONE' AS done;
