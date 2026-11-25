-- duckdb-privacy smoke tests — run with: duckdb -unsigned
--   LOAD 'privacy.duckdb_extension'; .read test/smoke.sql
-- Every assertion uses the extension's own output; deterministic ops are
-- cross-checked against the Lua reference (libs/privacy/privacy.lua) with
-- fixed seeds, so a regression shows up as a value mismatch.
--
-- Naming: `mask` = Lua-compatible mode-based starring; `mask(v, kind)` = PII
-- kind masking (phone/email/name/id/...); `mask_cn` follows GB/T 37964 rules.

LOAD 'privacy.duckdb_extension';

-- ── DP: structural invariants (PRNG stream position is not pinned) ──
SELECT dp_count(1000, 0.01) IS NOT NULL AS dp_count_runs;

-- laplace b=2: symmetric distribution over many draws.
-- The 2nd argument is a seed, so it must vary per row — a constant seed makes
-- every row return the identical value and the symmetry check is meaningless.
CREATE TEMP TABLE t AS SELECT laplace(2, i::DOUBLE) AS x FROM range(10000) AS r(i);
SELECT
  (SELECT count(*) FROM t WHERE CAST(x AS DOUBLE) > 0)::DOUBLE / 10000.0
    BETWEEN 0.45 AND 0.55 AS lap_symmetric;
DROP TABLE t;

-- ── DP session ledger: allocations accumulate, overspend is flagged ──
SELECT dp_alloc('t1', 'a', 0.5, 0.5) IS NOT NULL AS alloc_a;
SELECT dp_alloc('t1', 'b', 0.6, 0.5) IS NOT NULL AS alloc_b;
-- 0.5 + 0.6 = 1.1 > 0.5 budget: still recorded (audit), flagged over_budget
SELECT (dp_budget('t1') ->> 'total')::DOUBLE > 1.0 AS budget_overspent;
SELECT (dp_budget('t1') ->> 'entries')::INT = 2 AS ledger_entries;

-- ── mask: mode-based (Lua-compatible) ──
SELECT mask('13812345678') = '1*********8' AS mask_star_default;

-- ── mask(value, kind): PII kind rules ──
SELECT mask('13812345678', 'phone') = '138****5678' AS mask_phone;
SELECT mask('abc@example.com', 'email') = 'a**@example.com' AS mask_email;
SELECT mask('张三丰', 'name') = '张*丰' AS mask_name;
SELECT mask('110101199003078515', 'id') = '110101********8515' AS mask_id;
SELECT mask(NULL, 'phone') IS NULL AS mask_null;

-- ── CN rules (GB/T 37964) ──
SELECT mask_cn('13812345678', 'phone') = '138****5678' AS cn_phone;
SELECT mask_cn('张三', 'name') = '张*' AS cn_name_2char;
SELECT mask_cn('张三丰', 'name') = '张**' AS cn_name_3char;
SELECT mask_cn('110101199003078515', 'idcard') = '110101********8515' AS cn_id;
SELECT mask_cn('13812345678', 'mobile', 'star') = '138****5678' AS cn_3arg;

-- ── date shift (MIMIC-style, deterministic) ──
SELECT dateshift('2020-05-15') IS NOT NULL AS dateshift_runs;
SELECT dateshift('2020-05-15') = dateshift('2020-05-15') AS dateshift_deterministic;
SELECT dateshift('2020-01-01') < dateshift('2020-06-01') AS dateshift_order;
-- dateoffset(date, delta) undoes a shift: date - delta
CREATE TEMP TABLE td AS SELECT dateshift('2020-05-15') AS s, '2020-05-15' AS orig;
SELECT dateoffset(s::DATE, s::DATE - orig::DATE) = orig AS dateoffset_roundtrip FROM td;
DROP TABLE td;

-- ── redact_text: PHI types, including separator-bearing identifiers ──
SELECT redact_text('Call John at 555-123-4567 for the admission at St Mary''s Hospital')
  LIKE '%[**PHONE**]%' AS redact_phone;
SELECT redact_text('Patient born 1985-03-12, MRN: A-12345')
  LIKE '%[**DATE**]%' AS redact_dob;
SELECT redact_text('The SSN is 123-45-6789') LIKE '%[**SSN**]%' AS redact_ssn;

-- ── FPE: key is mandatory (an all-zero key would be no encryption) ──
SELECT fpe_encode('1234567890123456', 'key12345678901', '00000000000000')
  LIKE '%key%' AS fpe_rejects_bad_key;

CREATE TEMP TABLE fpe AS SELECT
  fpe_encode('1234567890123456', '0123456789abcdef0123456789abcdef', '00000000000000') AS enc;
SELECT
  length((SELECT enc FROM fpe)) = length('1234567890123456') AS fpe_len_preserved,
  (SELECT enc FROM fpe) <> '1234567890123456' AS fpe_changed,
  fpe_decode((SELECT enc FROM fpe), '0123456789abcdef0123456789abcdef', '00000000000000')
    = '1234567890123456' AS fpe_roundtrip;
DROP TABLE fpe;

-- deterministic per (key, tweak); a different tweak changes the ciphertext
SELECT fpe_encode('1234567890123456', '0123456789abcdef0123456789abcdef', '00000000000000')
     = fpe_encode('1234567890123456', '0123456789abcdef0123456789abcdef', '00000000000000')
  AS fpe_deterministic;
SELECT fpe_encode('1234567890123456', '0123456789abcdef0123456789abcdef', '00000000000000')
    <> fpe_encode('1234567890123456', '0123456789abcdef0123456789abcdef', '00000000000001')
  AS fpe_tweak_sensitive;

-- ── dispatcher: unknown op / bad JSON are NULL, not empty string ──
SELECT privacy('{"op":"nonexistent","x":1}') IS NULL AS unknown_op_is_null;
SELECT privacy('not json') IS NULL AS bad_json_is_null;
SELECT privacy('{"op":"mask","v":"13812345678","kind":"phone"}') = '138****5678'
  AS dispatcher_respects_kind;

-- ── k-anonymity via the dispatcher (records form) ──
SELECT privacy('{"op":"kanon","records":[{"id":1,"qi":{"age":25,"city":"hz"}},{"id":2,"qi":{"age":26,"city":"hz"}},{"id":3,"qi":{"age":60,"city":"sh"}},{"id":4,"qi":{"age":61,"city":"sh"}}],"k":2}')
  LIKE '%groups%' AS kanon_runs;

SELECT 'ALL SMOKE TESTS DONE' AS done;
