//! Deterministic PRNG + hashing — ported from privacy.lua.
//!
//! Park-Miller LCG (Schrage method) so every intermediate stays < 2^31.
//!
//! Divergence from the Lua reference, deliberate: the stream is warmed up
//! before the first draw (see `Rng::warm`). The un-warmed LCG emits
//! `x1 = 16807*seed`, which ties the first output tightly to the seed — for
//! small or adjacent seeds every Laplace draw landed on the same side of zero,
//! which voids the ε-DP guarantee. Determinism per seed is preserved; numeric
//! equality with the Lua implementation is not.

/// Park-Miller LCG state, Schrager form. `next()` returns u64 in [0, 2^31).
pub struct Rng {
    pub x: u32,
}

impl Rng {
    /// Lua: `x = (tonumber(seed) and (seed % 2147483646) or 1); if x<=0 then x=1 end`.
    /// Seeds come in as i64 (BIGINT) in the Lua world; we accept i64 here.
    pub fn new(seed: i64) -> Self {
        let x = (seed % 2_147_483_646) as i64;
        let mut x = if x <= 0 { 1 } else { x };
        // Lua `tonumber(seed) and ...` treats 0/false as nil → x=1
        if x == 0 {
            x = 1;
        }
        Rng { x: x as u32 }
    }

    /// One uniform in [0, 2^31) — the LCG step, matching the Lua closure's
    /// intermediate before it divides by 2^31.
    pub fn next_u31(&mut self) -> u32 {
        let q = self.x / 127_773;
        let r = self.x - q * 127_773;
        // Schrage's correction MUST be signed: 16807*r - 2836*q is genuinely
        // negative for some states. Holding it in u64 made `x < 0` dead code
        // (the compiler flagged the comparison), so the underflow wrapped to
        // ~2^64 and the `as u32` truncation produced states outside the
        // Park-Miller domain [1, 2^31). The resulting stream was so degenerate
        // that laplace() returned only negative values, which silently voids
        // the ε-DP guarantee (Laplace noise must be centred on 0).
        let mut x = 16_807i64 * i64::from(r) - 2_836i64 * i64::from(q);
        if x < 0 {
            x += 2_147_483_647;
        }
        self.x = x as u32;
        self.x
    }

    /// One uniform in [0, 1), bit-identical to the Lua `x / 2147483647`.
    pub fn next_f64(&mut self) -> f64 {
        self.next_u31() as f64 / 2_147_483_647.0
    }

    /// Advance the generator `n` steps, discarding the output.
    ///
    /// A Park-Miller stream seeded with a small integer puts its first draw at
    /// 16807*seed, which is strongly correlated with the seed and biased to one
    /// side. Warming up decorrelates the stream while keeping it reproducible
    /// for a given seed.
    pub fn warm(&mut self, n: usize) {
        for _ in 0..n {
            self.next_u31();
        }
    }

    /// Laplace(0, scale), exact port of the Lua inverse-CDF sampler:
    /// u = rng()-0.5 in (-0.5, 0.5]; scale * sign * -ln(1 - 2|u|).
    pub fn laplace(&mut self, scale: f64) -> f64 {
        let u = self.next_f64() - 0.5;
        let sign = if u >= 0.0 { 1.0 } else { -1.0 };
        -sign * scale * (1.0 - 2.0 * u.abs()).ln()
    }
}

/// FNV-1a 32-bit with salt — exact port. The Lua version does
/// `(salt or '') .. s` then per-byte: h = (h xor byte) * 16777619 mod 2^32.
pub fn fnv1a(s: &str, salt: &str) -> u32 {
    let mut h: u32 = 0x811C9DC5;
    for b in salt.as_bytes().iter().chain(s.as_bytes()) {
        h ^= u32::from(*b);
        h = h.wrapping_mul(16_777_619);
    }
    h
}

#[cfg(test)]
mod rng_tests {
    use super::Rng;

    /// Regression: `next_u31` used to accumulate Schrage's step in u64, so the
    /// `x < 0` correction was dead code and the state escaped the Park-Miller
    /// domain. The stream degenerated into values that made laplace() return
    /// *only negative* draws — noise biased by about -2.16*scale. Laplace noise
    /// must be centred on zero or the ε-DP guarantee does not hold.
    #[test]
    fn laplace_is_centred_and_symmetric() {
        let scale = 2.0;
        let mut rng = Rng::new(1);
        let n = 20_000;
        let mut sum = 0.0f64;
        let mut sum_sq = 0.0f64;
        let mut pos = 0usize;
        let mut neg = 0usize;
        for _ in 0..n {
            let v = rng.laplace(scale);
            sum += v;
            sum_sq += v * v;
            if v > 0.0 {
                pos += 1;
            } else if v < 0.0 {
                neg += 1;
            }
        }
        let mean = sum / n as f64;
        let var = sum_sq / n as f64 - mean * mean;
        let std = var.sqrt();

        // Laplace(0, b): mean 0, variance 2b^2 → std = b*sqrt(2).
        assert!(
            mean.abs() < 0.15 * scale,
            "laplace noise is biased: mean={mean:.4}, expected ~0"
        );
        assert!(
            (std - scale * 2f64.sqrt()).abs() < 0.15 * scale * 2f64.sqrt(),
            "laplace scale is wrong: std={std:.4}, expected {:.4}",
            scale * 2f64.sqrt()
        );
        // Both signs must be drawn; the old bug produced pos == 0.
        assert!(pos > 0 && neg > 0, "one-sided noise: pos={pos} neg={neg}");
        let ratio = pos as f64 / (pos + neg) as f64;
        assert!(
            (ratio - 0.5).abs() < 0.05,
            "laplace is not symmetric: pos ratio={ratio:.4}"
        );
    }

    /// The raw stream must stay inside the Park-Miller domain, otherwise the
    /// uniform → float conversion is not uniform at all.
    #[test]
    fn lcg_state_stays_in_domain() {
        let mut rng = Rng::new(42);
        for _ in 0..100_000 {
            let x = rng.next_u31();
            assert!(
                (1..2_147_483_647).contains(&x),
                "LCG state left [1, 2^31): {x}"
            );
        }
    }

    /// Uniformity smoke test: a degenerate stream shows up as a pile-up in one
    /// bucket. Ten buckets should each get roughly a tenth of the draws.
    #[test]
    fn uniform_stream_covers_the_unit_interval() {
        let mut rng = Rng::new(7);
        let n = 100_000;
        let mut buckets = [0usize; 10];
        for _ in 0..n {
            let u = rng.next_f64();
            assert!((0.0..=1.0).contains(&u), "u out of range: {u}");
            buckets[((u * 10.0) as usize).min(9)] += 1;
        }
        let expected = n / 10;
        for (i, &c) in buckets.iter().enumerate() {
            let dev = (c as f64 - expected as f64).abs() / expected as f64;
            assert!(dev < 0.1, "bucket {i} deviates {:.1}%", dev * 100.0);
        }
    }

    /// Determinism is a documented property (same seed → same noise).
    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::new(12345);
        let mut b = Rng::new(12345);
        for _ in 0..1000 {
            assert_eq!(a.next_u31(), b.next_u31());
        }
    }

    /// Known-value check on the first Park-Miller step from seed 1: the
    /// canonical sequence starts 16807, 282475249, ...
    #[test]
    fn known_park_miller_values() {
        let mut rng = Rng::new(1);
        assert_eq!(rng.next_u31(), 16_807);
        assert_eq!(rng.next_u31(), 282_475_249);
    }
}
