//! Deterministic PRNG + hashing — ported from privacy.lua.
//!
//! Park-Miller LCG (Schrage method) so every intermediate stays < 2^31 and
//! the port is bit-exact with the Lua reference (reproducible outputs
//! matter: the same seed must give the same noise, cross-language).

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
        let mut x = 16_807u64 * r as u64 - 2_836u64 * q as u64;
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
