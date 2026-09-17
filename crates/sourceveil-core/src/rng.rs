//! A tiny, frozen PRNG.
//!
//! `Build Diversification` promises that the same source plus the same seed
//! yields byte-identical output. That promise has to hold across toolchain
//! upgrades, so the name generator must not depend on a third-party RNG whose
//! stream can change between releases. This is `splitmix64`, which is ~10 lines
//! and will never move.

/// SplitMix64. Deterministic, seedable, and stable forever.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..bound` by rejection sampling, so the stream stays
    /// unbiased for every bound (a plain modulo would skew short names).
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0, "bound must be positive");
        let zone = u64::MAX - (u64::MAX % bound) - 1;
        loop {
            let v = self.next_u64();
            if v <= zone {
                return v % bound;
            }
        }
    }

    pub fn range_inclusive(&mut self, lo: usize, hi: usize) -> usize {
        assert!(lo <= hi, "empty range {lo}..={hi}");
        let span = (hi - lo) as u64 + 1;
        lo + self.below(span) as usize
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = SplitMix64::new(12345);
        let mut b = SplitMix64::new(12345);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seed_diverges() {
        assert_ne!(SplitMix64::new(1).next_u64(), SplitMix64::new(2).next_u64());
    }

    /// Pins the stream so a future refactor cannot silently invalidate every
    /// previously published mapping.
    #[test]
    fn stream_is_frozen() {
        let mut r = SplitMix64::new(0);
        assert_eq!(r.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(r.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(r.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn below_stays_in_range() {
        let mut r = SplitMix64::new(7);
        for _ in 0..1000 {
            assert!(r.below(10) < 10);
        }
        assert_eq!(r.below(1), 0);
    }

    #[test]
    fn range_inclusive_covers_both_ends() {
        let mut r = SplitMix64::new(99);
        let (mut lo_hit, mut hi_hit) = (false, false);
        for _ in 0..500 {
            let v = r.range_inclusive(5, 9);
            assert!((5..=9).contains(&v));
            lo_hit |= v == 5;
            hi_hit |= v == 9;
        }
        assert!(lo_hit && hi_hit);
    }
}
