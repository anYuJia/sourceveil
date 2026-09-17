//! High-entropy replacement identifiers.
//!
//! Three properties matter, in this order:
//!
//! 1. **No collisions.** Every generated name is unique across the whole build
//!    *and* disjoint from every identifier that already appears in the source.
//!    That is a stronger guarantee than "unique within a scope", and it removes
//!    the need to model Rust's shadowing rules during name selection.
//! 2. **No new lint noise.** Rust's casing lints (`non_snake_case`,
//!    `non_camel_case_types`, `non_upper_case_globals`) are warn-by-default, and
//!    plenty of projects build with `-D warnings`. A rename pass that turns a
//!    clean build red is worse than no obfuscation, so each item kind gets a
//!    name in the casing the compiler expects for it.
//! 3. **No keywords.** A 5-9 character lowercase name can land exactly on
//!    `await`, `crate`, `match`, `trait`, `union` and friends.

use crate::rng::SplitMix64;
use anyhow::{bail, Result};
use std::collections::HashSet;

/// Casing class a replacement name must satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCase {
    /// `snake_case`: functions, modules, locals, fields, parameters.
    Snake,
    /// `CamelCase`: structs, enums, unions, traits, type aliases, variants,
    /// generic type parameters.
    Camel,
    /// `SCREAMING_SNAKE`: `const` and `static` items.
    Screaming,
}

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &[u8] = b"0123456789";

/// Reserved words that must never be produced. Covers strict keywords, the 2018
/// and 2024 additions, reserved-for-future-use words, and `Self`/`self` family
/// so that generated names stay usable in every position we rename.
const KEYWORDS: &[&str] = &[
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "crate",
    "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl",
    "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "true", "try", "type",
    "typeof", "union", "unsafe", "unsized", "use", "virtual", "where", "while", "yield",
];

pub struct NameGenerator {
    rng: SplitMix64,
    used: HashSet<String>,
    len_min: usize,
    len_max: usize,
}

impl NameGenerator {
    /// `reserved` should contain every identifier that already occurs anywhere
    /// in the workspace. Passing the full set is what makes the no-collision
    /// guarantee hold without any scope analysis.
    pub fn new(seed: u64, len_min: usize, len_max: usize, reserved: HashSet<String>) -> Self {
        Self {
            rng: SplitMix64::new(seed),
            used: reserved,
            len_min,
            len_max,
        }
    }

    pub fn already_used(&self, name: &str) -> bool {
        self.used.contains(name)
    }

    /// Produce a fresh name in the requested casing, or fail after a bounded
    /// number of attempts. Failure here means the alphabet is exhausted, which
    /// for the default 5..=9 range cannot happen in practice.
    pub fn generate(&mut self, case: NameCase) -> Result<String> {
        // Probability of hitting an already-used name is tiny, so a small cap
        // is plenty; hitting it means something is systematically wrong.
        const MAX_ATTEMPTS: usize = 512;
        for _ in 0..MAX_ATTEMPTS {
            let len = self.rng.range_inclusive(self.len_min, self.len_max);
            let candidate = self.random_name(case, len);
            if KEYWORDS.contains(&candidate.as_str()) {
                continue;
            }
            if self.used.insert(candidate.clone()) {
                return Ok(candidate);
            }
        }
        bail!(
            "exhausted {MAX_ATTEMPTS} attempts to generate an unused {:?} name of length {}..={}",
            case,
            self.len_min,
            self.len_max
        );
    }

    fn random_name(&mut self, case: NameCase, len: usize) -> String {
        // First character is always a letter; digits may follow. This is what
        // keeps `Q8KAP` a legal identifier rather than a numeric literal prefix.
        let (first_alphabet, tail_alphabet) = match case {
            NameCase::Snake => (LOWER, LOWER),
            NameCase::Camel => (UPPER, LOWER),
            NameCase::Screaming => (UPPER, UPPER),
        };
        let mut out = String::with_capacity(len);
        out.push(*self.rng.pick(first_alphabet) as char);
        for _ in 1..len {
            let from_digits = self.rng.below(4) == 0;
            let c = if from_digits {
                *self.rng.pick(DIGIT)
            } else {
                *self.rng.pick(tail_alphabet)
            };
            out.push(c as char);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen(seed: u64) -> NameGenerator {
        NameGenerator::new(seed, 5, 9, HashSet::new())
    }

    #[test]
    fn deterministic_for_a_seed() {
        let mut a = gen(1);
        let mut b = gen(1);
        for _ in 0..100 {
            assert_eq!(
                a.generate(NameCase::Snake).unwrap(),
                b.generate(NameCase::Snake).unwrap()
            );
        }
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = gen(1);
        let mut b = gen(2);
        let names_a: Vec<_> = (0..20)
            .map(|_| a.generate(NameCase::Snake).unwrap())
            .collect();
        let names_b: Vec<_> = (0..20)
            .map(|_| b.generate(NameCase::Snake).unwrap())
            .collect();
        assert_ne!(names_a, names_b);
    }

    #[test]
    fn names_are_unique_and_respect_length() {
        let mut g = gen(42);
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            let n = g.generate(NameCase::Snake).unwrap();
            assert!((5..=9).contains(&n.len()), "bad length: {n}");
            assert!(seen.insert(n.clone()), "duplicate: {n}");
        }
    }

    #[test]
    fn casings_are_lint_safe() {
        let mut g = gen(7);
        for _ in 0..500 {
            let snake = g.generate(NameCase::Snake).unwrap();
            assert!(
                snake.starts_with(|c: char| c.is_ascii_lowercase()),
                "{snake}"
            );
            assert!(!snake.contains('_'), "{snake}");

            let camel = g.generate(NameCase::Camel).unwrap();
            assert!(
                camel.starts_with(|c: char| c.is_ascii_uppercase()),
                "{camel}"
            );

            let screaming = g.generate(NameCase::Screaming).unwrap();
            assert!(
                screaming
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "{screaming}"
            );
        }
    }

    #[test]
    fn reserved_identifiers_are_never_reissued() {
        let mut reserved = HashSet::new();
        reserved.insert("qk8ap".to_string());
        let mut g = NameGenerator::new(3, 5, 5, reserved);
        for _ in 0..5000 {
            assert_ne!(g.generate(NameCase::Snake).unwrap(), "qk8ap");
        }
    }

    #[test]
    fn keywords_are_never_produced() {
        // Sweep many seeds; a keyword would have to slip past the filter.
        for seed in 0..200 {
            let mut g = NameGenerator::new(seed, 5, 5, HashSet::new());
            for _ in 0..500 {
                let n = g.generate(NameCase::Snake).unwrap();
                assert!(!KEYWORDS.contains(&n.as_str()), "generated keyword {n}");
            }
        }
    }
}
