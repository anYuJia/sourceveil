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
//!
//! ## Why names are derived rather than drawn
//!
//! A single sequential stream is the obvious implementation and it is wrong for
//! a build tool. Drawing names in traversal order means every name depends on
//! how many candidates happened to be visited first, so adding one unrelated
//! function renames every symbol after it. Measured: a single new function at
//! the top of the first file the walker reaches renamed all ten symbols of the
//! `simple-rust` fixture.
//!
//! A release that cannot be rebuilt from its own tag is not reproducible in any
//! useful sense, and a mapping that churns on every unrelated commit makes the
//! answer key worthless for reading old crash reports.
//!
//! So a name is *computed* from its own identity:
//!
//! ```text
//! name = encode(HMAC-SHA256(seed, domain || identity || attempt))
//! ```
//!
//! The domain separates the namespaces, so a Tauri event and a Rust symbol can
//! never be confused for one another and neither can be moved by the other's
//! existence. The identity is the thing being named — a symbol path, a command
//! name, an event channel — so the name follows the thing and nothing else.

use crate::rng::SplitMix64;
use anyhow::{bail, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};

/// Which namespace a name belongs to.
///
/// Two names derived for the same identity in different domains are unrelated.
/// This is what keeps the passes from disturbing one another: adding an event
/// cannot move a symbol name, because the event's name never consulted the
/// symbol stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SeedDomain {
    RustSymbol,
    /// A private JavaScript/TypeScript lexical binding. Kept separate from
    /// Rust symbols so adding a frontend does not consume their namespace.
    FrontendSymbol,
    TauriCommand,
    TauriEvent,
    /// A generated dependency boundary wrapper module.
    DependencyWrapper,
}

impl SeedDomain {
    fn as_str(self) -> &'static str {
        match self {
            SeedDomain::RustSymbol => "symbol",
            SeedDomain::FrontendSymbol => "frontend-symbol",
            SeedDomain::TauriCommand => "command",
            SeedDomain::TauriEvent => "event",
            SeedDomain::DependencyWrapper => "dependency-wrapper",
        }
    }
}

/// Casing class a replacement name must satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameCase {
    /// `snake_case`: functions, modules, locals, fields, parameters.
    Snake,
    /// `_snake_case`: an intentionally-unused local or parameter. Keeping the
    /// leading underscore preserves Rust's unused-binding lint semantics.
    HiddenSnake,
    /// `CamelCase`: structs, enums, unions, traits, type aliases, variants,
    /// generic type parameters.
    Camel,
    /// `SCREAMING_SNAKE`: `const` and `static` items.
    Screaming,
    /// A protocol channel: `v7Kp21`. Tauri event names are strings, not
    /// identifiers, so no casing rule applies — but the alphabet is kept to
    /// `[A-Za-z0-9]` with a leading letter, because the framework's own rules
    /// for a channel name are not something to probe at the edges.
    Channel,
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

/// Derives replacement names, one identity at a time.
pub struct NameDeriver {
    seed: u64,
    len_min: usize,
    len_max: usize,
    /// Identifiers that already exist in the source. A derived name is rejected
    /// and redrawn if it lands on one of these — which is order-independent,
    /// because the set is a property of the source rather than of the walk.
    reserved: HashSet<String>,
    /// Names already handed out. Used only to *report* a collision.
    issued: HashSet<String>,
    /// Repeated requests for one logical identity must return one spelling.
    /// Field groups and same-spelled items use this to make syntax-only macro
    /// references unambiguous without depending on traversal order.
    assigned: HashMap<(SeedDomain, String, NameCase), String>,
}

impl NameDeriver {
    /// `reserved` should contain every identifier that already occurs anywhere
    /// in the workspace. Passing the full set is what makes the no-collision
    /// guarantee hold without any scope analysis.
    pub fn new(seed: u64, len_min: usize, len_max: usize, reserved: HashSet<String>) -> Self {
        Self {
            seed,
            len_min,
            len_max,
            reserved,
            issued: HashSet::new(),
            assigned: HashMap::new(),
        }
    }

    /// Keep `name` from being produced. Used to hold a whole namespace apart
    /// from another: event channels avoid the command names, say.
    pub fn reserve(&mut self, name: impl Into<String>) {
        self.reserved.insert(name.into());
    }

    pub fn already_used(&self, name: &str) -> bool {
        self.reserved.contains(name) || self.issued.contains(name)
    }

    /// The name for `identity` in `domain`.
    ///
    /// Depends on the seed, the domain and the identity — and on nothing else.
    /// Not on how many names were derived before it, not on traversal order,
    /// not on what else exists in the project.
    pub fn derive(&mut self, domain: SeedDomain, identity: &str, case: NameCase) -> Result<String> {
        let key = (domain, identity.to_owned(), case);
        if let Some(name) = self.assigned.get(&key) {
            return Ok(name.clone());
        }
        // The only reason to redraw is landing on an identifier the source
        // already uses, and `reserved` is a fixed set, so this loop cannot make
        // the result depend on order.
        const MAX_ATTEMPTS: u32 = 512;
        for attempt in 0..MAX_ATTEMPTS {
            let mut rng = SplitMix64::new(self.mix(domain, identity, attempt));
            let len = rng.range_inclusive(self.len_min, self.len_max);
            let name = random_name(&mut rng, case, len);
            if KEYWORDS.contains(&name.as_str()) || self.reserved.contains(&name) {
                continue;
            }
            if self.issued.contains(&name) {
                // Two identities hashed to the same name. This is far below the
                // noise floor for any real project, and the fallback is to try
                // this identity's next candidate. That is deterministic for a
                // given source, and — the property that matters — it cannot
                // move any *other* name.
                tracing::debug!(%name, %identity, "name collision; trying the next candidate");
                continue;
            }
            self.issued.insert(name.clone());
            self.assigned.insert(key, name.clone());
            return Ok(name);
        }
        bail!(
            "exhausted {MAX_ATTEMPTS} attempts to name `{identity}` in {domain:?} with a \
             {}..={} character name",
            self.len_min,
            self.len_max
        )
    }

    /// `HMAC-SHA256(seed, domain \0 identity \0 attempt)`, folded to 64 bits.
    ///
    /// HMAC rather than a hand-rolled mix: the construction is frozen by a
    /// standard, so a name derived today is the same name in five years.
    fn mix(&self, domain: SeedDomain, identity: &str, attempt: u32) -> u64 {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.seed.to_be_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(domain.as_str().as_bytes());
        mac.update(b"\0");
        mac.update(identity.as_bytes());
        mac.update(b"\0");
        mac.update(&attempt.to_be_bytes());

        let digest = mac.finalize().into_bytes();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest[..8]);
        u64::from_be_bytes(bytes)
    }
}

fn random_name(rng: &mut SplitMix64, case: NameCase, len: usize) -> String {
    let hidden = case == NameCase::HiddenSnake;
    let body_len = if hidden {
        // `_` alone is a discard pattern, not an identifier. A configured
        // one-character minimum therefore still needs one generated letter.
        len.saturating_sub(1).max(1)
    } else {
        len
    };
    // First character is always a letter; digits may follow. This is what
    // keeps `Q8KAP` a legal identifier rather than a numeric literal prefix.
    let first_alphabet: &[u8] = match case {
        NameCase::Snake | NameCase::HiddenSnake => LOWER,
        NameCase::Camel | NameCase::Screaming => UPPER,
        NameCase::Channel => &[LOWER, UPPER].concat(),
    };
    let tail_alphabet: &[u8] = match case {
        NameCase::Snake | NameCase::HiddenSnake => LOWER,
        NameCase::Camel => LOWER,
        NameCase::Screaming => UPPER,
        NameCase::Channel => &[LOWER, UPPER].concat(),
    };

    let mut out = String::with_capacity(body_len + usize::from(hidden));
    if hidden {
        out.push('_');
    }
    out.push(*rng.pick(first_alphabet) as char);
    for position in 1..body_len {
        // The last character is always a letter. A tail of nothing but digits
        // draws from 10^4 possibilities instead of 36^4, and that one corner is
        // where the birthday bound actually bites: it is the difference between
        // a collision being impossible at any real project size and being
        // merely unlikely.
        let letter_only = position == body_len - 1 || rng.below(4) != 0;
        let c = if letter_only {
            *rng.pick(tail_alphabet)
        } else {
            *rng.pick(DIGIT)
        };
        out.push(c as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deriver(seed: u64) -> NameDeriver {
        NameDeriver::new(seed, 5, 9, HashSet::new())
    }

    #[test]
    fn the_same_identity_always_derives_the_same_name() {
        let mut a = deriver(1);
        let mut b = deriver(1);
        for identity in ["crate::aaa", "crate::bbb", "crate::ccc"] {
            assert_eq!(
                a.derive(SeedDomain::RustSymbol, identity, NameCase::Snake)
                    .unwrap(),
                b.derive(SeedDomain::RustSymbol, identity, NameCase::Snake)
                    .unwrap(),
            );
        }
    }

    #[test]
    fn repeated_request_for_one_identity_reuses_the_name() {
        let mut names = deriver(9);
        let first = names
            .derive(SeedDomain::RustSymbol, "field::url", NameCase::Snake)
            .unwrap();
        let second = names
            .derive(SeedDomain::RustSymbol, "field::url", NameCase::Snake)
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = deriver(1);
        let mut b = deriver(2);
        assert_ne!(
            a.derive(SeedDomain::RustSymbol, "crate::x", NameCase::Snake)
                .unwrap(),
            b.derive(SeedDomain::RustSymbol, "crate::x", NameCase::Snake)
                .unwrap(),
        );
    }

    /// The property the whole design exists for: a name is a function of its
    /// own identity, so deriving anything else first changes nothing.
    #[test]
    fn a_name_does_not_depend_on_what_was_derived_before_it() {
        let mut alone = deriver(7);
        let target = alone
            .derive(SeedDomain::RustSymbol, "crate::aaa", NameCase::Snake)
            .unwrap();

        let mut crowded = deriver(7);
        for filler in ["crate::zzz", "crate::yyy", "crate::xxx"] {
            crowded
                .derive(SeedDomain::RustSymbol, filler, NameCase::Snake)
                .unwrap();
        }
        let after = crowded
            .derive(SeedDomain::RustSymbol, "crate::aaa", NameCase::Snake)
            .unwrap();

        assert_eq!(target, after);
    }

    /// Adding a command must not move an event, and vice versa — that is what
    /// the domain separator buys.
    #[test]
    fn domains_are_independent_of_one_another() {
        let mut without = deriver(11);
        let event_alone = without
            .derive(
                SeedDomain::TauriEvent,
                "download-progress",
                NameCase::Channel,
            )
            .unwrap();

        let mut with = deriver(11);
        with.derive(SeedDomain::TauriCommand, "sync_state", NameCase::Snake)
            .unwrap();
        with.derive(SeedDomain::TauriCommand, "get_user_info", NameCase::Snake)
            .unwrap();
        let event_after = with
            .derive(
                SeedDomain::TauriEvent,
                "download-progress",
                NameCase::Channel,
            )
            .unwrap();

        assert_eq!(event_alone, event_after);
    }

    #[test]
    fn names_are_unique_and_respect_length() {
        let mut d = deriver(42);
        let mut seen = HashSet::new();
        for index in 0..2000 {
            let n = d
                .derive(
                    SeedDomain::RustSymbol,
                    &format!("crate::sym{index}"),
                    NameCase::Snake,
                )
                .unwrap();
            assert!((5..=9).contains(&n.len()), "bad length: {n}");
            assert!(seen.insert(n.clone()), "duplicate: {n}");
        }
    }

    #[test]
    fn casings_are_lint_safe() {
        let mut d = deriver(7);
        for index in 0..500 {
            // Distinct identities, because that is what the pipeline supplies:
            // a symbol has one kind and therefore one casing.
            let snake = d
                .derive(
                    SeedDomain::RustSymbol,
                    &format!("a::{index}"),
                    NameCase::Snake,
                )
                .unwrap();
            assert!(
                snake.starts_with(|c: char| c.is_ascii_lowercase()),
                "{snake}"
            );
            assert!(!snake.contains('_'), "{snake}");

            let hidden = d
                .derive(
                    SeedDomain::RustSymbol,
                    &format!("hidden::{index}"),
                    NameCase::HiddenSnake,
                )
                .unwrap();
            assert!(hidden.starts_with('_'), "{hidden}");
            assert!(
                hidden[1..].starts_with(|c: char| c.is_ascii_lowercase()),
                "{hidden}"
            );

            let camel = d
                .derive(
                    SeedDomain::RustSymbol,
                    &format!("b::{index}"),
                    NameCase::Camel,
                )
                .unwrap();
            assert!(
                camel.starts_with(|c: char| c.is_ascii_uppercase()),
                "{camel}"
            );

            let screaming = d
                .derive(
                    SeedDomain::RustSymbol,
                    &format!("c::{index}"),
                    NameCase::Screaming,
                )
                .unwrap();
            assert!(
                screaming
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "{screaming}"
            );

            // A channel is a protocol string, not an identifier: mixed case is
            // expected, but the alphabet stays alphanumeric.
            let channel = d
                .derive(
                    SeedDomain::TauriEvent,
                    &format!("d::{index}"),
                    NameCase::Channel,
                )
                .unwrap();
            assert!(
                channel.starts_with(|c: char| c.is_ascii_alphabetic()),
                "{channel}"
            );
            assert!(
                channel.chars().all(|c| c.is_ascii_alphanumeric()),
                "{channel}"
            );
        }
    }

    #[test]
    fn reserved_identifiers_are_never_issued() {
        let mut reserved = HashSet::new();
        reserved.insert("qk8ap".to_string());
        let mut d = NameDeriver::new(3, 5, 5, reserved);
        for index in 0..2000 {
            let n = d
                .derive(
                    SeedDomain::RustSymbol,
                    &format!("crate::s{index}"),
                    NameCase::Snake,
                )
                .unwrap();
            assert_ne!(n, "qk8ap");
        }
    }

    #[test]
    fn keywords_are_never_produced() {
        // Sweep many seeds at the shortest legal length; a keyword would have
        // to slip past the filter to be seen here.
        for seed in 0..200 {
            let mut d = NameDeriver::new(seed, 5, 5, HashSet::new());
            for index in 0..200 {
                let n = d
                    .derive(
                        SeedDomain::RustSymbol,
                        &format!("crate::s{index}"),
                        NameCase::Snake,
                    )
                    .unwrap();
                assert!(!KEYWORDS.contains(&n.as_str()), "generated keyword {n}");
            }
        }
    }

    /// Pins the derivation.
    ///
    /// If this fails, every mapping already published is invalidated. That is a
    /// deliberate decision to make, not a side effect of a refactor, so it is
    /// checked here rather than discovered by a user.
    #[test]
    fn the_derivation_is_frozen() {
        let mut d = deriver(20240917);
        assert_eq!(
            d.derive(
                SeedDomain::TauriEvent,
                "download-progress",
                NameCase::Channel
            )
            .unwrap(),
            "mcwKh9g"
        );
        let mut d = deriver(20240917);
        assert_eq!(
            d.derive(SeedDomain::TauriCommand, "get_user_info", NameCase::Snake)
                .unwrap(),
            "cwvtuxso"
        );
        let mut d = deriver(20240917);
        assert_eq!(
            d.derive(
                SeedDomain::RustSymbol,
                "crate::auth::verify",
                NameCase::Snake
            )
            .unwrap(),
            "escmufw"
        );
    }
}
