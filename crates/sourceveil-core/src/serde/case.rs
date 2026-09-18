//! serde's `rename_all` rules.
//!
//! Ported from `serde_derive` 1.0.229's `internals/case.rs`, which is the
//! authority on what a wire name actually is. It is not a helper we can depend
//! on — `serde_derive` is a proc-macro crate and its internals are not API —
//! so the algorithm is reproduced here and pinned by tests that run the real
//! serde and compare.
//!
//! ## The rule that makes this dangerous
//!
//! **`apply_to_field` and `apply_to_variant` are not the same function.** On
//! fields, `lowercase` and `snake_case` are both the identity; on variants,
//! `snake_case` splits `WaitingForLogin` into `waiting_for_login`. A single
//! shared "apply the rule" helper would produce a wire format that differs from
//! serde's on real code, and nothing would fail to compile.

use std::fmt;

/// A `rename_all` rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameRule {
    /// No rule, or one that leaves the name alone.
    None,
    LowerCase,
    UpperCase,
    PascalCase,
    CamelCase,
    SnakeCase,
    ScreamingSnakeCase,
    KebabCase,
    ScreamingKebabCase,
}

/// The spellings serde accepts, in its own order.
const RULES: &[(&str, RenameRule)] = &[
    ("lowercase", RenameRule::LowerCase),
    ("UPPERCASE", RenameRule::UpperCase),
    ("PascalCase", RenameRule::PascalCase),
    ("camelCase", RenameRule::CamelCase),
    ("snake_case", RenameRule::SnakeCase),
    ("SCREAMING_SNAKE_CASE", RenameRule::ScreamingSnakeCase),
    ("kebab-case", RenameRule::KebabCase),
    ("SCREAMING-KEBAB-CASE", RenameRule::ScreamingKebabCase),
];

impl RenameRule {
    /// Parse the string serde would accept. Unknown rules are an error, because
    /// guessing at one means guessing at the wire format.
    pub fn parse(text: &str) -> Result<Self, UnknownRule> {
        RULES
            .iter()
            .find(|(name, _)| *name == text)
            .map(|(_, rule)| *rule)
            .ok_or_else(|| UnknownRule {
                given: text.to_string(),
            })
    }

    pub fn names() -> impl Iterator<Item = &'static str> {
        RULES.iter().map(|(name, _)| *name)
    }

    /// The wire name of a struct field under this rule.
    pub fn apply_to_field(self, field: &str) -> String {
        match self {
            RenameRule::None | RenameRule::LowerCase | RenameRule::SnakeCase => field.to_owned(),
            RenameRule::UpperCase => field.to_ascii_uppercase(),
            RenameRule::PascalCase => {
                let mut pascal = String::new();
                let mut capitalize = true;
                for ch in field.chars() {
                    if ch == '_' {
                        capitalize = true;
                    } else if capitalize {
                        pascal.push(ch.to_ascii_uppercase());
                        capitalize = false;
                    } else {
                        pascal.push(ch);
                    }
                }
                pascal
            }
            RenameRule::CamelCase => lower_first(&RenameRule::PascalCase.apply_to_field(field)),
            RenameRule::ScreamingSnakeCase => field.to_ascii_uppercase(),
            RenameRule::KebabCase => field.replace('_', "-"),
            RenameRule::ScreamingKebabCase => RenameRule::ScreamingSnakeCase
                .apply_to_field(field)
                .replace('_', "-"),
        }
    }

    /// The wire name of an enum variant under this rule.
    ///
    /// Deliberately a different function from [`RenameRule::apply_to_field`].
    pub fn apply_to_variant(self, variant: &str) -> String {
        match self {
            RenameRule::None | RenameRule::PascalCase => variant.to_owned(),
            RenameRule::LowerCase => variant.to_ascii_lowercase(),
            RenameRule::UpperCase => variant.to_ascii_uppercase(),
            RenameRule::CamelCase => lower_first(variant),
            RenameRule::SnakeCase => split_variant(variant),
            RenameRule::ScreamingSnakeCase => split_variant(variant).to_ascii_uppercase(),
            RenameRule::KebabCase => split_variant(variant).replace('_', "-"),
            RenameRule::ScreamingKebabCase => split_variant(variant)
                .to_ascii_uppercase()
                .replace('_', "-"),
        }
    }

    /// `rule_b` when this is `None`, as serde's `or` does.
    pub fn or(self, rule_b: Self) -> Self {
        match self {
            RenameRule::None => rule_b,
            _ => self,
        }
    }
}

/// `MyVariant` -> `my_variant`.
///
/// An underscore goes in before every uppercase character that is not the
/// first, so `HTTPServer` becomes `h_t_t_p_server` — which looks wrong and is
/// exactly what serde does.
fn split_variant(variant: &str) -> String {
    let mut snake = String::new();
    for (index, ch) in variant.char_indices() {
        if index > 0 && ch.is_uppercase() {
            snake.push('_');
        }
        snake.push(ch.to_ascii_lowercase());
    }
    snake
}

/// Lowercase the first character, leaving the rest alone.
///
/// Byte-slicing rather than `char` iteration, because that is what serde does;
/// the behaviour on non-ASCII input is part of the contract either way.
fn lower_first(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    text[..1].to_ascii_lowercase() + &text[1..]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRule {
    pub given: String,
}

impl fmt::Display for UnknownRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown rename rule {:?}, expected one of {}",
            self.given,
            RenameRule::names()
                .map(|n| format!("{n:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for UnknownRule {}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(name: &str) -> RenameRule {
        RenameRule::parse(name).unwrap()
    }

    #[test]
    fn every_spelling_serde_accepts_is_accepted() {
        for (name, expected) in RULES {
            assert_eq!(RenameRule::parse(name).unwrap(), *expected);
        }
        assert!(RenameRule::parse("camel_case").is_err());
        assert!(RenameRule::parse("").is_err());
    }

    /// The whole reason this module exists.
    ///
    /// On a field, `lowercase` and `snake_case` are the identity. On a variant
    /// they are not. A shared implementation would produce a different wire
    /// format from serde's and nothing would fail to compile.
    #[test]
    fn fields_and_variants_follow_different_rules() {
        assert_eq!(rule("lowercase").apply_to_field("userName"), "userName");
        assert_eq!(rule("lowercase").apply_to_variant("UserName"), "username");
        assert_eq!(rule("snake_case").apply_to_field("userName"), "userName");
        assert_eq!(
            rule("snake_case").apply_to_variant("WaitingForLogin"),
            "waiting_for_login"
        );
        assert_eq!(rule("PascalCase").apply_to_field("user_name"), "UserName");
        assert_eq!(
            rule("PascalCase").apply_to_variant("UserLogin"),
            "UserLogin"
        );
    }

    #[test]
    fn field_rules_match_serdes_table() {
        let cases = [
            // rule, input, expected
            ("lowercase", "user_name", "user_name"),
            ("UPPERCASE", "user_name", "USER_NAME"),
            ("PascalCase", "user_name", "UserName"),
            ("PascalCase", "userName", "UserName"),
            ("camelCase", "user_name", "userName"),
            ("snake_case", "user_name", "user_name"),
            ("SCREAMING_SNAKE_CASE", "user_name", "USER_NAME"),
            ("kebab-case", "user_name", "user-name"),
            ("SCREAMING-KEBAB-CASE", "user_name", "USER-NAME"),
        ];
        for (name, input, expected) in cases {
            assert_eq!(
                rule(name).apply_to_field(input),
                expected,
                "field {name} {input}"
            );
        }
    }

    #[test]
    fn variant_rules_match_serdes_table() {
        let cases = [
            ("lowercase", "WaitingForLogin", "waitingforlogin"),
            ("UPPERCASE", "WaitingForLogin", "WAITINGFORLOGIN"),
            ("PascalCase", "WaitingForLogin", "WaitingForLogin"),
            ("camelCase", "WaitingForLogin", "waitingForLogin"),
            ("snake_case", "WaitingForLogin", "waiting_for_login"),
            (
                "SCREAMING_SNAKE_CASE",
                "WaitingForLogin",
                "WAITING_FOR_LOGIN",
            ),
            ("kebab-case", "WaitingForLogin", "waiting-for-login"),
            (
                "SCREAMING-KEBAB-CASE",
                "WaitingForLogin",
                "WAITING-FOR-LOGIN",
            ),
        ];
        for (name, input, expected) in cases {
            assert_eq!(
                rule(name).apply_to_variant(input),
                expected,
                "variant {name} {input}"
            );
        }
    }

    /// serde inserts an underscore before *every* uppercase character but the
    /// first, so runs of capitals come apart. It looks like a bug and it is the
    /// contract, so it is pinned.
    #[test]
    fn a_run_of_capitals_splits_character_by_character() {
        assert_eq!(
            rule("snake_case").apply_to_variant("HTTPServer"),
            "h_t_t_p_server"
        );
        assert_eq!(rule("snake_case").apply_to_variant("A"), "a");
        assert_eq!(rule("snake_case").apply_to_variant(""), "");
    }

    #[test]
    fn empty_and_underscore_heavy_names_survive() {
        assert_eq!(rule("PascalCase").apply_to_field(""), "");
        assert_eq!(rule("PascalCase").apply_to_field("__"), "");
        assert_eq!(rule("PascalCase").apply_to_field("_x"), "X");
        assert_eq!(rule("camelCase").apply_to_field(""), "");
        assert_eq!(rule("kebab-case").apply_to_field("a__b"), "a--b");
    }

    #[test]
    fn or_prefers_the_non_none_rule() {
        assert_eq!(
            RenameRule::None.or(RenameRule::CamelCase),
            RenameRule::CamelCase
        );
        assert_eq!(
            RenameRule::SnakeCase.or(RenameRule::CamelCase),
            RenameRule::SnakeCase
        );
    }
}
