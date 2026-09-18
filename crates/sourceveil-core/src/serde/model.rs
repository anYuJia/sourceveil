//! What string serde puts on the wire for a member.
//!
//! This is the whole point of the phase. A field's Rust identifier and its
//! wire name are the same string until something says otherwise, and the
//! something is always one of three things, in this order:
//!
//! ```text
//! the member's own #[serde(rename)]
//!   > the container's #[serde(rename_all)]
//!     > the Rust identifier
//! ```
//!
//! The order is serde's, and it is why a wire name has to be computed *before*
//! an identifier is renamed — never after. Recomputing `rename_all` from the
//! new identifier would transform the protocol, and the code would still
//! compile.
//!
//! ## Three decisions serde makes that are easy to get wrong
//!
//! - **Fields and variants apply different rules.** See
//!   [`crate::serde::case`]; `lowercase` is the identity on a field and not on
//!   a variant.
//! - **The two directions are named independently.** `serialize_renamed` is a
//!   property of one direction: `#[serde(rename(serialize = "a"))]` leaves the
//!   deserialize name to the rule, not to `"a"`.
//! - **The rule runs on the name, it does not replace it.** serde starts from
//!   the Rust identifier and *applies* the rule to it.
//!
//! Each rule below mirrors `serde_derive` 1.0.229's
//! `Field::rename_by_rules` / `Variant::rename_by_rules`.

use super::attrs::{Directional, SerdeAttrs};
use super::case::RenameRule;

/// Which kind of member this is. It picks the casing rule serde applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    /// A field of a struct, or of a struct variant.
    Field,
    /// An enum variant.
    Variant,
}

impl MemberKind {
    fn apply(self, rule: RenameRule, name: &str) -> String {
        match self {
            MemberKind::Field => rule.apply_to_field(name),
            MemberKind::Variant => rule.apply_to_variant(name),
        }
    }
}

/// The `rename_all` rules in force for a member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RenameAllRules {
    pub serialize: RenameRule,
    pub deserialize: RenameRule,
}

impl RenameAllRules {
    /// Read a container's or variant's `rename_all`, or any `rename_all`-shaped
    /// attribute, into a pair of rules.
    pub fn from(directional: &Directional<String>) -> Result<Self, UnknownRule> {
        Ok(Self {
            serialize: match &directional.serialize {
                Some(text) => RenameRule::parse(text)?,
                None => RenameRule::None,
            },
            deserialize: match &directional.deserialize {
                Some(text) => RenameRule::parse(text)?,
                None => RenameRule::None,
            },
        })
    }
}

pub use super::case::UnknownRule;

/// The two names a member answers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireNames {
    pub serialize: String,
    pub deserialize: String,
}

impl WireNames {
    pub fn are_the_same(&self) -> bool {
        self.serialize == self.deserialize
    }
}

/// The wire names of a struct field or enum variant.
///
/// `rules` are the `rename_all` rules that apply to *this* member: the
/// container's for a struct field or an enum variant, and for a field inside a
/// variant the variant's own `rename_all` when it has one, else the container's
/// `rename_all_fields`.
pub fn wire_names(
    rust_name: &str,
    kind: MemberKind,
    member: &SerdeAttrs,
    rules: &RenameAllRules,
) -> WireNames {
    // `r#` is source syntax for spelling a Rust keyword as an identifier; it
    // is not part of the identifier serde places on the wire. In particular,
    // `r#type` serializes as `"type"`, and rename rules apply to `type`.
    let rust_name = rust_name.strip_prefix("r#").unwrap_or(rust_name);
    WireNames {
        serialize: one_direction(
            rust_name,
            kind,
            member.rename.serialize.as_deref(),
            rules.serialize,
        ),
        deserialize: one_direction(
            rust_name,
            kind,
            member.rename.deserialize.as_deref(),
            rules.deserialize,
        ),
    }
}

/// One direction of [`wire_names`].
///
/// An explicit rename for this direction wins outright. Otherwise the rule is
/// *applied to* the Rust identifier — it does not replace it, and it is not
/// skipped just because the other direction was named.
fn one_direction(
    rust_name: &str,
    kind: MemberKind,
    explicit: Option<&str>,
    rule: RenameRule,
) -> String {
    match explicit {
        Some(name) => name.to_string(),
        None => kind.apply(rule, rust_name),
    }
}

/// Which `rename_all` rules apply to a field inside an enum variant.
///
/// A variant may carry its own `rename_all`, which then governs its fields;
/// otherwise the container's `rename_all_fields` does. The container's plain
/// `rename_all` names the *variants*, not their fields, and does not reach
/// here.
pub fn variant_field_rules(
    container_fields: &RenameAllRules,
    variant: &SerdeAttrs,
) -> Result<RenameAllRules, UnknownRule> {
    let own = RenameAllRules::from(&variant.rename_all)?;
    Ok(RenameAllRules {
        serialize: own.serialize.or(container_fields.serialize),
        deserialize: own.deserialize.or(container_fields.deserialize),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serde::attrs;

    fn member_attrs(text: &str) -> SerdeAttrs {
        attrs::parse(text).unwrap().unwrap_or_default()
    }

    fn rules(serialize: &str, deserialize: &str) -> RenameAllRules {
        RenameAllRules {
            serialize: RenameRule::parse(serialize).unwrap(),
            deserialize: RenameRule::parse(deserialize).unwrap(),
        }
    }

    fn no_rules() -> RenameAllRules {
        RenameAllRules::default()
    }

    #[test]
    fn without_anything_a_name_is_itself() {
        let w = wire_names(
            "user_name",
            MemberKind::Field,
            &SerdeAttrs::default(),
            &no_rules(),
        );
        assert_eq!(w.serialize, "user_name");
        assert_eq!(w.deserialize, "user_name");
        assert!(w.are_the_same());
    }

    #[test]
    fn a_raw_identifier_uses_its_logical_name() {
        let w = wire_names(
            "r#type",
            MemberKind::Field,
            &SerdeAttrs::default(),
            &no_rules(),
        );
        assert_eq!(w.serialize, "type");
        assert_eq!(w.deserialize, "type");
    }

    #[test]
    fn an_explicit_rename_wins_over_the_rule() {
        let member = member_attrs(r#"#[serde(rename = "custom")]"#);
        let w = wire_names(
            "user_name",
            MemberKind::Field,
            &member,
            &rules("camelCase", "camelCase"),
        );
        assert_eq!(
            w.serialize, "custom",
            "the member's own rename outranks the container's rule"
        );
        assert_eq!(w.deserialize, "custom");
    }

    #[test]
    fn the_rule_runs_on_the_rust_name() {
        let w = wire_names(
            "user_name",
            MemberKind::Field,
            &SerdeAttrs::default(),
            &rules("camelCase", "camelCase"),
        );
        assert_eq!(w.serialize, "userName");
        assert_eq!(w.deserialize, "userName");
    }

    /// The two directions are independent, and a rename that names only one of
    /// them leaves the other to the rule.
    #[test]
    fn a_one_sided_rename_does_not_leak_into_the_other_direction() {
        let member = member_attrs(r#"#[serde(rename(serialize = "outName"))]"#);
        let w = wire_names(
            "user_name",
            MemberKind::Field,
            &member,
            &rules("camelCase", "snake_case"),
        );
        assert_eq!(w.serialize, "outName");
        assert_eq!(
            w.deserialize, "user_name",
            "the deserialize direction falls to its own rule, not to the serialize name"
        );
    }

    #[test]
    fn the_two_directions_can_be_named_apart() {
        let member =
            member_attrs(r#"#[serde(rename(serialize = "outName", deserialize = "in_name"))]"#);
        let w = wire_names("value", MemberKind::Field, &member, &no_rules());
        assert_eq!(w.serialize, "outName");
        assert_eq!(w.deserialize, "in_name");
        assert!(!w.are_the_same());
    }

    /// The trap, at the level of a whole member: the same rule and the same
    /// name give different wire names depending only on the kind.
    #[test]
    fn a_variant_and_a_field_disagree_about_the_same_rule() {
        let field = wire_names(
            "WaitingForLogin",
            MemberKind::Field,
            &SerdeAttrs::default(),
            &rules("snake_case", "snake_case"),
        );
        let variant = wire_names(
            "WaitingForLogin",
            MemberKind::Variant,
            &SerdeAttrs::default(),
            &rules("snake_case", "snake_case"),
        );
        assert_eq!(field.serialize, "WaitingForLogin");
        assert_eq!(variant.serialize, "waiting_for_login");
    }

    #[test]
    fn a_variant_uses_the_variant_rule() {
        let w = wire_names(
            "WaitingForLogin",
            MemberKind::Variant,
            &SerdeAttrs::default(),
            &rules("kebab-case", "kebab-case"),
        );
        assert_eq!(w.serialize, "waiting-for-login");
    }

    #[test]
    fn a_variant_field_takes_the_variants_own_rule_first() {
        let container = rules("UPPERCASE", "UPPERCASE");
        let variant = member_attrs(r#"#[serde(rename_all = "camelCase")]"#);
        let chosen = variant_field_rules(&container, &variant).unwrap();
        assert_eq!(chosen.serialize, RenameRule::CamelCase);

        let w = wire_names(
            "user_name",
            MemberKind::Field,
            &SerdeAttrs::default(),
            &chosen,
        );
        assert_eq!(w.serialize, "userName");
    }

    #[test]
    fn a_variant_field_falls_back_to_rename_all_fields() {
        let container = rules("camelCase", "camelCase");
        let variant = SerdeAttrs::default();
        let chosen = variant_field_rules(&container, &variant).unwrap();
        assert_eq!(chosen.serialize, RenameRule::CamelCase);

        let w = wire_names(
            "user_name",
            MemberKind::Field,
            &SerdeAttrs::default(),
            &chosen,
        );
        assert_eq!(w.serialize, "userName");
    }

    /// A rule written as an unknown string is an error, not a silent identity:
    /// guessing at a rule means guessing at the wire format.
    #[test]
    fn an_unparseable_rule_is_an_error() {
        let directional = Directional::both("camel_case".to_string());
        assert!(RenameAllRules::from(&directional).is_err());
    }
}
