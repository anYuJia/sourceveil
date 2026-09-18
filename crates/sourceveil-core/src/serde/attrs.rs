//! Semantic parsing of `#[serde(...)]`.
//!
//! The attribute is where a wire contract is written down, so it has to be read
//! as syntax rather than as text. `contains("rename")` and `split(',')` look
//! like they work and do not:
//!
//! ```rust,ignore
//! #[serde(
//!     rename(serialize = "foo", deserialize = "bar"),
//!     alias = "baz",
//!     default,
//! )]
//! ```
//!
//! `syn` does the parsing, because nested meta is a solved problem and a
//! hand-rolled reader is a bug farm. It supplies no source positions here: this
//! module answers *what does the attribute mean*, and every edit is expressed
//! against offsets from `ra_ap_syntax`.
//!
//! ## Unknown keys are not ignored
//!
//! A key this module does not recognise is recorded rather than dropped. serde
//! adds attributes over time, and an unrecognised one might be exactly the
//! thing that decides a wire name. Guessing is not available, so the caller
//! keeps the member.

use std::fmt;

/// A value that serde lets you write once, or once per direction.
///
/// `#[serde(rename = "x")]` is shorthand for naming both directions the same;
/// `#[serde(rename(serialize = "a", deserialize = "b"))]` names them apart.
/// Collapsing the two into one string is how a wire format gets changed by
/// accident, so they are kept apart.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Directional<T> {
    pub serialize: Option<T>,
    pub deserialize: Option<T>,
}

impl<T: Clone> Directional<T> {
    /// The shorthand form, which sets both directions.
    pub fn both(value: T) -> Self {
        Self {
            serialize: Some(value.clone()),
            deserialize: Some(value),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.serialize.is_none() && self.deserialize.is_none()
    }
}

/// Everything `#[serde(...)]` can say, as far as this tool understands it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SerdeAttrs {
    pub rename: Directional<String>,
    pub rename_all: Directional<String>,
    pub rename_all_fields: Directional<String>,
    /// Deserialization-only compatibility names. Never rewritten.
    pub aliases: Vec<String>,

    pub tag: Option<String>,
    pub content: Option<String>,

    pub flatten: bool,
    pub transparent: bool,
    pub untagged: bool,
    pub other: bool,

    pub skip: bool,
    pub skip_serializing: bool,
    pub skip_deserializing: bool,

    pub default: bool,
    pub borrow: bool,

    pub remote: Option<String>,
    pub from: Option<String>,
    pub try_from: Option<String>,
    pub into: Option<String>,

    pub with: Option<String>,
    pub serialize_with: Option<String>,
    pub deserialize_with: Option<String>,

    /// Keys this module does not know. Their presence makes the member
    /// unsafe to rename, because an unrecognised key may decide a wire name.
    pub unknown: Vec<String>,
}

impl SerdeAttrs {
    pub fn is_empty(&self) -> bool {
        *self == SerdeAttrs::default()
    }

    /// Does the container force a representation this pass does not model?
    pub fn has_conversion(&self) -> bool {
        self.from.is_some() || self.try_from.is_some() || self.into.is_some()
    }

    /// Is any direction of this member skipped?
    pub fn is_skipped(&self) -> bool {
        self.skip || self.skip_serializing || self.skip_deserializing
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub reason: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "could not parse serde attribute: {}", self.reason)
    }
}

impl std::error::Error for ParseError {}

/// Parse one attribute, given as written: `#[serde(...)]`, `#[serde]`, or the
/// inner `serde(...)`.
///
/// Returns `Ok(None)` when the attribute is not a serde attribute at all.
pub fn parse(text: &str) -> Result<Option<SerdeAttrs>, ParseError> {
    let inner = strip_brackets(text);
    if inner.is_empty() {
        return Ok(None);
    }

    let meta: syn::Meta = syn::parse_str(inner).map_err(|e| ParseError {
        reason: e.to_string(),
    })?;

    let path = meta.path();
    if path.segments.last().map(|s| s.ident.to_string()) != Some("serde".to_string()) {
        return Ok(None);
    }

    let mut attrs = SerdeAttrs::default();
    match meta {
        // A bare `#[serde]` says nothing.
        syn::Meta::Path(_) => {}
        syn::Meta::List(list) => {
            let mut first_error: Option<ParseError> = None;
            // `parse_nested_meta` stops at the first error, so the first one is
            // the one worth reporting.
            let result = list.parse_nested_meta(|item| {
                if let Err(e) = read_item(&item, &mut attrs) {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                    return Err(item.error("unsupported serde metadata"));
                }
                Ok(())
            });
            if let Some(error) = first_error {
                return Err(error);
            }
            result.map_err(|e| ParseError {
                reason: e.to_string(),
            })?;
        }
        syn::Meta::NameValue(_) => {
            return Err(ParseError {
                reason: "`serde = ...` is not a form serde accepts".into(),
            })
        }
    }

    Ok(Some(attrs))
}

/// Read one key of a `#[serde(...)]` list.
fn read_item(
    item: &syn::meta::ParseNestedMeta<'_>,
    out: &mut SerdeAttrs,
) -> Result<(), ParseError> {
    let key = item
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default();

    // A value written as `key = "..."`, or a nested list as `key(...)`.
    let mut string_value = |item: &syn::meta::ParseNestedMeta<'_>| -> Result<String, ParseError> {
        item.value()
            .and_then(|v| v.parse::<syn::LitStr>())
            .map(|lit| lit.value())
            .map_err(|e| ParseError {
                reason: format!("{key} expects a string literal: {e}"),
            })
    };

    match key.as_str() {
        "rename" => out.rename = directional(item, &key, &mut string_value)?,
        "rename_all" => out.rename_all = directional(item, &key, &mut string_value)?,
        "rename_all_fields" => out.rename_all_fields = directional(item, &key, &mut string_value)?,
        "alias" => out.aliases.push(string_value(item)?),

        "tag" => out.tag = Some(string_value(item)?),
        "content" => out.content = Some(string_value(item)?),

        "flatten" => out.flatten = true,
        "transparent" => out.transparent = true,
        "untagged" => out.untagged = true,
        "other" => out.other = true,

        "skip" => out.skip = true,
        "skip_serializing" => out.skip_serializing = true,
        "skip_deserializing" => out.skip_deserializing = true,

        "default" => out.default = true,
        "borrow" => out.borrow = true,

        "remote" => out.remote = Some(string_value(item)?),
        "from" => out.from = Some(string_value(item)?),
        "try_from" => out.try_from = Some(string_value(item)?),
        "into" => out.into = Some(string_value(item)?),

        "with" => out.with = Some(string_value(item)?),
        "serialize_with" => out.serialize_with = Some(string_value(item)?),
        "deserialize_with" => out.deserialize_with = Some(string_value(item)?),

        // Recorded, not dropped: an unrecognised key may be the one that
        // decides a wire name, and the caller keeps the member because of it.
        //
        // Its value still has to be consumed, or the enclosing list parser
        // stops at the `=` and reports a syntax error that has nothing to do
        // with the real problem.
        _ => {
            if item.input.peek(syn::Token![=]) {
                let _ = string_value(item);
            } else if item.input.peek(syn::token::Paren) {
                let _ = item.parse_nested_meta(|_| Ok(()));
            }
            out.unknown.push(key);
        }
    }
    Ok(())
}

/// A `key = "x"` or `key(serialize = "a", deserialize = "b")` value.
fn directional(
    item: &syn::meta::ParseNestedMeta<'_>,
    key: &str,
    string_value: &mut impl FnMut(&syn::meta::ParseNestedMeta<'_>) -> Result<String, ParseError>,
) -> Result<Directional<String>, ParseError> {
    // `key = "x"` — the shorthand.
    if item.input.peek(syn::Token![=]) {
        let value = string_value(item)?;
        return Ok(Directional::both(value));
    }

    // `key(...)` — one or both directions named separately.
    let mut out = Directional::default();
    item.parse_nested_meta(|inner| {
        let side = inner
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let value = inner
            .value()
            .and_then(|v| v.parse::<syn::LitStr>())
            .map(|lit| lit.value())
            .map_err(|e| inner.error(format!("{key}.{side} expects a string literal: {e}")))?;
        match side.as_str() {
            "serialize" => out.serialize = Some(value),
            "deserialize" => out.deserialize = Some(value),
            _ => {
                return Err(inner.error(format!("{key} accepts only `serialize` and `deserialize`")))
            }
        }
        Ok(())
    })
    .map_err(|e| ParseError {
        reason: e.to_string(),
    })?;
    Ok(out)
}

/// `#[serde(...)]` -> `serde(...)`.
fn strip_brackets(text: &str) -> &str {
    text.trim()
        .trim_start_matches("#!")
        .trim_start_matches('#')
        .trim_start()
        .trim_start_matches('[')
        .trim_end()
        .trim_end_matches(']')
        .trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(text: &str) -> SerdeAttrs {
        parse(text).unwrap().unwrap_or_default()
    }

    #[test]
    fn a_plain_rename_sets_both_directions() {
        let a = attrs(r#"#[serde(rename = "foo")]"#);
        assert_eq!(a.rename.serialize.as_deref(), Some("foo"));
        assert_eq!(a.rename.deserialize.as_deref(), Some("foo"));
    }

    #[test]
    fn a_directional_rename_keeps_the_directions_apart() {
        let a = attrs(r#"#[serde(rename(serialize = "foo", deserialize = "bar"))]"#);
        assert_eq!(a.rename.serialize.as_deref(), Some("foo"));
        assert_eq!(a.rename.deserialize.as_deref(), Some("bar"));
    }

    #[test]
    fn a_half_directional_rename_is_kept_half_written() {
        let a = attrs(r#"#[serde(rename(serialize = "foo"))]"#);
        assert_eq!(a.rename.serialize.as_deref(), Some("foo"));
        assert_eq!(a.rename.deserialize, None);
    }

    #[test]
    fn rename_all_is_read_both_ways() {
        assert_eq!(
            attrs(r#"#[serde(rename_all = "camelCase")]"#)
                .rename_all
                .serialize
                .as_deref(),
            Some("camelCase")
        );
        let a =
            attrs(r#"#[serde(rename_all(serialize = "camelCase", deserialize = "snake_case"))]"#);
        assert_eq!(a.rename_all.serialize.as_deref(), Some("camelCase"));
        assert_eq!(a.rename_all.deserialize.as_deref(), Some("snake_case"));
    }

    #[test]
    fn rename_all_fields_is_read() {
        assert_eq!(
            attrs(r#"#[serde(rename_all_fields = "camelCase")]"#)
                .rename_all_fields
                .serialize
                .as_deref(),
            Some("camelCase")
        );
    }

    #[test]
    fn aliases_accumulate() {
        let a = attrs(r#"#[serde(alias = "old", alias = "legacy", rename = "current")]"#);
        assert_eq!(a.aliases, vec!["old", "legacy"]);
        assert_eq!(a.rename.serialize.as_deref(), Some("current"));
    }

    #[test]
    fn tagging_is_read() {
        let a = attrs(r#"#[serde(tag = "type", content = "data")]"#);
        assert_eq!(a.tag.as_deref(), Some("type"));
        assert_eq!(a.content.as_deref(), Some("data"));

        let a = attrs(r#"#[serde(tag = "kind")]"#);
        assert_eq!(a.tag.as_deref(), Some("kind"));
        assert_eq!(a.content, None);
    }

    #[test]
    fn flags_are_read() {
        let a = attrs("#[serde(flatten)]");
        assert!(a.flatten);

        let a = attrs("#[serde(transparent)]");
        assert!(a.transparent);

        let a = attrs("#[serde(untagged)]");
        assert!(a.untagged);

        let a = attrs("#[serde(other)]");
        assert!(a.other);

        let a = attrs("#[serde(default, borrow)]");
        assert!(a.default && a.borrow);
    }

    #[test]
    fn skip_is_distinguished_from_its_two_halves() {
        assert!(attrs("#[serde(skip)]").is_skipped());
        assert!(attrs("#[serde(skip_serializing)]").is_skipped());
        assert!(attrs("#[serde(skip_deserializing)]").is_skipped());

        let a = attrs("#[serde(skip_serializing)]");
        assert!(!a.skip, "the halves are recorded apart from the whole");
        assert!(a.skip_serializing);
        assert!(!a.skip_deserializing);
    }

    #[test]
    fn conversions_and_custom_serializers_are_read() {
        let a = attrs(r#"#[serde(remote = "ExternalType")]"#);
        assert_eq!(a.remote.as_deref(), Some("ExternalType"));

        let a = attrs(r#"#[serde(from = "Other", into = "Third")]"#);
        assert!(a.has_conversion());
        assert_eq!(a.from.as_deref(), Some("Other"));
        assert_eq!(a.into.as_deref(), Some("Third"));

        let a = attrs(r#"#[serde(try_from = "Other")]"#);
        assert!(a.has_conversion());

        let a = attrs(r#"#[serde(with = "module")]"#);
        assert_eq!(a.with.as_deref(), Some("module"));

        let a = attrs(r#"#[serde(serialize_with = "ser", deserialize_with = "de")]"#);
        assert_eq!(a.serialize_with.as_deref(), Some("ser"));
        assert_eq!(a.deserialize_with.as_deref(), Some("de"));
    }

    /// The shape that a text-matching parser gets wrong.
    #[test]
    fn multi_line_nested_metadata_is_read() {
        let a = attrs(
            r#"#[serde(
                rename(
                    serialize = "foo",
                    deserialize = "bar"
                ),
                alias = "baz",
                default
            )]"#,
        );
        assert_eq!(a.rename.serialize.as_deref(), Some("foo"));
        assert_eq!(a.rename.deserialize.as_deref(), Some("bar"));
        assert_eq!(a.aliases, vec!["baz"]);
        assert!(a.default);
    }

    /// `rename` inside a comment, or a string containing `rename`, must not be
    /// mistaken for the key.
    #[test]
    fn text_that_merely_mentions_a_key_is_not_a_key() {
        let a = attrs(r#"#[serde(alias = "rename = \"foo\"")]"#);
        assert_eq!(a.aliases, vec![r#"rename = "foo""#]);
        assert!(a.rename.is_empty(), "the alias value is data, not metadata");
    }

    #[test]
    fn an_unknown_key_is_recorded_rather_than_dropped() {
        let a = attrs(r#"#[serde(rename = "x", something_new = "y")]"#);
        assert_eq!(a.rename.serialize.as_deref(), Some("x"));
        assert_eq!(a.unknown, vec!["something_new"]);
    }

    #[test]
    fn a_non_serde_attribute_is_not_ours() {
        assert!(parse("#[derive(Serialize)]").unwrap().is_none());
        assert!(parse("#[no_mangle]").unwrap().is_none());
    }

    #[test]
    fn a_bare_serde_attribute_parses_as_empty() {
        let a = parse("#[serde]").unwrap().unwrap();
        assert!(a.is_empty());
    }

    #[test]
    fn malformed_metadata_is_an_error_not_a_guess() {
        assert!(parse(r#"#[serde(rename = )]"#).is_err());
        assert!(parse(r#"#[serde(rename(unknown = "x"))]"#).is_err());
        assert!(parse(r#"#[serde(rename_all = 7)]"#).is_err());
    }
}
