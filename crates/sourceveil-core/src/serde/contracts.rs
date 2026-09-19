//! Rewrite Rust paths embedded in serde string metadata after semantic rename.
//!
//! Serde accepts several Rust paths as strings (`remote`, `default`, `with`,
//! `serialize_with`, ...). rust-analyzer correctly renames the definitions but
//! cannot edit inside a string literal. This pass runs after the semantic edit
//! transaction, parses only `#[serde(...)]` attributes, and rewrites only
//! metadata keys whose grammar is a Rust path. Wire names such as `rename`,
//! `alias`, `tag`, and `content` are deliberately outside the key set.

use crate::edits::apply_indels;
use anyhow::{Context, Result};
use ra_ap_ide::Indel;
use ra_ap_syntax::{
    ast::{self, AstNode, AstToken, IsString},
    Edition, SourceFile, SyntaxKind, SyntaxToken, TextRange,
};
use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
};

const PATH_KEYS: &[&str] = &[
    "bound",
    "crate",
    "default",
    "deserialize_with",
    "from",
    "getter",
    "into",
    "remote",
    "serialize_with",
    "skip_serializing_if",
    "try_from",
];

#[derive(Debug, Default)]
pub struct Outcome {
    pub files_scanned: usize,
    pub files_edited: usize,
    pub paths_rewritten: usize,
}

pub fn rewrite_workspace(root: &Path, symbols: &BTreeMap<String, String>) -> Result<Outcome> {
    let names = leaf_mapping(symbols)?;
    if names.is_empty() {
        return Ok(Outcome::default());
    }

    let mut outcome = Outcome::default();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| {
            entry.depth() == 0
                || !entry.file_type().is_dir()
                || !matches!(
                    entry.file_name().to_str(),
                    Some("target" | "node_modules" | ".git" | ".obfuscator")
                )
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "rs")
        {
            continue;
        }
        outcome.files_scanned += 1;
        let source = std::fs::read_to_string(entry.path())
            .with_context(|| format!("reading {}", entry.path().display()))?;
        let edits = contract_edits(&source, &names)?;
        if edits.is_empty() {
            continue;
        }
        let rewritten = apply_indels(&source, &edits)
            .with_context(|| format!("rewriting serde paths in {}", entry.path().display()))?;
        std::fs::write(entry.path(), rewritten)
            .with_context(|| format!("writing {}", entry.path().display()))?;
        outcome.files_edited += 1;
        outcome.paths_rewritten += edits.len();
    }
    Ok(outcome)
}

fn leaf_mapping(symbols: &BTreeMap<String, String>) -> Result<HashMap<String, String>> {
    let mut names = HashMap::new();
    for (path, replacement) in symbols {
        let Some(leaf) = path.rsplit("::").next() else {
            continue;
        };
        // Lexical binding identities carry `name@offset`; serde metadata can
        // only name items, so they are not part of this dictionary.
        if leaf.contains('@') {
            continue;
        }
        let logical = leaf.strip_prefix("r#").unwrap_or(leaf);
        if let Some(existing) = names.insert(logical.to_string(), replacement.clone()) {
            if existing != *replacement {
                anyhow::bail!(
                    "serde path segment `{logical}` has two generated spellings: \
                     `{existing}` and `{replacement}`"
                );
            }
        }
    }
    Ok(names)
}

fn contract_edits(source: &str, names: &HashMap<String, String>) -> Result<Vec<Indel>> {
    let parsed = SourceFile::parse(source, Edition::Edition2024).tree();
    let mut edits = Vec::new();

    for attr in parsed.syntax().descendants().filter_map(ast::Attr::cast) {
        if attr
            .path()
            .is_none_or(|path| path.syntax().text().to_string().replace(' ', "") != "serde")
        {
            continue;
        }
        let attr_range = attr.syntax().text_range();
        for token in attr
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
        {
            let Some(string) = ast::String::cast(token.clone()) else {
                continue;
            };
            let Some(key_token) = metadata_key(&token, attr_range) else {
                continue;
            };
            let key = key_token.text();
            let value = string.text_without_quotes();
            if key == "with" {
                let module = rewrite_rust_path(value, names);
                let serialize = names
                    .get("serialize")
                    .map(String::as_str)
                    .unwrap_or("serialize");
                let deserialize = names
                    .get("deserialize")
                    .map(String::as_str)
                    .unwrap_or("deserialize");
                if module != value || serialize != "serialize" || deserialize != "deserialize" {
                    let delete =
                        TextRange::new(key_token.text_range().start(), token.text_range().end());
                    edits.push(Indel {
                        delete,
                        insert: format!(
                            "serialize_with = {:?}, deserialize_with = {:?}",
                            format!("{module}::{serialize}"),
                            format!("{module}::{deserialize}")
                        ),
                    });
                }
                continue;
            }
            let path_metadata = PATH_KEYS.contains(&key)
                || (matches!(key, "serialize" | "deserialize")
                    && enclosing_metadata_key(&key_token, attr_range).as_deref() == Some("bound"));
            if !path_metadata {
                continue;
            }
            let rewritten = rewrite_rust_path(value, names);
            if rewritten == value {
                continue;
            }
            let Some(contents) = string.text_range_between_quotes() else {
                continue;
            };
            edits.push(Indel {
                delete: contents,
                insert: rewritten,
            });
        }
    }

    edits.sort_by_key(|edit| (edit.delete.start(), edit.delete.end()));
    edits.dedup_by(|left, right| left.delete == right.delete && left.insert == right.insert);
    Ok(edits)
}

fn metadata_key(token: &SyntaxToken, attr_range: TextRange) -> Option<SyntaxToken> {
    let equals = previous_non_trivia(token.prev_token()?, attr_range)?;
    if equals.kind() != SyntaxKind::EQ {
        return None;
    }
    let key = previous_non_trivia(equals.prev_token()?, attr_range)?;
    Some(key)
}

/// For a directional value such as
/// `bound(serialize = "T: Trait", deserialize = "T: Other")`, return the
/// key that owns the parenthesized list. Wire-name metadata uses the same
/// `serialize`/`deserialize` words, so the parent key is required before a
/// string can be treated as Rust syntax.
fn enclosing_metadata_key(token: &SyntaxToken, attr_range: TextRange) -> Option<String> {
    let mut current = token.prev_token()?;
    let mut depth = 0usize;
    loop {
        if !attr_range.contains_range(current.text_range()) {
            return None;
        }
        if !current.kind().is_trivia() {
            match current.kind() {
                SyntaxKind::R_PAREN => depth += 1,
                SyntaxKind::L_PAREN if depth == 0 => {
                    return previous_non_trivia(current.prev_token()?, attr_range)
                        .map(|owner| owner.text().to_string());
                }
                SyntaxKind::L_PAREN => depth -= 1,
                _ => {}
            }
        }
        current = current.prev_token()?;
    }
}

fn previous_non_trivia(mut token: SyntaxToken, within: TextRange) -> Option<SyntaxToken> {
    loop {
        if !within.contains_range(token.text_range()) {
            return None;
        }
        if !token.kind().is_trivia() {
            return Some(token);
        }
        token = token.prev_token()?;
    }
}

fn rewrite_rust_path(value: &str, names: &HashMap<String, String>) -> String {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let raw = cursor + 2 < bytes.len()
            && bytes[cursor] == b'r'
            && bytes[cursor + 1] == b'#'
            && (bytes[cursor + 2].is_ascii_alphabetic() || bytes[cursor + 2] == b'_');
        let start = if raw { cursor + 2 } else { cursor };
        if !(bytes[start].is_ascii_alphabetic() || bytes[start] == b'_') {
            output.push(bytes[cursor] as char);
            cursor += 1;
            continue;
        }
        let mut end = start + 1;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let name = &value[start..end];
        if let Some(replacement) = names.get(name) {
            output.push_str(replacement);
        } else {
            output.push_str(&value[cursor..end]);
        }
        cursor = end;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_rust_path_metadata_moves() {
        let names = HashMap::from([
            ("helper".into(), "x7helper".into()),
            ("Model".into(), "Q9model".into()),
        ]);
        let source = r#"
            #[serde(rename = "Model", alias = "helper", remote = "helper::Model")]
            struct Wire;
        "#;
        let edits = contract_edits(source, &names).unwrap();
        let output = apply_indels(source, &edits).unwrap();
        assert!(output.contains("rename = \"Model\""));
        assert!(output.contains("alias = \"helper\""));
        assert!(output.contains("remote = \"x7helper::Q9model\""));
    }

    #[test]
    fn with_expands_to_the_two_renamed_helpers() {
        let names = HashMap::from([
            ("hex_u32".into(), "m7hex".into()),
            ("serialize".into(), "s8write".into()),
            ("deserialize".into(), "d9read".into()),
        ]);
        let source = r#"struct X { #[serde(with = "hex_u32")] value: u32 }"#;
        let output = apply_indels(source, &contract_edits(source, &names).unwrap()).unwrap();
        assert!(output.contains("serialize_with = \"m7hex::s8write\""));
        assert!(output.contains("deserialize_with = \"m7hex::d9read\""));
        assert!(!output.contains("#[serde(with ="));
    }

    #[test]
    fn every_rust_bearing_official_metadata_form_is_rewritten() {
        let names = HashMap::from([
            ("make_default".into(), "d7make".into()),
            ("predicate".into(), "p8check".into()),
            ("Model".into(), "Q9model".into()),
            ("Trait".into(), "T6trait".into()),
            ("Remote".into(), "R5remote".into()),
            ("getter".into(), "g4read".into()),
        ]);
        let source = r#"
            #[serde(bound(
                serialize = "Model: Trait",
                deserialize = "Model: Trait"
            ))]
            struct X {
                #[serde(
                    default = "make_default",
                    skip_serializing_if = "predicate",
                    getter = "Remote::getter"
                )]
                value: Model,
            }
        "#;
        let output = apply_indels(source, &contract_edits(source, &names).unwrap()).unwrap();
        assert!(output.contains("serialize = \"Q9model: T6trait\""));
        assert!(output.contains("deserialize = \"Q9model: T6trait\""));
        assert!(output.contains("default = \"d7make\""));
        assert!(output.contains("skip_serializing_if = \"p8check\""));
        assert!(output.contains("getter = \"R5remote::g4read\""));
    }
}
