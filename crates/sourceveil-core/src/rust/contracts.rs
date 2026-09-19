//! Rust identifiers embedded in proc-macro attribute strings.
//!
//! Semantic rename APIs cannot edit string literals. Some attributes still use
//! identifier syntax inside those strings: `thiserror` format captures are the
//! common example. This pass handles only proven contracts. It requires a
//! `thiserror::Error` derive, an `#[error(...)]` attribute, a named capture, and
//! a renamed field with the generated spelling on that exact variant/struct.

use super::{bindings::format_names, candidates};
use crate::edits::{apply_indels, replace};
use anyhow::{Context, Result};
use ra_ap_ide::Indel;
use ra_ap_syntax::{
    ast::{self, AstNode, HasName},
    AstToken, Edition, SourceFile, SyntaxKind, SyntaxNode,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

#[derive(Debug, Default)]
pub struct Outcome {
    pub files_scanned: usize,
    pub files_edited: usize,
    pub captures_rewritten: usize,
}

pub fn rewrite_workspace(root: &Path, symbols: &BTreeMap<String, String>) -> Result<Outcome> {
    let names = unambiguous_leaf_names(symbols);
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
        let rewritten = apply_indels(&source, &edits).with_context(|| {
            format!(
                "rewriting Rust attribute contracts in {}",
                entry.path().display()
            )
        })?;
        std::fs::write(entry.path(), rewritten)
            .with_context(|| format!("writing {}", entry.path().display()))?;
        outcome.files_edited += 1;
        outcome.captures_rewritten += edits.len();
    }
    Ok(outcome)
}

fn unambiguous_leaf_names(symbols: &BTreeMap<String, String>) -> HashMap<String, String> {
    let mut names: HashMap<String, Option<String>> = HashMap::new();
    for (path, replacement) in symbols {
        let Some(leaf) = path.rsplit("::").next() else {
            continue;
        };
        if leaf.contains('@') {
            continue;
        }
        let original = leaf.strip_prefix("r#").unwrap_or(leaf).to_string();
        match names.entry(original) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(replacement.clone()));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().as_ref() != Some(replacement) {
                    entry.insert(None);
                }
            }
        }
    }
    names
        .into_iter()
        .filter_map(|(name, replacement)| replacement.map(|replacement| (name, replacement)))
        .collect()
}

fn contract_edits(source: &str, names: &HashMap<String, String>) -> Result<Vec<Indel>> {
    let parsed = SourceFile::parse(source, Edition::Edition2024).tree();
    let mut edits = Vec::new();
    for attr in parsed.syntax().descendants().filter_map(ast::Attr::cast) {
        if attr.path().is_none_or(|path| {
            path.syntax()
                .text()
                .to_string()
                .rsplit("::")
                .next()
                .is_none_or(|name| name.trim() != "error")
        }) || !is_thiserror_attribute(&attr, source)
        {
            continue;
        }
        let Some(owner) = attribute_owner(&attr) else {
            continue;
        };
        let current_fields: HashSet<String> = owner
            .descendants()
            .filter_map(ast::RecordField::cast)
            .filter_map(|field| field.name().map(|name| name.text().to_string()))
            .collect();
        if current_fields.is_empty() {
            continue;
        }
        let explicit_arguments = explicit_format_arguments(&attr);
        for string in attr
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .filter_map(ast::String::cast)
        {
            for (capture, range) in format_names(&string)? {
                if explicit_arguments.contains(&capture) {
                    continue;
                }
                let Some(replacement) = names.get(capture.trim_start_matches("r#")) else {
                    continue;
                };
                if current_fields.contains(replacement) {
                    edits.push(replace(
                        u32::from(range.start()),
                        u32::from(range.end()),
                        replacement.clone(),
                    ));
                }
            }
        }
    }
    edits.sort_by_key(|edit| (edit.delete.start(), edit.delete.end()));
    edits.dedup_by(|left, right| left.delete == right.delete && left.insert == right.insert);
    Ok(edits)
}

fn attribute_owner(attr: &ast::Attr) -> Option<SyntaxNode> {
    attr.syntax()
        .ancestors()
        .skip(1)
        .find(|node| matches!(node.kind(), SyntaxKind::VARIANT | SyntaxKind::STRUCT))
}

fn is_thiserror_attribute(attr: &ast::Attr, source: &str) -> bool {
    let Some(container) = attr
        .syntax()
        .ancestors()
        .skip(1)
        .find(|node| matches!(node.kind(), SyntaxKind::ENUM | SyntaxKind::STRUCT))
    else {
        return false;
    };
    let derives = candidates::derived_traits(&container);
    derives.iter().any(|derive| {
        matches!(
            derive.as_str(),
            "thiserror::Error" | "thiserror_derive::Error"
        ) || (derive == "Error"
            && source.lines().any(|line| {
                let compact = line.split_whitespace().collect::<String>();
                compact.starts_with("usethiserror::") && compact.contains("Error")
            }))
    })
}

fn explicit_format_arguments(attr: &ast::Attr) -> HashSet<String> {
    let tokens: Vec<_> = attr
        .syntax()
        .descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| !token.kind().is_trivia())
        .collect();
    tokens
        .windows(2)
        .filter(|pair| pair[0].kind() == SyntaxKind::IDENT && pair[1].kind() == SyntaxKind::EQ)
        .map(|pair| pair[0].text().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thiserror_named_field_captures_follow_the_field_rename() {
        let source = r#"
            use thiserror::Error;
            #[derive(Debug, Error)]
            enum AppError {
                #[error("API error: {code} - {message}; {{literal}}")]
                Api { code_hidden: i64, message_hidden: String },
            }
        "#;
        let names = HashMap::from([
            ("code".into(), "code_hidden".into()),
            ("message".into(), "message_hidden".into()),
            ("literal".into(), "must_not_move".into()),
        ]);
        let edits = contract_edits(source, &names).unwrap();
        let output = apply_indels(source, &edits).unwrap();
        assert_eq!(edits.len(), 2);
        assert!(output.contains("{code_hidden} - {message_hidden}"));
        assert!(output.contains("{{literal}}"));
    }

    #[test]
    fn explicit_format_arguments_and_unproven_error_attributes_are_untouched() {
        let source = r#"
            #[derive(Error)]
            enum Local {
                #[error("{label}", label = .0)]
                Item(String),
            }
        "#;
        let names = HashMap::from([("label".into(), "hidden".into())]);
        assert!(contract_edits(source, &names).unwrap().is_empty());
    }
}
