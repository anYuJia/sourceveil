//! serde-aware member rename.
//!
//! A serde field or variant is both a Rust identifier and a protocol value.
//! This pass owns those members. Under the safe profile it claims and keeps
//! them. Under balanced/aggressive it may rename the Rust identifier, but only
//! in the same transaction that materialises the pre-rename wire name with an
//! explicit #[serde(rename = "...")] attribute.
//!
//! Unsupported representations are claimed and kept. They never fall through
//! to the generic symbol pass.

use super::attrs::{Directional, SerdeAttrs};
use super::model::{self, MemberKind, RenameAllRules, WireNames};
use crate::config::Profile;
use crate::edits::{replace, Contribution, EditPlan};
use crate::mapping::Mapping;
use crate::names::{NameDeriver, SeedDomain};
use crate::plan::{Plan, INTRINSIC_KEEP_ATTRIBUTES};
use crate::report::{RenameStats, SkipReason, SkippedSymbol};
use crate::rust::analysis::RustAnalysis;
use crate::rust::candidates::{self, Candidate, FileContext, Visibility};
use crate::rust::rename::{
    crate_for_file, module_prefix_for, propose_rename, resolve_change_edits,
};
use crate::rust::ItemKind;
use crate::scanner::CrateGraph;
use anyhow::Result;
use ra_ap_ide::{FileId, Indel};
use ra_ap_syntax::ast::{self, AstNode, HasName};
use ra_ap_syntax::{SyntaxKind, SyntaxNode, TextRange};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

pub struct SerdeRenameRequest<'a> {
    pub input_root: &'a Path,
    pub copied: &'a BTreeSet<PathBuf>,
    pub plan: &'a Plan,
    pub graph: &'a CrateGraph,
    pub seed: u64,
}

#[derive(Debug, Default)]
pub struct SerdeRenameOutcome {
    pub stats: RenameStats,
    pub mapping: Mapping,
    pub skipped: Vec<SkippedSymbol>,
    pub warnings: Vec<String>,
    pub claimed: HashSet<(PathBuf, TextRange)>,
    pub files_edited: BTreeSet<PathBuf>,
}

struct MemberContext {
    node: SyntaxNode,
    wire: WireNames,
    needs_materialized_rename: bool,
}

pub fn run(
    analysis: &RustAnalysis,
    req: &SerdeRenameRequest<'_>,
    names: &mut NameDeriver,
    edits: &mut EditPlan,
    macro_referenced: &HashSet<String>,
) -> Result<SerdeRenameOutcome> {
    let mut outcome = SerdeRenameOutcome {
        mapping: Mapping::new(req.seed),
        ..Default::default()
    };

    let files = analysis.rust_files();
    let mut members: Vec<(FileId, Candidate)> = Vec::new();
    let mut texts: BTreeMap<PathBuf, String> = BTreeMap::new();

    for (file_id, path) in &files {
        let Some(krate) = crate_for_file(req.graph, path) else {
            continue;
        };
        let Some((parsed, text)) = analysis.parse(*file_id) else {
            continue;
        };

        let prefix = module_prefix_for(krate, path);
        let ctx = FileContext {
            path,
            text: &text,
            crate_name: &krate.name,
            module_prefix: &prefix,
        };
        members.extend(
            candidates::collect(&parsed, &ctx)
                .into_iter()
                .filter(|c| c.serde_model && matches!(c.kind, ItemKind::Field | ItemKind::Variant))
                .map(|c| (*file_id, c)),
        );
        texts.insert(path.clone(), text);
    }

    members.sort_by(|a, b| {
        a.1.file
            .cmp(&b.1.file)
            .then(a.1.name_range.start().cmp(&b.1.name_range.start()))
    });

    let keep_patterns = crate::copier::build_globset(&req.plan.keep.patterns)
        .unwrap_or_else(|_| globset::GlobSet::empty());
    let intrinsic: HashSet<&str> = INTRINSIC_KEEP_ATTRIBUTES.iter().copied().collect();
    let keep_attrs: HashSet<&str> = req
        .plan
        .keep
        .attributes
        .iter()
        .map(String::as_str)
        .collect();
    let keep_names: HashSet<&str> = req.plan.keep.symbols.iter().map(String::as_str).collect();

    for (file_id, candidate) in members {
        // Ownership is unconditional. Even when kept below, the member cannot
        // be reconsidered by the generic symbol pass.
        outcome
            .claimed
            .insert((candidate.file.clone(), candidate.name_range));

        if let Some((reason, detail)) = common_skip(
            &candidate,
            req,
            macro_referenced,
            &keep_patterns,
            &intrinsic,
            &keep_attrs,
            &keep_names,
        ) {
            outcome.skipped.push(skipped(&candidate, reason, detail));
            continue;
        }

        // Safe intentionally preserves serde members. Balanced is the first
        // profile that opts into materialising the wire contract.
        if !matches!(req.plan.profile, Profile::Balanced | Profile::Aggressive) {
            outcome
                .skipped
                .push(skipped(&candidate, SkipReason::SerdeModel, None));
            continue;
        }

        let Some((parsed, _)) = analysis.parse(file_id) else {
            outcome.skipped.push(skipped(
                &candidate,
                SkipReason::SerdeAttributeParseFailed,
                Some("could not reparse the defining file".into()),
            ));
            continue;
        };
        let Some(source) = texts.get(&candidate.file) else {
            outcome.skipped.push(skipped(
                &candidate,
                SkipReason::SerdeAttributeParseFailed,
                Some("no analysed source snapshot for the defining file".into()),
            ));
            continue;
        };

        let context = match member_context(&parsed, source, &candidate) {
            Ok(context) => context,
            Err(detail) => {
                outcome.skipped.push(skipped(
                    &candidate,
                    SkipReason::SerdeUnsupported,
                    Some(detail),
                ));
                continue;
            }
        };

        let new_name = names.derive(
            SeedDomain::RustSymbol,
            &candidate.path,
            candidate.kind.name_case(),
        )?;
        let change = match propose_rename(analysis, file_id, candidate.name_range, &new_name) {
            Ok(change) => change,
            Err((reason, detail)) => {
                outcome.skipped.push(skipped(&candidate, reason, detail));
                continue;
            }
        };
        let mut by_file = match resolve_change_edits(analysis, req.input_root, req.copied, &change)
        {
            Ok(edits) => edits,
            Err((reason, detail)) => {
                outcome.skipped.push(skipped(&candidate, reason, detail));
                continue;
            }
        };

        if !definition_present(&by_file, &candidate) {
            outcome.skipped.push(skipped(
                &candidate,
                SkipReason::Unresolvable,
                Some("rust-analyzer's edit set did not include the definition".into()),
            ));
            continue;
        }

        if context.needs_materialized_rename {
            if let Err(detail) = materialize_wire_name(
                &mut by_file,
                source,
                &candidate,
                &context.node,
                &context.wire,
                &new_name,
            ) {
                outcome.skipped.push(skipped(
                    &candidate,
                    SkipReason::SerdeUnsupported,
                    Some(detail),
                ));
                continue;
            }
        }

        let mut contributions = Vec::new();
        let mut missing_snapshot = None;
        for (path, indels) in &by_file {
            let Some(text) = texts.get(path) else {
                missing_snapshot = Some(path.clone());
                break;
            };
            contributions.push(Contribution::new(path, text, indels.clone()));
        }
        if let Some(path) = missing_snapshot {
            outcome.skipped.push(skipped(
                &candidate,
                SkipReason::EditOutsideOutput,
                Some(format!(
                    "no analysed source snapshot for {}",
                    path.display()
                )),
            ));
            continue;
        }

        match edits.stage_transaction(contributions) {
            Ok(applied) => {
                outcome.stats.bump(candidate.kind);
                outcome.stats.edits_applied += applied;
                outcome.files_edited.extend(by_file.keys().cloned());
                outcome.mapping.record_symbol(candidate.path, new_name);
            }
            Err(error) => outcome.skipped.push(skipped(
                &candidate,
                SkipReason::EditConflict,
                Some(error.to_string()),
            )),
        }
    }

    outcome.stats.files_edited = outcome.files_edited.len();
    Ok(outcome)
}

fn common_skip(
    candidate: &Candidate,
    req: &SerdeRenameRequest<'_>,
    macro_referenced: &HashSet<String>,
    keep_patterns: &globset::GlobSet,
    intrinsic: &HashSet<&str>,
    keep_attrs: &HashSet<&str>,
    keep_names: &HashSet<&str>,
) -> Option<(SkipReason, Option<String>)> {
    if !candidate.kind.enabled_in(&req.plan.rename) {
        return Some((SkipReason::KindDisabled, None));
    }
    if candidate.inline_keep {
        return Some((SkipReason::InlineKeepComment, None));
    }
    if keep_names.contains(candidate.name.as_str()) || keep_patterns.is_match(&candidate.name) {
        return Some((SkipReason::KeepRule, None));
    }
    if candidate.attributes.iter().any(|a| {
        // serde is owned by this pass, but an explicit user keep rule still
        // wins. Only the built-in protocol pin is bypassed here.
        keep_attrs.contains(a.as_str()) || (a != "serde" && intrinsic.contains(a.as_str()))
    }) {
        return Some((SkipReason::IntrinsicAttribute, None));
    }
    if candidate.visibility == Visibility::Public {
        if let Some(krate) = crate_for_file(req.graph, &candidate.file) {
            if krate.has_external_consumers(req.graph) || krate.is_proc_macro {
                return Some((SkipReason::ExternallyReachable, None));
            }
        }
    }
    if macro_referenced.contains(&candidate.name) {
        return Some((SkipReason::MacroCallReference, None));
    }
    None
}

fn member_context(
    parsed: &ast::SourceFile,
    source: &str,
    candidate: &Candidate,
) -> std::result::Result<MemberContext, String> {
    let node = find_member_node(parsed, candidate)
        .ok_or_else(|| "could not locate the member syntax node".to_string())?;

    let container = node
        .ancestors()
        .skip(1)
        .find(|n| {
            matches!(
                n.kind(),
                SyntaxKind::STRUCT | SyntaxKind::ENUM | SyntaxKind::UNION
            )
        })
        .ok_or_else(|| "serde member has no aggregate container".to_string())?;

    if container.kind() == SyntaxKind::UNION {
        return Err("serde union members are kept".into());
    }
    if !definitely_serde_container(&container, source) {
        return Err("Serialize/Deserialize derive could not be proven to come from serde".into());
    }

    let container_attrs =
        parse_attrs(&container).map_err(|e| format!("container attribute: {e}"))?;
    if let Some(reason) = unsupported_container(&container_attrs) {
        return Err(reason.into());
    }

    let member_attrs = parse_attrs(&node).map_err(|e| format!("member attribute: {e}"))?;
    if let Some(reason) = unsupported_member(&member_attrs) {
        return Err(reason.into());
    }

    // A one-sided explicit rename needs an edit inside the existing nested
    // metadata rather than a second ambiguous rename declaration. Keep it
    // until that exact edit is implemented.
    if member_attrs.rename.serialize.is_some() != member_attrs.rename.deserialize.is_some() {
        return Err("one-sided serde rename is kept".into());
    }

    let rules = match candidate.kind {
        ItemKind::Variant => {
            RenameAllRules::from(&container_attrs.rename_all).map_err(|e| e.to_string())?
        }
        ItemKind::Field => {
            let variant = node
                .ancestors()
                .skip(1)
                .find(|n| n.kind() == SyntaxKind::VARIANT);
            if let Some(variant) = variant {
                let variant_attrs =
                    parse_attrs(&variant).map_err(|e| format!("variant attribute: {e}"))?;
                if let Some(reason) = unsupported_member(&variant_attrs) {
                    return Err(reason.into());
                }
                let container_fields = RenameAllRules::from(&container_attrs.rename_all_fields)
                    .map_err(|e| e.to_string())?;
                model::variant_field_rules(&container_fields, &variant_attrs)
                    .map_err(|e| e.to_string())?
            } else {
                RenameAllRules::from(&container_attrs.rename_all).map_err(|e| e.to_string())?
            }
        }
        _ => return Err("not a serde field or variant".into()),
    };

    let kind = if candidate.kind == ItemKind::Field {
        MemberKind::Field
    } else {
        MemberKind::Variant
    };
    let wire = model::wire_names(&candidate.name, kind, &member_attrs, &rules);
    let needs_materialized_rename =
        member_attrs.rename.serialize.is_none() && member_attrs.rename.deserialize.is_none();

    Ok(MemberContext {
        node,
        wire,
        needs_materialized_rename,
    })
}

fn definitely_serde_container(node: &SyntaxNode, source: &str) -> bool {
    let traits = candidates::derived_traits(node);
    let mut bare = false;
    for trait_name in traits {
        match trait_name.as_str() {
            "serde::Serialize"
            | "serde::Deserialize"
            | "serde_derive::Serialize"
            | "serde_derive::Deserialize" => return true,
            "Serialize" | "Deserialize" => bare = true,
            _ => {}
        }
    }
    if !bare {
        return false;
    }

    // Conservative proof for the ordinary import forms. A project-local trait
    // merely called Serialize is intentionally not transformed.
    source.lines().any(|line| {
        let line = line.trim();
        line.starts_with("use serde")
            && (line.contains("Serialize") || line.contains("Deserialize"))
    })
}

fn unsupported_container(attrs: &SerdeAttrs) -> Option<&'static str> {
    if !attrs.unknown.is_empty() {
        return Some("unknown serde container metadata");
    }
    if attrs.remote.is_some() {
        return Some("serde remote container");
    }
    if attrs.transparent {
        return Some("serde transparent container");
    }
    if attrs.untagged {
        return Some("serde untagged enum");
    }
    if attrs.has_conversion() {
        return Some("serde conversion container");
    }
    None
}

fn unsupported_member(attrs: &SerdeAttrs) -> Option<&'static str> {
    if !attrs.unknown.is_empty() {
        return Some("unknown serde member metadata");
    }
    if attrs.flatten {
        return Some("serde flatten member");
    }
    if attrs.other {
        return Some("serde other variant");
    }
    if attrs.is_skipped() {
        return Some("serde skipped member");
    }
    None
}

fn find_member_node(parsed: &ast::SourceFile, candidate: &Candidate) -> Option<SyntaxNode> {
    parsed
        .syntax()
        .descendants()
        .find(|node| match candidate.kind {
            ItemKind::Field => ast::RecordField::cast(node.clone())
                .and_then(|field| field.name())
                .map(|name| name.syntax().text_range() == candidate.name_range)
                .unwrap_or(false),
            ItemKind::Variant => ast::Variant::cast(node.clone())
                .and_then(|variant| variant.name())
                .map(|name| name.syntax().text_range() == candidate.name_range)
                .unwrap_or(false),
            _ => false,
        })
}

fn parse_attrs(node: &SyntaxNode) -> std::result::Result<SerdeAttrs, String> {
    let mut out = SerdeAttrs::default();
    for attr in node.children().filter_map(ast::Attr::cast) {
        let text = attr.syntax().text().to_string();
        let Some(next) = super::attrs::parse(&text).map_err(|e| e.to_string())? else {
            continue;
        };
        merge_attrs(&mut out, next)?;
    }
    Ok(out)
}

fn merge_attrs(dst: &mut SerdeAttrs, src: SerdeAttrs) -> std::result::Result<(), String> {
    merge_directional(&mut dst.rename, src.rename, "rename")?;
    merge_directional(&mut dst.rename_all, src.rename_all, "rename_all")?;
    merge_directional(
        &mut dst.rename_all_fields,
        src.rename_all_fields,
        "rename_all_fields",
    )?;
    dst.aliases.extend(src.aliases);

    merge_option(&mut dst.tag, src.tag, "tag")?;
    merge_option(&mut dst.content, src.content, "content")?;
    merge_option(&mut dst.remote, src.remote, "remote")?;
    merge_option(&mut dst.from, src.from, "from")?;
    merge_option(&mut dst.try_from, src.try_from, "try_from")?;
    merge_option(&mut dst.into, src.into, "into")?;
    merge_option(&mut dst.with, src.with, "with")?;
    merge_option(
        &mut dst.serialize_with,
        src.serialize_with,
        "serialize_with",
    )?;
    merge_option(
        &mut dst.deserialize_with,
        src.deserialize_with,
        "deserialize_with",
    )?;

    dst.flatten |= src.flatten;
    dst.transparent |= src.transparent;
    dst.untagged |= src.untagged;
    dst.other |= src.other;
    dst.skip |= src.skip;
    dst.skip_serializing |= src.skip_serializing;
    dst.skip_deserializing |= src.skip_deserializing;
    dst.default |= src.default;
    dst.borrow |= src.borrow;
    dst.unknown.extend(src.unknown);
    Ok(())
}

fn merge_directional<T>(
    dst: &mut Directional<T>,
    src: Directional<T>,
    label: &str,
) -> std::result::Result<(), String> {
    if src.serialize.is_some() {
        if dst.serialize.is_some() {
            return Err(format!("duplicate serde {label}.serialize"));
        }
        dst.serialize = src.serialize;
    }
    if src.deserialize.is_some() {
        if dst.deserialize.is_some() {
            return Err(format!("duplicate serde {label}.deserialize"));
        }
        dst.deserialize = src.deserialize;
    }
    Ok(())
}

fn merge_option<T>(
    dst: &mut Option<T>,
    src: Option<T>,
    label: &str,
) -> std::result::Result<(), String> {
    if let Some(value) = src {
        if dst.is_some() {
            return Err(format!("duplicate serde {label}"));
        }
        *dst = Some(value);
    }
    Ok(())
}

fn definition_present(by_file: &BTreeMap<PathBuf, Vec<Indel>>, candidate: &Candidate) -> bool {
    by_file
        .get(&candidate.file)
        .map(|indels| {
            indels
                .iter()
                .any(|indel| indel.delete.contains_range(candidate.name_range))
        })
        .unwrap_or(false)
}

fn materialize_wire_name(
    by_file: &mut BTreeMap<PathBuf, Vec<Indel>>,
    source: &str,
    candidate: &Candidate,
    node: &SyntaxNode,
    wire: &WireNames,
    new_name: &str,
) -> std::result::Result<(), String> {
    let member_start = usize::from(node.text_range().start());
    let name_start = usize::from(candidate.name_range.start());
    let name_end = usize::from(candidate.name_range.end());
    if member_start > name_start || name_end > source.len() {
        return Err("invalid member/name ranges".into());
    }

    let def_edits = by_file
        .get_mut(&candidate.file)
        .ok_or_else(|| "definition file missing from rust-analyzer edit set".to_string())?;
    let positions: Vec<usize> = def_edits
        .iter()
        .enumerate()
        .filter_map(|(index, edit)| {
            edit.delete
                .contains_range(candidate.name_range)
                .then_some(index)
        })
        .collect();
    if positions.len() != 1 {
        return Err(format!(
            "expected one definition edit, found {}",
            positions.len()
        ));
    }
    def_edits.remove(positions[0]);

    let line_start = source[..member_start]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let before_member = &source[line_start..member_start];
    let indent = before_member
        .chars()
        .all(|c| c == ' ' || c == '\t')
        .then_some(before_member)
        .unwrap_or("");
    let prefix = &source[member_start..name_start];

    let attr = serde_rename_attribute(wire);
    let replacement = format!("{attr}\n{indent}{prefix}{new_name}");
    def_edits.push(replace(
        u32::from(node.text_range().start()),
        u32::from(candidate.name_range.end()),
        replacement,
    ));
    Ok(())
}

fn serde_rename_attribute(wire: &WireNames) -> String {
    let serialize = format!("{:?}", wire.serialize);
    let deserialize = format!("{:?}", wire.deserialize);
    if wire.are_the_same() {
        format!("#[serde(rename = {serialize})]")
    } else {
        format!("#[serde(rename(serialize = {serialize}, deserialize = {deserialize}))]")
    }
}

fn skipped(candidate: &Candidate, reason: SkipReason, detail: Option<String>) -> SkippedSymbol {
    SkippedSymbol {
        name: candidate.name.clone(),
        symbol_path: candidate.path.clone(),
        file: candidate.file.display().to_string(),
        line: candidate.line,
        reason,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn materialized_name_uses_one_value_when_both_directions_match() {
        let wire = WireNames {
            serialize: "userName".into(),
            deserialize: "userName".into(),
        };
        assert_eq!(
            serde_rename_attribute(&wire),
            "#[serde(rename = \"userName\")]"
        );
    }

    #[test]
    fn materialized_name_keeps_directions_apart() {
        let wire = WireNames {
            serialize: "outName".into(),
            deserialize: "in_name".into(),
        };
        assert_eq!(
            serde_rename_attribute(&wire),
            "#[serde(rename(serialize = \"outName\", deserialize = \"in_name\"))]"
        );
    }
}
