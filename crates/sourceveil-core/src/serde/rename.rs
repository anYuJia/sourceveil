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
    crate_for_file, module_prefix_for, propose_rename, reconcile_resolved_edits,
    remove_already_staged_exact_edits, resolve_change_edits,
};
use crate::rust::ItemKind;
use crate::scanner::{is_root_like, CrateGraph};
use anyhow::Result;
use ra_ap_ide::{FileId, Indel};
use ra_ap_syntax::ast::{self, AstNode, HasName};
use ra_ap_syntax::{SyntaxKind, SyntaxNode, TextRange};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

pub struct SerdeRenameRequest<'a> {
    pub input_root: &'a Path,
    pub copied: &'a BTreeSet<PathBuf>,
    pub plan: &'a Plan,
    pub graph: &'a CrateGraph,
    pub seed: u64,
    pub allow_unresolved_macro_references: bool,
}

#[derive(Debug, Default)]
pub struct SerdeRenameOutcome {
    pub stats: RenameStats,
    pub mapping: Mapping,
    /// Wire values that remain part of the serialized protocol after a
    /// successful Rust-side rename. The later string pass must reserve these:
    /// some values are materialized by this pass and therefore do not exist in
    /// the immutable analysis snapshot inspected by string protection.
    pub wire_values: HashSet<String>,
    pub skipped: Vec<SkippedSymbol>,
    pub warnings: Vec<String>,
    pub claimed: HashSet<(PathBuf, TextRange)>,
    pub files_edited: BTreeSet<PathBuf>,
}

struct MemberContext {
    node: SyntaxNode,
    wire: WireNames,
    materialize: WireDirections,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WireDirections {
    serialize: bool,
    deserialize: bool,
}

impl WireDirections {
    fn is_empty(self) -> bool {
        !self.serialize && !self.deserialize
    }
}

pub fn run(
    analysis: &RustAnalysis,
    req: &SerdeRenameRequest<'_>,
    names: &mut NameDeriver,
    edits: &mut EditPlan,
    macro_referenced: &HashSet<String>,
    macro_references: &HashMap<(PathBuf, TextRange), Vec<(PathBuf, TextRange)>>,
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
        let collected = candidates::collect(&parsed, &ctx);
        members.extend(
            collected
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

        // Even a member that must remain unchanged still contributes an
        // implicit serde wire value. Reserve the Rust spelling immediately;
        // unsupported/duplicate models may never reach `member_context`, but
        // derive-generated names can still be emitted into the final binary.
        outcome.wire_values.insert(candidate.name.clone());

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

        let name_case = candidate.kind.name_case();
        let identity = format!("rust-name::{name_case:?}::{}", candidate.name);
        let new_name = names.derive(SeedDomain::RustSymbol, &identity, name_case)?;
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

        reconcile_resolved_edits(
            &mut by_file,
            &candidate,
            macro_references.get(&(candidate.file.clone(), candidate.name_range)),
            &new_name,
            &texts,
        );

        if !definition_present(&by_file, &candidate) {
            outcome.skipped.push(skipped(
                &candidate,
                SkipReason::Unresolvable,
                Some("rust-analyzer's edit set did not include the definition".into()),
            ));
            continue;
        }

        if !context.materialize.is_empty() {
            if let Err(detail) = materialize_wire_name(
                &mut by_file,
                source,
                &candidate,
                &context.node,
                &context.wire,
                context.materialize,
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

        remove_already_staged_exact_edits(&mut by_file, edits);

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
                record_wire_values(&mut outcome.wire_values, &context.wire);
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

fn record_wire_values(values: &mut HashSet<String>, wire: &WireNames) {
    values.insert(wire.serialize.clone());
    values.insert(wire.deserialize.clone());
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
    if let Some(krate) = crate_for_file(req.graph, &candidate.file) {
        if !is_root_like(req.graph, &krate.name) {
            match req.plan.dependencies.mode_for(&krate.name) {
                crate::config::DependencyMode::External
                | crate::config::DependencyMode::Wrapper => {
                    return Some((SkipReason::DependencyExternal, None));
                }
                crate::config::DependencyMode::PrivateObfuscate
                    if candidate.visibility == Visibility::Public =>
                {
                    return Some((SkipReason::ExternallyReachable, None));
                }
                crate::config::DependencyMode::PrivateObfuscate
                | crate::config::DependencyMode::Obfuscate => {}
            }
        }
        if candidate.visibility == Visibility::Public
            && (krate.has_external_consumers(req.graph) || krate.is_proc_macro)
        {
            return Some((SkipReason::ExternallyReachable, None));
        }
    }
    if !req.allow_unresolved_macro_references && macro_referenced.contains(&candidate.name) {
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
    let mut materialize = WireDirections {
        serialize: member_attrs.rename.serialize.is_none(),
        deserialize: member_attrs.rename.deserialize.is_none(),
    };

    // These representations do not use this member's Rust spelling as a wire
    // key in the indicated direction. Renaming the Rust member is therefore
    // safe without manufacturing an attribute that would change semantics.
    if member_attrs.flatten || member_attrs.other || member_attrs.skip {
        materialize = WireDirections::default();
    } else {
        if member_attrs.skip_serializing {
            materialize.serialize = false;
        }
        if member_attrs.skip_deserializing {
            materialize.deserialize = false;
        }
        if candidate.kind == ItemKind::Field && container_attrs.transparent {
            materialize = WireDirections::default();
        }
        if candidate.kind == ItemKind::Variant && container_attrs.untagged {
            materialize = WireDirections::default();
        }
        if container_attrs.into.is_some() {
            materialize.serialize = false;
        }
        if container_attrs.from.is_some() || container_attrs.try_from.is_some() {
            materialize.deserialize = false;
        }
    }

    Ok(MemberContext {
        node,
        wire,
        materialize,
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
    None
}

fn unsupported_member(attrs: &SerdeAttrs) -> Option<&'static str> {
    if !attrs.unknown.is_empty() {
        return Some("unknown serde member metadata");
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
    merge_directional(&mut dst.bound, src.bound, "bound")?;
    dst.aliases.extend(src.aliases);

    merge_option(&mut dst.tag, src.tag, "tag")?;
    merge_option(&mut dst.content, src.content, "content")?;
    merge_option(&mut dst.remote, src.remote, "remote")?;
    merge_option(&mut dst.from, src.from, "from")?;
    merge_option(&mut dst.try_from, src.try_from, "try_from")?;
    merge_option(&mut dst.into, src.into, "into")?;
    merge_option(&mut dst.with, src.with, "with")?;
    merge_option(
        &mut dst.skip_serializing_if,
        src.skip_serializing_if,
        "skip_serializing_if",
    )?;
    merge_option(&mut dst.default_path, src.default_path, "default")?;
    merge_option(&mut dst.borrow_lifetimes, src.borrow_lifetimes, "borrow")?;
    merge_option(&mut dst.getter, src.getter, "getter")?;
    merge_option(&mut dst.crate_path, src.crate_path, "crate")?;
    merge_option(&mut dst.expecting, src.expecting, "expecting")?;
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
    dst.deny_unknown_fields |= src.deny_unknown_fields;
    dst.field_identifier |= src.field_identifier;
    dst.variant_identifier |= src.variant_identifier;
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
    directions: WireDirections,
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
    let indent = if before_member.chars().all(|c| c == ' ' || c == '\t') {
        before_member
    } else {
        ""
    };
    let prefix = &source[member_start..name_start];

    let attr = serde_rename_attribute(wire, directions);
    let replacement = format!("{attr}\n{indent}{prefix}{new_name}");
    def_edits.push(replace(
        u32::from(node.text_range().start()),
        u32::from(candidate.name_range.end()),
        replacement,
    ));
    Ok(())
}

fn serde_rename_attribute(wire: &WireNames, directions: WireDirections) -> String {
    let serialize = format!("{:?}", wire.serialize);
    let deserialize = format!("{:?}", wire.deserialize);
    if directions.serialize && directions.deserialize && wire.are_the_same() {
        format!("#[serde(rename = {serialize})]")
    } else if directions.serialize && directions.deserialize {
        format!("#[serde(rename(serialize = {serialize}, deserialize = {deserialize}))]")
    } else if directions.serialize {
        format!("#[serde(rename(serialize = {serialize}))]")
    } else {
        debug_assert!(directions.deserialize);
        format!("#[serde(rename(deserialize = {deserialize}))]")
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
            serde_rename_attribute(
                &wire,
                WireDirections {
                    serialize: true,
                    deserialize: true,
                }
            ),
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
            serde_rename_attribute(
                &wire,
                WireDirections {
                    serialize: true,
                    deserialize: true,
                }
            ),
            "#[serde(rename(serialize = \"outName\", deserialize = \"in_name\"))]"
        );
    }

    #[test]
    fn one_sided_materialization_only_adds_the_missing_contract() {
        let wire = WireNames {
            serialize: "already_explicit".into(),
            deserialize: "legacy_input".into(),
        };
        assert_eq!(
            serde_rename_attribute(
                &wire,
                WireDirections {
                    serialize: false,
                    deserialize: true,
                }
            ),
            "#[serde(rename(deserialize = \"legacy_input\"))]"
        );
    }

    #[test]
    fn successful_serde_rename_reserves_both_wire_directions() {
        let wire = WireNames {
            serialize: "outName".into(),
            deserialize: "in_name".into(),
        };
        let mut values = HashSet::new();
        record_wire_values(&mut values, &wire);
        assert_eq!(values, HashSet::from(["outName".into(), "in_name".into()]));
    }
}
