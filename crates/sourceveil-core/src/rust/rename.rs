//! The symbol rename pass.
//!
//! Each candidate is resolved by rust-analyzer into an *edit set*: every text
//! span in the workspace that names that symbol. The pass never decides for
//! itself which occurrences matter — that is the whole point of using a real
//! name resolver, and it is what separates this from a regex rename.
//!
//! A rename is applied only if it survives three checks, and it is applied
//! all-or-nothing:
//!
//! 1. **Every edited file is one we copied.** An edit that lands in the
//!    sysroot, the registry, or `target/` means the rename reaches outside the
//!    generated tree. Applying the rest would leave the output inconsistent.
//! 2. **No file moves.** rust-analyzer renames a file-backed module by moving
//!    the file. That is a coherent operation, but it is a separate pass with
//!    its own verification, so here it is a skip.
//! 3. **No span is written twice.** An identifier occurrence resolves to
//!    exactly one definition, so two renames cannot legitimately want the same
//!    span. A collision means an assumption is wrong, and the second rename is
//!    dropped and reported rather than applied on top of the first.

use super::analysis::{LoadOptions, RustAnalysis};
use super::candidates::{self, Candidate, FileContext, Visibility};
use crate::edits::{Contribution, EditPlan, FileMove};
use crate::mapping::Mapping;
use crate::names::{NameCase, NameDeriver, SeedDomain};
use crate::plan::Plan;
use crate::report::{RenameStats, SkipReason, SkippedSymbol};
use crate::rust::ItemKind;
use crate::scanner::{
    is_root_like, path_eq, path_starts_with, strip_prefix_path, CrateGraph, CrateInfo,
};
use anyhow::{Context, Result};
use ra_ap_ide::{
    Analysis, FileId, FilePosition, GotoDefinitionConfig, Indel, RenameConfig, SourceChange,
    TextSize,
};
use ra_ap_ide_db::source_change::FileSystemEdit;
use ra_ap_syntax::ast::{self, AstNode, HasName};
use ra_ap_syntax::{Edition, SourceFile, TextRange};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// State shared with the other passes.
///
/// The name generator is shared because the Tauri command pass draws from the
/// same stream: two generators seeded alike would produce the same first name
/// and collide. `claimed` carries the definition sites another pass has already
/// renamed, so this pass does not rename them a second time.
pub struct Shared<'a> {
    pub names: &'a mut NameDeriver,
    /// The one plan every pass stages into. Applied once, by the pipeline.
    pub plan: &'a mut EditPlan,
    pub claimed: &'a HashSet<(PathBuf, TextRange)>,
    /// Identifiers occurring inside a macro token tree, collected once by the
    /// pipeline because both passes need them.
    pub macro_referenced: HashSet<String>,
    /// Unresolved implicit captures in format strings. These live in Rust's
    /// value namespace: they may denote locals/parameters (handled by the
    /// lexical binding pass) or constants/statics, but never fields or types.
    pub macro_format_referenced: HashSet<String>,
    /// Exact macro call-site references keyed by their semantic definition.
    pub macro_references: HashMap<(PathBuf, TextRange), Vec<(PathBuf, TextRange)>>,
}

pub struct RenameRequest<'a> {
    pub input_root: &'a Path,
    pub output_root: &'a Path,
    /// Workspace-relative paths of files present in the output tree. A rename
    /// touching anything else is refused.
    pub copied: &'a BTreeSet<PathBuf>,
    pub plan: &'a Plan,
    pub graph: &'a CrateGraph,
    pub seed: u64,
    /// A later rustc feedback pass can distinguish real unresolved macro
    /// references from unrelated DSL labels, so a name-level macro hit need
    /// not conservatively pin every same-spelled definition.
    pub allow_unresolved_macro_references: bool,
}

#[derive(Debug, Default)]
pub struct RenameOutcome {
    pub stats: RenameStats,
    pub mapping: Mapping,
    pub skipped: Vec<SkippedSymbol>,
    pub warnings: Vec<String>,
    /// Files this pass staged edits into, workspace-relative.
    pub files_edited: BTreeSet<PathBuf>,
    /// Symbols considered before any filtering.
    pub candidates_considered: usize,
    pub rust_files_scanned: usize,
}

pub fn run(
    analysis: &RustAnalysis,
    req: &RenameRequest<'_>,
    shared: Shared<'_>,
) -> Result<RenameOutcome> {
    let Shared {
        names,
        plan,
        claimed,
        macro_referenced,
        macro_format_referenced,
        macro_references,
    } = shared;
    let mut outcome = RenameOutcome {
        mapping: Mapping::new(req.seed),
        ..Default::default()
    };

    let files = analysis.rust_files();
    let mut all_candidates: Vec<(FileId, Candidate)> = Vec::new();
    // rust-analyzer's own view of each file, kept so the rewrite step can prove
    // the copy it is editing is the same text the edits were computed against.
    let mut analyzed_text: BTreeMap<PathBuf, String> = BTreeMap::new();

    for (file_id, path) in &files {
        // Only files inside this workspace's crates are candidates. Anything
        // else in the analysis (sysroot, registry) is not ours to rewrite.
        let Some(krate) = crate_for_file(req.graph, path) else {
            continue;
        };
        let Some((parsed, text)) = analysis.parse(*file_id) else {
            outcome
                .warnings
                .push(format!("could not parse {}; skipped", path.display()));
            continue;
        };

        let prefix = module_prefix_for(krate, path);
        let ctx = FileContext {
            path,
            text: &text,
            crate_name: &krate.name,
            module_prefix: &prefix,
        };
        for candidate in candidates::collect(&parsed, &ctx) {
            all_candidates.push((*file_id, candidate));
        }
        analyzed_text.insert(path.clone(), text);
    }

    outcome.rust_files_scanned = files
        .iter()
        .filter(|(_, p)| crate_for_file(req.graph, p).is_some())
        .count();
    outcome.candidates_considered = all_candidates.len();

    // Deterministic order: names are drawn from a seeded stream, so the order
    // candidates reach the generator decides what they are called. Sorting by
    // (file, offset) makes that reproducible.
    all_candidates.sort_by(|a, b| {
        a.1.file
            .cmp(&b.1.file)
            .then(a.1.name_range.start().cmp(&b.1.name_range.start()))
    });

    let mut skipped: Vec<SkippedSymbol> = Vec::new();

    let keep = KeepRules::new(
        req.plan,
        macro_referenced,
        macro_format_referenced,
        req.allow_unresolved_macro_references,
    );

    for (file_id, candidate) in &all_candidates {
        // Bindings are rewritten in a dedicated scope-aware post-pass, after
        // field/shorthand and module edits have settled. A workspace-wide
        // macro-name blacklist must not pin unrelated closure parameters.
        if matches!(candidate.kind, ItemKind::Local | ItemKind::Param) {
            continue;
        }
        // Another pass owns this one. It has already been renamed, from the
        // same snapshot, and renaming it again here would produce a second
        // name for the same symbol.
        if claimed.contains(&(candidate.file.clone(), candidate.name_range)) {
            continue;
        }

        if let Some(reason) = keep.reject(candidate, req.graph) {
            skipped.push(skipped_for(candidate, reason, None));
            continue;
        }

        let name_case = if matches!(candidate.kind, ItemKind::Local | ItemKind::Param)
            && candidate.name.starts_with('_')
        {
            NameCase::HiddenSnake
        } else {
            candidate.kind.name_case()
        };
        // Every workspace symbol with the same spelling and casing receives
        // one replacement. Semantic edits still decide each reference; the
        // shared target makes macro expansions, generated serde paths, and
        // duplicate field groups composable without a textual search/replace.
        let identity = format!("rust-name::{name_case:?}::{}", candidate.name);
        let new_name = names.derive(SeedDomain::RustSymbol, &identity, name_case)?;

        let change = match propose_rename(analysis, *file_id, candidate.name_range, &new_name) {
            Ok(change) => change,
            Err(reason) => {
                if reason.0 == SkipReason::Unresolvable
                    && candidate
                        .attributes
                        .iter()
                        .any(|attribute| attribute == "cfg")
                {
                    if let Ok((applied, files)) =
                        stage_cfg_inactive_change(candidate, &new_name, &analyzed_text, plan)
                    {
                        outcome.stats.bump(candidate.kind);
                        outcome.stats.edits_applied += applied;
                        outcome.files_edited.extend(files);
                        outcome
                            .mapping
                            .record_symbol(candidate.path.clone(), new_name.clone());
                        continue;
                    }
                }
                skipped.push(skipped_for(candidate, reason.0, reason.1));
                continue;
            }
        };

        let stage = StageChangeContext {
            analysis,
            req,
            analyzed_text: &analyzed_text,
        };
        match stage_change(
            &stage,
            change,
            candidate,
            &new_name,
            plan,
            macro_references.get(&(candidate.file.clone(), candidate.name_range)),
        ) {
            Ok((applied, files)) => {
                outcome.stats.bump(candidate.kind);
                outcome.stats.edits_applied += applied;
                outcome.files_edited.extend(files);
                outcome
                    .mapping
                    .record_symbol(candidate.path.clone(), new_name.clone());
            }
            Err(reason) => skipped.push(skipped_for(candidate, reason.0, reason.1)),
        }
    }

    // Nothing is written here. The pipeline applies the whole plan once, after
    // every pass has contributed to it, so that no pass sees a file another
    // pass has already changed the length of.
    outcome.stats.files_edited = outcome.files_edited.len();
    outcome.skipped = skipped;
    Ok(outcome)
}

/// Rename an item that is syntactically present but inactive for the host
/// target. rust-analyzer quite correctly has no definition graph for it. The
/// fallback is constrained to identifiers under `#[cfg(...)]`, uses only
/// candidate-shaped syntax, and stages through the same conflict-checked edit
/// transaction as semantic renames.
fn stage_cfg_inactive_change(
    candidate: &Candidate,
    new_name: &str,
    analyzed_text: &BTreeMap<PathBuf, String>,
    plan: &mut EditPlan,
) -> std::result::Result<(usize, Vec<PathBuf>), Skip> {
    let mut by_file: BTreeMap<PathBuf, Vec<Indel>> = BTreeMap::new();
    for (path, source) in analyzed_text {
        let parsed = SourceFile::parse(source, Edition::Edition2024).tree();
        for token in parsed
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
        {
            if token.kind() != ra_ap_syntax::SyntaxKind::IDENT || token.text() != candidate.name {
                continue;
            }
            let range = token.text_range();
            let definition = *path == candidate.file && range == candidate.name_range;
            if !definition && !token_is_under_cfg(&token) {
                continue;
            }
            if !definition && !cfg_reference_shape(candidate.kind, &token) {
                continue;
            }
            let edit =
                field_shorthand_edit(source, range, candidate, new_name).unwrap_or_else(|| Indel {
                    delete: range,
                    insert: new_name.to_string(),
                });
            by_file.entry(path.clone()).or_default().push(edit);
        }
    }

    if !by_file.get(&candidate.file).is_some_and(|edits| {
        edits
            .iter()
            .any(|edit| edit.delete.contains_range(candidate.name_range))
    }) {
        return Err((
            SkipReason::Unresolvable,
            Some("cfg fallback did not find the definition".into()),
        ));
    }
    for edits in by_file.values_mut() {
        edits.sort_by_key(|edit| (edit.delete.start(), edit.delete.end()));
        edits.dedup_by(|left, right| left.delete == right.delete && left.insert == right.insert);
    }
    remove_already_staged_exact_edits(&mut by_file, plan);
    let applied = by_file.values().map(Vec::len).sum();
    let files: Vec<_> = by_file
        .iter()
        .filter(|(_, edits)| !edits.is_empty())
        .map(|(path, _)| path.clone())
        .collect();
    let contributions = by_file
        .iter()
        .map(|(path, edits)| Contribution::new(path, &analyzed_text[path], edits.clone()));
    plan.stage_transaction(contributions)
        .map_err(|error| (SkipReason::EditConflict, Some(error.to_string())))?;
    Ok((applied, files))
}

fn token_is_under_cfg(token: &ra_ap_syntax::SyntaxToken) -> bool {
    token.parent().is_some_and(|parent| {
        parent.ancestors().any(|node| {
            candidates::attribute_names(&node)
                .iter()
                .any(|name| name == "cfg")
        })
    })
}

fn cfg_reference_shape(kind: ItemKind, token: &ra_ap_syntax::SyntaxToken) -> bool {
    let previous = previous_non_trivia_token(token.prev_token());
    let next = next_non_trivia_token(token.next_token());
    match kind {
        ItemKind::Function => {
            next.as_ref().is_some_and(|next| next.text() == "(")
                || previous
                    .as_ref()
                    .is_some_and(|previous| previous.text() == ".")
                || token_ends_path_separator(previous)
        }
        ItemKind::Module => {
            token_ends_path_separator(previous) || token_begins_path_separator(next)
        }
        ItemKind::Field => {
            previous
                .as_ref()
                .is_some_and(|previous| previous.text() == ".")
                || next.as_ref().is_some_and(|next| next.text() == ":")
                || token.parent().is_some_and(|parent| {
                    parent.ancestors().any(|node| {
                        matches!(
                            node.kind(),
                            ra_ap_syntax::SyntaxKind::RECORD_EXPR_FIELD
                                | ra_ap_syntax::SyntaxKind::RECORD_PAT_FIELD
                        )
                    })
                })
        }
        _ => true,
    }
}

pub(crate) type Skip = (SkipReason, Option<String>);

/// Ask rust-analyzer for the edit set of renaming this candidate.
pub(crate) fn propose_rename(
    analysis: &RustAnalysis,
    file_id: FileId,
    name_range: TextRange,
    new_name: &str,
) -> std::result::Result<SourceChange, Skip> {
    let position = FilePosition {
        file_id,
        offset: TextSize::from(u32::from(name_range.start())),
    };

    let config = RenameConfig {
        prefer_no_std: false,
        prefer_prelude: false,
        prefer_absolute: false,
        // Ask rust-analyzer to validate that the new name does not collide
        // with anything in scope. Our names are globally unique, so a reported
        // conflict means an assumption is wrong and we want to hear about it.
        show_conflicts: true,
    };

    let analysis_handle = analysis.analysis();

    match analysis_handle.rename(position, new_name, &config) {
        Err(_cancelled) => Err((
            SkipReason::Unresolvable,
            Some("rust-analyzer cancelled the request".into()),
        )),
        Ok(Err(e)) => Err((SkipReason::Unresolvable, Some(e.to_string()))),
        Ok(Ok(change)) => Ok(change),
    }
}

/// Check a proposed rename against the three correctness rules and, if it
/// passes, schedule its edits.
/// Resolve a rust-analyzer edit set onto the files we are allowed to write.
///
/// Shared with the Tauri command pass, which needs the same treatment of the
/// same kind of edit set — a rename rust-analyzer produced, bounded by what we
/// actually copied.
pub(crate) fn resolve_change_edits(
    analysis: &RustAnalysis,
    input_root: &Path,
    copied: &BTreeSet<PathBuf>,
    change: &SourceChange,
) -> std::result::Result<BTreeMap<PathBuf, Vec<Indel>>, Skip> {
    if !change.file_system_edits.is_empty() {
        return Err((
            SkipReason::RequiresFileRename,
            Some("rust-analyzer wants to move a file; that is a separate pass".into()),
        ));
    }

    let mut by_file: BTreeMap<PathBuf, Vec<Indel>> = BTreeMap::new();
    for (file_id, (text_edit, _snippet)) in change.source_file_edits.iter() {
        let Some(abs) = resolve_edit_target(analysis, input_root, copied, *file_id) else {
            return Err((
                SkipReason::EditOutsideOutput,
                Some(format!(
                    "edit targets file id {file_id:?}, which is not a copied workspace file"
                )),
            ));
        };
        by_file
            .entry(abs)
            .or_default()
            .extend(text_edit.iter().cloned());
    }

    if by_file.is_empty() {
        return Err((
            SkipReason::Unresolvable,
            Some("rust-analyzer produced no edits".into()),
        ));
    }

    Ok(by_file)
}

struct StageChangeContext<'a, 'request> {
    analysis: &'a RustAnalysis,
    req: &'a RenameRequest<'request>,
    analyzed_text: &'a BTreeMap<PathBuf, String>,
}

fn stage_change(
    context: &StageChangeContext<'_, '_>,
    change: SourceChange,
    candidate: &Candidate,
    new_name: &str,
    plan: &mut EditPlan,
    macro_references: Option<&Vec<(PathBuf, TextRange)>>,
) -> std::result::Result<(usize, Vec<PathBuf>), Skip> {
    // Inline modules have no backing path to move. rust-analyzer expresses a
    // file-backed module rename with filesystem edits; only that concrete
    // signal opts into the move transaction.
    let allow_file_moves = candidate.kind == ItemKind::Module
        && context.req.plan.rename.module_files
        && !change.file_system_edits.is_empty();
    let (mut by_file, file_moves) = if allow_file_moves {
        if context
            .analyzed_text
            .values()
            .any(|text| text.contains("include!("))
        {
            return Err((
                SkipReason::RequiresFileRename,
                Some(
                    "module file moves are disabled when include! paths are present; \
                     rust-analyzer cannot prove those macro-relative paths"
                        .into(),
                ),
            ));
        }
        resolve_change_edits_with_file_moves(
            context.analysis,
            context.req.input_root,
            context.req.copied,
            &change,
        )?
    } else {
        (
            resolve_change_edits(
                context.analysis,
                context.req.input_root,
                context.req.copied,
                &change,
            )?,
            Vec::new(),
        )
    };

    reconcile_resolved_edits(
        &mut by_file,
        candidate,
        macro_references,
        new_name,
        context.analyzed_text,
    );

    // Verify the definition site is among the edits. If rust-analyzer resolved
    // the position to something other than the item we think we are renaming,
    // this is where that shows up.
    let definition_present = by_file
        .get(&candidate.file)
        .map(|indels| {
            indels
                .iter()
                .any(|i| i.delete.contains_range(candidate.name_range))
        })
        .unwrap_or(false);
    if !definition_present {
        return Err((
            SkipReason::Unresolvable,
            Some(format!(
                "the edit set does not rewrite the definition of `{}`; \
                 rust-analyzer resolved the position to something else",
                candidate.name
            )),
        ));
    }

    remove_already_staged_exact_edits(&mut by_file, plan);
    let staged = by_file.values().map(Vec::len).sum();
    let touched: Vec<PathBuf> = by_file
        .iter()
        .filter(|(_, edits)| !edits.is_empty())
        .map(|(path, _)| path.clone())
        .collect();
    let mut contributions = Vec::with_capacity(by_file.len());
    for (path, indels) in &by_file {
        for indel in indels {
            tracing::debug!(
                symbol = %candidate.name,
                file = %path.display(),
                start = u32::from(indel.delete.start()),
                end = u32::from(indel.delete.end()),
                insert = %indel.insert,
                "staged edit"
            );
        }
        let Some(text) = context.analyzed_text.get(path) else {
            return Err((
                SkipReason::EditOutsideOutput,
                Some(format!(
                    "no analysed text for {}; refusing to edit a file we did not read",
                    path.display()
                )),
            ));
        };
        contributions.push(Contribution::new(path, text, indels.clone()));
    }

    // Stage the text edits and every associated file move on a clone. A move
    // conflict must not leave the rename's source edits (or an earlier move
    // from the same semantic change) in the shared plan.
    let mut trial = plan.clone();
    if let Err(error) = trial.stage_transaction(contributions) {
        return Err((SkipReason::EditConflict, Some(error.to_string())));
    }
    for file_move in file_moves {
        if let Err(detail) = trial.stage_move(file_move) {
            return Err((SkipReason::EditConflict, Some(detail)));
        }
    }
    *plan = trial;

    Ok((staged, touched))
}

/// Turn a rename into a definition-indexed edit set.
///
/// rust-analyzer's high-level rename result is useful for validating the
/// definition and for module filesystem moves, but on large macro-heavy crates
/// it can omit inferred field/method references and occasionally include a
/// same-spelled shadowed local. `collect_syntax_facts` independently resolves
/// every candidate-shaped token with goto-definition. We therefore retain the
/// definition edit from `rename` and reconstruct all reference edits from that
/// exact graph. This is semantic filtering, not a textual fallback.
pub(crate) fn reconcile_resolved_edits(
    by_file: &mut BTreeMap<PathBuf, Vec<Indel>>,
    candidate: &Candidate,
    references: Option<&Vec<(PathBuf, TextRange)>>,
    new_name: &str,
    analyzed_text: &BTreeMap<PathBuf, String>,
) {
    // A missing exact index is different from a proven empty reference set.
    // It can happen when the host and rust-analyzer use different-but-equal
    // spellings for a Windows path. In that case the high-level rename is the
    // only complete semantic transaction we have; retaining it is safer than
    // reducing the change to the definition and leaving its call sites stale.
    let Some(references) = references else {
        return;
    };

    // Retain only the definition from rust-analyzer's high-level rename. Its
    // search can include a same-spelled shadowed binding in macro-heavy code;
    // references are rebuilt from the exact definition index below. Module
    // navigation targets are canonicalized to their `mod` declaration while
    // collecting that index, so file-backed modules follow the same rule.
    for (path, edits) in by_file.iter_mut() {
        edits.retain(|edit| {
            *path == candidate.file && edit.delete.contains_range(candidate.name_range)
        });
    }
    by_file.retain(|_, edits| !edits.is_empty());

    for (path, range) in references {
        if *path == candidate.file && range.contains_range(candidate.name_range) {
            continue;
        }
        if candidate.kind == ItemKind::Module
            && analyzed_text
                .get(path)
                .is_none_or(|source| !is_module_path_reference(source, *range))
        {
            continue;
        }
        let edits = by_file.entry(path.clone()).or_default();
        if edits.iter().any(|edit| edit.delete == *range) {
            continue;
        }
        let edit = analyzed_text
            .get(path)
            .and_then(|source| field_shorthand_edit(source, *range, candidate, new_name))
            .unwrap_or_else(|| Indel {
                delete: *range,
                insert: new_name.to_string(),
            });
        if !edits
            .iter()
            .any(|existing| existing.delete == edit.delete && existing.insert == edit.insert)
        {
            edits.push(edit);
        }
    }
}

/// rust-analyzer can occasionally resolve a value expression to a same-named
/// module after a large proc-macro expansion. A module is only usable through
/// a Rust path, so require `::` adjacency or a `use` item before accepting the
/// reference. This rejects `cookie.clone()` when a `cookie` module also exists
/// while retaining `cookie::parse()` and `use cookie as cookies`.
fn is_module_path_reference(source: &str, range: TextRange) -> bool {
    let parsed = SourceFile::parse(source, Edition::Edition2024).tree();
    let Some(token) = parsed
        .syntax()
        .token_at_offset(range.start())
        .find(|token| token.text_range() == range)
    else {
        return false;
    };
    let previous = previous_non_trivia_token(token.prev_token());
    let next = next_non_trivia_token(token.next_token());
    token_ends_path_separator(previous)
        || token_begins_path_separator(next)
        || token.parent().is_some_and(|parent| {
            parent
                .ancestors()
                .any(|node| node.kind() == ra_ap_syntax::SyntaxKind::USE)
        })
}

fn previous_non_trivia_token(
    mut token: Option<ra_ap_syntax::SyntaxToken>,
) -> Option<ra_ap_syntax::SyntaxToken> {
    while token.as_ref().is_some_and(|token| token.kind().is_trivia()) {
        token = token.and_then(|token| token.prev_token());
    }
    token
}

fn next_non_trivia_token(
    mut token: Option<ra_ap_syntax::SyntaxToken>,
) -> Option<ra_ap_syntax::SyntaxToken> {
    while token.as_ref().is_some_and(|token| token.kind().is_trivia()) {
        token = token.and_then(|token| token.next_token());
    }
    token
}

fn token_begins_path_separator(token: Option<ra_ap_syntax::SyntaxToken>) -> bool {
    token.is_some_and(|token| {
        token.kind() == ra_ap_syntax::SyntaxKind::COLON2
            || (token.text() == ":"
                && next_non_trivia_token(token.next_token()).is_some_and(|next| next.text() == ":"))
    })
}

fn token_ends_path_separator(token: Option<ra_ap_syntax::SyntaxToken>) -> bool {
    token.is_some_and(|token| {
        token.kind() == ra_ap_syntax::SyntaxKind::COLON2
            || (token.text() == ":"
                && previous_non_trivia_token(token.prev_token())
                    .is_some_and(|previous| previous.text() == ":"))
    })
}

fn field_shorthand_edit(
    source: &str,
    range: TextRange,
    candidate: &Candidate,
    new_name: &str,
) -> Option<Indel> {
    if candidate.kind != ItemKind::Field {
        return None;
    }
    let parsed = SourceFile::parse(source, Edition::Edition2024).tree();
    let token = parsed
        .syntax()
        .token_at_offset(range.start())
        .find(|token| token.text_range() == range)?;
    let record = token.parent()?.ancestors().find(|node| {
        matches!(
            node.kind(),
            ra_ap_syntax::SyntaxKind::RECORD_EXPR_FIELD
                | ra_ap_syntax::SyntaxKind::RECORD_PAT_FIELD
        )
    })?;
    if record
        .children_with_tokens()
        .any(|element| element.kind() == ra_ap_syntax::SyntaxKind::COLON)
    {
        return None;
    }
    Some(Indel {
        delete: TextRange::empty(record.text_range().start()),
        insert: format!("{new_name}: "),
    })
}

/// Same-spelled field definitions deliberately share a generated spelling.
/// Their semantic edit sets can therefore contain the same call-site edit.
/// Treat an already-staged byte-for-byte identical edit as fulfilled, while a
/// different edit on the same span remains a hard conflict in `EditPlan`.
pub(crate) fn remove_already_staged_exact_edits(
    by_file: &mut BTreeMap<PathBuf, Vec<Indel>>,
    plan: &EditPlan,
) {
    for (path, edits) in by_file {
        let Some(staged) = plan.pending_edits(path) else {
            continue;
        };
        edits.retain(|incoming| {
            !staged.iter().any(|existing| {
                existing.delete == incoming.delete && existing.insert == incoming.insert
            })
        });
    }
}

type ResolvedFileMoves = (BTreeMap<PathBuf, Vec<Indel>>, Vec<FileMove>);

/// Resolve a semantic rename that includes rust-analyzer's module file-system
/// edits. The ordinary symbol pass deliberately rejects those edits; module
/// file renaming opts into them only after the source/destination paths have
/// been proven to stay within the copied workspace.
fn resolve_change_edits_with_file_moves(
    analysis: &RustAnalysis,
    input_root: &Path,
    copied: &BTreeSet<PathBuf>,
    change: &SourceChange,
) -> std::result::Result<ResolvedFileMoves, Skip> {
    let mut by_file = BTreeMap::new();
    for (file_id, (text_edit, _snippet)) in change.source_file_edits.iter() {
        let Some(abs) = resolve_edit_target(analysis, input_root, copied, *file_id) else {
            return Err((
                SkipReason::EditOutsideOutput,
                Some(format!(
                    "edit targets file id {file_id:?}, which is not a copied workspace file"
                )),
            ));
        };
        by_file
            .entry(abs)
            .or_insert_with(Vec::new)
            .extend(text_edit.iter().cloned());
    }

    if change.file_system_edits.is_empty() {
        return Err((
            SkipReason::Unresolvable,
            Some("module rename did not produce a file move".into()),
        ));
    }

    let mut moves = Vec::new();
    for fs_edit in &change.file_system_edits {
        let file_move = match fs_edit {
            FileSystemEdit::MoveFile { src, dst } => {
                let Some(source) = analysis.file_path(*src) else {
                    return Err((
                        SkipReason::RequiresFileRename,
                        Some("module move source has no filesystem path".into()),
                    ));
                };
                let Some(destination) = resolve_anchored_path(analysis, dst) else {
                    return Err((
                        SkipReason::RequiresFileRename,
                        Some("module move destination has no filesystem path".into()),
                    ));
                };
                FileMove {
                    source,
                    destination,
                    directory: false,
                }
            }
            FileSystemEdit::MoveDir { src, dst, .. } => {
                let Some(source) = resolve_anchored_path(analysis, src) else {
                    return Err((
                        SkipReason::RequiresFileRename,
                        Some("module directory move source has no filesystem path".into()),
                    ));
                };
                let Some(destination) = resolve_anchored_path(analysis, dst) else {
                    return Err((
                        SkipReason::RequiresFileRename,
                        Some("module directory move destination has no filesystem path".into()),
                    ));
                };
                FileMove {
                    source,
                    destination,
                    directory: true,
                }
            }
            FileSystemEdit::CreateFile { .. } => {
                return Err((
                    SkipReason::RequiresFileRename,
                    Some("module rename requested file creation, not a simple move".into()),
                ));
            }
        };

        let source_rel = strip_prefix_path(&file_move.source, input_root);
        let destination_rel = strip_prefix_path(&file_move.destination, input_root);
        let (Some(source_rel), Some(_destination_rel)) = (source_rel, destination_rel) else {
            return Err((
                SkipReason::EditOutsideOutput,
                Some(format!(
                    "module move {} -> {} leaves the copied workspace",
                    file_move.source.display(),
                    file_move.destination.display()
                )),
            ));
        };

        if file_move.directory {
            if !copied.iter().any(|p| p.starts_with(&source_rel)) {
                return Err((
                    SkipReason::EditOutsideOutput,
                    Some(format!(
                        "module directory {} contains no copied source files",
                        source_rel.display()
                    )),
                ));
            }
        } else if !copied.contains(&source_rel) {
            return Err((
                SkipReason::EditOutsideOutput,
                Some(format!(
                    "module file {} was not copied into the output",
                    source_rel.display()
                )),
            ));
        }

        moves.push(file_move);
    }

    if by_file.is_empty() {
        return Err((
            SkipReason::Unresolvable,
            Some("rust-analyzer produced no text edits for the module rename".into()),
        ));
    }
    Ok((by_file, moves))
}

fn resolve_anchored_path(
    analysis: &RustAnalysis,
    path: &ra_ap_vfs::AnchoredPathBuf,
) -> Option<PathBuf> {
    let anchor = analysis.file_path(path.anchor)?;
    let parent = anchor.parent()?;
    Some(normalize_path(&parent.join(&path.path)))
}

/// Normalize an anchored rust-analyzer path without touching the filesystem.
/// `MoveDir` commonly uses paths such as `src/auth/../auth`; lexical
/// normalization is required before comparing them with the copier's relative
/// file set, and `canonicalize` cannot be used because a destination does not
/// exist yet.
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Map a rust-analyzer `FileId` onto the output tree, refusing anything we did
/// not copy.
///
/// This is the rule that keeps the output self-consistent. rust-analyzer will
/// happily propose renaming a symbol defined in a registry crate, or rewriting
/// a file under `target/` — neither of which exists in the generated tree in a
/// form we may edit.
pub(crate) fn resolve_edit_target(
    analysis: &RustAnalysis,
    input_root: &Path,
    copied: &BTreeSet<PathBuf>,
    file_id: FileId,
) -> Option<PathBuf> {
    let abs = analysis.file_path(file_id)?;
    let rel = strip_prefix_path(&abs, input_root)?;
    copied.contains(&rel).then_some(abs)
}

fn skipped_for(candidate: &Candidate, reason: SkipReason, detail: Option<String>) -> SkippedSymbol {
    SkippedSymbol {
        name: candidate.name.clone(),
        symbol_path: candidate.path.clone(),
        file: candidate.file.display().to_string(),
        line: candidate.line,
        reason,
        detail,
    }
}

/// Which workspace crate owns a file.
///
/// Two guards matter here, and both were added after pointing the tool at a
/// real Tauri project:
///
/// - Anything under cargo's target directory is a build artifact, not source.
///   Build scripts emit `.rs` files into `OUT_DIR` (serde, thiserror, selectors
///   and `web_atoms` all do), and rust-analyzer loads them. They are not ours to
///   rewrite, and on a real project they contributed over a thousand candidates
///   — every one of them a skip — burying the handful that came from the
///   project's own source.
/// - The crate-wrapper fallback matches direct children of the crate directory
///   only. That is what admits `build.rs`, which lives outside `src/`; matching
///   at any depth is what swept in `target/` in the first place.
pub(crate) fn crate_for_file<'a>(graph: &'a CrateGraph, path: &Path) -> Option<&'a CrateInfo> {
    if let Some(target) = &graph.target_directory {
        if path_starts_with(path, target) {
            return None;
        }
    }

    let mut best: Option<(&CrateInfo, usize)> = None;
    let mut consider = |krate: &'a CrateInfo, dir: &Path| {
        if !path_starts_with(path, dir) {
            return;
        }
        let depth = dir.components().count();
        if best.map(|(_, d)| depth > d).unwrap_or(true) {
            best = Some((krate, depth));
        }
    };

    for krate in graph.workspace.values() {
        if let Some(src_dir) = &krate.src_dir {
            consider(krate, src_dir);
        }
        if path
            .parent()
            .is_some_and(|parent| path_eq(parent, &krate.manifest_dir))
        {
            consider(krate, &krate.manifest_dir);
        }
    }
    best.map(|(k, _)| k)
}

/// Path segments implied by a file's location inside its crate.
pub(crate) fn module_prefix_for(krate: &CrateInfo, path: &Path) -> Vec<String> {
    let Some(src_dir) = &krate.src_dir else {
        return Vec::new();
    };
    let Ok(rel) = path.strip_prefix(src_dir) else {
        return Vec::new();
    };

    let mut segments: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    let Some(last) = segments.pop() else {
        return Vec::new();
    };
    let stem = last.strip_suffix(".rs").unwrap_or(&last).to_string();

    // `lib.rs` and `main.rs` are the crate root; `mod.rs` names its directory.
    if stem != "lib" && stem != "main" && stem != "mod" && !stem.is_empty() {
        segments.push(stem);
    }
    segments
}

/// What one pass over the workspace's syntax trees yields.
#[derive(Debug, Default)]
pub struct SyntaxFacts {
    /// Every identifier in workspace source, used to keep generated names from
    /// colliding with, or shadowing, one that already exists.
    pub identifiers: HashSet<String>,
    /// Identifiers in macro DSL positions whose definition cannot be proven.
    /// Resolved macro references are recorded separately and rewritten at
    /// their exact source ranges.
    pub macro_referenced: HashSet<String>,
    /// Implicit named format captures which rust-analyzer could not resolve.
    /// Kept separate so a local `{value}` never pins every field called
    /// `value`; only const/static candidates use this conservative fallback.
    pub macro_format_referenced: HashSet<String>,
    /// Macro call-site spans grouped by the exact definition they resolve to.
    /// This is the semantic bridge that lets fields/functions referenced from
    /// `assert!`, `format!`, `json!`, and similar macros move without global
    /// textual replacement.
    pub macro_references: HashMap<(PathBuf, TextRange), Vec<(PathBuf, TextRange)>>,
}

/// Keeps the generated copy byte-for-byte recoverable while a second
/// rust-analyzer snapshot reads same-length standard-macro shells. Restoration
/// happens explicitly on the success path and again from `Drop` on every
/// early-return/error path.
#[derive(Default)]
struct FileRestore {
    files: Vec<(PathBuf, String)>,
    restored: bool,
}

impl FileRestore {
    fn replace(&mut self, path: &Path, replacement: &str) -> Result<()> {
        let original =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if original.len() != replacement.len() {
            anyhow::bail!(
                "macro analysis shell for {} changed byte length ({} -> {})",
                path.display(),
                original.len(),
                replacement.len()
            );
        }
        std::fs::write(path, replacement)
            .with_context(|| format!("writing macro analysis shell {}", path.display()))?;
        self.files.push((path.to_path_buf(), original));
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
        for (path, original) in &self.files {
            std::fs::write(path, original)
                .with_context(|| format!("restoring {}", path.display()))?;
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for FileRestore {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        for (path, original) in &self.files {
            let _ = std::fs::write(path, original);
        }
    }
}

/// Collect both identifier sets in a single walk.
pub fn collect_syntax_facts(
    analysis: &RustAnalysis,
    files: &[(FileId, PathBuf)],
    graph: &CrateGraph,
    input_root: &Path,
    output_root: &Path,
    macro_analysis_root: &Path,
) -> Result<SyntaxFacts> {
    let mut facts = SyntaxFacts::default();
    let mut shadowed_macros = HashSet::new();
    let mut candidate_names = HashSet::new();
    let mut module_candidates = Vec::new();
    for (file_id, path) in files {
        let Some(krate) = crate_for_file(graph, path) else {
            continue;
        };
        let Some((parsed, source)) = analysis.parse(*file_id) else {
            continue;
        };
        let prefix = module_prefix_for(krate, path);
        let context = FileContext {
            path,
            text: &source,
            crate_name: &krate.name,
            module_prefix: &prefix,
        };
        for candidate in candidates::collect(&parsed, &context) {
            candidate_names.insert(candidate.name.clone());
            if candidate.kind == ItemKind::Module {
                module_candidates.push((candidate.file, candidate.name_range));
            }
        }
        for definition in parsed
            .syntax()
            .descendants()
            .filter_map(ast::MacroRules::cast)
        {
            if let Some(name) = definition.name() {
                shadowed_macros.insert(name.text().to_string());
            }
        }
    }

    let mut macro_sources = HashMap::new();
    let mut source_texts = HashMap::new();
    let mut restore = FileRestore::default();
    for (file_id, path) in files {
        if crate_for_file(graph, path).is_none() {
            continue;
        }
        let Some((_, source)) = analysis.parse(*file_id) else {
            continue;
        };
        source_texts.insert(*file_id, source.clone());
        if let Ok(expanded) = super::bindings::macro_analysis_source(&source, &shadowed_macros) {
            if let Some(relative) = strip_prefix_path(path, input_root) {
                let output_path = output_root.join(relative);
                if output_path.is_file() {
                    restore
                        .replace(&output_path, &expanded.text)
                        .with_context(|| {
                            format!("preparing macro analysis for {}", output_path.display())
                        })?;
                }
            }
            macro_sources.insert(*file_id, expanded);
        }
    }
    let source_handle = analysis.analysis();
    let macro_analysis_result = RustAnalysis::load(
        macro_analysis_root,
        &LoadOptions {
            load_out_dirs_from_check: false,
            proc_macros: true,
        },
    );
    restore
        .restore()
        .context("restoring macro analysis shells")?;
    let macro_analysis = macro_analysis_result.context("loading standard-macro analysis shell")?;
    let macro_handle = macro_analysis.analysis();
    let source_file_ids: HashMap<PathBuf, FileId> =
        files.iter().map(|(id, path)| (path.clone(), *id)).collect();
    let mut definition_aliases: HashMap<(PathBuf, TextRange), Vec<(PathBuf, TextRange)>> =
        HashMap::new();
    for (file, range) in module_candidates {
        let canonical = (file.clone(), range);
        definition_aliases
            .entry(canonical.clone())
            .or_default()
            .push(canonical.clone());
        let Some(file_id) = source_file_ids.get(&file) else {
            continue;
        };
        // Module navigation intentionally targets the backing file, whereas
        // rename is anchored at the `mod name` declaration. Record both as
        // one semantic identity so references inside macro token trees are
        // joined to the declaration candidate as well.
        for target in semantic_definition_targets(
            &source_handle,
            analysis,
            input_root,
            input_root,
            *file_id,
            range,
        ) {
            definition_aliases
                .entry(target)
                .or_default()
                .push(canonical.clone());
        }
    }
    for aliases in definition_aliases.values_mut() {
        aliases.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then(left.1.start().cmp(&right.1.start()))
                .then(left.1.end().cmp(&right.1.end()))
        });
        aliases.dedup();
    }
    let mut macro_file_ids = HashMap::new();
    for (macro_file_id, macro_path) in macro_analysis.rust_files() {
        let Some(relative) = strip_prefix_path(&macro_path, output_root) else {
            continue;
        };
        macro_file_ids.insert(input_root.join(relative), macro_file_id);
    }

    for (file_id, path) in files {
        if crate_for_file(graph, path).is_none() {
            continue;
        }
        let Some(source) = source_texts.get(file_id) else {
            continue;
        };
        let parsed = SourceFile::parse(source, Edition::Edition2024).tree();
        let labels =
            super::bindings::macro_label_ranges(source, &shadowed_macros).unwrap_or_default();
        for token in parsed
            .syntax()
            .descendants_with_tokens()
            .filter_map(|el| el.into_token())
        {
            if token.kind() == ra_ap_syntax::SyntaxKind::IDENT {
                let text = token.text().to_string();
                if is_inside_macro_token_tree(&token) && !labels.contains(&token.text_range()) {
                    let analysis_range = macro_sources
                        .get(file_id)
                        .map(|expanded| expanded.analysis_range(token.text_range()))
                        .unwrap_or_else(|| token.text_range());
                    let definitions = macro_file_ids
                        .get(path)
                        .map(|macro_file_id| {
                            semantic_definition_targets(
                                &macro_handle,
                                &macro_analysis,
                                input_root,
                                output_root,
                                *macro_file_id,
                                analysis_range,
                            )
                        })
                        .unwrap_or_default();
                    let definitions =
                        canonical_definition_targets(definitions, &definition_aliases);
                    record_resolved_macro_reference(
                        path,
                        token.text_range(),
                        &text,
                        definitions,
                        &mut facts,
                    );
                } else if candidate_names.contains(&text) {
                    // `rename` in rust-analyzer is intentionally conservative
                    // for inferred fields/methods and can also return a
                    // same-spelled, shadowed local in an incomplete edit set.
                    // Index every ordinary reference independently with
                    // goto-definition. The rename pass later intersects the
                    // proposed edits with this exact definition graph and
                    // fills any reference `rename` omitted.
                    let definitions = semantic_definition_targets(
                        &source_handle,
                        analysis,
                        input_root,
                        input_root,
                        *file_id,
                        token.text_range(),
                    );
                    let definitions =
                        canonical_definition_targets(definitions, &definition_aliases);
                    for definition in definitions {
                        facts
                            .macro_references
                            .entry(definition)
                            .or_default()
                            .push((path.clone(), token.text_range()));
                    }
                }
                facts.identifiers.insert(text);
            }
        }
        for (name, range) in
            super::bindings::macro_format_references(source, &shadowed_macros).unwrap_or_default()
        {
            let analysis_range = macro_sources
                .get(file_id)
                .map(|expanded| expanded.analysis_range(range))
                .unwrap_or(range);
            // rust-analyzer understands implicit format captures in the real
            // macro invocation even though rename does not always return an
            // edit for the identifier inside the string. Resolve there first;
            // the same-length shell is the fallback for ordinary macro tokens.
            // This distinction matters for a common spelling such as `value`:
            // an unresolved local capture must not pin every unrelated field
            // named `value` in the workspace.
            let mut definitions = semantic_definition_targets(
                &source_handle,
                analysis,
                input_root,
                input_root,
                *file_id,
                range,
            );
            if definitions.is_empty() {
                definitions = macro_file_ids
                    .get(path)
                    .map(|macro_file_id| {
                        semantic_definition_targets(
                            &macro_handle,
                            &macro_analysis,
                            input_root,
                            output_root,
                            *macro_file_id,
                            analysis_range,
                        )
                    })
                    .unwrap_or_default();
            }
            definitions = canonical_definition_targets(definitions, &definition_aliases);
            if definitions.is_empty() {
                facts.macro_format_referenced.insert(name);
            } else {
                record_resolved_macro_reference(path, range, &name, definitions, &mut facts);
            }
        }
    }
    for references in facts.macro_references.values_mut() {
        references.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then(left.1.start().cmp(&right.1.start()))
                .then(left.1.end().cmp(&right.1.end()))
        });
        references.dedup();
    }
    Ok(facts)
}

fn canonical_definition_targets(
    definitions: Vec<(PathBuf, TextRange)>,
    aliases: &HashMap<(PathBuf, TextRange), Vec<(PathBuf, TextRange)>>,
) -> Vec<(PathBuf, TextRange)> {
    let mut canonical = Vec::new();
    for definition in definitions {
        if let Some(targets) = aliases.get(&definition) {
            canonical.extend(targets.iter().cloned());
        } else {
            canonical.push(definition);
        }
    }
    canonical.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.start().cmp(&right.1.start()))
            .then(left.1.end().cmp(&right.1.end()))
    });
    canonical.dedup();
    canonical
}

fn semantic_definition_targets(
    semantic: &Analysis,
    paths: &RustAnalysis,
    input_root: &Path,
    output_root: &Path,
    file_id: FileId,
    range: TextRange,
) -> Vec<(PathBuf, TextRange)> {
    let config = GotoDefinitionConfig {
        ra_fixture: ra_ap_ide_db::ra_fixture::RaFixtureConfig::default(),
    };
    // At the exact start of `.field`, `path::item`, or a token following
    // whitespace, rust-analyzer may left-bias to the preceding punctuation.
    // Place the cursor inside the identifier whenever its span permits it.
    let offset = if range.len() > TextSize::from(1) {
        range.start() + TextSize::from(1)
    } else {
        range.start()
    };
    let mut definitions: Vec<_> = semantic
        .goto_definition(FilePosition { file_id, offset }, &config)
        .ok()
        .flatten()
        .map(|info| info.info)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|target| {
            let macro_path = paths.file_path(target.file_id)?;
            // When both roots name the same analysis tree, keep the VFS path
            // verbatim. Rebuilding it through strip/join can change a Windows
            // drive/prefix spelling and make an otherwise identical HashMap
            // key fail to match the candidate path. A macro-shell analysis is
            // the only case that actually needs output -> input remapping.
            let source_path = if path_eq(input_root, output_root) {
                macro_path
            } else {
                let relative = strip_prefix_path(&macro_path, output_root)?;
                input_root.join(relative)
            };
            Some((source_path, target.focus_or_full_range()))
        })
        .collect();
    definitions.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.start().cmp(&right.1.start()))
            .then(left.1.end().cmp(&right.1.end()))
    });
    definitions.dedup();
    definitions
}

fn record_resolved_macro_reference(
    path: &Path,
    range: TextRange,
    name: &str,
    definitions: Vec<(PathBuf, TextRange)>,
    facts: &mut SyntaxFacts,
) {
    if definitions.is_empty() {
        facts.macro_referenced.insert(name.to_string());
        return;
    }
    for definition in definitions {
        facts
            .macro_references
            .entry(definition)
            .or_default()
            .push((path.to_path_buf(), range));
    }
}

/// Is this token inside a macro's token tree rather than in ordinary code?
///
/// Both the arguments of a macro invocation and the body of a `macro_rules!`
/// definition count. See the module docs for why this matters.
///
/// Note the loop condition. A macro's arguments are themselves token trees, so
/// any `(...)`, `{...}` or `[...]` inside them nests another one:
///
/// ```text
/// MACRO_CALL
///   TOKEN_TREE          <- the macro's argument list; parent is MACRO_CALL
///     IDENT "format"
///     TOKEN_TREE        <- the `(target_fn())` call; parent is another TOKEN_TREE
///       IDENT "target_fn"
/// ```
///
/// Returning at the first `TOKEN_TREE` would therefore see `target_fn`'s parent
/// token tree, notice its parent is not `MACRO_CALL`, and conclude the token is
/// ordinary code. The walk has to continue outwards until it either finds a
/// token tree belonging to a macro or runs out of ancestors.
pub(crate) fn is_inside_macro_token_tree(token: &ra_ap_syntax::SyntaxToken) -> bool {
    use ra_ap_syntax::SyntaxKind as K;
    let mut node = token.parent();
    while let Some(current) = node {
        if current.kind() == K::TOKEN_TREE
            && matches!(
                current.parent().map(|p| p.kind()),
                Some(K::MACRO_CALL) | Some(K::MACRO_RULES)
            )
        {
            return true;
        }
        node = current.parent();
    }
    false
}

/// Attribute paths that bind a Rust name to a linker symbol.
const LINKAGE_ATTRIBUTES: &[&str] = &[
    "no_mangle",
    "export_name",
    "link_name",
    "unsafe(no_mangle)",
    "unsafe(export_name)",
    "unsafe(link_name)",
];

/// The keep rules, compiled once.
struct KeepRules {
    rename: crate::plan::RenamePlan,
    dependencies: crate::plan::DependenciesPlan,
    symbols: HashSet<String>,
    patterns: globset::GlobSet,
    attributes: HashSet<String>,
    /// Names occurring inside a macro token tree. See
    /// [`SkipReason::MacroCallReference`].
    macro_referenced: HashSet<String>,
    macro_format_referenced: HashSet<String>,
    allow_unresolved_macro_references: bool,
}

impl KeepRules {
    fn new(
        plan: &Plan,
        macro_referenced: HashSet<String>,
        macro_format_referenced: HashSet<String>,
        allow_unresolved_macro_references: bool,
    ) -> Self {
        let mut attributes: HashSet<String> = crate::plan::INTRINSIC_KEEP_ATTRIBUTES
            .iter()
            .map(|s| s.to_string())
            .collect();

        // Attributes that name a cross-language protocol. Until the pass that
        // rewrites the other side exists, renaming the Rust side alone would
        // silently break the contract, so they are pinned. `command` covers
        // the `use tauri::command; #[command]` spelling; it also catches
        // clap's `#[command]`, which is a harmless over-keep.
        attributes.insert("tauri::command".into());
        attributes.insert("command".into());
        attributes.extend(plan.keep.attributes.iter().cloned());

        let mut symbols: HashSet<String> = plan.keep.symbols.iter().cloned().collect();
        symbols.extend(
            crate::plan::INTRINSIC_KEEP_NAMES
                .iter()
                .map(|s| s.to_string()),
        );

        Self {
            rename: plan.rename.clone(),
            dependencies: plan.dependencies.clone(),
            symbols,
            patterns: crate::copier::build_globset(&plan.keep.patterns)
                .unwrap_or_else(|_| globset::GlobSet::empty()),
            attributes,
            macro_referenced,
            macro_format_referenced,
            allow_unresolved_macro_references,
        }
    }

    fn reject(&self, candidate: &Candidate, graph: &CrateGraph) -> Option<SkipReason> {
        if !candidate.kind.enabled_in(&self.rename) {
            return Some(SkipReason::KindDisabled);
        }

        if candidate.inline_keep {
            return Some(SkipReason::InlineKeepComment);
        }

        if self.symbols.contains(&candidate.name) || self.patterns.is_match(&candidate.name) {
            return Some(SkipReason::KeepRule);
        }

        // Trait declarations and implementations are contracts. Inherent
        // methods—including conventional names such as `new`, `get`, and
        // `save`—are ordinary workspace symbols and are resolved semantically;
        // they do not need a spelling blacklist.
        if candidate.kind == ItemKind::Function && candidate.trait_method {
            return Some(SkipReason::KeepRule);
        }

        // Workspace members are inside the requested closed world. Local path
        // dependencies outside that workspace (and registry/git packages)
        // default to an external boundary unless the dependency policy opts
        // them in explicitly.
        if let Some(krate) = crate_for_file(graph, &candidate.file) {
            if !is_root_like(graph, &krate.name) {
                match self.dependencies.mode_for(&krate.name) {
                    crate::config::DependencyMode::External
                    | crate::config::DependencyMode::Wrapper => {
                        return Some(SkipReason::DependencyExternal);
                    }
                    crate::config::DependencyMode::PrivateObfuscate
                        if candidate.visibility == Visibility::Public =>
                    {
                        return Some(SkipReason::ExternallyReachable);
                    }
                    crate::config::DependencyMode::PrivateObfuscate
                    | crate::config::DependencyMode::Obfuscate => {}
                }
            }
        }

        if candidate.kind == ItemKind::Module
            && self.rename.module_files
            && candidate.attributes.iter().any(|a| a == "path")
        {
            return Some(SkipReason::RequiresFileRename);
        }

        // Serde members are owned by the earlier dedicated pass, which can
        // materialise their wire names and update Rust paths inside serde
        // metadata. A member that reaches this generic pass was deliberately
        // kept there, so it must not be reconsidered without its protocol
        // transaction. This covers externally-tagged enum variants as well as
        // fields.
        if candidate.serde_model
            && matches!(
                candidate.kind,
                crate::rust::ItemKind::Field | crate::rust::ItemKind::Variant
            )
        {
            return Some(SkipReason::SerdeModel);
        }

        // A foreign ABI plus a linkage attribute is an exported symbol: the
        // name is part of the ABI, not of the Rust code.
        if candidate.is_extern_abi
            && candidate
                .attributes
                .iter()
                .any(|a| LINKAGE_ATTRIBUTES.contains(&a.as_str()))
        {
            return Some(SkipReason::AbiBoundary);
        }

        if candidate
            .attributes
            .iter()
            .any(|a| self.attributes.contains(a))
        {
            return Some(SkipReason::IntrinsicAttribute);
        }

        // A `pub` item in a crate that something outside the workspace depends
        // on is a published API. A proc-macro crate's exports are consumed at
        // compile time by other crates, which puts them in the same category.
        if candidate.visibility == Visibility::Public {
            if let Some(krate) = crate_for_file(graph, &candidate.file) {
                if krate.has_external_consumers(graph) || krate.is_proc_macro {
                    return Some(SkipReason::ExternallyReachable);
                }
            }
        }

        // rust-analyzer's search misses some identifiers inside macro token
        // trees. When compiler-guided exact reference completion is enabled,
        // those candidates may proceed and rustc supplies only the actual
        // missing spans. Without that safety net they are pinned here. This is
        // checked last so a structural reason (an ABI boundary, for example)
        // wins in the report.
        if !self.allow_unresolved_macro_references
            && self.macro_referenced.contains(&candidate.name)
        {
            return Some(SkipReason::MacroCallReference);
        }
        if matches!(candidate.kind, ItemKind::Const | ItemKind::Static)
            && self.macro_format_referenced.contains(&candidate.name)
        {
            return Some(SkipReason::MacroCallReference);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_exact_index_keeps_the_complete_semantic_rename() {
        let path = PathBuf::from("C:/workspace/helper/src/lib.rs");
        let source = "fn private_calculation() {} fn call() { private_calculation(); }";
        let definition_start = source.find("private_calculation").unwrap() as u32;
        let call_start = source.rfind("private_calculation").unwrap() as u32;
        let name_len = "private_calculation".len() as u32;
        let definition = TextRange::new(
            TextSize::from(definition_start),
            TextSize::from(definition_start + name_len),
        );
        let call = TextRange::new(
            TextSize::from(call_start),
            TextSize::from(call_start + name_len),
        );
        let mut edits = BTreeMap::from([(
            path.clone(),
            vec![
                Indel::replace(definition, "hidden_calculation".into()),
                Indel::replace(call, "hidden_calculation".into()),
            ],
        )]);
        let candidate = Candidate {
            kind: ItemKind::Function,
            name: "private_calculation".into(),
            name_range: definition,
            file: path.clone(),
            line: 1,
            path: "helper::private_calculation".into(),
            visibility: Visibility::Private,
            attributes: Vec::new(),
            inline_keep: false,
            is_extern_abi: false,
            serde_model: false,
            is_method: false,
            trait_method: false,
            scope_range: None,
        };

        reconcile_resolved_edits(
            &mut edits,
            &candidate,
            None,
            "hidden_calculation",
            &BTreeMap::new(),
        );

        assert_eq!(edits[&path].len(), 2);
        assert!(edits[&path].iter().any(|edit| edit.delete == call));
    }

    #[test]
    fn module_prefix_reflects_file_location() {
        let krate = CrateInfo {
            name: "app".into(),
            manifest_dir: PathBuf::from("/p/src-tauri"),
            src_dir: Some(PathBuf::from("/p/src-tauri/src")),
            crate_types: Default::default(),
            is_proc_macro: false,
            is_library: true,
        };

        let prefix = |p: &str| module_prefix_for(&krate, Path::new(p));
        assert!(prefix("/p/src-tauri/src/lib.rs").is_empty());
        assert!(prefix("/p/src-tauri/src/main.rs").is_empty());
        assert_eq!(prefix("/p/src-tauri/src/network.rs"), vec!["network"]);
        assert_eq!(prefix("/p/src-tauri/src/network/mod.rs"), vec!["network"]);
        assert_eq!(
            prefix("/p/src-tauri/src/network/client.rs"),
            vec!["network", "client"]
        );
    }

    #[test]
    fn crate_lookup_prefers_the_deepest_match() {
        let mut graph = CrateGraph::default();
        graph.workspace.insert(
            "outer".into(),
            CrateInfo {
                name: "outer".into(),
                manifest_dir: PathBuf::from("/p/src-tauri"),
                src_dir: Some(PathBuf::from("/p/src-tauri/src")),
                crate_types: Default::default(),
                is_proc_macro: false,
                is_library: true,
            },
        );
        graph.workspace.insert(
            "inner".into(),
            CrateInfo {
                name: "inner".into(),
                manifest_dir: PathBuf::from("/p/src-tauri/crates/inner"),
                src_dir: Some(PathBuf::from("/p/src-tauri/crates/inner/src")),
                crate_types: Default::default(),
                is_proc_macro: false,
                is_library: true,
            },
        );

        let found = crate_for_file(&graph, Path::new("/p/src-tauri/crates/inner/src/lib.rs"));
        assert_eq!(found.map(|k| k.name.as_str()), Some("inner"));
    }

    #[test]
    fn macro_token_tree_detection() {
        let src = r#"
            fn a() { format!("{}", target_fn()); }
            fn b() { println!("{}", Foo::Bar { baz: 1 }); }
            fn c() {
                println!(
                    "{}",
                    Multi::Line(nested_fn(x)),
                );
            }
            fn d() { let plain = target_fn(); }
            fn e() { vec![target_fn()] }
        "#;
        let file = ra_ap_syntax::SourceFile::parse(src, ra_ap_syntax::Edition::Edition2021).tree();

        let mut found = std::collections::BTreeSet::new();
        for token in file
            .syntax()
            .descendants_with_tokens()
            .filter_map(|el| el.into_token())
        {
            if token.kind() == ra_ap_syntax::SyntaxKind::IDENT && is_inside_macro_token_tree(&token)
            {
                found.insert(token.text().to_string());
            }
        }
        let found: Vec<&str> = found.iter().map(String::as_str).collect();

        // Direct arguments.
        assert!(found.contains(&"target_fn"), "{found:?}");
        // Inside a nested `{...}` token tree, which is the case that made the
        // first version of this function wrong.
        for expected in ["Foo", "Bar", "baz"] {
            assert!(found.contains(&expected), "missing {expected} in {found:?}");
        }
        // Inside a nested `(...)` token tree, two levels down.
        for expected in ["Multi", "Line", "nested_fn", "x"] {
            assert!(found.contains(&expected), "missing {expected} in {found:?}");
        }

        // The macro's own path is not part of its argument list. Nothing is
        // gained by keeping a symbol named `sum` because some macro is called
        // `sum!`.
        for excluded in ["format", "println", "vec"] {
            assert!(
                !found.contains(&excluded),
                "the macro path `{excluded}` is not a token-tree reference: {found:?}"
            );
        }
        assert!(
            !found.contains(&"plain"),
            "`plain` is ordinary code: {found:?}"
        );
        assert!(
            !found.contains(&"a"),
            "fn names are not macro contents: {found:?}"
        );
    }

    fn probe_graph() -> CrateGraph {
        let mut graph = CrateGraph {
            target_directory: Some(PathBuf::from("/p/src-tauri/target")),
            ..Default::default()
        };
        graph.workspace.insert(
            "app".into(),
            CrateInfo {
                name: "app".into(),
                manifest_dir: PathBuf::from("/p/src-tauri"),
                src_dir: Some(PathBuf::from("/p/src-tauri/src")),
                crate_types: Default::default(),
                is_proc_macro: false,
                is_library: false,
            },
        );
        graph
    }

    #[test]
    fn source_files_are_attributed_to_their_crate() {
        let graph = probe_graph();
        let found = crate_for_file(&graph, Path::new("/p/src-tauri/src/commands.rs"));
        assert_eq!(found.map(|k| k.name.as_str()), Some("app"));
    }

    /// Build scripts emit `.rs` files into `OUT_DIR` and rust-analyzer loads
    /// them. On a real Tauri project these accounted for over a thousand of the
    /// reported candidates, every one a skip, burying the handful that came
    /// from the project's own source.
    #[test]
    fn build_artifacts_are_not_candidates() {
        let graph = probe_graph();
        assert!(crate_for_file(
            &graph,
            Path::new("/p/src-tauri/target/debug/build/web_atoms-1234/out/generated.rs")
        )
        .is_none());
    }

    /// `build.rs` lives outside `src/`, so the crate-root fallback has to keep
    /// admitting it — but only at depth one, which is what stopped `target/`
    /// being swept in.
    #[test]
    fn build_rs_is_still_attributed_to_its_crate() {
        let graph = probe_graph();
        let found = crate_for_file(&graph, Path::new("/p/src-tauri/build.rs"));
        assert_eq!(found.map(|k| k.name.as_str()), Some("app"));
    }

    #[test]
    fn only_direct_children_of_a_crate_root_are_attributed() {
        let graph = probe_graph();
        assert!(crate_for_file(&graph, Path::new("/p/src-tauri/vendor/dep/src/lib.rs")).is_none());
    }

    /// §40, at the level the rule actually lives: a `pub` variant in a crate
    /// something outside the workspace depends on is that crate's API.
    #[test]
    fn a_public_variant_in_an_api_boundary_crate_is_kept() {
        use crate::config::Config;
        use crate::plan::Plan;

        let plan = Plan::resolve(&Config::default()).unwrap();
        let keep = KeepRules::new(&plan, Default::default(), Default::default(), false);

        let mut graph = CrateGraph::default();
        graph.workspace.insert(
            "libcrate".into(),
            CrateInfo {
                name: "libcrate".into(),
                manifest_dir: PathBuf::from("/p/lib"),
                src_dir: Some(PathBuf::from("/p/lib/src")),
                crate_types: Default::default(),
                is_proc_macro: false,
                is_library: true,
            },
        );

        let candidate = |visibility| Candidate {
            kind: crate::rust::ItemKind::Variant,
            name: "Connected".into(),
            name_range: TextRange::new(TextSize::from(9), TextSize::from(18)),
            file: PathBuf::from("/p/lib/src/lib.rs"),
            line: 1,
            path: "libcrate::PublicState::Connected".into(),
            visibility,
            attributes: Vec::new(),
            inline_keep: false,
            is_extern_abi: false,
            // Not a serde model, so this measures the API boundary alone.
            serde_model: false,
            is_method: false,
            trait_method: false,
            scope_range: None,
        };

        // Nothing outside depends on it yet, so it is an ordinary internal item.
        graph.boundary.clear();
        assert_eq!(keep.reject(&candidate(Visibility::Public), &graph), None);

        // One crate outside the workspace depends on it. Now `pub` is a
        // contract, and the variant is exactly as public as its enum.
        graph.boundary.insert("libcrate".into());
        assert_eq!(
            keep.reject(&candidate(Visibility::Public), &graph),
            Some(SkipReason::ExternallyReachable)
        );

        // A private enum's variants are still nobody's business.
        assert_ne!(
            keep.reject(&candidate(Visibility::Private), &graph),
            Some(SkipReason::ExternallyReachable)
        );
    }

    #[test]
    fn inherent_conventional_methods_are_not_pinned() {
        use crate::config::{Config, Profile};
        let source = "struct Session; impl Session { fn new() -> Self { Self } }";
        let parsed = SourceFile::parse(source, Edition::Edition2021).tree();
        let ctx = FileContext {
            path: Path::new("/p/src-tauri/src/lib.rs"),
            text: source,
            crate_name: "app",
            module_prefix: &[],
        };
        let method = candidates::collect(&parsed, &ctx)
            .into_iter()
            .find(|candidate| candidate.name == "new")
            .unwrap();
        for profile in [Profile::Safe, Profile::Balanced, Profile::Aggressive] {
            let config = Config {
                profile: Some(profile),
                ..Config::default()
            };
            let plan = Plan::resolve(&config).unwrap();
            let keep = KeepRules::new(&plan, Default::default(), Default::default(), false);
            assert_eq!(keep.reject(&method, &probe_graph()), None);
        }
    }

    #[test]
    fn module_reference_filter_rejects_same_named_values() {
        let source = "mod cookie; use cookie as jar; fn f(cookie: String) { cookie.clone(); cookie::parse(); }";
        let ranges: Vec<_> = source
            .match_indices("cookie")
            .map(|(start, name)| {
                TextRange::at(
                    TextSize::from(start as u32),
                    TextSize::from(name.len() as u32),
                )
            })
            .collect();
        assert_eq!(ranges.len(), 5);
        assert!(is_module_path_reference(source, ranges[1]));
        assert!(!is_module_path_reference(source, ranges[2]));
        assert!(!is_module_path_reference(source, ranges[3]));
        assert!(is_module_path_reference(source, ranges[4]));

        let macro_source = r#"fn main() { println!("{}", network::describe()); }"#;
        let start = macro_source.find("network").unwrap();
        let range = TextRange::at(TextSize::from(start as u32), TextSize::from(7));
        assert!(is_module_path_reference(macro_source, range));
    }

    #[test]
    fn cfg_fallback_is_confined_to_inactive_item_syntax() {
        let source = r#"
#[cfg(windows)]
fn platform_only() {}
#[cfg(windows)]
fn windows_caller() { platform_only(); let platform_only = 1; let _ = platform_only; }
fn host_code() { #[cfg(windows)] { platform_only(); } platform_only(); }
"#;
        let path = PathBuf::from("/workspace/src/lib.rs");
        let parsed = SourceFile::parse(source, Edition::Edition2024).tree();
        let context = FileContext {
            path: &path,
            text: source,
            crate_name: "fixture",
            module_prefix: &[],
        };
        let candidate = candidates::collect(&parsed, &context)
            .into_iter()
            .find(|candidate| candidate.name == "platform_only")
            .unwrap();
        assert!(candidate.attributes.iter().any(|name| name == "cfg"));
        let texts = BTreeMap::from([(path.clone(), source.to_string())]);
        let mut plan = EditPlan::new();
        let (applied, _) =
            stage_cfg_inactive_change(&candidate, "hidden_platform", &texts, &mut plan).unwrap();
        assert_eq!(applied, 3);
        let rewritten =
            crate::edits::apply_indels(source, plan.pending_edits(&path).unwrap()).unwrap();
        assert!(rewritten.contains("fn hidden_platform()"));
        assert!(rewritten.contains("windows_caller() { hidden_platform();"));
        assert!(rewritten.contains("let platform_only = 1"));
        assert!(rewritten.contains("#[cfg(windows)] { hidden_platform(); } platform_only();"));
    }
}
