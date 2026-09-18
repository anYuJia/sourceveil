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

use super::analysis::RustAnalysis;
use super::candidates::{self, Candidate, FileContext, Visibility};
use crate::edits::{Contribution, EditPlan, FileMove};
use crate::mapping::Mapping;
use crate::names::{NameDeriver, SeedDomain};
use crate::plan::Plan;
use crate::report::{RenameStats, SkipReason, SkippedSymbol};
use crate::rust::ItemKind;
use crate::scanner::{
    is_root_like, path_eq, path_starts_with, strip_prefix_path, CrateGraph, CrateInfo,
};
use anyhow::Result;
use ra_ap_ide::{FileId, FilePosition, Indel, RenameConfig, SourceChange, TextSize};
use ra_ap_ide_db::source_change::FileSystemEdit;
use ra_ap_syntax::ast::AstNode;
use ra_ap_syntax::TextRange;
use std::collections::{BTreeMap, BTreeSet, HashSet};
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

    let keep = KeepRules::new(req.plan, macro_referenced);

    for (file_id, candidate) in &all_candidates {
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

        let new_name = names.derive(
            SeedDomain::RustSymbol,
            &candidate.path,
            candidate.kind.name_case(),
        )?;

        let change = match propose_rename(analysis, *file_id, candidate.name_range, &new_name) {
            Ok(change) => change,
            Err(reason) => {
                skipped.push(skipped_for(candidate, reason.0, reason.1));
                continue;
            }
        };

        let allow_file_moves = candidate.kind == ItemKind::Module && req.plan.rename.module_files;
        match stage_change(
            analysis,
            change,
            candidate,
            req,
            &analyzed_text,
            plan,
            allow_file_moves,
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

fn stage_change(
    analysis: &RustAnalysis,
    change: SourceChange,
    candidate: &Candidate,
    req: &RenameRequest<'_>,
    analyzed_text: &BTreeMap<PathBuf, String>,
    plan: &mut EditPlan,
    allow_file_moves: bool,
) -> std::result::Result<(usize, Vec<PathBuf>), Skip> {
    let (by_file, file_moves) = if allow_file_moves {
        if analyzed_text
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
        resolve_change_edits_with_file_moves(analysis, req.input_root, req.copied, &change)?
    } else {
        (
            resolve_change_edits(analysis, req.input_root, req.copied, &change)?,
            Vec::new(),
        )
    };

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

    let staged = by_file.values().map(Vec::len).sum();
    let touched: Vec<PathBuf> = by_file.keys().cloned().collect();
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
        let Some(text) = analyzed_text.get(path) else {
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
    /// Identifiers appearing inside a macro token tree.
    pub macro_referenced: HashSet<String>,
}

/// Collect both identifier sets in a single walk.
pub fn collect_syntax_facts(
    analysis: &RustAnalysis,
    files: &[(FileId, PathBuf)],
    graph: &CrateGraph,
) -> SyntaxFacts {
    let mut facts = SyntaxFacts::default();
    for (file_id, path) in files {
        if crate_for_file(graph, path).is_none() {
            continue;
        }
        let Some((parsed, _)) = analysis.parse(*file_id) else {
            continue;
        };
        for token in parsed
            .syntax()
            .descendants_with_tokens()
            .filter_map(|el| el.into_token())
            .filter(|t| t.kind() == ra_ap_syntax::SyntaxKind::IDENT)
        {
            let text = token.text().to_string();
            if is_inside_macro_token_tree(&token) {
                facts.macro_referenced.insert(text.clone());
            }
            facts.identifiers.insert(text);
        }
    }
    facts
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
}

impl KeepRules {
    fn new(plan: &Plan, macro_referenced: HashSet<String>) -> Self {
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
        // `#[serde(...)]` on a field is a wire-format contract that the
        // dedicated serde pass will rewrite deliberately. Until then, pinning
        // the item is the only safe option.
        attributes.insert("serde".into());

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

        // The wire-format rule.
        //
        // `#[derive(Serialize)]` makes every field name a JSON key. Renaming
        // the field changes what the program writes and what it accepts, and
        // the compiler cannot tell you: the code still builds, the tests that
        // do not round-trip still pass, and the breakage shows up against a
        // real peer. Until the dedicated serde pass exists — the one that
        // emits `#[serde(rename = "user_name")]` alongside the new identifier —
        // the only safe amount of field rename inside a serde model is none.
        //
        // This covers enum variants too, and not only fields: a variant name is
        // an externally-tagged representation's key, which is why this rule has
        // to hold under the `safe` profile as well, where variants are renamed
        // by default.
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

        // The load-bearing rule. rust-analyzer resolves references through its
        // own search, and that search does not reach identifiers inside a macro
        // token tree: it renames `target_fn()` in ordinary code but leaves it
        // alone inside `format!(..)`, `vec![..]`, `println!(..)` and inside the
        // body of a `macro_rules!` definition. The reference is real and the
        // build depends on it, so a rename that cannot rewrite it is not a
        // rename at all — it is a syntax error that only shows up later.
        //
        // This is measured, not assumed: see the module docs in
        // `super`, and the e2e test `macro_referenced_symbols_are_kept`.
        //
        // Checked last so that a symbol pinned for a structural reason — an
        // ABI boundary, say — reports that reason rather than this one.
        if self.macro_referenced.contains(&candidate.name) {
            return Some(SkipReason::MacroCallReference);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let keep = KeepRules::new(&plan, Default::default());

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
}
