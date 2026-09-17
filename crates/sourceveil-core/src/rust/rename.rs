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
use crate::mapping::Mapping;
use crate::names::NameGenerator;
use crate::plan::Plan;
use crate::report::{RenameStats, SkipReason, SkippedSymbol};
use crate::scanner::{CrateGraph, CrateInfo};
use anyhow::{Context, Result};
use ra_ap_ide::{FileId, FilePosition, Indel, RenameConfig, SourceChange, TextSize};
use ra_ap_syntax::ast::AstNode;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

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
    /// Files rewritten, workspace-relative.
    pub files_edited: BTreeSet<PathBuf>,
    /// Symbols considered before any filtering.
    pub candidates_considered: usize,
    pub rust_files_scanned: usize,
}

/// Edits accumulated for one file, expressed as spans in the *original* text.
#[derive(Debug, Default)]
struct FileEdits {
    indels: Vec<Indel>,
}

impl FileEdits {
    /// Would adding this indel overlap something already scheduled?
    fn conflicts_with(&self, indel: &Indel) -> bool {
        self.indels.iter().any(|existing| {
            existing.delete.start() < indel.delete.end()
                && indel.delete.start() < existing.delete.end()
        })
    }

    fn push(&mut self, indel: Indel) {
        self.indels.push(indel);
    }
}

pub fn run(analysis: &RustAnalysis, req: &RenameRequest<'_>) -> Result<RenameOutcome> {
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

    // Reserve every identifier already present anywhere in the workspace, so a
    // generated name can never collide with, or shadow, an existing one. This
    // is what removes the need for scope analysis during name selection.
    let facts = collect_syntax_facts(analysis, &files, req.graph);
    tracing::debug!(
        identifiers = facts.identifiers.len(),
        macro_referenced = facts.macro_referenced.len(),
        "collected identifiers from source"
    );

    let (len_min, len_max) = req.plan.rename.name_len;
    let mut names = NameGenerator::new(req.seed, len_min, len_max, facts.identifiers);

    let mut edits: BTreeMap<PathBuf, FileEdits> = BTreeMap::new();
    let mut skipped: Vec<SkippedSymbol> = Vec::new();

    let keep = KeepRules::new(req.plan, facts.macro_referenced);

    for (file_id, candidate) in &all_candidates {
        if let Some(reason) = keep.reject(candidate, req.graph) {
            skipped.push(skipped_for(candidate, reason, None));
            continue;
        }

        let new_name = names.generate(candidate.kind.name_case())?;

        let change = match propose_rename(analysis, *file_id, candidate, &new_name) {
            Ok(change) => change,
            Err(reason) => {
                skipped.push(skipped_for(candidate, reason.0, reason.1));
                continue;
            }
        };

        match stage_change(analysis, change, candidate, req, &mut edits) {
            Ok(applied) => {
                outcome.stats.bump(candidate.kind);
                outcome.stats.edits_applied += applied;
                outcome
                    .mapping
                    .record_symbol(candidate.path.clone(), new_name.clone());
            }
            Err(reason) => skipped.push(skipped_for(candidate, reason.0, reason.1)),
        }
    }

    // Write the edited files into the output tree.
    for (abs_path, file_edits) in &edits {
        let rel = abs_path
            .strip_prefix(req.input_root)
            .with_context(|| format!("{} is not under the input root", abs_path.display()))?;
        let target = req.output_root.join(rel);

        let disk = std::fs::read_to_string(&target)
            .with_context(|| format!("reading generated file {}", target.display()))?;

        // Every offset in `file_edits` indexes into the text rust-analyzer was
        // given. The copy is supposed to be byte-identical, and if it is not
        // the edits would be applied at the wrong places — silently producing
        // a tree that does not compile, or worse, one that does and means
        // something different. So divergence is a hard failure, not a warning:
        // continuing would also make `mapping.json` a lie.
        if let Some(analyzed) = analyzed_text.get(abs_path) {
            if &disk != analyzed {
                anyhow::bail!(
                    "{} changed between analysis and rewrite; refusing to apply {} edit(s) \
                     against text that no longer matches",
                    target.display(),
                    file_edits.indels.len()
                );
            }
        }

        let rewritten = apply_indels(&disk, &file_edits.indels).with_context(|| {
            format!(
                "applying {} edits to {}",
                file_edits.indels.len(),
                target.display()
            )
        })?;
        std::fs::write(&target, rewritten)
            .with_context(|| format!("writing {}", target.display()))?;
        outcome.files_edited.insert(rel.to_path_buf());
    }

    outcome.stats.files_edited = outcome.files_edited.len();
    outcome.skipped = skipped;
    Ok(outcome)
}

type Skip = (SkipReason, Option<String>);

/// Ask rust-analyzer for the edit set of renaming this candidate.
fn propose_rename(
    analysis: &RustAnalysis,
    file_id: FileId,
    candidate: &Candidate,
    new_name: &str,
) -> std::result::Result<SourceChange, Skip> {
    let position = FilePosition {
        file_id,
        offset: TextSize::from(u32::from(candidate.name_range.start())),
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
fn stage_change(
    analysis: &RustAnalysis,
    change: SourceChange,
    candidate: &Candidate,
    req: &RenameRequest<'_>,
    edits: &mut BTreeMap<PathBuf, FileEdits>,
) -> std::result::Result<usize, Skip> {
    if !change.file_system_edits.is_empty() {
        return Err((
            SkipReason::RequiresFileRename,
            Some("rust-analyzer wants to move a file; that is a separate pass".into()),
        ));
    }

    // Resolve every target file and validate before touching anything, so a
    // rename is never half-applied.
    let mut planned: Vec<(PathBuf, Indel)> = Vec::new();

    for (file_id, (text_edit, _snippet)) in change.source_file_edits.iter() {
        let Some(abs) = resolve_edit_target(analysis, req, *file_id) else {
            return Err((
                SkipReason::EditOutsideOutput,
                Some(format!(
                    "edit targets file id {file_id:?}, which is not a copied workspace file"
                )),
            ));
        };
        for indel in text_edit.iter() {
            planned.push((abs.clone(), indel.clone()));
        }
    }

    if planned.is_empty() {
        return Err((
            SkipReason::Unresolvable,
            Some("rust-analyzer produced no edits".into()),
        ));
    }

    // Verify the definition site is among the edits. If rust-analyzer resolved
    // the position to something other than the item we think we are renaming,
    // this is where that shows up.
    let definition_present = planned.iter().any(|(path, indel)| {
        *path == candidate.file && indel.delete.contains_range(candidate.name_range)
    });
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

    // Check for span collisions, then commit.
    for (path, indel) in &planned {
        if edits
            .get(path)
            .map(|e| e.conflicts_with(indel))
            .unwrap_or(false)
        {
            return Err((
                SkipReason::EditConflict,
                Some(format!(
                    "another rename already scheduled an overlapping edit at {}",
                    path.display()
                )),
            ));
        }
    }
    let staged = planned.len();
    for (path, indel) in &planned {
        tracing::debug!(
            symbol = %candidate.name,
            file = %path.display(),
            start = u32::from(indel.delete.start()),
            end = u32::from(indel.delete.end()),
            insert = %indel.insert,
            "staged edit"
        );
    }
    for (path, indel) in planned {
        edits.entry(path).or_default().push(indel);
    }

    Ok(staged)
}

/// Map a rust-analyzer `FileId` onto the output tree, refusing anything we did
/// not copy.
///
/// This is the rule that keeps the output self-consistent. rust-analyzer will
/// happily propose renaming a symbol defined in a registry crate, or rewriting
/// a file under `target/` — neither of which exists in the generated tree in a
/// form we may edit.
fn resolve_edit_target(
    analysis: &RustAnalysis,
    req: &RenameRequest<'_>,
    file_id: FileId,
) -> Option<PathBuf> {
    let abs = analysis.file_path(file_id)?;
    let rel = abs.strip_prefix(req.input_root).ok()?;
    req.copied.contains(rel).then_some(abs)
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
fn crate_for_file<'a>(graph: &'a CrateGraph, path: &Path) -> Option<&'a CrateInfo> {
    let mut best: Option<(&CrateInfo, usize)> = None;
    for krate in graph.workspace.values() {
        for dir in [krate.src_dir.as_deref(), Some(krate.manifest_dir.as_path())]
            .into_iter()
            .flatten()
        {
            if path.starts_with(dir) {
                let depth = dir.components().count();
                if best.map(|(_, d)| depth > d).unwrap_or(true) {
                    best = Some((krate, depth));
                }
            }
        }
    }
    best.map(|(k, _)| k)
}

/// Path segments implied by a file's location inside its crate.
fn module_prefix_for(krate: &CrateInfo, path: &Path) -> Vec<String> {
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
struct SyntaxFacts {
    /// Every identifier in workspace source, used to keep generated names from
    /// colliding with, or shadowing, one that already exists.
    identifiers: HashSet<String>,
    /// Identifiers appearing inside a macro token tree.
    macro_referenced: HashSet<String>,
}

/// Collect both identifier sets in a single walk.
fn collect_syntax_facts(
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
fn is_inside_macro_token_tree(token: &ra_ap_syntax::SyntaxToken) -> bool {
    use ra_ap_syntax::SyntaxKind as K;
    let mut node = token.parent();
    while let Some(current) = node {
        if current.kind() == K::TOKEN_TREE {
            return matches!(
                current.parent().map(|p| p.kind()),
                Some(K::MACRO_CALL) | Some(K::MACRO_RULES)
            );
        }
        node = current.parent();
    }
    false
}

/// Apply indels, which are expressed against the original text, in descending
/// order so earlier offsets stay valid.
fn apply_indels(text: &str, indels: &[Indel]) -> Result<String> {
    let mut ordered: Vec<&Indel> = indels.iter().collect();
    ordered.sort_by_key(|i| std::cmp::Reverse(i.delete.start()));

    let mut out = text.to_string();
    for indel in ordered {
        let start = usize::from(indel.delete.start());
        let end = usize::from(indel.delete.end());
        if end > out.len() {
            anyhow::bail!("edit at {start}..{end} is past the end of the file");
        }
        if !out.is_char_boundary(start) || !out.is_char_boundary(end) {
            anyhow::bail!("edit at {start}..{end} is not on a character boundary");
        }
        out.replace_range(start..end, &indel.insert);
    }
    Ok(out)
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
    use ra_ap_ide::TextRange;

    fn indel(start: u32, end: u32, insert: &str) -> Indel {
        Indel {
            insert: insert.to_string(),
            delete: TextRange::new(TextSize::from(start), TextSize::from(end)),
        }
    }

    #[test]
    fn indels_apply_backwards_so_offsets_stay_valid() {
        // Two renames in one line: `aa` at 0..2 and `bb` at 5..7.
        let text = "aa = bb";
        let edits = vec![indel(0, 2, "X"), indel(5, 7, "Y")];
        assert_eq!(apply_indels(text, &edits).unwrap(), "X = Y");
    }

    #[test]
    fn indels_can_grow_and_shrink_text() {
        let text = "fn foo() {}";
        let edits = vec![indel(3, 6, "qq8kap")];
        assert_eq!(apply_indels(text, &edits).unwrap(), "fn qq8kap() {}");

        let text = "fn qq8kap() {}";
        let edits = vec![indel(3, 9, "a")];
        assert_eq!(apply_indels(text, &edits).unwrap(), "fn a() {}");
    }

    #[test]
    fn out_of_range_edits_are_rejected_rather_than_panicking() {
        let err = apply_indels("short", &[indel(100, 105, "x")]).unwrap_err();
        assert!(format!("{err}").contains("past the end"));
    }

    #[test]
    fn mid_character_edits_are_rejected() {
        // "é" is two bytes; offset 1 is inside it.
        let err = apply_indels("é", &[indel(1, 2, "x")]).unwrap_err();
        assert!(format!("{err}").contains("character boundary"));
    }

    #[test]
    fn overlapping_indels_are_detected() {
        let mut fe = FileEdits::default();
        fe.push(indel(0, 10, "a"));
        assert!(
            fe.conflicts_with(&indel(5, 15, "b")),
            "overlap must be caught"
        );
        assert!(
            fe.conflicts_with(&indel(9, 11, "b")),
            "touching at the end overlaps"
        );
        assert!(!fe.conflicts_with(&indel(10, 20, "b")), "adjacent is fine");
        assert!(!fe.conflicts_with(&indel(20, 30, "b")), "disjoint is fine");
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
}
