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
use crate::edits::{EditPlan, SourceRef};
use crate::mapping::Mapping;
use crate::names::NameGenerator;
use crate::plan::Plan;
use crate::report::{RenameStats, SkipReason, SkippedSymbol};
use crate::scanner::{CrateGraph, CrateInfo};
use anyhow::Result;
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
    /// Edits this pass wants, expressed against the original text. The pipeline
    /// applies them once every pass has contributed.
    pub plan: EditPlan,
    /// Symbols considered before any filtering.
    pub candidates_considered: usize,
    pub rust_files_scanned: usize,
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

    let mut edits = EditPlan::new();
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

        match stage_change(analysis, change, candidate, req, &analyzed_text, &mut edits) {
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

    // Nothing is written here. The pipeline applies the whole plan once, after
    // every pass has contributed to it, so that no pass sees a file another
    // pass has already changed the length of.
    outcome.stats.files_edited = edits.edited_files().count();
    outcome.plan = edits;
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
    analyzed_text: &BTreeMap<PathBuf, String>,
    plan: &mut EditPlan,
) -> std::result::Result<usize, Skip> {
    if !change.file_system_edits.is_empty() {
        return Err((
            SkipReason::RequiresFileRename,
            Some("rust-analyzer wants to move a file; that is a separate pass".into()),
        ));
    }

    // Group the edit set by file first, so validation can cover all of them
    // before any of them is scheduled.
    let mut by_file: BTreeMap<PathBuf, Vec<Indel>> = BTreeMap::new();
    for (file_id, (text_edit, _snippet)) in change.source_file_edits.iter() {
        let Some(abs) = resolve_edit_target(analysis, req, *file_id) else {
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

    // All-or-nothing across every file the rename touches, not just within one.
    for (path, indels) in &by_file {
        for indel in indels {
            if let Some(clash) = plan.would_conflict(path, indel) {
                return Err((SkipReason::EditConflict, Some(clash.to_string())));
            }
        }
    }

    let staged = by_file.values().map(Vec::len).sum();
    for (path, indels) in by_file {
        for indel in &indels {
            tracing::debug!(
                symbol = %candidate.name,
                file = %path.display(),
                start = u32::from(indel.delete.start()),
                end = u32::from(indel.delete.end()),
                insert = %indel.insert,
                "staged edit"
            );
        }
        let Some(text) = analyzed_text.get(&path) else {
            return Err((
                SkipReason::EditOutsideOutput,
                Some(format!(
                    "no analysed text for {}; refusing to edit a file we did not read",
                    path.display()
                )),
            ));
        };
        if let Err(clash) = plan.stage(SourceRef { path: &path, text }, indels) {
            // Unreachable: the same spans were checked above. Reported rather
            // than unwrapped, because a panic here would be a bug in this
            // function and not in the project being transformed.
            return Err((SkipReason::EditConflict, Some(clash.to_string())));
        }
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
fn crate_for_file<'a>(graph: &'a CrateGraph, path: &Path) -> Option<&'a CrateInfo> {
    if let Some(target) = &graph.target_directory {
        if path.starts_with(target) {
            return None;
        }
    }

    let mut best: Option<(&CrateInfo, usize)> = None;
    let mut consider = |krate: &'a CrateInfo, dir: &Path| {
        if !path.starts_with(dir) {
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
        if path.parent() == Some(krate.manifest_dir.as_path()) {
            consider(krate, &krate.manifest_dir);
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
fn is_inside_macro_token_tree(token: &ra_ap_syntax::SyntaxToken) -> bool {
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
}
