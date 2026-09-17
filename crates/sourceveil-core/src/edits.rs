//! Text edits accumulated by every pass, applied once.
//!
//! Passes do not write files. They record what they would change, expressed
//! against the *original* text of the file, and a single apply step at the end
//! of the pipeline merges everything and writes.
//!
//! That split is not tidiness. The Tauri command pass and the symbol rename
//! pass both edit Rust files, and rust-analyzer hands out byte offsets that are
//! only valid against the snapshot it analysed. If one pass wrote to disk
//! first, every offset the second pass computed would be stale by exactly the
//! number of bytes the first pass added or removed — a corruption that lands in
//! the middle of identifiers and produces source that does not compile, or
//! worse, source that does and means something else.
//!
//! So: collect against one snapshot, apply once, in one direction per file.

use anyhow::{Context, Result};
use ra_ap_ide::{Indel, TextSize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Two passes wanted to write the same bytes.
///
/// This cannot happen by accident if each pass is correct — a rename owns the
/// spans of one symbol, a command rename owns the spans of one command — so it
/// means an assumption is broken, and the caller reports it rather than
/// guessing which edit was meant.
#[derive(Debug, Clone)]
pub struct Conflict {
    pub file: PathBuf,
    pub existing: (u32, u32),
    pub incoming: (u32, u32),
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: an edit at {}..{} overlaps one already scheduled at {}..{}",
            self.file.display(),
            self.incoming.0,
            self.incoming.1,
            self.existing.0,
            self.existing.1,
        )
    }
}

/// What a pass knows about a file it is editing.
#[derive(Debug, Clone, Copy)]
pub struct SourceRef<'a> {
    pub path: &'a Path,
    /// The text the edits were computed against.
    pub text: &'a str,
}

/// One file's share of a [`EditPlan::stage_transaction`] call.
#[derive(Debug, Clone)]
pub struct Contribution<'a> {
    pub source: SourceRef<'a>,
    pub indels: Vec<Indel>,
}

impl<'a> Contribution<'a> {
    pub fn new(path: &'a Path, text: &'a str, indels: Vec<Indel>) -> Self {
        Self {
            source: SourceRef { path, text },
            indels,
        }
    }
}

/// Why a transaction was refused.
///
/// Every variant means the same thing operationally — the plan is unchanged —
/// but they point at different bugs, so they are kept apart.
#[derive(Debug, Clone)]
pub enum StagingError {
    /// Two edits want the same bytes, either within the transaction or against
    /// something already scheduled.
    Conflict(Conflict),
    /// Two passes described the same file's original text differently, so at
    /// least one of them computed its offsets against source that is not what
    /// is on disk.
    SnapshotMismatch { file: PathBuf },
}

impl std::fmt::Display for StagingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StagingError::Conflict(c) => write!(f, "{c}"),
            StagingError::SnapshotMismatch { file } => write!(
                f,
                "{}: two passes supplied different source text for the same file",
                file.display()
            ),
        }
    }
}

impl std::error::Error for StagingError {}

#[derive(Debug)]
struct GroupedEdits {
    text: String,
    indels: Vec<Indel>,
}

/// The first pair of edits in `indels` that overlap, as two `(start, end)`.
///
/// Sorted by start so the check is a walk rather than a quadratic scan; these
/// sets are small but they are built per file per transaction.
fn first_overlap(indels: &[Indel]) -> Option<((u32, u32), (u32, u32))> {
    let mut sorted: Vec<&Indel> = indels.iter().collect();
    sorted.sort_by_key(|i| i.delete.start());
    sorted.windows(2).find_map(|pair| {
        overlaps(pair[0], pair[1]).then(|| {
            (
                (existing_start(pair[0]), existing_end(pair[0])),
                (existing_start(pair[1]), existing_end(pair[1])),
            )
        })
    })
}

#[derive(Debug, Default)]
pub struct EditPlan {
    /// The contents each edited file had when its edits were computed. Kept so
    /// the apply step can prove that the copy on disk is the same text, rather
    /// than trusting that nothing touched it in between.
    sources: BTreeMap<PathBuf, String>,
    edits: BTreeMap<PathBuf, Vec<Indel>>,
}

#[derive(Debug, Default)]
pub struct ApplyOutcome {
    pub files_edited: usize,
    pub edits_applied: usize,
}

impl EditPlan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.edits.values().all(|v| v.is_empty())
    }

    pub fn edit_count(&self) -> usize {
        self.edits.values().map(Vec::len).sum()
    }

    /// Files that will be rewritten, workspace-relative to `input_root`.
    pub fn edited_files(&self) -> impl Iterator<Item = &Path> {
        self.edits.keys().map(PathBuf::as_path)
    }

    /// Record the text a file had when the edits were computed.
    pub fn note_source(&mut self, path: &Path, text: &str) {
        self.sources
            .entry(path.to_path_buf())
            .or_insert_with(|| text.to_string());
    }

    /// Would staging this edit collide with one already scheduled?
    ///
    /// Exposed so a pass can validate every file it wants to touch *before*
    /// staging any of them. [`EditPlan::stage`] is atomic per file, and a
    /// rename that spans several files needs to be atomic across all of them.
    pub fn would_conflict(&self, path: &Path, indel: &Indel) -> Option<Conflict> {
        let existing = self.edits.get(path)?;
        existing
            .iter()
            .find(|e| overlaps(e, indel))
            .map(|clash| Conflict {
                file: path.to_path_buf(),
                existing: (existing_start(clash), existing_end(clash)),
                incoming: (existing_start(indel), existing_end(indel)),
            })
    }

    /// Schedule edits for one file.
    ///
    /// All-or-nothing: if any incoming edit overlaps one already scheduled, none
    /// of them are recorded, so a partially-applied pass cannot leave the file
    /// half rewritten.
    pub fn stage(
        &mut self,
        source: SourceRef<'_>,
        indels: impl IntoIterator<Item = Indel>,
    ) -> std::result::Result<usize, Conflict> {
        let incoming: Vec<Indel> = indels.into_iter().collect();
        if incoming.is_empty() {
            return Ok(0);
        }
        self.note_source(source.path, source.text);

        let existing = self.edits.entry(source.path.to_path_buf()).or_default();
        for candidate in &incoming {
            if let Some(clash) = existing.iter().find(|e| overlaps(e, candidate)) {
                return Err(Conflict {
                    file: source.path.to_path_buf(),
                    existing: (existing_start(clash), existing_end(clash)),
                    incoming: (existing_start(candidate), existing_end(candidate)),
                });
            }
        }
        let count = incoming.len();
        existing.extend(incoming);
        Ok(count)
    }

    /// Stage edits for many files at once, or stage none of them.
    ///
    /// [`EditPlan::stage`] is atomic per file, which is enough for a rename
    /// that owns one symbol. A Tauri command is not like that: its name lives
    /// in a Rust definition, in a `generate_handler!` token tree, in a frontend
    /// `invoke("...")` call and possibly in a Rust allow-list, and those are
    /// four different files. Committing three of the four would leave a project
    /// that does not compile or, worse, one that compiles and dispatches the
    /// wrong command.
    ///
    /// So the whole set is validated first and written second, and any problem
    /// anywhere means the plan is untouched.
    pub fn stage_transaction<'a>(
        &mut self,
        contributions: impl IntoIterator<Item = Contribution<'a>>,
    ) -> std::result::Result<usize, StagingError> {
        // Group by file first: two passes contributing to the same file is
        // normal (the command pass and the rename pass both touch `lib.rs`),
        // and the checks below are per file.
        let mut grouped: BTreeMap<PathBuf, GroupedEdits> = BTreeMap::new();
        for contribution in contributions {
            let path = contribution.source.path.to_path_buf();
            let entry = grouped.entry(path.clone()).or_insert_with(|| GroupedEdits {
                text: contribution.source.text.to_string(),
                indels: Vec::new(),
            });
            if entry.text != contribution.source.text {
                return Err(StagingError::SnapshotMismatch { file: path });
            }
            entry.indels.extend(contribution.indels);
        }

        // ---- validate the whole transaction before recording any of it ----

        for (path, group) in &grouped {
            if group.indels.is_empty() {
                continue;
            }

            // The snapshot this transaction works from must be the one the
            // plan already holds for that file. Two different texts for the
            // same path means one pass is working from a stale or wrong source,
            // and every offset it computed is suspect.
            if let Some(known) = self.sources.get(path) {
                if known != &group.text {
                    return Err(StagingError::SnapshotMismatch { file: path.clone() });
                }
            }

            // Edits inside this transaction must not overlap each other. Two
            // passes that both want the same span are not a merge problem to be
            // resolved here; one of them is wrong.
            if let Some((a, b)) = first_overlap(&group.indels) {
                return Err(StagingError::Conflict(Conflict {
                    file: path.clone(),
                    existing: (a.0, a.1),
                    incoming: (b.0, b.1),
                }));
            }

            // Nor may they overlap anything already scheduled.
            for indel in &group.indels {
                if let Some(clash) = self.would_conflict(path, indel) {
                    return Err(StagingError::Conflict(clash));
                }
            }
        }

        // ---- commit; nothing below can fail ----

        let mut staged = 0;
        for (path, group) in grouped {
            if group.indels.is_empty() {
                continue;
            }
            staged += group.indels.len();
            self.sources.entry(path.clone()).or_insert(group.text);
            self.edits.entry(path).or_default().extend(group.indels);
        }
        Ok(staged)
    }

    /// Write every scheduled edit into the generated tree.
    pub fn apply(&self, input_root: &Path, output_root: &Path) -> Result<ApplyOutcome> {
        let mut outcome = ApplyOutcome::default();

        for (abs_path, indels) in &self.edits {
            if indels.is_empty() {
                continue;
            }
            let rel = abs_path
                .strip_prefix(input_root)
                .with_context(|| format!("{} is not under the input root", abs_path.display()))?;
            let target = output_root.join(rel);

            let disk = std::fs::read_to_string(&target)
                .with_context(|| format!("reading generated file {}", target.display()))?;

            // Every offset indexes into the text the passes were given. The copy
            // is supposed to be byte-identical to it, and if it is not, the
            // edits would land in the wrong places — silently producing a tree
            // that does not compile, or one that does and means something else.
            // Divergence is a hard failure, not a warning: continuing would also
            // make `mapping.json` a lie.
            if let Some(expected) = self.sources.get(abs_path) {
                if &disk != expected {
                    anyhow::bail!(
                        "{} changed between analysis and rewrite; refusing to apply {} edit(s) \
                         against text that no longer matches",
                        target.display(),
                        indels.len()
                    );
                }
            }

            let rewritten = apply_indels(&disk, indels).with_context(|| {
                format!("applying {} edit(s) to {}", indels.len(), target.display())
            })?;
            std::fs::write(&target, rewritten)
                .with_context(|| format!("writing {}", target.display()))?;

            outcome.files_edited += 1;
            outcome.edits_applied += indels.len();
        }

        Ok(outcome)
    }
}

fn overlaps(a: &Indel, b: &Indel) -> bool {
    let a_empty = a.delete.is_empty();
    let b_empty = b.delete.is_empty();
    // Two pure insertions at the same offset do not overlap by the range test
    // — an empty range contains nothing — but the order they are applied in
    // decides the result, and nothing here is entitled to pick that order.
    if a_empty && b_empty {
        return a.delete.start() == b.delete.start();
    }
    a.delete.start() < b.delete.end() && b.delete.start() < a.delete.end()
}

fn existing_start(i: &Indel) -> u32 {
    u32::from(i.delete.start())
}

fn existing_end(i: &Indel) -> u32 {
    u32::from(i.delete.end())
}

/// Apply indels, which are expressed against the original text, in descending
/// order so that earlier offsets stay valid.
pub fn apply_indels(text: &str, indels: &[Indel]) -> Result<String> {
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

/// Build an indel that replaces `range` with `text`.
pub fn replace(start: u32, end: u32, text: impl Into<String>) -> Indel {
    Indel {
        insert: text.into(),
        delete: ra_ap_ide::TextRange::new(TextSize::from(start), TextSize::from(end)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indel(start: u32, end: u32, insert: &str) -> Indel {
        replace(start, end, insert)
    }

    fn source(path: &str, text: &str) -> (PathBuf, String) {
        (PathBuf::from(path), text.to_string())
    }

    #[test]
    fn indels_apply_backwards_so_offsets_stay_valid() {
        // Two renames in one line: `aa` at 0..2 and `bb` at 5..7.
        let edits = vec![indel(0, 2, "X"), indel(5, 7, "Y")];
        assert_eq!(apply_indels("aa = bb", &edits).unwrap(), "X = Y");
    }

    #[test]
    fn indels_can_grow_and_shrink_text() {
        assert_eq!(
            apply_indels("fn foo() {}", &[indel(3, 6, "qq8kap")]).unwrap(),
            "fn qq8kap() {}"
        );
        assert_eq!(
            apply_indels("fn qq8kap() {}", &[indel(3, 9, "a")]).unwrap(),
            "fn a() {}"
        );
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
    fn overlapping_edits_from_different_passes_are_rejected_atomically() {
        let (path, text) = source("src/lib.rs", "fn alpha() {}");
        let mut plan = EditPlan::new();
        plan.stage(
            SourceRef {
                path: &path,
                text: &text,
            },
            [indel(3, 8, "one")],
        )
        .unwrap();

        // A second pass wants a span that overlaps.
        let clash = plan
            .stage(
                SourceRef {
                    path: &path,
                    text: &text,
                },
                [indel(6, 10, "two")],
            )
            .unwrap_err();
        assert_eq!(clash.file, path);
        assert_eq!(clash.incoming, (6, 10));
        assert_eq!(clash.existing, (3, 8));

        // The rejected batch was not recorded, so the file is not half edited.
        assert_eq!(plan.edit_count(), 1);
    }

    #[test]
    fn disjoint_edits_from_different_passes_merge() {
        let (path, text) = source("src/lib.rs", "fn alpha() { beta(); }");
        let mut plan = EditPlan::new();
        plan.stage(
            SourceRef {
                path: &path,
                text: &text,
            },
            [indel(3, 8, "one")],
        )
        .unwrap();
        plan.stage(
            SourceRef {
                path: &path,
                text: &text,
            },
            [indel(13, 17, "two")],
        )
        .unwrap();

        assert_eq!(plan.edit_count(), 2);
        assert_eq!(
            apply_indels(&text, &plan.edits[&path]).unwrap(),
            "fn one() { two(); }"
        );
    }

    #[test]
    fn apply_refuses_when_the_copy_on_disk_diverged() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");
        std::fs::create_dir_all(input.join("src")).unwrap();
        std::fs::create_dir_all(output.join("src")).unwrap();
        std::fs::write(input.join("src/lib.rs"), "fn alpha() {}").unwrap();
        // The copy is not what the passes analysed.
        std::fs::write(output.join("src/lib.rs"), "fn alpha() {}\n// extra\n").unwrap();

        let mut plan = EditPlan::new();
        let path = input.join("src/lib.rs");
        plan.stage(
            SourceRef {
                path: &path,
                text: "fn alpha() {}",
            },
            [indel(3, 8, "one")],
        )
        .unwrap();

        let err = plan.apply(&input, &output).unwrap_err();
        assert!(
            format!("{err:#}").contains("changed between analysis and rewrite"),
            "{err:#}"
        );
        // And it did not write a mangled file.
        assert_eq!(
            std::fs::read_to_string(output.join("src/lib.rs")).unwrap(),
            "fn alpha() {}\n// extra\n"
        );
    }

    #[test]
    fn apply_writes_every_scheduled_edit() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");
        std::fs::create_dir_all(input.join("src")).unwrap();
        std::fs::create_dir_all(output.join("src")).unwrap();
        std::fs::write(input.join("src/a.rs"), "fn alpha() {}").unwrap();
        std::fs::write(input.join("src/b.rs"), "fn beta() {}").unwrap();
        std::fs::copy(input.join("src/a.rs"), output.join("src/a.rs")).unwrap();
        std::fs::copy(input.join("src/b.rs"), output.join("src/b.rs")).unwrap();

        let mut plan = EditPlan::new();
        for (name, original, replacement) in [("a.rs", "alpha", "one"), ("b.rs", "beta", "two")] {
            let path = input.join("src").join(name);
            let text = std::fs::read_to_string(&path).unwrap();
            let start = text.find(original).expect("name in source") as u32;
            plan.stage(
                SourceRef {
                    path: &path,
                    text: &text,
                },
                [indel(start, start + original.len() as u32, replacement)],
            )
            .unwrap();
        }

        let outcome = plan.apply(&input, &output).unwrap();
        assert_eq!(outcome.files_edited, 2);
        assert_eq!(
            std::fs::read_to_string(output.join("src/a.rs")).unwrap(),
            "fn one() {}"
        );
        assert_eq!(
            std::fs::read_to_string(output.join("src/b.rs")).unwrap(),
            "fn two() {}"
        );
    }

    // -- transactions ------------------------------------------------------

    /// Two files, one call, both written.
    #[test]
    fn a_transaction_spanning_files_commits_together() {
        let mut plan = EditPlan::new();
        let staged = plan
            .stage_transaction([
                Contribution::new(
                    Path::new("src/a.rs"),
                    "fn alpha() {}",
                    vec![indel(3, 8, "one")],
                ),
                Contribution::new(
                    Path::new("src/b.rs"),
                    "invoke(\"beta\")",
                    vec![indel(8, 12, "two")],
                ),
            ])
            .expect("clean transaction");

        assert_eq!(staged, 2);
        assert_eq!(plan.edit_count(), 2);
        assert_eq!(plan.edited_files().count(), 2);
    }

    /// Two edits inside one transaction that want the same bytes: nothing is
    /// recorded, including the edits that were fine.
    #[test]
    fn overlap_inside_the_batch_rolls_the_whole_transaction_back() {
        let mut plan = EditPlan::new();
        let before = plan.edit_count();

        let err = plan
            .stage_transaction([
                Contribution::new(
                    Path::new("src/a.rs"),
                    "fn alpha() {}",
                    vec![indel(3, 8, "one")],
                ),
                // A different file, which is perfectly fine on its own.
                Contribution::new(
                    Path::new("src/b.rs"),
                    "invoke(\"beta\")",
                    vec![indel(8, 12, "two")],
                ),
                // And this one collides with the first.
                Contribution::new(
                    Path::new("src/a.rs"),
                    "fn alpha() {}",
                    vec![indel(6, 10, "clash")],
                ),
            ])
            .expect_err("overlapping batch");

        match err {
            StagingError::Conflict(c) => {
                assert_eq!(c.file, PathBuf::from("src/a.rs"));
                assert_eq!(c.incoming, (6, 10), "the later edit is the incoming one");
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
        assert_eq!(
            plan.edit_count(),
            before,
            "a failed transaction writes nothing"
        );
        assert_eq!(plan.edited_files().count(), 0);
    }

    /// A transaction that collides with something already scheduled is refused
    /// whole, and the earlier edits survive untouched.
    #[test]
    fn existing_conflict_rolls_the_whole_transaction_back() {
        let path = Path::new("src/a.rs");
        let text = "fn alpha() { beta(); }";

        let mut plan = EditPlan::new();
        plan.stage(SourceRef { path, text }, [indel(13, 17, "one")])
            .expect("first staging");
        let before = plan.edit_count();

        let err = plan
            .stage_transaction([
                Contribution::new(
                    Path::new("src/b.rs"),
                    "invoke(\"beta\")",
                    vec![indel(8, 12, "two")],
                ),
                Contribution::new(path, text, vec![indel(15, 19, "clash")]),
            ])
            .expect_err("conflicts with existing");

        assert!(matches!(err, StagingError::Conflict(_)), "{err:?}");
        assert_eq!(plan.edit_count(), before);
        assert_eq!(
            plan.edited_files().count(),
            1,
            "the earlier edit, and only it, is still scheduled"
        );
    }

    /// The same file described two different ways: one pass is working from a
    /// snapshot that is not what the other saw.
    #[test]
    fn snapshot_mismatch_rolls_the_whole_transaction_back() {
        let mut plan = EditPlan::new();
        plan.stage(
            SourceRef {
                path: Path::new("src/a.rs"),
                text: "fn alpha() {}",
            },
            [indel(3, 8, "one")],
        )
        .expect("first staging");
        let before = plan.edit_count();

        let err = plan
            .stage_transaction([
                Contribution::new(
                    Path::new("src/b.rs"),
                    "invoke(\"beta\")",
                    vec![indel(8, 12, "two")],
                ),
                // Same path, different text.
                Contribution::new(
                    Path::new("src/a.rs"),
                    "fn ALPHA() {}",
                    vec![indel(3, 8, "two")],
                ),
            ])
            .expect_err("snapshot mismatch");

        match err {
            StagingError::SnapshotMismatch { file } => {
                assert_eq!(file, PathBuf::from("src/a.rs"));
            }
            other => panic!("expected a snapshot mismatch, got {other:?}"),
        }
        assert_eq!(plan.edit_count(), before);
    }

    /// Two passes may contribute to the same file, as long as they agree about
    /// its text and their spans are disjoint. The command pass and the rename
    /// pass both need this.
    #[test]
    fn contributions_to_one_file_merge_when_they_agree() {
        let path = Path::new("src/lib.rs");
        let text = "fn alpha() { invoke(\"beta\"); }";

        let mut plan = EditPlan::new();
        let staged = plan
            .stage_transaction([
                Contribution::new(path, text, vec![indel(3, 8, "one")]),
                Contribution::new(path, text, vec![indel(20, 24, "two")]),
            ])
            .expect("disjoint contributions to one file");

        assert_eq!(staged, 2);
        assert_eq!(plan.edit_count(), 2);
    }

    /// A transaction may not describe one file two different ways even when it
    /// is the only thing staging: that is a bug in the caller, not a merge.
    #[test]
    fn a_transaction_may_not_disagree_with_itself() {
        let path = Path::new("src/lib.rs");
        let mut plan = EditPlan::new();

        let err = plan
            .stage_transaction([
                Contribution::new(path, "fn alpha() {}", vec![indel(3, 8, "one")]),
                Contribution::new(path, "fn beta() {}", vec![indel(3, 7, "two")]),
            ])
            .expect_err("self-contradictory transaction");

        assert!(
            matches!(err, StagingError::SnapshotMismatch { .. }),
            "{err:?}"
        );
        assert_eq!(plan.edit_count(), 0);
    }

    /// Insertions at one offset have no defined order, so they are a conflict
    /// rather than a coin flip.
    #[test]
    fn two_insertions_at_one_offset_conflict() {
        let mut plan = EditPlan::new();
        let path = Path::new("src/lib.rs");

        let err = plan
            .stage_transaction([Contribution::new(
                path,
                "x",
                vec![indel(0, 0, "a"), indel(0, 0, "b")],
            )])
            .expect_err("ambiguous ordering");

        assert!(matches!(err, StagingError::Conflict(_)), "{err:?}");
        assert_eq!(plan.edit_count(), 0);
    }

    /// An empty contribution is not a failure and does not record a file.
    #[test]
    fn empty_contributions_are_ignored() {
        let mut plan = EditPlan::new();
        let staged = plan
            .stage_transaction([
                Contribution::new(Path::new("src/a.rs"), "fn alpha() {}", vec![]),
                Contribution::new(
                    Path::new("src/b.rs"),
                    "fn beta() {}",
                    vec![indel(3, 7, "x")],
                ),
            ])
            .expect("one real contribution");

        assert_eq!(staged, 1);
        assert_eq!(plan.edited_files().count(), 1);
    }
}
