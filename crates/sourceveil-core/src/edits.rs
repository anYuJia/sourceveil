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
}
