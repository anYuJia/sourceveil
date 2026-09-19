//! Output workspace copier.
//!
//! Deliberately not `cp -r`. A Tauri project's build depends on a specific set
//! of files surviving verbatim — `Cargo.lock`, `tauri.conf.json`, `capabilities/`,
//! `icons/`, `scripts/` — and on a set of generated directories *not* surviving,
//! because a stale `target/` or `frontend/dist/` in the output would make the
//! verification step test artifacts rather than the transformed source.
//!
//! Everything not matched by an ignore rule is copied, which is the safe
//! default: a file we did not copy is a file whose absence could break the
//! build in a way that is hard to attribute.

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Directory names skipped at any depth. These are all reproducible build
/// outputs or VCS/tooling state — never source.
const IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".jj",
    ".svn",
    "target",
    "node_modules",
    "dist",
    ".obfuscated",
    ".obfuscator",
    ".idea",
    ".vscode",
    ".vs",
    "coverage",
    ".next",
    ".turbo",
    ".cache",
    ".parcel-cache",
    ".pytest_cache",
    "__pycache__",
    ".venv",
    "venv",
    ".gradle",
    ".mypy_cache",
    ".ruff_cache",
    ".svelte-kit",
    ".vercel",
    ".netlify",
];

/// Individual files skipped anywhere in the tree.
///
/// Git worktrees use a `.git` *file* pointing at the repository's worktree
/// metadata instead of a `.git` directory.  Copying that pointer makes the
/// generated workspace depend on the source checkout and leaves a broken Git
/// link as soon as the temporary worktree is removed.
const IGNORED_FILES: &[&str] = &[
    ".git",
    ".hg",
    ".jj",
    ".svn",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
];

#[derive(Debug, Clone, Default)]
pub struct CopyStats {
    pub files_copied: usize,
    pub dirs_created: usize,
    pub bytes_copied: u64,
    pub entries_skipped: usize,
}

#[derive(Debug, Clone)]
pub struct CopyOutcome {
    /// Workspace-relative paths of every regular file that landed in the
    /// output. The rename pass refuses to emit an edit for any file outside
    /// this set, so an incomplete copy surfaces as a skipped rename rather
    /// than as output that does not compile.
    pub copied: BTreeSet<PathBuf>,
    pub stats: CopyStats,
    pub warnings: Vec<String>,
}

/// Copy `input` into `output`, skipping build outputs and VCS state.
///
/// `extra_ignore` holds additional gitignore-style globs, matched against
/// workspace-relative paths.
pub fn copy_workspace(input: &Path, output: &Path, extra_ignore: &[String]) -> Result<CopyOutcome> {
    copy_workspace_preserving(input, output, extra_ignore, &[])
}

/// Copy a workspace while allowing explicitly configured source roots to
/// override the built-in generated-directory list for that exact directory.
/// Descendant `target`, `node_modules`, or nested `dist` directories remain
/// ignored.
pub fn copy_workspace_preserving(
    input: &Path,
    output: &Path,
    extra_ignore: &[String],
    preserve_roots: &[PathBuf],
) -> Result<CopyOutcome> {
    let input = input
        .canonicalize()
        .with_context(|| format!("resolving input root {}", input.display()))?;

    if output.exists() {
        let mut entries = std::fs::read_dir(output)
            .with_context(|| format!("reading output dir {}", output.display()))?;
        if entries.next().is_some() {
            anyhow::bail!(
                "output directory {} already exists and is not empty; \
                 refusing to write into it (remove it first, or pass a fresh path)",
                output.display()
            );
        }
    } else {
        std::fs::create_dir_all(output)
            .with_context(|| format!("creating output root {}", output.display()))?;
    }

    let output_abs = absolutize(output)?;
    let extra = build_globset(extra_ignore)?;
    let preserve_roots: BTreeSet<PathBuf> = preserve_roots
        .iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect();

    let mut outcome = CopyOutcome {
        copied: BTreeSet::new(),
        stats: CopyStats::default(),
        warnings: Vec::new(),
    };

    let walker = WalkDir::new(&input)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| should_descend(e, &input, &output_abs, &extra, &preserve_roots));

    for entry in walker {
        let entry = entry.with_context(|| format!("walking {}", input.display()))?;
        let path = entry.path();
        let rel = match path.strip_prefix(&input) {
            Ok(r) => r,
            // The root itself.
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() {
            continue;
        }

        let dest = output.join(rel);
        let file_type = entry.file_type();

        if file_type.is_dir() {
            std::fs::create_dir_all(&dest)
                .with_context(|| format!("creating {}", dest.display()))?;
            outcome.stats.dirs_created += 1;
        } else if file_type.is_file() {
            std::fs::copy(path, &dest)
                .with_context(|| format!("copying {} -> {}", path.display(), dest.display()))?;
            outcome.stats.files_copied += 1;
            outcome.stats.bytes_copied += entry.metadata().map(|m| m.len()).unwrap_or(0);
            outcome.copied.insert(rel.to_path_buf());
        } else if file_type.is_symlink() {
            match copy_symlink(path, &dest) {
                Ok(()) => {
                    // A symlink is not a file we can rewrite; record it as
                    // uncopyable for edit purposes by leaving it out of
                    // `copied`, and say so.
                    outcome.warnings.push(format!(
                        "preserved symlink {} (its target is not transformed)",
                        rel.display()
                    ));
                }
                Err(e) => {
                    outcome.stats.entries_skipped += 1;
                    outcome
                        .warnings
                        .push(format!("skipped symlink {}: {e}", rel.display()));
                }
            }
        } else {
            outcome.stats.entries_skipped += 1;
        }
    }

    Ok(outcome)
}

/// Decide whether to descend into (and copy) an entry.
fn should_descend(
    entry: &walkdir::DirEntry,
    input: &Path,
    output_abs: &Path,
    extra: &GlobSet,
    preserve_roots: &BTreeSet<PathBuf>,
) -> bool {
    let path = entry.path();
    if path == input {
        return true;
    }

    // Never copy the output tree into itself.
    if let Ok(abs) = absolutize(path) {
        if abs == *output_abs || abs.starts_with(output_abs) {
            return false;
        }
    }

    let name = entry.file_name().to_string_lossy();
    let explicitly_preserved = preserve_roots.contains(path);

    if entry.file_type().is_dir() {
        if !explicitly_preserved && IGNORED_DIRS.iter().any(|d| *d == name) {
            return false;
        }
    } else if IGNORED_FILES.iter().any(|f| *f == name) {
        return false;
    }

    if !extra.is_empty() {
        if let Ok(rel) = path.strip_prefix(input) {
            if extra.is_match(rel) {
                return false;
            }
        }
    }

    true
}

fn copy_symlink(src: &Path, dest: &Path) -> Result<()> {
    let target = std::fs::read_link(src)?;
    if dest.exists() || dest.symlink_metadata().is_ok() {
        std::fs::remove_file(dest).ok();
    }
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, dest)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // Windows symlinks need privileges; fall back to copying the target
        // contents when it is a regular file.
        let resolved = src
            .parent()
            .map(|p| p.join(&target))
            .unwrap_or(target.clone());
        if resolved.is_file() {
            std::fs::copy(&resolved, dest)?;
            Ok(())
        } else {
            anyhow::bail!("cannot recreate symlink to {}", target.display())
        }
    }
}

fn absolutize(p: &Path) -> Result<PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(p))
    }
}

pub fn build_globset(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p).with_context(|| format!("invalid glob pattern {p:?}"))?);

        // A trailing `/**` should prune the directory it names, not merely
        // empty it. Without this, `vendor/**` matches `vendor/skip.rs` but not
        // `vendor` itself, so the walker descends and leaves an empty
        // directory behind in the output.
        if let Some(prefix) = p.strip_suffix("/**") {
            if !prefix.is_empty() {
                builder.add(
                    Glob::new(prefix)
                        .with_context(|| format!("invalid glob pattern {prefix:?}"))?,
                );
            }
        }
    }
    builder.build().context("building glob set")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn copies_sources_and_skips_build_outputs() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");

        write(&input.join("Cargo.toml"), "[package]");
        write(&input.join("Cargo.lock"), "lock");
        write(&input.join("src/main.rs"), "fn main() {}");
        write(&input.join("src-tauri/tauri.conf.json"), "{}");
        write(&input.join("target/debug/junk"), "junk");
        write(&input.join("node_modules/pkg/index.js"), "junk");
        write(&input.join("frontend/dist/app.js"), "junk");
        write(&input.join(".git/config"), "junk");
        write(&input.join(".DS_Store"), "junk");

        let out = copy_workspace(&input, &output, &[]).unwrap();

        assert!(output.join("Cargo.toml").is_file());
        assert!(
            output.join("Cargo.lock").is_file(),
            "Cargo.lock must survive"
        );
        assert!(output.join("src/main.rs").is_file());
        assert!(
            output.join("src-tauri/tauri.conf.json").is_file(),
            "tauri.conf.json must survive"
        );
        assert!(!output.join("target").exists());
        assert!(!output.join("node_modules").exists());
        assert!(!output.join("frontend/dist").exists());
        assert!(!output.join(".git").exists());
        assert!(!output.join(".DS_Store").exists());

        assert!(out.copied.contains(Path::new("Cargo.lock")));
        assert!(out.copied.contains(Path::new("src/main.rs")));
        assert_eq!(out.stats.files_copied, 4);
    }

    #[test]
    fn skips_git_worktree_pointer_file() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");

        write(
            &input.join(".git"),
            "gitdir: /repo/.git/worktrees/example\n",
        );
        write(&input.join("src/main.rs"), "fn main() {}");

        let out = copy_workspace(&input, &output, &[]).unwrap();

        assert!(!output.join(".git").exists());
        assert!(output.join("src/main.rs").is_file());
        assert!(!out.copied.contains(Path::new(".git")));
        assert_eq!(out.stats.files_copied, 1);
    }

    #[test]
    fn extra_globs_are_honoured() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");

        write(&input.join("keep.rs"), "x");
        write(&input.join("vendor/skip.rs"), "x");

        copy_workspace(&input, &output, &["vendor/**".to_string()]).unwrap();

        assert!(output.join("keep.rs").is_file());
        assert!(!output.join("vendor").exists());
    }

    #[test]
    fn explicit_static_frontend_root_is_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");

        write(&input.join("src/main.rs"), "fn main() {}");
        write(&input.join("dist/app.js"), "invoke('ping')");
        write(&input.join("dist/node_modules/pkg/index.js"), "junk");
        write(&input.join("dist/nested/dist/stale.js"), "junk");

        let out = copy_workspace_preserving(&input, &output, &[], &[input.join("dist")]).unwrap();

        assert!(output.join("dist/app.js").is_file());
        assert!(!output.join("dist/node_modules").exists());
        assert!(!output.join("dist/nested/dist").exists());
        assert!(out.copied.contains(Path::new("dist/app.js")));
    }

    #[test]
    fn refuses_to_write_into_a_populated_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in");
        let output = tmp.path().join("out");
        write(&input.join("a.rs"), "x");
        write(&output.join("existing.rs"), "x");

        let err = copy_workspace(&input, &output, &[]).unwrap_err();
        assert!(format!("{err}").contains("already exists and is not empty"));
    }

    /// The output directory often lives inside the project (`./.obfuscated`).
    /// Recursing into it would copy the build into itself.
    #[test]
    fn output_inside_input_is_not_recursed_into() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("in");
        write(&input.join("a.rs"), "x");

        let output = input.join(".obfuscated");
        // `copy_workspace` creates the output directory before it walks, so it
        // is present (and empty) by the time the walker reaches it.
        copy_workspace(&input, &output, &[]).unwrap();

        assert!(output.join("a.rs").is_file());
        assert!(
            !output.join(".obfuscated").exists(),
            "the output tree must not be copied into itself"
        );
    }
}
