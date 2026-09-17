//! The verification pipeline.
//!
//! Generating output is not the same as having generated *correct* output. A
//! source-to-source transform can produce text that looks plausible and does
//! not compile, or compiles and no longer means the same thing. Neither is
//! detectable by inspecting the diff, so the pipeline builds what it produced.
//!
//! Stages run in a fixed order, each one strictly more expensive than the last,
//! and the caller decides whether to stop at the first failure. `LeakScan` is
//! not a build stage — it is the check that the transform actually achieved
//! anything, by grepping the generated tree for the names it claims to have
//! removed.

use crate::config::VerifyStage;
use crate::mapping::Mapping;
use crate::report::StageResult;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

pub struct VerifyContext<'a> {
    /// Root of the generated workspace.
    pub output_root: &'a Path,
    /// Directory holding the generated `Cargo.toml`.
    pub rust_root: &'a Path,
    /// Directory holding the generated `package.json`.
    pub frontend_root: Option<&'a Path>,
    /// Directory the mapping was written to; excluded from the leak scan.
    pub mapping_dir: Option<&'a Path>,
    pub mapping: &'a Mapping,
}

pub struct VerifyReport {
    pub stages: Vec<StageResult>,
}

impl VerifyReport {
    pub fn passed(&self) -> bool {
        self.stages.iter().all(|s| s.passed)
    }
}

/// Run the requested stages in order.
///
/// `stages` is assumed to already be in the order the caller wants; the config
/// layer preserves the order the user wrote.
pub fn run(ctx: &VerifyContext<'_>, stages: &[VerifyStage]) -> VerifyReport {
    let mut out = Vec::new();
    for stage in stages {
        let result = run_one(ctx, *stage);
        let failed = !result.passed;
        out.push(result);
        if failed {
            // Later stages build on earlier ones succeeding; continuing would
            // produce a cascade of noise rather than information.
            break;
        }
    }
    VerifyReport { stages: out }
}

fn run_one(ctx: &VerifyContext<'_>, stage: VerifyStage) -> StageResult {
    let started = Instant::now();
    let outcome = match stage {
        VerifyStage::CargoMetadata => cargo(ctx, &["metadata", "--format-version", "1"]),
        VerifyStage::CargoCheck => cargo(ctx, &["check", "--all-targets"]),
        VerifyStage::CargoTest => cargo(ctx, &["test", "--no-run"]),
        VerifyStage::CargoClippy => cargo(ctx, &["clippy", "--all-targets"]),
        VerifyStage::NpmCi => npm(ctx, &["ci"]),
        VerifyStage::NpmTypecheck => npm_script(ctx, "typecheck"),
        VerifyStage::NpmBuild => npm_script(ctx, "build"),
        VerifyStage::TauriBuild => tauri_build(ctx),
        VerifyStage::LeakScan => leak_scan(ctx),
    };

    let duration_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(detail) => StageResult {
            stage: stage.as_str().to_string(),
            passed: true,
            duration_ms,
            detail,
        },
        Err(e) => StageResult {
            stage: stage.as_str().to_string(),
            passed: false,
            duration_ms,
            detail: Some(format!("{e:#}")),
        },
    }
}

/// `cargo <args>` in the generated Rust root.
fn cargo(ctx: &VerifyContext<'_>, args: &[&str]) -> Result<Option<String>> {
    let mut cmd = Command::new("cargo");
    cmd.args(args).current_dir(ctx.rust_root);
    // `--locked` keeps verification honest: it fails if the generated tree
    // would have resolved dependencies differently than the input did.
    // Without a copied lockfile there is nothing to lock against.
    if ctx.rust_root.join("Cargo.lock").is_file() {
        cmd.arg("--locked");
    }
    exec(cmd, "cargo")
}

fn npm(ctx: &VerifyContext<'_>, args: &[&str]) -> Result<Option<String>> {
    let Some(frontend) = ctx.frontend_root else {
        // A Rust-only project is not a project whose frontend failed to
        // install. Failing here would make the tool unusable on half of all
        // real projects, which is the same reasoning as `npm_script` below.
        return Ok(Some("no frontend root was detected; skipped".to_string()));
    };
    let mut cmd = Command::new(npm_program());
    cmd.args(args).current_dir(frontend);
    exec(cmd, "npm")
}

/// Run an npm script, treating "script not defined" as a pass with a note.
///
/// A project without a `typecheck` script is not a project that failed to
/// typecheck, and failing the build over it would make the tool unusable on
/// half of all real projects.
fn npm_script(ctx: &VerifyContext<'_>, script: &str) -> Result<Option<String>> {
    let Some(frontend) = ctx.frontend_root else {
        return Ok(Some("no frontend root was detected; skipped".to_string()));
    };
    if !has_npm_script(frontend, script)? {
        return Ok(Some(format!(
            "no `{script}` script in package.json; skipped"
        )));
    }
    let mut cmd = Command::new(npm_program());
    cmd.args(["run", script]).current_dir(frontend);
    exec(cmd, "npm")
}

fn tauri_build(ctx: &VerifyContext<'_>) -> Result<Option<String>> {
    let Some(frontend) = ctx.frontend_root else {
        return Ok(Some("no frontend root was detected; skipped".to_string()));
    };
    if !has_tauri_dependency(frontend) {
        return Ok(Some("tauri is not a dependency; skipped".to_string()));
    }
    let mut cmd = Command::new(npm_program());
    cmd.args(["exec", "--", "tauri", "build", "--no-bundle"])
        .current_dir(frontend);
    exec(cmd, "tauri")
}

/// Is `tauri` (the CLI package) available to the frontend?
fn has_tauri_dependency(frontend: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(frontend.join("package.json")) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    ["dependencies", "devDependencies"].iter().any(|section| {
        json.get(section)
            .and_then(|d| d.as_object())
            .map(|d| d.contains_key("@tauri-apps/cli") || d.contains_key("tauri"))
            .unwrap_or(false)
    })
}

fn has_npm_script(frontend: &Path, script: &str) -> Result<bool> {
    let manifest = frontend.join("package.json");
    let text = std::fs::read_to_string(&manifest)
        .with_context(|| format!("reading {}", manifest.display()))?;
    let json: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", manifest.display()))?;
    Ok(json.get("scripts").and_then(|s| s.get(script)).is_some())
}

/// npm is a batch script on Windows and cannot be spawned directly.
fn npm_program() -> &'static str {
    if cfg!(windows) {
        "npm.cmd"
    } else {
        "npm"
    }
}

fn exec(mut cmd: Command, label: &str) -> Result<Option<String>> {
    tracing::debug!(?cmd, "running {label}");
    let output = cmd
        .output()
        .with_context(|| format!("spawning {label}; is it on PATH?"))?;

    if output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let tail = |s: &str| -> String {
        const MAX_LINES: usize = 40;
        let lines: Vec<&str> = s.lines().collect();
        let start = lines.len().saturating_sub(MAX_LINES);
        lines[start..].join("\n")
    };

    anyhow::bail!(
        "{label} exited with {}\n--- stderr ---\n{}\n--- stdout ---\n{}",
        output.status,
        tail(&stderr),
        tail(&stdout)
    )
}

// ---------------------------------------------------------------------------
// leak scan
// ---------------------------------------------------------------------------

/// Extensions worth scanning for leaked identifiers.
const SCANNABLE: &[&str] = &[
    "rs", "ts", "tsx", "js", "jsx", "mjs", "cjs", "json", "html", "css", "toml", "vue", "svelte",
];

/// How many individual leaks to name before summarizing.
const MAX_REPORTED_LEAKS: usize = 40;

/// Directories the leak scan does not descend into.
///
/// Note what is *absent*: `dist`. Built frontend output is exactly where a
/// leaked identifier does the most damage — it is what actually ships — so it
/// is the one directory the scan must always reach. `target` is skipped
/// because it is compiled artifacts, which the separate binary scanner covers.
const SCAN_SKIP_DIRS: &[&str] = &[
    "target",
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    ".obfuscated",
    ".obfuscator",
    "__pycache__",
    ".venv",
    "venv",
];

fn leak_scan(ctx: &VerifyContext<'_>) -> Result<Option<String>> {
    let mut leaks: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    // Names that must no longer be findable. Single-character and very short
    // names are excluded: they match too much to be evidence of anything.
    let mut needles: Vec<&str> = ctx
        .mapping
        .sensitive_originals()
        .into_iter()
        .filter(|n| n.len() >= 3)
        .collect();
    needles.sort_unstable();
    needles.dedup();

    let mapping_abs = ctx.mapping_dir.map(|p| p.to_path_buf());

    for entry in walkdir::WalkDir::new(ctx.output_root)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                if crate::verify::SCAN_SKIP_DIRS.contains(&name.as_ref()) {
                    return false;
                }
            }
            if let Some(m) = &mapping_abs {
                if e.path().starts_with(m) {
                    return false;
                }
            }
            true
        })
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();

        let rel = path
            .strip_prefix(ctx.output_root)
            .unwrap_or(path)
            .display()
            .to_string();

        // Source maps must not ship at all, whatever they contain.
        if ext == "map" {
            leaks.push(format!("source map present: {rel}"));
            continue;
        }

        if !SCANNABLE.contains(&ext.as_str()) {
            continue;
        }

        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };

        if matches!(ext.as_str(), "js" | "mjs" | "cjs" | "ts" | "tsx")
            && text.contains("sourceMappingURL=")
        {
            leaks.push(format!("sourceMappingURL directive: {rel}"));
        }

        if needles.is_empty() {
            continue;
        }
        for needle in &needles {
            if contains_word(&text, needle) {
                leaks.push(format!("{needle:?} found in {rel}"));
            }
        }
    }

    if !ctx.mapping.is_empty() && needles.is_empty() {
        notes.push("mapping contained no names long enough to scan for".to_string());
    }

    if leaks.is_empty() {
        notes.push(format!("scanned for {} original name(s)", needles.len()));
        return Ok(Some(notes.join("; ")));
    }

    leaks.sort();
    leaks.dedup();
    let shown = leaks.len().min(MAX_REPORTED_LEAKS);
    let mut message = format!("{} leak(s) in the generated tree:\n", leaks.len());
    for leak in &leaks[..shown] {
        message.push_str(&format!("  {leak}\n"));
    }
    if leaks.len() > shown {
        message.push_str(&format!("  ... and {} more\n", leaks.len() - shown));
    }
    anyhow::bail!(message.trim_end().to_string())
}

/// Word-boundary containment.
///
/// A plain `contains` would report `connect` as leaking when all that is
/// present is `disconnected`, which would make the scan useless on any real
/// project.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() || needle_bytes.len() > bytes.len() {
        return false;
    }
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';

    let mut start = 0;
    while let Some(found) = haystack[start..].find(needle) {
        let at = start + found;
        let before_ok = at == 0 || !is_word(bytes[at - 1]);
        let after = at + needle_bytes.len();
        let after_ok = after >= bytes.len() || !is_word(bytes[after]);
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
        if start >= haystack.len() {
            break;
        }
    }
    false
}

/// Convenience for callers that need the mapping directory excluded.
pub fn resolve_mapping_dir(output_root: &Path, dir: &Path) -> PathBuf {
    if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        output_root.join(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_boundaries_prevent_false_positives() {
        assert!(contains_word("let connect = 1;", "connect"));
        assert!(!contains_word("disconnected", "connect"));
        assert!(!contains_word("connectivity", "connect"));
        assert!(!contains_word("reconnect", "connect"));
        assert!(contains_word("a.connect()", "connect"));
        assert!(contains_word("connect", "connect"));
    }

    #[test]
    fn word_boundary_check_handles_underscores() {
        assert!(contains_word("get_secret_status", "get_secret_status"));
        assert!(!contains_word(
            "my_get_secret_status_x",
            "get_secret_status"
        ));
        assert!(contains_word(
            "x = get_secret_status();",
            "get_secret_status"
        ));
    }

    #[test]
    fn repeated_partial_matches_do_not_hide_a_real_one() {
        // `connect` appears twice as a substring of longer words before the
        // real standalone occurrence.
        let text = "reconnect disconnected x = connect;";
        assert!(contains_word(text, "connect"));
    }

    #[test]
    fn leak_scan_finds_source_maps_and_original_names() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        std::fs::create_dir_all(out.join("frontend/dist")).unwrap();
        std::fs::write(
            out.join("frontend/dist/app.js"),
            "invoke('get_secret_status')",
        )
        .unwrap();

        let mut mapping = Mapping::new(1);
        mapping
            .commands
            .insert("get_secret_status".into(), "K81qm".into());

        // The mapping dir is excluded, so a mapping file inside the tree is
        // not itself reported as a leak.
        let mapping_dir = out.join(".obfuscator");
        std::fs::create_dir_all(&mapping_dir).unwrap();
        mapping.write(&mapping_dir.join("mapping.json")).unwrap();

        let ctx = VerifyContext {
            output_root: &out,
            rust_root: &out,
            frontend_root: None,
            mapping_dir: Some(&mapping_dir),
            mapping: &mapping,
        };

        let err = leak_scan(&ctx).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("get_secret_status"), "{msg}");
        assert!(msg.contains("app.js"), "{msg}");

        // Once the name is gone, the scan passes.
        std::fs::write(out.join("frontend/dist/app.js"), "invoke('K81qm')").unwrap();
        assert!(leak_scan(&ctx).unwrap().is_some());
    }

    #[test]
    fn leak_scan_reports_a_bare_source_map() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        std::fs::create_dir_all(out.join("dist")).unwrap();
        std::fs::write(out.join("dist/app.js.map"), "{}").unwrap();

        let mapping = Mapping::new(1);
        let ctx = VerifyContext {
            output_root: &out,
            rust_root: &out,
            frontend_root: None,
            mapping_dir: None,
            mapping: &mapping,
        };

        let err = leak_scan(&ctx).unwrap_err();
        assert!(format!("{err:#}").contains("source map present"), "{err:#}");
    }

    #[test]
    fn short_names_are_not_scanned_for() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("a.rs"), "fn ab() {}").unwrap();

        let mut mapping = Mapping::new(1);
        mapping.record_symbol("crate::ab", "Qx1");
        let ctx = VerifyContext {
            output_root: &out,
            rust_root: &out,
            frontend_root: None,
            mapping_dir: None,
            mapping: &mapping,
        };
        // Two-character names match too much to be evidence.
        assert!(leak_scan(&ctx).unwrap().is_some());
    }
}
