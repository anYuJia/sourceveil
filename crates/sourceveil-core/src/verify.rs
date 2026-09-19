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
use crate::edits::{apply_indels, replace};
use crate::mapping::Mapping;
use crate::report::StageResult;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceRepairOutcome {
    pub passes: usize,
    pub references_repaired: usize,
    pub check_passed: bool,
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

/// Complete reference edits that the IDE analysis could not prove but rustc's
/// fully expanded type checker can. This is intentionally a narrow feedback
/// loop: only primary spans from missing field/method/path diagnostics are
/// eligible, the span must still contain one exact original identifier, and
/// that identifier must have one unambiguous replacement in the mapping.
///
/// This covers proc-macro-generated `Deref` wrappers (for example
/// `tauri::State<T>.field`) and inference that rust-analyzer omits, without
/// falling back to global text replacement. Every batch is followed by a new
/// compiler run; the ordinary verification stage still runs afterward.
pub fn repair_rust_references(
    rust_root: &Path,
    mapping: &Mapping,
    max_passes: usize,
) -> Result<ReferenceRepairOutcome> {
    let replacements = unambiguous_symbol_names(mapping);
    if replacements.is_empty() || max_passes == 0 {
        return Ok(ReferenceRepairOutcome::default());
    }

    let canonical_root = rust_root
        .canonicalize()
        .with_context(|| format!("resolving {}", rust_root.display()))?;
    let mut outcome = ReferenceRepairOutcome::default();

    for _ in 0..max_passes {
        outcome.passes += 1;
        let mut cmd = Command::new("cargo");
        cmd.args(["check", "--all-targets", "--message-format=json"])
            .current_dir(rust_root);
        if rust_root.join("Cargo.lock").is_file() {
            cmd.arg("--locked");
        }
        let output = cmd
            .output()
            .context("spawning cargo for compiler-guided reference repair")?;
        if output.status.success() {
            outcome.check_passed = true;
            break;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut by_file: BTreeMap<PathBuf, Vec<ra_ap_ide::Indel>> = BTreeMap::new();
        for line in stdout.lines() {
            let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if message.get("reason").and_then(|value| value.as_str()) != Some("compiler-message")
                || message
                    .pointer("/message/level")
                    .and_then(|value| value.as_str())
                    != Some("error")
            {
                continue;
            }
            let code = message
                .pointer("/message/code/code")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            if !matches!(
                code,
                "E0412"
                    | "E0422"
                    | "E0425"
                    | "E0433"
                    | "E0531"
                    | "E0532"
                    | "E0559"
                    | "E0560"
                    | "E0599"
                    | "E0609"
            ) {
                continue;
            }
            let Some(spans) = message
                .pointer("/message/spans")
                .and_then(|value| value.as_array())
            else {
                continue;
            };
            for span in spans {
                if span.get("is_primary").and_then(|value| value.as_bool()) != Some(true) {
                    continue;
                }
                let Some(relative) = span.get("file_name").and_then(|value| value.as_str()) else {
                    continue;
                };
                let path = rust_root.join(relative);
                let Ok(canonical_path) = path.canonicalize() else {
                    continue;
                };
                if !canonical_path.starts_with(&canonical_root) {
                    continue;
                }
                let Some(start) = span.get("byte_start").and_then(|value| value.as_u64()) else {
                    continue;
                };
                let Some(end) = span.get("byte_end").and_then(|value| value.as_u64()) else {
                    continue;
                };
                let Ok(source) = std::fs::read_to_string(&canonical_path) else {
                    continue;
                };
                let (start, end) = (start as usize, end as usize);
                let Some(original) = source.get(start..end) else {
                    continue;
                };
                let logical = original.strip_prefix("r#").unwrap_or(original);
                let Some(replacement) = replacements.get(logical) else {
                    continue;
                };
                by_file.entry(canonical_path).or_default().push(replace(
                    start as u32,
                    end as u32,
                    replacement.clone(),
                ));
            }
        }

        let mut repaired_this_pass = 0usize;
        for (path, edits) in &mut by_file {
            edits.sort_by_key(|edit| (edit.delete.start(), edit.delete.end()));
            edits
                .dedup_by(|left, right| left.delete == right.delete && left.insert == right.insert);
            let source = std::fs::read_to_string(path)
                .with_context(|| format!("reading {} for reference repair", path.display()))?;
            let rewritten = apply_indels(&source, edits)
                .with_context(|| format!("repairing references in {}", path.display()))?;
            std::fs::write(path, rewritten)
                .with_context(|| format!("writing repaired {}", path.display()))?;
            repaired_this_pass += edits.len();
        }
        outcome.references_repaired += repaired_this_pass;
        if repaired_this_pass == 0 {
            break;
        }
    }

    Ok(outcome)
}

fn unambiguous_symbol_names(mapping: &Mapping) -> HashMap<String, String> {
    let mut names: HashMap<String, Option<String>> = HashMap::new();
    for (path, replacement) in &mapping.symbols {
        let Some(leaf) = path.rsplit("::").next() else {
            continue;
        };
        if leaf.contains('@') {
            continue;
        }
        let logical = leaf.strip_prefix("r#").unwrap_or(leaf).to_string();
        match names.entry(logical) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Some(replacement.clone()));
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().as_ref() != Some(replacement) {
                    entry.insert(None);
                }
            }
        }
    }
    names
        .into_iter()
        .filter_map(|(name, replacement)| replacement.map(|replacement| (name, replacement)))
        .collect()
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
    let mut fatal: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    // Grouped so a hundred hits of one common name is one line, not a hundred.
    let mut symbol_hits: BTreeMap<String, (usize, String)> = BTreeMap::new();

    // Protocol values are unambiguous: a command name is a value the frontend
    // sends, so finding one in the output means a call site was missed. Symbol
    // names are ordinary identifiers and are only reported — see
    // [`crate::mapping::Mapping::symbol_originals`] for why.
    let protocol: Vec<&str> = ctx
        .mapping
        .protocol_originals()
        .into_iter()
        .filter(|n| n.len() >= 3)
        .collect();
    let symbols: Vec<&str> = ctx
        .mapping
        .symbol_originals()
        .into_iter()
        .filter(|n| n.len() >= 3)
        .collect();

    let mapping_abs = ctx.mapping_dir.map(|p| p.to_path_buf());

    for entry in walkdir::WalkDir::new(ctx.output_root)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                if SCAN_SKIP_DIRS.contains(&name.as_ref()) {
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
            fatal.push(format!("source map present: {rel}"));
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
            fatal.push(format!("sourceMappingURL directive: {rel}"));
        }

        for needle in &protocol {
            let allow_backtick = matches!(
                ext.as_str(),
                "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "html" | "vue" | "svelte"
            );
            if contains_quoted(&text, needle, allow_backtick) {
                fatal.push(format!("{needle:?} found in {rel}"));
            }
        }
        for needle in &symbols {
            if contains_word(&text, needle) {
                let entry = symbol_hits
                    .entry((*needle).to_string())
                    .or_insert((0, rel.clone()));
                entry.0 += 1;
            }
        }
    }

    if !fatal.is_empty() {
        fatal.sort();
        fatal.dedup();
        let shown = fatal.len().min(MAX_REPORTED_LEAKS);
        let mut message = format!("{} leak(s) in the generated tree:\n", fatal.len());
        for leak in &fatal[..shown] {
            message.push_str(&format!("  {leak}\n"));
        }
        if fatal.len() > shown {
            message.push_str(&format!("  ... and {} more\n", fatal.len() - shown));
        }
        anyhow::bail!(message.trim_end().to_string());
    }

    notes.push(format!(
        "scanned for {} protocol value(s) and {} symbol name(s)",
        protocol.len(),
        symbols.len()
    ));
    if !symbol_hits.is_empty() {
        // Not a failure: the same text survives legitimately in comments, in
        // the other language, and as unrelated API names.
        let mut names: Vec<(&String, &(usize, String))> = symbol_hits.iter().collect();
        names.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
        notes.push(format!(
            "{} renamed symbol name(s) still appear as text, which is expected for common \
             words and cross-language names: {}",
            names.len(),
            names
                .iter()
                .take(8)
                .map(|(name, (count, file))| format!("{name} x{count} (e.g. {file})"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    Ok(Some(notes.join("; ")))
}

/// Does the text contain this value as a quoted literal?
///
/// A protocol value leaks by surviving as a *string* — an `invoke("...")` that
/// was not rewritten, a command name left in an allow-list. Matching the bare
/// word instead would also fire on an unrelated identifier that happens to
/// share the name, which is common: a frontend helper named `ping` beside a
/// command named `ping` is not a leak.
fn contains_quoted(haystack: &str, needle: &str, allow_backtick: bool) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut quotes = vec!['"', '\''];
    if allow_backtick {
        quotes.push('`');
    }
    quotes
        .iter()
        .any(|quote| haystack.contains(&format!("{quote}{needle}{quote}")))
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

    /// A command name beside an unrelated identifier of the same name.
    #[test]
    fn a_bare_identifier_sharing_a_protocol_value_is_not_a_leak() {
        assert!(contains_quoted(r#"invoke("ping")"#, "ping", true));
        assert!(!contains_quoted(
            "export function ping() { return 1; }",
            "ping",
            true,
        ));
        assert!(!contains_quoted(
            "#[tauri::command] fn ping() {}",
            "ping",
            false,
        ));
        assert!(contains_quoted("const ALLOWED = ['ping'];", "ping", true));
        assert!(contains_quoted("const s = `ping`;", "ping", true));
        assert!(!contains_quoted(
            "/// Reads the hidden `.downloaded` marker.",
            ".downloaded",
            false,
        ));
    }

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

    #[test]
    fn rustc_diagnostics_complete_only_exact_mapped_member_spans() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='repair_fixture'\nversion='0.1.0'\nedition='2024'\n[workspace]\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.rs"),
            "struct Item { x_hidden:i32 }\nimpl Item { fn run_hidden(&self){} }\nfn main(){let item=Item{x:1};let _=item.x;item.run();}\n",
        )
        .unwrap();
        let mut mapping = Mapping::new(1);
        mapping.record_symbol("repair_fixture::Item::x", "x_hidden");
        mapping.record_symbol("repair_fixture::Item::run", "run_hidden");

        let repaired = repair_rust_references(root, &mapping, 4).unwrap();
        assert!(repaired.check_passed, "{repaired:?}");
        assert_eq!(repaired.references_repaired, 3);
        let source = std::fs::read_to_string(root.join("src/main.rs")).unwrap();
        assert!(source.contains("Item{x_hidden:1}"));
        assert!(source.contains("item.x_hidden"));
        assert!(source.contains("item.run_hidden()"));
    }

    #[test]
    fn rustc_diagnostics_complete_enum_variant_record_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='repair_enum_fixture'\nversion='0.1.0'\nedition='2024'\n[workspace]\n",
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.rs"),
            "enum Event { Changed { task_hidden:String, state_hidden:u8 } }\nfn main(){let _=Event::Changed{task:String::new(),state:1};}\n",
        )
        .unwrap();
        let mut mapping = Mapping::new(1);
        mapping.record_symbol("repair_enum_fixture::Event::Changed::task", "task_hidden");
        mapping.record_symbol("repair_enum_fixture::Event::Changed::state", "state_hidden");

        let repaired = repair_rust_references(root, &mapping, 4).unwrap();
        assert!(repaired.check_passed, "{repaired:?}");
        assert_eq!(repaired.references_repaired, 2);
        let source = std::fs::read_to_string(root.join("src/main.rs")).unwrap();
        assert!(source.contains("task_hidden:String::new()"));
        assert!(source.contains("state_hidden:1"));
    }
}
