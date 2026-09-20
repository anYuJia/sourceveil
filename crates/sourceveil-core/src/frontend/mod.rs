//! Frontend analysis, for the parts of the cross-language protocol that live
//! in TypeScript.
//!
//! This module is the shared half: finding source files, parsing them, and the
//! small helpers every analysis needs. The analyses live beside it —
//! [`commands`] for `invoke`, [`events`] for the event channel API — because
//! they have almost nothing in common. A command has a registry
//! (`generate_handler!`) and a fixed callee; an event has neither, and its
//! callee names are shared with every JavaScript event emitter in existence.
//!
//! ## Why an unresolved call is fatal rather than skipped
//!
//! `invoke(commandName)` and `listen(eventName, ...)` compute their name at
//! runtime. Nothing static can enumerate what it might be, so it might be *any*
//! name in that namespace. Renaming the other side while such a call exists
//! means the frontend asks for a name that no longer exists. There is no way to
//! rename "the statically referenced ones" and leave the rest — every name is
//! potentially the dynamic one. So one dynamic call keeps the entire
//! namespace, and the report says exactly where it is.

pub mod commands;
pub mod events;
pub mod rename;
pub mod strings;

use oxc_allocator::Allocator;
use oxc_ast::ast::Program;
use oxc_parser::Parser;
use oxc_span::SourceType;
use std::path::{Path, PathBuf};

/// Byte range in a frontend file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}

/// Every string literal in the frontend, kept so that a literal naming a
/// command can be found outside an `invoke` call.
#[derive(Debug, Clone)]
pub struct StringLiteral {
    pub file: PathBuf,
    pub span: Span,
    pub value: String,
}

/// One frontend source file, read once and shared by every analysis.
#[derive(Debug, Clone)]
pub struct SourceFile {
    pub path: PathBuf,
    pub text: String,
}

/// Extensions worth parsing.
const FRONTEND_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];

/// Directories never walked.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "dist",
    "build",
    "target",
    ".git",
    "coverage",
    "out",
];

/// Read every frontend source file below `root`.
///
/// Sorted by path so every analysis downstream — and therefore every edit
/// derived from it — comes out the same way on every run.
pub fn collect_sources(root: &Path) -> (Vec<SourceFile>, Vec<String>) {
    let mut sources = Vec::new();
    let mut warnings = Vec::new();
    for path in collect_files(root) {
        match std::fs::read_to_string(&path) {
            Ok(text) => sources.push(SourceFile { path, text }),
            Err(_) => warnings.push(format!("could not read {}; skipped", path.display())),
        }
    }
    (sources, warnings)
}

fn parse<'a>(allocator: &'a Allocator, source: &'a str, path: &Path) -> Option<Program<'a>> {
    let source_type = SourceType::from_path(path).unwrap_or_default();
    let ret = Parser::new(allocator, source, source_type).parse();
    if !ret.diagnostics.is_empty() {
        return None;
    }
    Some(ret.program)
}

fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            // A configured source root is authoritative even when its own
            // directory name is normally considered generated output (for
            // example a static Tauri frontend rooted directly at `dist`).
            // Skip matching directories only below that root.
            if e.depth() == 0 {
                return true;
            }
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                return !SKIP_DIRS.contains(&name.as_ref());
            }
            true
        })
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        if FRONTEND_EXTENSIONS.contains(&ext.as_str()) {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    files
}

/// The quote character a string literal starts with.
fn quote_at(source: &str, start: u32) -> char {
    source
        .get(start as usize..)
        .and_then(|s| s.chars().next())
        .unwrap_or('"')
}

fn slice(source: &str, start: u32, end: u32) -> &str {
    let (start, end) = (start as usize, (end as usize).min(source.len()));
    if start >= end {
        return "";
    }
    &source[start..end]
}

fn line_of(source: &str, offset: u32) -> u32 {
    let offset = (offset as usize).min(source.len());
    1 + source[..offset].matches('\n').count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_dist_root_is_scanned_but_nested_dist_is_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let dist = tmp.path().join("dist");
        std::fs::create_dir_all(dist.join("nested/dist")).unwrap();
        std::fs::write(dist.join("app.js"), "invoke('ping')").unwrap();
        std::fs::write(dist.join("nested/dist/stale.js"), "invoke('stale')").unwrap();

        let files = collect_files(&dist);
        assert_eq!(files, vec![dist.join("app.js")]);
    }
}
