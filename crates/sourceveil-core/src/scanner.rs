//! Project discovery.
//!
//! Locates the Rust manifest and the frontend root, then asks `cargo metadata`
//! for the real crate graph. The graph is what lets the rename pass answer the
//! only visibility question that matters: *can anything outside this workspace
//! reach this item?* A `pub` item in a binary crate is private in every sense
//! that counts; the same `pub` item in a library that a third-party crate
//! depends on is a contract.

use anyhow::{bail, Context, Result};
use cargo_metadata::{CrateType, Metadata, MetadataCommand, PackageId, TargetKind};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// A Tauri project's canonical layout, as far as this tool cares.
#[derive(Debug, Clone)]
pub struct ProjectLayout {
    /// Root of the input tree.
    pub root: PathBuf,
    /// Directory holding the application's `Cargo.toml`.
    pub rust_root: PathBuf,
    /// The manifest passed to `cargo metadata`.
    pub rust_manifest: PathBuf,
    /// Directory holding `package.json`, when the project has a frontend.
    pub frontend_root: Option<PathBuf>,
    /// Frontend source directory (defaults to `<frontend_root>/src`).
    pub frontend_source: Option<PathBuf>,
    /// `true` when a `tauri.conf.json` was found next to the Rust manifest.
    pub is_tauri: bool,
    pub crates: CrateGraph,
}

/// The subset of `cargo metadata` the passes actually consume.
#[derive(Debug, Clone, Default)]
pub struct CrateGraph {
    /// Every workspace member, by crate name.
    pub workspace: BTreeMap<String, CrateInfo>,
    /// Workspace members that something outside the workspace depends on.
    /// Their public API is a contract and must not be renamed.
    pub boundary: BTreeSet<String>,
    pub target_directory: Option<PathBuf>,
    pub workspace_root: Option<PathBuf>,
    /// Warnings worth surfacing in the run report.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CrateInfo {
    pub name: String,
    pub manifest_dir: PathBuf,
    pub src_dir: Option<PathBuf>,
    /// Crate types across all targets: `lib`, `bin`, `cdylib`, `proc-macro`, …
    pub crate_types: BTreeSet<String>,
    pub is_proc_macro: bool,
    /// The crate has at least one `lib`/`cdylib`/`staticlib` target, so it can
    /// be linked against from outside.
    pub is_library: bool,
}

impl CrateInfo {
    /// Public items in this crate are reachable from outside the workspace.
    pub fn has_external_consumers(&self, graph: &CrateGraph) -> bool {
        graph.boundary.contains(&self.name)
    }
}

impl ProjectLayout {
    /// Locate the project rooted at `root`, honouring explicit config overrides.
    pub fn discover(
        root: &Path,
        rust_root_override: Option<&Path>,
        frontend_root_override: Option<&Path>,
        frontend_source_override: Option<&Path>,
    ) -> Result<Self> {
        let root = root
            .canonicalize()
            .with_context(|| format!("resolving project root {}", root.display()))?;

        let rust_root = match rust_root_override {
            Some(p) => root.join(p),
            None => detect_rust_root(&root)?,
        };
        let rust_manifest = rust_root.join("Cargo.toml");
        if !rust_manifest.is_file() {
            bail!(
                "no Cargo.toml at {}; set [project] rust_root in the obfuscator config",
                rust_manifest.display()
            );
        }

        let crates = load_crate_graph(&rust_manifest)?;

        let frontend_root = match frontend_root_override {
            Some(p) => Some(root.join(p)),
            None => detect_frontend_root(&root, &rust_root),
        };
        let frontend_root = frontend_root.filter(|p| p.join("package.json").is_file());

        let frontend_source = match (frontend_root.as_ref(), frontend_source_override) {
            (Some(fr), Some(p)) => Some(fr.join(p)),
            (Some(fr), None) => {
                let src = fr.join("src");
                src.is_dir().then_some(src)
            }
            (None, _) => None,
        };

        let is_tauri = crate::scanner::find_tauri_conf(&rust_root).is_some();

        Ok(ProjectLayout {
            root,
            rust_root,
            rust_manifest,
            frontend_root,
            frontend_source,
            is_tauri,
            crates,
        })
    }

    /// Workspace-relative path for an absolute path inside the project, if any.
    pub fn rel(&self, abs: &Path) -> Option<PathBuf> {
        abs.strip_prefix(&self.root).ok().map(|p| p.to_path_buf())
    }
}

/// `src-tauri/Cargo.toml` for a Tauri app, else the nearest root manifest.
fn detect_rust_root(root: &Path) -> Result<PathBuf> {
    let src_tauri = root.join("src-tauri/Cargo.toml");
    if src_tauri.is_file() {
        return Ok(root.join("src-tauri"));
    }
    if root.join("Cargo.toml").is_file() {
        return Ok(root.to_path_buf());
    }
    // Last resort: a single crate directory below the root.
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("reading {}", root.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_dir() && entry.path().join("Cargo.toml").is_file() {
            found.push(entry.path());
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => bail!(
            "could not find a Cargo.toml under {}; set [project] rust_root",
            root.display()
        ),
        _ => bail!(
            "found {} candidate crates under {}; set [project] rust_root to disambiguate",
            found.len(),
            root.display()
        ),
    }
}

fn detect_frontend_root(root: &Path, rust_root: &Path) -> Option<PathBuf> {
    if root.join("package.json").is_file() {
        return Some(root.to_path_buf());
    }
    // The conventional Tauri layout keeps the UI next to `src-tauri`.
    let parent = rust_root.parent().unwrap_or(root);
    for name in ["frontend", "ui", "web", "app", "client"] {
        let candidate = parent.join(name);
        if candidate.join("package.json").is_file() {
            return Some(candidate);
        }
    }
    // Any immediate subdirectory with a package.json, if there is exactly one.
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                && entry.path().join("package.json").is_file()
            {
                found.push(entry.path());
            }
        }
    }
    if found.len() == 1 {
        found.pop()
    } else {
        None
    }
}

/// Locate `tauri.conf.json` (or its json5 variant) next to the manifest.
pub fn find_tauri_conf(rust_root: &Path) -> Option<PathBuf> {
    ["tauri.conf.json", "tauri.conf.json5", "Tauri.toml"]
        .iter()
        .map(|n| rust_root.join(n))
        .find(|p| p.is_file())
}

/// Run `cargo metadata` and fold the result into a [`CrateGraph`].
pub fn load_crate_graph(manifest: &Path) -> Result<CrateGraph> {
    let metadata = MetadataCommand::new()
        .manifest_path(manifest)
        .exec()
        .with_context(|| {
            format!(
                "running `cargo metadata` for {}; the project must build far enough \
                 for cargo to resolve its dependency graph",
                manifest.display()
            )
        })?;

    fold_metadata(&metadata)
}

fn fold_metadata(metadata: &Metadata) -> Result<CrateGraph> {
    let mut graph = CrateGraph {
        target_directory: Some(metadata.target_directory.clone().into_std_path_buf()),
        workspace_root: Some(metadata.workspace_root.clone().into_std_path_buf()),
        ..Default::default()
    };

    let members: BTreeSet<&PackageId> = metadata.workspace_members.iter().collect();

    for package in &metadata.packages {
        if !members.contains(&package.id) {
            continue;
        }
        let manifest_dir = package
            .manifest_path
            .parent()
            .map(|p| p.as_std_path().to_path_buf())
            .unwrap_or_default();

        let mut crate_types = BTreeSet::new();
        for ct in package.targets.iter().flat_map(|t| t.crate_types.iter()) {
            crate_types.insert(crate_type_name(ct));
        }
        for kind in package.targets.iter().flat_map(|t| t.kind.iter()) {
            crate_types.insert(target_kind_name(kind));
        }

        let is_proc_macro = crate_types.contains("proc-macro");
        let is_library = crate_types.iter().any(|c| {
            matches!(
                c.as_str(),
                "lib" | "rlib" | "dylib" | "cdylib" | "staticlib"
            )
        });

        let name = package.name.to_string();
        graph.workspace.insert(
            name.clone(),
            CrateInfo {
                name,
                src_dir: package
                    .targets
                    .iter()
                    .filter_map(|t| t.src_path.parent())
                    .map(|p| p.as_std_path().to_path_buf())
                    .next(),
                manifest_dir,
                crate_types,
                is_proc_macro,
                is_library,
            },
        );
    }

    // Which workspace crates are reachable from outside the workspace?
    if let Some(resolve) = &metadata.resolve {
        let member_names: BTreeMap<&PackageId, String> = metadata
            .packages
            .iter()
            .filter(|p| members.contains(&p.id))
            .map(|p| (&p.id, p.name.to_string()))
            .collect();

        for node in &resolve.nodes {
            if member_names.contains_key(&node.id) {
                continue;
            }
            for dep in &node.deps {
                if let Some(name) = member_names.get(&dep.pkg) {
                    graph.boundary.insert(name.clone());
                }
            }
        }
    } else {
        graph.warnings.push(
            "`cargo metadata` returned no resolve graph; cross-workspace reachability \
             could not be computed, so every workspace crate is treated as an API boundary"
                .to_string(),
        );
        graph.boundary = graph.workspace.keys().cloned().collect();
    }

    Ok(graph)
}

/// Cargo's crate-type vocabulary, as a string.
///
/// `CrateType` is `#[non_exhaustive]` and carries an `Unknown(String)` arm for
/// values cargo adds later, so the match cannot be exhaustive by construction.
fn crate_type_name(ct: &CrateType) -> String {
    match ct {
        CrateType::Bin => "bin",
        CrateType::CDyLib => "cdylib",
        CrateType::DyLib => "dylib",
        CrateType::Lib => "lib",
        CrateType::ProcMacro => "proc-macro",
        CrateType::RLib => "rlib",
        CrateType::StaticLib => "staticlib",
        CrateType::Unknown(s) => return s.clone(),
        other => return format!("{other:?}").to_lowercase(),
    }
    .to_string()
}

fn target_kind_name(kind: &TargetKind) -> String {
    match kind {
        TargetKind::Bin => "bin",
        TargetKind::Lib => "lib",
        TargetKind::RLib => "rlib",
        TargetKind::DyLib => "dylib",
        TargetKind::CDyLib => "cdylib",
        TargetKind::StaticLib => "staticlib",
        TargetKind::ProcMacro => "proc-macro",
        TargetKind::Example => "example",
        TargetKind::Test => "test",
        TargetKind::Bench => "bench",
        TargetKind::CustomBuild => "custom-build",
        other => return format!("{other:?}").to_lowercase(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scanner must find `src-tauri` in a conventional Tauri layout
    /// without any config.
    #[test]
    fn detects_src_tauri_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src-tauri/src")).unwrap();
        std::fs::write(
            root.join("src-tauri/Cargo.toml"),
            "[package]\nname=\"app\"\n",
        )
        .unwrap();
        std::fs::write(root.join("src-tauri/tauri.conf.json"), "{}").unwrap();

        assert_eq!(detect_rust_root(root).unwrap(), root.join("src-tauri"));
        assert!(find_tauri_conf(&root.join("src-tauri")).is_some());
    }

    #[test]
    fn detects_frontend_next_to_src_tauri() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src-tauri")).unwrap();
        std::fs::create_dir_all(root.join("frontend/src")).unwrap();
        std::fs::write(root.join("frontend/package.json"), "{}").unwrap();

        let found = detect_frontend_root(root, &root.join("src-tauri"));
        assert_eq!(found, Some(root.join("frontend")));
    }

    #[test]
    fn ambiguous_layout_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for d in ["a", "b"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
            std::fs::write(root.join(d).join("Cargo.toml"), "[package]").unwrap();
        }
        let err = detect_rust_root(root).unwrap_err();
        assert!(format!("{err}").contains("disambiguate"));
    }
}
