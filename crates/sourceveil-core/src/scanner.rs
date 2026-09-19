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
    /// Frontend directory; explicit static roots need not contain package.json.
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
    /// Every local package cargo made available to the analysis, by crate
    /// name. This includes path dependencies outside the workspace when cargo
    /// reports them, because they are eligible for an explicit closed-world
    /// dependency policy.
    pub workspace: BTreeMap<String, CrateInfo>,
    /// Packages that are actual members of the discovered workspace. A local
    /// path dependency can be present in `workspace` without being a member.
    pub workspace_members: BTreeSet<String>,
    /// Crates rooted at the manifest the user asked us to transform. A virtual
    /// workspace has no package at that path, so the set can be empty.
    pub root_crates: BTreeSet<String>,
    /// Cargo dependency name(s) by local package name. The dependency name is
    /// the identifier that appears in Rust source (`foo_bar`), while the
    /// package name can legally contain hyphens (`foo-bar`).
    pub dependency_aliases: BTreeMap<String, BTreeSet<String>>,
    /// Manifest directories for dependency packages, including registry/git
    /// crates loaded by rust-analyzer. Used to prove a wrapper path resolves to
    /// the intended dependency rather than a same-named local module.
    pub dependency_manifest_dirs: BTreeMap<String, PathBuf>,
    /// Every dependency package directory, without collapsing multiple
    /// resolved versions that share a package name. Consumers that inspect
    /// linked source (for example plaintext-collision detection) need the full
    /// set, while semantic name resolution above intentionally stays keyed by
    /// package name.
    pub dependency_source_dirs: BTreeSet<PathBuf>,
    /// Workspace members that something outside the workspace depends on.
    /// Their public API is a contract and must not be renamed.
    pub boundary: BTreeSet<String>,
    pub target_directory: Option<PathBuf>,
    pub workspace_root: Option<PathBuf>,
    /// Warnings worth surfacing in the run report.
    pub warnings: Vec<String>,
}

/// Path comparisons between Cargo metadata and rust-analyzer need to tolerate
/// Windows' extended-length (`\\\\?\\`) prefix. Cargo may report a normal
/// drive path while the VFS returns the extended spelling (or vice versa).
pub(crate) fn path_starts_with(path: &Path, base: &Path) -> bool {
    if path.starts_with(base) {
        return true;
    }
    #[cfg(windows)]
    {
        let path = normalize_windows_path(path);
        let base = normalize_windows_path(base);
        path == base
            || path
                .strip_prefix(&base)
                .is_some_and(|tail| tail.starts_with('\\'))
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub(crate) fn path_eq(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    #[cfg(windows)]
    {
        normalize_windows_path(left) == normalize_windows_path(right)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Return a relative path using the same Windows normalization as
/// [`path_starts_with`]. This is used only as a fallback; the ordinary
/// `Path::strip_prefix` result remains preferred on every platform.
pub(crate) fn strip_prefix_path(path: &Path, base: &Path) -> Option<PathBuf> {
    if let Ok(relative) = path.strip_prefix(base) {
        return Some(relative.to_path_buf());
    }
    #[cfg(windows)]
    {
        let normalized_path = normalize_windows_path(path);
        let normalized_base = normalize_windows_path(base);
        normalized_path.strip_prefix(&normalized_base)?;
        // Preserve the original casing in the relative path: `copied` comes
        // from the filesystem and its `PathBuf` keys remain case-sensitive in
        // Rust even though Windows lookup is not.
        let component_count = base.components().count();
        Some(path.components().skip(component_count).collect())
    }
    #[cfg(not(windows))]
    {
        None
    }
}

#[cfg(windows)]
fn normalize_windows_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('/', "\\");
    raw.strip_prefix(r"\\?\")
        .unwrap_or(&raw)
        .to_ascii_lowercase()
}

/// Whether a crate belongs to the requested closed-world transform. Graphs
/// produced by cargo metadata carry either the explicit root set or workspace
/// members; hand-built/unit-test graphs may carry neither, in which case every
/// listed crate is treated as local for backwards-compatible decision tests.
pub fn is_root_like(graph: &CrateGraph, name: &str) -> bool {
    if !graph.workspace_members.is_empty() {
        return graph.workspace_members.contains(name);
    }
    if !graph.root_crates.is_empty() {
        return graph.root_crates.contains(name);
    }
    true
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

        let tauri_frontend = detect_tauri_frontend_dist(&root, &rust_root);
        let frontend_root = match frontend_root_override {
            Some(p) => {
                let configured = root.join(p);
                if !configured.is_dir() {
                    bail!(
                        "configured frontend root {} is not a directory",
                        configured.display()
                    );
                }
                // An explicit root may be a pre-built/static frontend. Those
                // projects often have no package.json, but their JS still
                // contains Tauri invoke/event protocol references that must be
                // rewritten together with Rust.
                Some(configured)
            }
            None => detect_frontend_root(&root, &rust_root)
                .filter(|p| p.join("package.json").is_file())
                .or_else(|| tauri_frontend.clone()),
        };

        let frontend_source = match (frontend_root.as_ref(), frontend_source_override) {
            (Some(fr), Some(p)) => Some(fr.join(p)),
            (Some(fr), None) => {
                let src = fr.join("src");
                if src.is_dir() {
                    Some(src)
                } else if tauri_frontend
                    .as_ref()
                    .is_some_and(|root| path_eq(root, fr))
                {
                    // A pre-built/static frontend still contains the shipped
                    // invoke/event call sites and is also required by
                    // `tauri::generate_context!` during verification.
                    Some(fr.clone())
                } else {
                    None
                }
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
    let root_package = root.join("package.json").is_file();
    // A root package with its own source tree is the ordinary single-package
    // Tauri layout. When it only proxies scripts into `frontend/`, prefer the
    // actual nested package so semantic binding rename and npm verification run
    // against the code that ships.
    if root_package && root.join("src").is_dir() {
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
    if root_package {
        return Some(root.to_path_buf());
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

/// Resolve Tauri's configured static frontend directory. The path is relative
/// to the directory containing `tauri.conf.json`, not to the process cwd.
/// URLs name a dev server and are deliberately ignored.
fn detect_tauri_frontend_dist(root: &Path, rust_root: &Path) -> Option<PathBuf> {
    let config = find_tauri_conf(rust_root)?;
    if config
        .extension()
        .is_none_or(|extension| extension != "json")
    {
        return None;
    }
    let source = std::fs::read_to_string(config).ok()?;
    let value: serde_json::Value = serde_json::from_str(&source).ok()?;
    let configured = value
        .get("build")?
        .get("frontendDist")
        .or_else(|| value.get("build")?.get("distDir"))?
        .as_str()?;
    if configured.contains("://") {
        return None;
    }
    let path = rust_root.join(configured).canonicalize().ok()?;
    (path.is_dir() && path_starts_with(&path, root)).then_some(path)
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

    let mut graph = fold_metadata(&metadata)?;
    let manifest_dir = manifest.parent().unwrap_or_else(|| Path::new("."));
    for krate in graph.workspace.values() {
        if path_eq(&krate.manifest_dir, manifest_dir) {
            graph.root_crates.insert(krate.name.clone());
        }
    }
    Ok(graph)
}

fn fold_metadata(metadata: &Metadata) -> Result<CrateGraph> {
    let mut graph = CrateGraph {
        target_directory: Some(metadata.target_directory.clone().into_std_path_buf()),
        workspace_root: Some(metadata.workspace_root.clone().into_std_path_buf()),
        ..Default::default()
    };

    let members: BTreeSet<&PackageId> = metadata.workspace_members.iter().collect();
    let member_names: BTreeMap<&PackageId, String> = metadata
        .packages
        .iter()
        .filter(|p| members.contains(&p.id))
        .map(|p| (&p.id, p.name.to_string()))
        .collect();

    for package in &metadata.packages {
        let manifest_dir = package
            .manifest_path
            .parent()
            .map(|p| p.as_std_path().to_path_buf())
            .unwrap_or_default();
        let name = package.name.to_string();
        // Keep manifest paths even for registry/git dependencies. Their source
        // is never copied or edited, but a wrapper policy still needs to prove
        // that rust-analyzer resolved a crate-root reference to this package.
        graph
            .dependency_manifest_dirs
            .insert(name.clone(), manifest_dir.clone());
        graph.dependency_source_dirs.insert(manifest_dir.clone());

        // Registry/git dependencies are analyzed by rust-analyzer but are
        // never part of the copied source tree. Local path dependencies are
        // retained so an explicit dependency policy can reason about them;
        // resolve_edit_target still prevents edits outside the copied root.
        if package.source.is_some() && !members.contains(&package.id) {
            continue;
        }

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

        graph.workspace.insert(
            name.clone(),
            CrateInfo {
                name: name.clone(),
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
        if members.contains(&package.id) {
            graph.workspace_members.insert(name);
        }
    }

    // Which workspace crates are reachable from outside the workspace?
    if let Some(resolve) = &metadata.resolve {
        for node in &resolve.nodes {
            // A member is an API boundary only when a package outside the
            // discovered workspace depends on it. Workspace-internal edges
            // remain inside the closed world and must not pin public items.
            if !member_names.contains_key(&node.id) {
                for dep in &node.deps {
                    if let Some(name) = member_names.get(&dep.pkg) {
                        graph.boundary.insert(name.clone());
                    }
                }
            }

            // Keep aliases for every local package, including path
            // dependencies outside the workspace. These are used by the
            // explicit wrapper policy to rewrite only semantically resolved
            // crate-root paths.
            for dep in &node.deps {
                let Some(package) = metadata.packages.iter().find(|p| p.id == dep.pkg) else {
                    continue;
                };
                graph
                    .dependency_aliases
                    .entry(package.name.to_string())
                    .or_default()
                    .insert(dep.name.clone());
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
    fn nested_frontend_beats_a_root_script_proxy_package() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir_all(root.join("src-tauri")).unwrap();
        std::fs::create_dir_all(root.join("frontend/src")).unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"scripts":{"build":"npm --prefix frontend run build"}}"#,
        )
        .unwrap();
        std::fs::write(root.join("frontend/package.json"), "{}").unwrap();

        let found = detect_frontend_root(root, &root.join("src-tauri"));
        assert_eq!(found, Some(root.join("frontend")));
    }

    #[test]
    fn detects_static_frontend_from_tauri_configuration() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let rust_root = root.join("src-tauri");
        std::fs::create_dir_all(&rust_root).unwrap();
        std::fs::create_dir_all(root.join("dist/assets")).unwrap();
        std::fs::write(
            rust_root.join("tauri.conf.json"),
            r#"{"build":{"frontendDist":"../dist"}}"#,
        )
        .unwrap();

        assert_eq!(
            detect_tauri_frontend_dist(&root, &rust_root),
            Some(root.join("dist"))
        );
    }

    #[test]
    fn explicit_static_frontend_does_not_require_package_json() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("src-tauri/src")).unwrap();
        std::fs::create_dir_all(root.join("dist/js")).unwrap();
        std::fs::write(
            root.join("src-tauri/Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(root.join("src-tauri/src/lib.rs"), "").unwrap();

        let layout =
            ProjectLayout::discover(root, None, Some(Path::new("dist")), Some(Path::new(".")))
                .unwrap();

        let canonical_root = root.canonicalize().unwrap();
        assert_eq!(layout.frontend_root, Some(canonical_root.join("dist")));
        assert_eq!(layout.frontend_source, Some(canonical_root.join("dist")));
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
