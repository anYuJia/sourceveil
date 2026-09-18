//! `obfuscator.toml` schema and the resolution of it into a concrete plan.
//!
//! Precedence, highest first:
//!   1. explicit value in the TOML file
//!   2. the selected `profile` (`safe` / `balanced` / `aggressive`)
//!   3. the built-in default
//!
//! Every toggle is an `Option<T>` in [`Config`] so that "not mentioned in the
//! file" is distinguishable from "explicitly set to the default". [`Config::resolve`]
//! collapses that into [`crate::plan::Plan`], which is what the passes consume.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Current config schema version. Bumped on breaking changes.
pub const CONFIG_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// profile
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Maximum compatibility, near-zero runtime cost. Symbol rename, IPC/event
    /// mapping and build diversification only.
    #[default]
    Safe,
    /// `safe` plus internal-string protection, private field rename and
    /// module-file rename.
    Balanced,
    /// Reserved for future transforms (function splitting, limited indirect
    /// dispatch). V1 ships `safe` plus the `balanced` subset.
    Aggressive,
}

// ---------------------------------------------------------------------------
// raw schema
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: Option<u32>,
    #[serde(default)]
    pub profile: Option<Profile>,
    #[serde(default)]
    pub project: Project,
    #[serde(default)]
    pub rename: Rename,
    #[serde(default)]
    pub strings: Strings,
    #[serde(default)]
    pub tauri: Tauri,
    #[serde(default)]
    pub frontend: Frontend,
    #[serde(default)]
    pub dependencies: Dependencies,
    #[serde(default)]
    pub build: Build,
    #[serde(default)]
    pub keep: Keep,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    /// Directory containing the application's root `Cargo.toml`.
    /// Auto-detected when omitted.
    pub rust_root: Option<PathBuf>,
    /// Directory containing `package.json`. Auto-detected when omitted.
    pub frontend_root: Option<PathBuf>,
    /// Directory containing frontend sources, relative to `frontend_root`.
    pub frontend_source: Option<PathBuf>,
    /// Extra ignore patterns applied by the workspace copier, on top of the
    /// built-in set. Gitignore-style globs matched against workspace-relative
    /// paths.
    #[serde(default)]
    pub ignore: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rename {
    /// Free functions and inherent/trait method definitions.
    pub functions: Option<bool>,
    /// `struct`, `enum`, `union` and `type` aliases.
    pub types: Option<bool>,
    pub traits: Option<bool>,
    /// Enum variant names.
    pub enums: Option<bool>,
    pub consts: Option<bool>,
    pub statics: Option<bool>,
    /// Inline `mod name { .. }` blocks. File-backed `mod name;` additionally
    /// moves the file; that only happens when `module_files` is also enabled.
    pub modules: Option<bool>,
    /// Physically rename `foo.rs` / `foo/mod.rs` alongside the module.
    /// V2 capability; defaults to `false` even under `balanced`.
    pub module_files: Option<bool>,
    /// Local `macro_rules!` definitions.
    pub macros: Option<bool>,
    /// Named struct/enum fields.
    pub fields: Option<bool>,
    /// Local `let` bindings.
    pub locals: Option<bool>,
    /// Function parameters.
    pub params: Option<bool>,
    /// Shortest generated name.
    pub name_len_min: Option<usize>,
    /// Longest generated name.
    pub name_len_max: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Strings {
    pub enabled: Option<bool>,
    /// `log::*`, `tracing::*`, `println!`-family arguments.
    pub logs: Option<bool>,
    /// Arguments to error constructors.
    pub errors: Option<bool>,
    /// Semantic literals that are neither IPC names, UI text nor plumbing
    /// (e.g. `"license-check"`, `"device-validation"`).
    pub internal: Option<bool>,
    /// User-visible copy. Protected only when explicitly asked for.
    pub ui: Option<bool>,
    pub endpoints: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tauri {
    /// Rename `#[tauri::command]` handlers together with every frontend
    /// `invoke("...")` that calls them.
    pub commands: Option<bool>,
    /// Rename `emit`/`listen` channel names on both sides.
    pub events: Option<bool>,
    /// Window labels. Framework-level, so `false` by default.
    pub window_labels: Option<bool>,
    /// Rewrite command-name string literals found in Rust match arms and
    /// allow-lists, not just `invoke()` calls.
    pub scan_command_literals: Option<bool>,
    /// Extra callee names to treat as `invoke`. `invoke` and `tauriInvoke` are
    /// always recognised, as are local functions that forward their first
    /// parameter to one of them.
    #[serde(default)]
    pub invoke_names: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frontend {
    /// Enable the frontend semantic pass. It is conservative by construction:
    /// member properties, object keys, imports and exports stay untouched.
    pub enabled: Option<bool>,
    /// Rename private lexical bindings proven local by OXC's semantic model.
    pub rename_private_identifiers: Option<bool>,
    /// Off by design. Property names cross the JSON / React-prop / store
    /// boundary and cannot be proven safe from the frontend alone.
    pub property_mangling: Option<bool>,
}

/// Per-dependency treatment.
///
/// Note the absence of `deny_unknown_fields`: serde cannot honour it on a
/// struct that also uses `#[serde(flatten)]`, because the flattened map has to
/// consume whatever remains. Per-crate modes are therefore validated by the
/// consumers of [`Dependencies::crates`] rather than by serde.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependencies {
    /// Treatment for dependencies not listed individually:
    /// `external` (leave alone), `private-obfuscate` (rename private items only).
    #[serde(default = "default_dep_mode")]
    pub default: DependencyMode,
    /// Per-crate overrides, keyed by crate name.
    #[serde(flatten)]
    pub crates: std::collections::BTreeMap<String, DependencyOverride>,
}

impl Default for Dependencies {
    fn default() -> Self {
        Self {
            default: DependencyMode::External,
            crates: Default::default(),
        }
    }
}

fn default_dep_mode() -> DependencyMode {
    DependencyMode::External
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyMode {
    /// Do not touch this crate's source at all.
    #[default]
    External,
    /// Rename private items; keep the public API intact.
    PrivateObfuscate,
    /// Full obfuscation (workspace-owned crates only).
    Obfuscate,
    /// Generate a rename-participating wrapper module around its API.
    Wrapper,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, untagged)]
pub enum DependencyOverride {
    Mode(DependencyMode),
    Table { mode: DependencyMode },
}

impl DependencyOverride {
    pub fn mode(&self) -> DependencyMode {
        match self {
            DependencyOverride::Mode(m) => *m,
            DependencyOverride::Table { mode } => *mode,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    /// `auto` | `random` | `hmac` | a decimal `u64`.
    #[serde(default = "default_seed")]
    pub seed: String,
    /// Run the verification pipeline after generating.
    pub verify: Option<bool>,
    /// Stages to run. See [`VerifyStage`].
    pub verify_stages: Option<Vec<VerifyStage>>,
    /// Emit `.obfuscator/mapping.json`.
    pub write_mapping: Option<bool>,
    /// Where to write the mapping directory, relative to the output root.
    pub mapping_dir: Option<PathBuf>,
    /// Analyze the input workspace (`input`) or the generated copy (`output`).
    pub analyze: Option<AnalyzeSource>,
    /// Run `cargo check` while loading so build-script `OUT_DIR`s resolve.
    pub load_out_dirs: Option<bool>,
    /// Abort instead of skipping when a symbol cannot be safely renamed.
    pub strict: Option<bool>,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            seed: default_seed(),
            verify: None,
            verify_stages: None,
            write_mapping: None,
            mapping_dir: None,
            analyze: None,
            load_out_dirs: None,
            strict: None,
        }
    }
}

fn default_seed() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalyzeSource {
    Input,
    Output,
}

/// A verification stage. Names match the CLI's `--stage` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerifyStage {
    CargoMetadata,
    CargoCheck,
    CargoTest,
    CargoClippy,
    NpmCi,
    NpmTypecheck,
    NpmBuild,
    TauriBuild,
    LeakScan,
}

impl VerifyStage {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyStage::CargoMetadata => "cargo-metadata",
            VerifyStage::CargoCheck => "cargo-check",
            VerifyStage::CargoTest => "cargo-test",
            VerifyStage::CargoClippy => "cargo-clippy",
            VerifyStage::NpmCi => "npm-ci",
            VerifyStage::NpmTypecheck => "npm-typecheck",
            VerifyStage::NpmBuild => "npm-build",
            VerifyStage::TauriBuild => "tauri-build",
            VerifyStage::LeakScan => "leak-scan",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keep {
    /// Exact item names that must never be renamed.
    #[serde(default)]
    pub symbols: Vec<String>,
    /// Glob patterns matched against the item name.
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Workspace-relative file globs excluded from transformation entirely.
    #[serde(default)]
    pub files: Vec<String>,
    /// Attribute paths that force an item to be kept.
    #[serde(default)]
    pub attributes: Vec<String>,
}

// ---------------------------------------------------------------------------
// loading
// ---------------------------------------------------------------------------

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text).context("parsing obfuscator config")?;
        if let Some(v) = cfg.version {
            if v != CONFIG_VERSION {
                bail!(
                    "unsupported config version {v}; this build understands version {CONFIG_VERSION}"
                );
            }
        }
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Self::parse(&text)
    }

    pub fn profile(&self) -> Profile {
        self.profile.unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_is_valid() {
        let c = Config::parse("").unwrap();
        assert_eq!(c.profile(), Profile::Safe);
        assert_eq!(c.build.seed, "auto");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::parse("[rename]\nfnctions = true\n").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
    }

    #[test]
    fn wrong_version_is_rejected() {
        let err = Config::parse("version = 99\n").unwrap_err();
        assert!(format!("{err:#}").contains("unsupported config version"));
    }

    #[test]
    fn dependency_modes_parse_both_shapes() {
        let c = Config::parse(
            r#"
            [dependencies]
            default = "external"
            reqwest = { mode = "wrapper" }
            core_lib = "private-obfuscate"
            "#,
        )
        .unwrap();
        assert_eq!(c.dependencies.default, DependencyMode::External);
        assert_eq!(
            c.dependencies.crates["reqwest"].mode(),
            DependencyMode::Wrapper
        );
        assert_eq!(
            c.dependencies.crates["core_lib"].mode(),
            DependencyMode::PrivateObfuscate
        );
    }
}
