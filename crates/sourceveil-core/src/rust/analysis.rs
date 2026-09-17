//! Loading a project into rust-analyzer, and reading files back out of it.
//!
//! The analysis is a *snapshot*. Renames are computed against it and applied to
//! the generated copy, never fed back into the database. That is deliberate:
//! it makes every rename independent of every other rename, so the result does
//! not depend on the order they happen to be processed in, which is what makes
//! `same seed -> identical output` achievable at all.

use anyhow::{Context, Result};
use ra_ap_ide::{Analysis, AnalysisHost, FileId};
use ra_ap_load_cargo::{load_workspace_at, LoadCargoConfig, ProcMacroServerChoice};
use ra_ap_proc_macro_api::ProcMacroClient;
use ra_ap_project_model::CargoConfig;
use ra_ap_syntax::ast::AstNode;
use ra_ap_syntax::SourceFile;
use ra_ap_vfs::Vfs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// Run `cargo check` during loading so `OUT_DIR` artifacts resolve.
    /// Correct, but it compiles the whole workspace once.
    pub load_out_dirs_from_check: bool,
    /// Start the proc-macro server so `#[derive]`-generated code is visible.
    pub proc_macros: bool,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            load_out_dirs_from_check: true,
            proc_macros: true,
        }
    }
}

pub struct RustAnalysis {
    host: AnalysisHost,
    vfs: Vfs,
    /// Held only to keep the proc-macro server process alive for as long as
    /// the analysis is usable.
    _proc_macros: Option<ProcMacroClient>,
    root: PathBuf,
}

impl RustAnalysis {
    /// Load the cargo project rooted at `root` (a directory holding a
    /// `Cargo.toml`, or the manifest itself).
    pub fn load(root: &Path, opts: &LoadOptions) -> Result<Self> {
        let cargo_config = CargoConfig {
            // rust-analyzer does not analyse `#[cfg(test)]` modules unless the
            // `test` cfg is enabled. Test code is real code with real
            // references to the symbols we are about to rename, and it is
            // compiled by `cargo check --all-targets`, so leaving it invisible
            // means renaming a symbol out from under its own tests.
            set_test: true,
            ..CargoConfig::default()
        };

        let load_config = LoadCargoConfig {
            load_out_dirs_from_check: opts.load_out_dirs_from_check,
            with_proc_macro_server: if opts.proc_macros {
                ProcMacroServerChoice::Sysroot
            } else {
                ProcMacroServerChoice::None
            },
            prefill_caches: false,
            num_worker_threads: 0,
            proc_macro_processes: 1,
        };

        let progress = |msg: String| tracing::debug!(target: "rust_analyzer", "{msg}");

        let (db, vfs, proc_macros) =
            load_workspace_at(root, &cargo_config, &load_config, &progress)
                .with_context(|| format!("loading {} into rust-analyzer", root.display()))?;

        Ok(Self {
            host: AnalysisHost::with_database(db),
            vfs,
            _proc_macros: proc_macros,
            root: root.to_path_buf(),
        })
    }

    pub fn analysis(&self) -> Analysis {
        self.host.analysis()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Absolute path of a file known to the analysis, if it has one.
    pub fn file_path(&self, file: FileId) -> Option<PathBuf> {
        let path = self.vfs.file_path(file);
        Some(to_std_path(path.as_path()?))
    }

    /// Every `.rs` file in the analysis, as `(FileId, absolute path)`.
    ///
    /// Ordered by path so that candidate enumeration — and therefore the
    /// generated names — is reproducible across runs.
    pub fn rust_files(&self) -> Vec<(FileId, PathBuf)> {
        let mut files: Vec<(FileId, PathBuf)> = self
            .vfs
            .iter()
            .filter(|(_, path)| is_rust_file(path))
            .filter_map(|(id, path)| Some((id, to_std_path(path.as_path()?))))
            .collect();
        files.sort_by(|a, b| a.1.cmp(&b.1));
        files
    }

    /// Syntax tree plus source text for a file.
    ///
    /// The text comes from the analysis rather than from disk so that byte
    /// offsets returned by rust-analyzer are guaranteed to index into it.
    pub fn parse(&self, file: FileId) -> Option<(SourceFile, String)> {
        let analysis = self.analysis();
        let parsed = analysis.parse(file).ok()?;
        let text = parsed.syntax().text().to_string();
        Some((parsed, text))
    }
}

fn is_rust_file(path: &ra_ap_vfs::VfsPath) -> bool {
    path.as_path()
        .map(|p| <ra_ap_vfs::AbsPath as AsRef<Path>>::as_ref(p).extension() == Some("rs".as_ref()))
        .unwrap_or(false)
}

/// `ra_ap_paths::AbsPath` is not `std::path::Path`; this is the one conversion
/// point so the rest of the crate can work in ordinary path types.
fn to_std_path(path: &ra_ap_vfs::AbsPath) -> PathBuf {
    <ra_ap_vfs::AbsPath as AsRef<Path>>::as_ref(path).to_path_buf()
}
