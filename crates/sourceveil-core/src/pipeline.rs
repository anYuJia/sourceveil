//! Top-level orchestration.
//!
//! The order here is not arbitrary. Reading it top to bottom:
//!
//! ```text
//! resolve config and seed
//!   -> locate the project
//!   -> copy the workspace          (before transforming, so edits land on the copy)
//!   -> analyze and rename
//!   -> write mapping               (inside the generated tree, but never in a shipped dir)
//!   -> verify the generated tree
//! ```
//!
//! Renaming happens *after* the copy and edits land only on the copy, which is
//! what makes "the input tree is never written to" true by construction rather
//! than by discipline.

use crate::config::{AnalyzeSource, Config, VerifyStage};
use crate::copier;
use crate::mapping::Mapping;
use crate::plan::Plan;
use crate::report::Report;
use crate::rust::analysis::{LoadOptions, RustAnalysis};
use crate::rust::rename::{self, RenameRequest};
use crate::scanner::ProjectLayout;
use crate::seed::{self, SeedInfo};
use crate::verify::{self, VerifyContext};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct TransformRequest {
    pub input: PathBuf,
    pub output: PathBuf,
    pub config: Config,
    /// Overrides `[build] seed`.
    pub seed_override: Option<String>,
    /// Overrides `[build] verify_stages`.
    pub stages_override: Option<Vec<VerifyStage>>,
    /// Skip the verification pipeline entirely.
    pub skip_verify: bool,
}

pub struct TransformOutcome {
    pub plan: Plan,
    pub seed: SeedInfo,
    pub report: Report,
    pub mapping: Mapping,
    pub layout: ProjectLayout,
    pub output_root: PathBuf,
    pub mapping_path: Option<PathBuf>,
}

/// Run the whole pipeline.
pub fn transform(req: &TransformRequest) -> Result<TransformOutcome> {
    let plan = Plan::resolve(&req.config).context("resolving the configuration")?;

    let seed_spec = req
        .seed_override
        .clone()
        .unwrap_or_else(|| plan.build.seed.clone());
    let seed = seed::resolve(&seed_spec)?;

    let layout = ProjectLayout::discover(
        &req.input,
        plan.project.rust_root.as_deref(),
        plan.project.frontend_root.as_deref(),
        plan.project.frontend_source.as_deref(),
    )?;

    let mut report = Report::new(format!("{:?}", plan.profile).to_lowercase(), seed.clone());
    report
        .warnings
        .extend(layout.crates.warnings.iter().cloned());
    if let Some(w) = &seed.warning {
        report.warnings.push(w.clone());
    }
    for unsupported in &plan.unsupported {
        report.warnings.push(unsupported.clone());
    }

    tracing::info!(
        input = %layout.root.display(),
        rust_root = %layout.rust_root.display(),
        tauri = layout.is_tauri,
        crates = layout.crates.workspace.len(),
        "located project"
    );

    // --- 1. copy ---------------------------------------------------------
    let copy = copier::copy_workspace(&layout.root, &req.output, &plan.project.ignore)
        .context("copying the workspace")?;
    report.warnings.extend(copy.warnings.iter().cloned());
    tracing::info!(
        files = copy.stats.files_copied,
        bytes = copy.stats.bytes_copied,
        "copied workspace"
    );

    let output_root = req
        .output
        .canonicalize()
        .unwrap_or_else(|_| req.output.clone());

    // --- 2. analyze and rename -------------------------------------------
    let mut mapping = Mapping::new(seed.seed);

    if !plan.rename.is_noop() {
        let analysis_root = match plan.build.analyze {
            AnalyzeSource::Input => layout.rust_root.clone(),
            AnalyzeSource::Output => output_root.join(layout.rust_relative()),
        };

        let opts = LoadOptions {
            load_out_dirs_from_check: plan.build.load_out_dirs,
            proc_macros: true,
        };
        let analysis = RustAnalysis::load(&analysis_root, &opts)
            .with_context(|| format!("loading {} into rust-analyzer", analysis_root.display()))?;

        let request = RenameRequest {
            input_root: &layout.root,
            output_root: &output_root,
            copied: &copy.copied,
            plan: &plan,
            graph: &layout.crates,
            seed: seed.seed,
        };

        let outcome = rename::run(&analysis, &request).context("running the rename pass")?;

        // Edits are applied by the pipeline, not by the pass: every pass
        // contributes to one plan and the plan is written once, so that no pass
        // ever sees a file another pass has already changed the length of.
        let applied = outcome
            .plan
            .apply(&layout.root, &output_root)
            .context("applying the rename edits")?;
        tracing::info!(
            files = applied.files_edited,
            edits = applied.edits_applied,
            "applied edits"
        );

        report.files.rust_scanned = outcome.rust_files_scanned;
        report.rename = outcome.stats;
        for skipped in outcome.skipped {
            report.skip(skipped);
        }
        report.warnings.extend(outcome.warnings);
        mapping = outcome.mapping;

        tracing::info!(
            renamed = report.rename.total(),
            kept = report.skipped_by_reason.values().sum::<usize>(),
            files = report.rename.files_edited,
            "rename pass complete"
        );
    }

    // --- 3. mapping ------------------------------------------------------
    let mut mapping_path = None;
    if plan.build.write_mapping {
        let dir = verify::resolve_mapping_dir(&output_root, &plan.build.mapping_dir);
        let path = dir.join("mapping.json");
        mapping.assert_not_in_output(&path)?;
        mapping.write(&path)?;
        seed::write_seed_info(&dir.join("seed-info.json"), &seed, &plan)?;
        tracing::info!(path = %path.display(), "wrote mapping");
        mapping_path = Some(path);
    }

    // --- 4. verify -------------------------------------------------------
    if !req.skip_verify && plan.build.verify {
        let stages = req
            .stages_override
            .clone()
            .unwrap_or_else(|| plan.build.verify_stages.clone());

        let rust_root_out = output_root.join(layout.rust_relative());
        let frontend_out = layout
            .frontend_root
            .as_ref()
            .and_then(|p| p.strip_prefix(&layout.root).ok())
            .map(|p| output_root.join(p));

        let ctx = VerifyContext {
            output_root: &output_root,
            rust_root: &rust_root_out,
            frontend_root: frontend_out.as_deref(),
            mapping_dir: mapping_path.as_ref().and_then(|p| p.parent()),
            mapping: &mapping,
        };

        let results = verify::run(&ctx, &stages);
        report.verification = results.stages;
    }

    let report_path = output_root.join(".obfuscator/report.json");
    if let Err(e) = report.write(&report_path) {
        tracing::warn!("could not write {}: {e:#}", report_path.display());
    }

    Ok(TransformOutcome {
        plan,
        seed,
        report,
        mapping,
        layout,
        output_root,
        mapping_path,
    })
}

impl ProjectLayout {
    /// Path of the Rust root relative to the project root.
    pub fn rust_relative(&self) -> PathBuf {
        self.rust_root
            .strip_prefix(&self.root)
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| PathBuf::from("."))
    }
}

/// Shared entry point used by the CLI for `scan`.
pub fn scan_only(input: &Path, config: &Config) -> Result<ProjectLayout> {
    let plan = Plan::resolve(config)?;
    ProjectLayout::discover(
        input,
        plan.project.rust_root.as_deref(),
        plan.project.frontend_root.as_deref(),
        plan.project.frontend_source.as_deref(),
    )
}
