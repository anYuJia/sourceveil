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
use crate::edits::EditPlan;
use crate::mapping::Mapping;
use crate::names::NameDeriver;
use crate::plan::Plan;
use crate::report::{CommandStats, EventStats, Report};
use crate::rust::analysis::{LoadOptions, RustAnalysis};
use crate::rust::rename::{self, RenameRequest, Shared};
use crate::scanner::ProjectLayout;
use crate::seed::{self, SeedInfo};
use crate::serde::rename::{self as serde_rename, SerdeRenameRequest};
use crate::strings::{self as string_protection, StringRequest};
use crate::tauri::event::{self as tauri_event, EventRequest};
use crate::tauri::{self, CommandRequest};
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

    // --- 2. analyze, then run the passes ----------------------------------
    let mut mapping = Mapping::new(seed.seed);
    let mut command_stats = CommandStats::default();
    let mut event_stats = EventStats::default();

    if !plan.rename.is_noop()
        || plan.tauri.commands
        || plan.tauri.events
        || plan.strings.enabled
    {
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

        // One name stream for every pass. Two generators seeded alike would
        // produce the same first name and collide, so the passes draw from the
        // same one, in a fixed order.
        let files = analysis.rust_files();
        let facts = rename::collect_syntax_facts(&analysis, &files, &layout.crates);
        let (len_min, len_max) = plan.rename.name_len;
        let mut names = NameDeriver::new(seed.seed, len_min, len_max, facts.identifiers);

        // One plan for every pass, applied once.
        let mut edits = EditPlan::new();

        // Tauri commands first: this pass consumes names and claims the
        // definition sites it renames, so the symbol pass must see them as
        // taken rather than rename them a second time.
        let mut claimed = if plan.tauri.commands {
            let request = CommandRequest {
                input_root: &layout.root,
                copied: &copy.copied,
                plan: &plan,
                graph: &layout.crates,
                frontend_root: layout.frontend_root.as_deref(),
                invoke_names: &plan.tauri.invoke_names,
            };
            let outcome = tauri::run(&analysis, &request, &mut names, &mut edits)
                .context("running the tauri command pass")?;

            command_stats = CommandStats::from_outcome(&outcome);
            mapping.commands = outcome.mapping;
            report.warnings.extend(outcome.warnings);
            report.files.frontend_scanned =
                outcome.refs.frontend_static + outcome.refs.frontend_dynamic;
            outcome.claimed
        } else {
            Default::default()
        };

        // Events next: they draw from their own domain, so they cannot move a
        // command name, but they do edit some of the same files.
        if plan.tauri.events {
            let request = EventRequest {
                input_root: &layout.root,
                copied: &copy.copied,
                plan: &plan,
                graph: &layout.crates,
                frontend_root: layout.frontend_root.as_deref(),
            };
            let outcome = tauri_event::run(&analysis, &request, &mut names, &mut edits)
                .context("running the tauri event pass")?;

            event_stats = EventStats::from_outcome(&outcome);
            mapping.events = outcome.mapping;
            report.warnings.extend(outcome.warnings);
        }

        let mut serde_stats = crate::report::RenameStats::default();
        let mut serde_files = std::collections::BTreeSet::new();
        if !plan.rename.is_noop() {
            let request = SerdeRenameRequest {
                input_root: &layout.root,
                copied: &copy.copied,
                plan: &plan,
                graph: &layout.crates,
                seed: seed.seed,
            };
            let outcome = serde_rename::run(
                &analysis,
                &request,
                &mut names,
                &mut edits,
                &facts.macro_referenced,
            )
            .context("running the serde rename pass")?;

            serde_stats = outcome.stats;
            serde_files = outcome.files_edited;
            claimed.extend(outcome.claimed);
            mapping.symbols.extend(outcome.mapping.symbols);
            for skipped in outcome.skipped {
                report.skip(skipped);
            }
            report.warnings.extend(outcome.warnings);
        }

        if !plan.rename.is_noop() {
            let request = RenameRequest {
                input_root: &layout.root,
                output_root: &output_root,
                copied: &copy.copied,
                plan: &plan,
                graph: &layout.crates,
                seed: seed.seed,
            };

            let outcome = rename::run(
                &analysis,
                &request,
                Shared {
                    names: &mut names,
                    plan: &mut edits,
                    claimed: &claimed,
                    macro_referenced: facts.macro_referenced,
                },
            )
            .context("running the rename pass")?;

            report.files.rust_scanned = outcome.rust_files_scanned;
            let mut combined = outcome.stats;
            combined.fields += serde_stats.fields;
            combined.enums += serde_stats.enums;
            combined.edits_applied += serde_stats.edits_applied;
            let mut edited_files = outcome.files_edited.clone();
            edited_files.extend(serde_files);
            combined.files_edited = edited_files.len();
            report.rename = combined;
            for skipped in outcome.skipped {
                report.skip(skipped);
            }
            report.warnings.extend(outcome.warnings);
            // Symbol renames and command renames both land in the one mapping;
            // they are separate sections because a command name is a protocol
            // value rather than a Rust identifier.
            mapping.symbols.extend(outcome.mapping.symbols);

            tracing::info!(
                renamed = report.rename.total(),
                kept = report.skipped_by_reason.values().sum::<usize>(),
                files = report.rename.files_edited,
                "rename pass complete"
            );
        }

        if plan.strings.enabled {
            let mut protocol_values = std::collections::HashSet::new();
            protocol_values.extend(mapping.commands.keys().cloned());
            protocol_values.extend(mapping.events.keys().cloned());
            protocol_values.extend(command_stats.kept.iter().map(|item| item.name.clone()));
            protocol_values.extend(event_stats.kept.iter().map(|item| item.name.clone()));

            let request = StringRequest {
                input_root: &layout.root,
                copied: &copy.copied,
                graph: &layout.crates,
                plan: &plan.strings,
                seed: seed.seed,
                reserved_protocol_values: &protocol_values,
            };
            let outcome = string_protection::run(&analysis, &request, &mut edits)
                .context("running the string protection pass")?;

            report.strings = crate::report::StringStats {
                values_discovered: outcome.values_discovered,
                occurrences_discovered: outcome.occurrences_discovered,
                values_protected: outcome.values_protected,
                occurrences_protected: outcome.occurrences_protected,
                kept_unsafe_context: outcome.kept_unsafe_context,
                kept_conflict: outcome.kept_conflict,
            };
            mapping.strings.extend(outcome.mapping);
            report.warnings.extend(outcome.warnings);
        }

        // Every pass has contributed; nothing has been written yet. This is the
        // only place the output tree is modified.
        let applied = edits
            .apply(&layout.root, &output_root)
            .context("applying the collected edits")?;
        tracing::info!(
            files = applied.files_edited,
            edits = applied.edits_applied,
            "applied edits"
        );
    }

    report.commands = command_stats;
    report.events = event_stats;

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
