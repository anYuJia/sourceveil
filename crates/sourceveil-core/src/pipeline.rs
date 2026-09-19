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
use crate::dependencies::{self as dependency_wrappers, DependencyRequest};
use crate::edits::EditPlan;
use crate::frontend::rename as frontend_rename;
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
    let verification_stages = (!req.skip_verify && plan.build.verify).then(|| {
        req.stages_override
            .clone()
            .unwrap_or_else(|| plan.build.verify_stages.clone())
    });
    let compiler_repair_enabled = verification_stages
        .as_ref()
        .is_some_and(|stages| stages.contains(&VerifyStage::CargoCheck));

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
    let mut preserve_roots = Vec::new();
    if let Some(root) = &layout.frontend_root {
        preserve_roots.push(root.clone());
    }
    if let Some(source) = &layout.frontend_source {
        preserve_roots.push(source.clone());
    }
    let copy = copier::copy_workspace_preserving(
        &layout.root,
        &req.output,
        &plan.project.ignore,
        &preserve_roots,
    )
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
    let mut frontend_stats = crate::report::FrontendStats::default();

    let dependency_wrappers_enabled = plan.dependencies.default
        == crate::config::DependencyMode::Wrapper
        || plan
            .dependencies
            .crates
            .values()
            .any(|mode| *mode == crate::config::DependencyMode::Wrapper);

    let mut semantic_rename = plan.rename.clone();
    semantic_rename.locals = false;
    semantic_rename.params = false;
    if !semantic_rename.is_noop()
        || plan.tauri.commands
        || plan.tauri.events
        || plan.strings.enabled
        || plan.frontend.rename_private_identifiers
        || dependency_wrappers_enabled
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
        let macro_analysis_root = output_root.join(layout.rust_relative());
        let facts = rename::collect_syntax_facts(
            &analysis,
            &files,
            &layout.crates,
            &layout.root,
            &output_root,
            &macro_analysis_root,
        )
        .context("building semantic macro reference index")?;
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

        if plan
            .dependencies
            .crates
            .values()
            .any(|mode| *mode == crate::config::DependencyMode::Wrapper)
            || plan.dependencies.default == crate::config::DependencyMode::Wrapper
        {
            let request = DependencyRequest {
                input_root: &layout.root,
                copied: &copy.copied,
                graph: &layout.crates,
                plan: &plan,
            };
            let outcome = dependency_wrappers::run(&analysis, &request, &mut names, &mut edits)
                .context("running the dependency boundary wrapper pass")?;
            report.dependencies = crate::report::DependencyStats {
                wrappers_generated: outcome.wrappers_generated,
                references_rewritten: outcome.references_rewritten,
                files_edited: outcome.files_edited.len(),
            };
            mapping.dependency_wrappers.extend(outcome.mapping);
            report.warnings.extend(outcome.warnings);
        }

        let mut serde_stats = crate::report::RenameStats::default();
        let mut serde_files = std::collections::BTreeSet::new();
        let mut serde_wire_values = std::collections::HashSet::new();
        if !plan.rename.is_noop() {
            let request = SerdeRenameRequest {
                input_root: &layout.root,
                copied: &copy.copied,
                plan: &plan,
                graph: &layout.crates,
                seed: seed.seed,
                allow_unresolved_macro_references: compiler_repair_enabled,
            };
            let outcome = serde_rename::run(
                &analysis,
                &request,
                &mut names,
                &mut edits,
                &facts.macro_referenced,
                &facts.macro_references,
            )
            .context("running the serde rename pass")?;

            serde_stats = outcome.stats;
            serde_files = outcome.files_edited;
            serde_wire_values = outcome.wire_values;
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
                allow_unresolved_macro_references: compiler_repair_enabled,
            };

            let outcome = rename::run(
                &analysis,
                &request,
                Shared {
                    names: &mut names,
                    plan: &mut edits,
                    claimed: &claimed,
                    macro_referenced: facts.macro_referenced,
                    macro_format_referenced: facts.macro_format_referenced,
                    macro_references: facts.macro_references,
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
            protocol_values.extend(serde_wire_values);

            let request = StringRequest {
                input_root: &layout.root,
                copied: &copy.copied,
                graph: &layout.crates,
                plan: &plan.strings,
                dependencies: &plan.dependencies,
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
                kept_external_collision: outcome.kept_external_collision,
                kept_conflict: outcome.kept_conflict,
            };
            mapping.strings.extend(outcome.mapping);
            report.warnings.extend(outcome.warnings);
        }

        if plan.frontend.rename_private_identifiers {
            if let Some(source_root) = layout.frontend_source.as_deref() {
                let request = frontend_rename::RenameRequest {
                    input_root: &layout.root,
                    source_root,
                    copied: &copy.copied,
                };
                let outcome = frontend_rename::run(&request, &mut names, &mut edits)
                    .context("running the frontend semantic rename pass")?;

                frontend_stats = outcome.stats;
                mapping
                    .frontend_symbols
                    .extend(outcome.mapping.frontend_symbols);
                report.warnings.extend(outcome.warnings);
            } else if plan.frontend.enabled {
                report.warnings.push(
                    "frontend rename requested but no frontend source directory was found".into(),
                );
            }
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

        // Serde stores Rust paths inside string metadata. They cannot
        // participate in rust-analyzer's source change, so rewrite those exact
        // grammar positions after the semantic transaction has landed and
        // before any build/binding verification sees the generated tree.
        let contracts = crate::serde::contracts::rewrite_workspace(&output_root, &mapping.symbols)
            .context("rewriting serde path contracts")?;
        report.rename.edits_applied += contracts.paths_rewritten;
        tracing::info!(
            files = contracts.files_edited,
            paths = contracts.paths_rewritten,
            "rewrote serde path contracts"
        );

        // Proc-macro helper attributes can also contain Rust identifiers in
        // strings. Handle only structurally proven contracts (currently
        // thiserror named-field captures) after field renames have landed.
        let contracts = crate::rust::contracts::rewrite_workspace(&output_root, &mapping.symbols)
            .context("rewriting Rust attribute contracts")?;
        report.rename.edits_applied += contracts.captures_rewritten;
        tracing::info!(
            files = contracts.files_edited,
            captures = contracts.captures_rewritten,
            "rewrote Rust attribute contracts"
        );
    }

    report.commands = command_stats;
    report.events = event_stats;
    report.frontend = frontend_stats;

    if plan.rename.locals || plan.rename.params {
        let outcome = crate::rust::bindings::run(
            &output_root,
            &layout.root,
            &layout.crates,
            &plan,
            seed.seed,
            &mapping.symbols,
        )?;
        report.rename.locals += outcome.stats.locals;
        report.rename.params += outcome.stats.params;
        report.rename.edits_applied += outcome.stats.edits_applied;
        report.rename.binding_files_edited = outcome.stats.files_edited;
        report.files.rust_scanned = report.files.rust_scanned.max(outcome.files_scanned);
        mapping.symbols.extend(outcome.mapping);
        for skipped in outcome.skipped {
            report.skip(skipped);
        }
    }

    // Keep directives and macro references must be read before comments vanish.
    // Read the generated tree here so moved module paths and generated files
    // are covered, without invalidating any semantic edit offsets.
    if plan.strip_comments {
        let outcome = crate::comments::strip_workspace(&output_root)?;
        report.comments = outcome.stats;
        report.warnings.extend(outcome.warnings);
    }

    let rust_root_out = output_root.join(layout.rust_relative());

    // rust-analyzer intentionally does not model every proc-macro-generated
    // deref or every inference edge. When cargo-check is part of the requested
    // proof, use rustc's typed diagnostics to complete only those exact
    // references whose original identifier has one mapping. This runs before
    // the recorded verification; that later stage independently proves the
    // repaired tree.
    if verification_stages
        .as_ref()
        .is_some_and(|stages| stages.contains(&VerifyStage::CargoCheck))
    {
        let repaired = verify::repair_rust_references(&rust_root_out, &mapping, 6)
            .context("completing references from rustc diagnostics")?;
        report.rename.edits_applied += repaired.references_repaired;
        if repaired.references_repaired > 0 {
            report.warnings.push(format!(
                "compiler-guided reference completion repaired {} exact span(s) in {} pass(es)",
                repaired.references_repaired, repaired.passes
            ));
        }
        tracing::info!(
            passes = repaired.passes,
            references = repaired.references_repaired,
            passed = repaired.check_passed,
            "compiler-guided reference completion"
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
    if let Some(stages) = verification_stages {
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

        for stage in stages {
            let results = verify::run(&ctx, &[stage]);
            let passed = results.passed();
            report.verification.extend(results.stages);
            // Build tools can regenerate commented assets or Cargo.lock.
            // Clean them before the following stage and before handing off.
            if plan.strip_comments {
                let outcome = crate::comments::strip_workspace(&output_root)?;
                report.comments.files_scanned += outcome.stats.files_scanned;
                report.comments.files_edited += outcome.stats.files_edited;
                report.comments.comments_removed += outcome.stats.comments_removed;
                report.comments.notices_extracted += outcome.stats.notices_extracted;
                for warning in outcome.warnings {
                    if !report.warnings.contains(&warning) {
                        report.warnings.push(warning);
                    }
                }
            }
            if !passed {
                break;
            }
        }
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
