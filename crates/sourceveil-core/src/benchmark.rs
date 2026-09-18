//! Reproducible performance and size measurements for transformed workspaces.
//!
//! The benchmark is intentionally a normal CLI operation rather than a
//! criterion suite: it exercises the exact source-to-source pipeline and the
//! ordinary Cargo release build a user ships. Build artifacts are directed to
//! temporary target directories so neither the input tree nor the generated
//! source tree is polluted.

use crate::config::Config;
use crate::pipeline::{self, TransformRequest};
use crate::scanner::ProjectLayout;
use anyhow::{bail, Context, Result};
use cargo_metadata::{MetadataCommand, TargetKind};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use tempfile::TempDir;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct BenchmarkRequest {
    pub input: PathBuf,
    pub output: PathBuf,
    pub config: Config,
    pub seed_override: Option<String>,
    pub iterations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    pub input: PathBuf,
    pub output: PathBuf,
    pub binary_name: String,
    pub iterations: usize,
    pub transform_ms: u128,
    pub baseline_build_ms: u128,
    pub transformed_build_ms: u128,
    pub baseline_source_bytes: u64,
    pub transformed_source_bytes: u64,
    pub source_delta_bytes: i64,
    pub baseline_binary_bytes: u64,
    pub transformed_binary_bytes: u64,
    pub binary_delta_bytes: i64,
    pub baseline_startup_ms: Vec<u128>,
    pub transformed_startup_ms: Vec<u128>,
}

impl BenchmarkReport {
    pub fn render(&self) -> String {
        format!(
            "sourceveil benchmark\n====================\n\
             binary:             {}\n\
             iterations:         {}\n\
             transform:          {} ms\n\
             baseline build:     {} ms\n\
             transformed build:  {} ms\n\
             source bytes:        {} -> {} ({:+})\n\
             binary bytes:        {} -> {} ({:+})\n\
             baseline startup:    {:?} ms\n\
             transformed startup: {:?} ms\n",
            self.binary_name,
            self.iterations,
            self.transform_ms,
            self.baseline_build_ms,
            self.transformed_build_ms,
            self.baseline_source_bytes,
            self.transformed_source_bytes,
            self.source_delta_bytes,
            self.baseline_binary_bytes,
            self.transformed_binary_bytes,
            self.binary_delta_bytes,
            self.baseline_startup_ms,
            self.transformed_startup_ms,
        )
    }
}

pub fn run(req: &BenchmarkRequest) -> Result<BenchmarkReport> {
    let input = req
        .input
        .canonicalize()
        .with_context(|| format!("resolving benchmark input {}", req.input.display()))?;
    if req.output.exists() {
        let mut entries = std::fs::read_dir(&req.output)
            .with_context(|| format!("reading benchmark output {}", req.output.display()))?;
        if entries.next().is_some() {
            bail!(
                "benchmark output {} already exists and is not empty",
                req.output.display()
            );
        }
    }

    let layout = ProjectLayout::discover(
        &input,
        req.config.project.rust_root.as_deref(),
        req.config.project.frontend_root.as_deref(),
        req.config.project.frontend_source.as_deref(),
    )?;
    let metadata = MetadataCommand::new()
        .manifest_path(&layout.rust_manifest)
        .no_deps()
        .exec()
        .context("loading benchmark Cargo metadata")?;
    let package = metadata
        .root_package()
        .or_else(|| {
            metadata
                .packages
                .iter()
                .find(|p| p.manifest_path == layout.rust_manifest)
        })
        .context("benchmark project has no root Cargo package")?;
    let target = package
        .targets
        .iter()
        .find(|t| t.kind.iter().any(|k| matches!(k, TargetKind::Bin)))
        .context("benchmark project has no binary target")?;
    let binary_name = target.name.to_string();

    let temp_targets = TempDir::new().context("creating benchmark target directory")?;
    let baseline_target = temp_targets.path().join("baseline");
    let transformed_target = temp_targets.path().join("transformed");
    let baseline_source_bytes = source_bytes(&input)?;

    let baseline_started = Instant::now();
    cargo_build(&layout.rust_manifest, &baseline_target)?;
    let baseline_build_ms = baseline_started.elapsed().as_millis();
    let baseline_binary = release_binary(&baseline_target, &binary_name);
    let baseline_binary_bytes = std::fs::metadata(&baseline_binary)
        .with_context(|| format!("reading {}", baseline_binary.display()))?
        .len();

    let transform_started = Instant::now();
    pipeline::transform(&TransformRequest {
        input: input.clone(),
        output: req.output.clone(),
        config: req.config.clone(),
        seed_override: req.seed_override.clone(),
        stages_override: None,
        skip_verify: true,
    })
    .context("benchmark transform")?;
    let transform_ms = transform_started.elapsed().as_millis();

    let output_root = req
        .output
        .canonicalize()
        .unwrap_or_else(|_| req.output.clone());
    let output_manifest = output_root.join(
        layout
            .rust_manifest
            .strip_prefix(&input)
            .context("root manifest is not under benchmark input")?,
    );
    let transformed_source_bytes = source_bytes(&output_root)?;

    let transformed_started = Instant::now();
    cargo_build(&output_manifest, &transformed_target)?;
    let transformed_build_ms = transformed_started.elapsed().as_millis();
    let transformed_binary = release_binary(&transformed_target, &binary_name);
    let transformed_binary_bytes = std::fs::metadata(&transformed_binary)
        .with_context(|| format!("reading {}", transformed_binary.display()))?
        .len();

    let iterations = req.iterations.max(1);
    let transformed_rust_root = output_root.join(layout.rust_relative());
    let baseline_startup_ms = startup_samples(&baseline_binary, &layout.rust_root, iterations)?;
    let transformed_startup_ms =
        startup_samples(&transformed_binary, &transformed_rust_root, iterations)?;

    Ok(BenchmarkReport {
        input,
        output: output_root,
        binary_name,
        iterations,
        transform_ms,
        baseline_build_ms,
        transformed_build_ms,
        baseline_source_bytes,
        transformed_source_bytes,
        source_delta_bytes: signed_delta(baseline_source_bytes, transformed_source_bytes),
        baseline_binary_bytes,
        transformed_binary_bytes,
        binary_delta_bytes: signed_delta(baseline_binary_bytes, transformed_binary_bytes),
        baseline_startup_ms,
        transformed_startup_ms,
    })
}

fn cargo_build(manifest: &Path, target_dir: &Path) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .args(["build", "--release", "--manifest-path"])
        .arg(manifest)
        .args(["--target-dir"])
        .arg(target_dir);
    if manifest
        .parent()
        .is_some_and(|parent| parent.join("Cargo.lock").is_file())
    {
        command.arg("--locked");
    }
    let output = command
        .output()
        .with_context(|| format!("building {}", manifest.display()))?;
    if !output.status.success() {
        bail!(
            "cargo release build failed for {}\n{}",
            manifest.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn release_binary(target_dir: &Path, binary_name: &str) -> PathBuf {
    let name = if cfg!(windows) {
        format!("{binary_name}.exe")
    } else {
        binary_name.to_string()
    };
    target_dir.join("release").join(name)
}

fn startup_samples(binary: &Path, cwd: &Path, iterations: usize) -> Result<Vec<u128>> {
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let output = Command::new(binary)
            .current_dir(cwd)
            .output()
            .with_context(|| format!("running benchmark binary {}", binary.display()))?;
        if !output.status.success() {
            bail!(
                "benchmark binary {} exited with {}",
                binary.display(),
                output.status
            );
        }
        samples.push(started.elapsed().as_millis());
    }
    Ok(samples)
}

fn source_bytes(root: &Path) -> Result<u64> {
    let mut total = 0;
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() || ignored_path(entry.path(), root) {
            continue;
        }
        total += entry.metadata()?.len();
    }
    Ok(total)
}

fn ignored_path(path: &Path, root: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(root) else {
        return true;
    };
    rel.components().any(|component| {
        matches!(
            component.as_os_str().to_string_lossy().as_ref(),
            ".git" | ".obfuscator" | "target" | "node_modules" | "dist"
        )
    })
}

fn signed_delta(before: u64, after: u64) -> i64 {
    after as i64 - before as i64
}

#[cfg(test)]
mod tests {
    use super::{ignored_path, signed_delta};
    use std::path::Path;

    #[test]
    fn benchmark_deltas_are_signed() {
        assert_eq!(signed_delta(10, 12), 2);
        assert_eq!(signed_delta(12, 10), -2);
    }

    #[test]
    fn benchmark_ignores_generated_artifacts() {
        assert!(ignored_path(
            Path::new("/tmp/out/target/release/app"),
            Path::new("/tmp/out")
        ));
        assert!(!ignored_path(
            Path::new("/tmp/out/src/main.rs"),
            Path::new("/tmp/out")
        ));
    }
}
