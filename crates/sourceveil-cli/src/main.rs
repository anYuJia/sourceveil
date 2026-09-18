//! `cargo-obfuscator` — CLI front-end.
//!
//! Named so that `cargo obfuscate` resolves to it, and so it can be invoked
//! directly as `cargo-obfuscator`.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use sourceveil_core::config::{Config, VerifyStage};
use sourceveil_core::pipeline::{self, TransformRequest};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "cargo-obfuscator",
    version,
    about = "Semantic-aware source-to-source obfuscator for Rust/Tauri workspaces",
    long_about = "Transforms a Rust/Tauri project into a new, complete source tree whose \
                  symbols are renamed and whose build is diversified, without touching the \
                  input tree. The output is ordinary source: build it with the ordinary \
                  toolchain."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a transformed copy of a project.
    Transform(TransformArgs),

    /// Report what a transform would do, without writing anything.
    Scan(ScanArgs),

    /// Run the verification pipeline against an already-generated tree.
    Verify(VerifyArgs),

    /// Scan a final executable or library for original protocol values.
    ScanBinary(ScanBinaryArgs),
}

#[derive(Debug, Parser)]
struct TransformArgs {
    /// Project root to read. Never written to.
    #[arg(long, default_value = ".")]
    input: PathBuf,

    /// Directory to write the generated workspace into. Must not exist, or
    /// must be empty.
    #[arg(long)]
    output: PathBuf,

    /// Path to `obfuscator.toml`.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override `[build] seed`: `auto`, `random`, `hmac`, or a decimal u64.
    #[arg(long)]
    seed: Option<String>,

    /// Verification stage to run. Repeatable; replaces the configured list.
    #[arg(long = "stage", value_enum)]
    stages: Vec<StageArg>,

    /// Skip the verification pipeline.
    #[arg(long)]
    no_verify: bool,

    /// Print more detail about what was and was not transformed.
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Parser)]
struct ScanArgs {
    #[arg(long, default_value = ".")]
    input: PathBuf,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Parser)]
struct ScanBinaryArgs {
    /// Built PE/ELF/Mach-O (or any binary blob) to inspect.
    #[arg(long)]
    binary: PathBuf,

    /// mapping.json produced by the transform.
    #[arg(long)]
    mapping: PathBuf,

    /// Emit the full machine-readable report as JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Parser)]
struct VerifyArgs {
    /// A previously generated workspace root.
    #[arg(long)]
    output: PathBuf,

    #[arg(long)]
    config: Option<PathBuf>,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StageArg {
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

impl From<StageArg> for VerifyStage {
    fn from(value: StageArg) -> Self {
        match value {
            StageArg::CargoMetadata => VerifyStage::CargoMetadata,
            StageArg::CargoCheck => VerifyStage::CargoCheck,
            StageArg::CargoTest => VerifyStage::CargoTest,
            StageArg::CargoClippy => VerifyStage::CargoClippy,
            StageArg::NpmCi => VerifyStage::NpmCi,
            StageArg::NpmTypecheck => VerifyStage::NpmTypecheck,
            StageArg::NpmBuild => VerifyStage::NpmBuild,
            StageArg::TauriBuild => VerifyStage::TauriBuild,
            StageArg::LeakScan => VerifyStage::LeakScan,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let verbose = match &cli.command {
        Command::Transform(a) => a.verbose,
        Command::Scan(a) => a.verbose,
        Command::Verify(a) => a.verbose,
        Command::ScanBinary(_) => false,
    };
    init_tracing(verbose);

    match cli.command {
        Command::Transform(args) => run_transform(args),
        Command::Scan(args) => run_scan(args),
        Command::Verify(args) => run_verify(args),
        Command::ScanBinary(args) => run_scan_binary(args),
    }
}

fn run_transform(args: TransformArgs) -> Result<()> {
    let config = load_config(args.config.as_deref())?;

    let request = TransformRequest {
        input: args.input,
        output: args.output,
        config,
        seed_override: args.seed,
        stages_override: (!args.stages.is_empty())
            .then(|| args.stages.into_iter().map(VerifyStage::from).collect()),
        skip_verify: args.no_verify,
    };

    let outcome = pipeline::transform(&request)?;

    print!("{}", outcome.report.render());

    if let Some(path) = &outcome.mapping_path {
        println!();
        println!("mapping written to {}", path.display());
        println!(
            "  keep this out of any shipped artifact; it is the only record of the \
             original names"
        );
    }

    println!();
    println!("generated workspace: {}", outcome.output_root.display());

    if !outcome.report.verification_passed() {
        anyhow::bail!(
            "verification failed; the generated tree at {} is not usable as-is",
            outcome.output_root.display()
        );
    }

    Ok(())
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let config = load_config(args.config.as_deref())?;
    let layout = pipeline::scan_only(&args.input, &config)?;

    println!("project root:   {}", layout.root.display());
    println!("rust root:      {}", layout.rust_root.display());
    println!("manifest:       {}", layout.rust_manifest.display());
    match &layout.frontend_root {
        Some(p) => println!("frontend root:  {}", p.display()),
        None => println!("frontend root:  (none detected)"),
    }
    if let Some(p) = &layout.frontend_source {
        println!("frontend src:   {}", p.display());
    }
    if let Some(p) = sourceveil_core::scanner::find_tauri_conf(&layout.rust_root) {
        println!("tauri config:   {}", p.display());
    }

    println!();
    println!("workspace crates ({})", layout.crates.workspace.len());
    for krate in layout.crates.workspace.values() {
        let boundary = if layout.crates.boundary.contains(&krate.name) {
            "  [api boundary: public items kept]"
        } else if krate.is_proc_macro {
            "  [proc-macro: public items kept]"
        } else {
            ""
        };
        println!(
            "  {:<28} {}{}",
            krate.name,
            krate
                .crate_types
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
            boundary
        );
    }

    for warning in &layout.crates.warnings {
        eprintln!("warning: {warning}");
    }

    Ok(())
}

fn run_verify(args: VerifyArgs) -> Result<()> {
    let config = load_config(args.config.as_deref())?;
    let plan = sourceveil_core::plan::Plan::resolve(&config)?;

    let root = args
        .output
        .canonicalize()
        .with_context(|| format!("resolving {}", args.output.display()))?;

    // The generated tree keeps the input's layout, so rediscovering it works
    // the same way it did before the transform.
    let layout = pipeline::scan_only(&root, &config)?;
    let mapping_path = sourceveil_core::verify::resolve_mapping_dir(&root, &plan.build.mapping_dir)
        .join("mapping.json");
    let mapping = sourceveil_core::mapping::Mapping::read(&mapping_path)
        .with_context(|| format!("reading {}", mapping_path.display()))?;

    let ctx = sourceveil_core::verify::VerifyContext {
        output_root: &root,
        rust_root: &layout.rust_root,
        frontend_root: layout.frontend_root.as_deref(),
        mapping_dir: mapping_path.parent(),
        mapping: &mapping,
    };

    let report = sourceveil_core::verify::run(&ctx, &plan.build.verify_stages);
    for stage in &report.stages {
        let status = if stage.passed { "PASS" } else { "FAIL" };
        println!(
            "{:<16} {status}  ({:.1}s)",
            stage.stage,
            stage.duration_ms as f64 / 1000.0
        );
        if let Some(detail) = &stage.detail {
            println!("    {detail}");
        }
    }

    if !report.passed() {
        anyhow::bail!("verification failed");
    }
    Ok(())
}

fn run_scan_binary(args: ScanBinaryArgs) -> Result<()> {
    let mapping = sourceveil_core::mapping::Mapping::read(&args.mapping)
        .with_context(|| format!("reading {}", args.mapping.display()))?;
    let report = sourceveil_core::binary_scan::scan_file(&args.binary, &mapping)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "scanned {} ({} bytes)",
            report.path.display(),
            report.bytes_scanned
        );
        println!("protocol leaks: {}", report.protocol_leaks.len());
        for leak in report.protocol_leaks.iter().take(40) {
            println!(
                "  FAIL {:<10} @ 0x{:x}  {:?}",
                leak.encoding, leak.offset, leak.value
            );
        }
        println!("symbol text hits: {} (informational)", report.symbol_hits.len());
        for hit in report.symbol_hits.iter().take(12) {
            println!(
                "  note {:<10} @ 0x{:x}  {:?}",
                hit.encoding, hit.offset, hit.value
            );
        }
    }

    if !report.passed() {
        anyhow::bail!(
            "{} original protocol value occurrence(s) remain in {}",
            report.protocol_leaks.len(),
            args.binary.display()
        );
    }
    Ok(())
}

fn load_config(path: Option<&std::path::Path>) -> Result<Config> {
    match path {
        Some(p) => Config::load(p),
        None => {
            let default = PathBuf::from("obfuscator.toml");
            if default.is_file() {
                Config::load(&default)
            } else {
                // A missing config is not an error: every setting has a
                // default, and the defaults are the `safe` profile.
                Ok(Config::default())
            }
        }
    }
}

fn init_tracing(verbose: bool) {
    use tracing_subscriber::{fmt, EnvFilter};

    // Default to this tool's own logs only. rust-analyzer emits an INFO line
    // for every salsa query it runs, which buries the run report under
    // thousands of lines of query traces. Set SOURCEVEIL_LOG to see them —
    // `SOURCEVEIL_LOG=rust_analyzer=debug,sourceveil_core=debug` is the useful
    // combination when tracking down why a symbol was not renamed.
    let default = if verbose {
        "sourceveil_core=debug,cargo_obfuscator=debug"
    } else {
        "sourceveil_core=info,cargo_obfuscator=info"
    };

    let filter = EnvFilter::try_from_env("SOURCEVEIL_LOG")
        .or_else(|_| EnvFilter::try_new(default))
        .unwrap_or_else(|_| EnvFilter::new("sourceveil_core=info"));

    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
