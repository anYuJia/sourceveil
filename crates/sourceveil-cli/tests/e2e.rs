//! End-to-end tests: run the real binary over the real fixture.
//!
//! These are the tests that actually establish the tool works, and they are
//! deliberately not mocked. The unit tests cover the decision logic — which
//! symbol is safe, which casing a name needs — but none of them can tell you
//! whether the tree rust-analyzer produced still compiles. Only building it
//! can, so the central test here ends in a real `cargo check`.
//!
//! They are slow, because each transform loads a cargo project into
//! rust-analyzer. That cost is the point: it is the same work a user pays. The
//! read-only assertions therefore share one transform between them rather than
//! paying for it seven times.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use tempfile::TempDir;

// ---------------------------------------------------------------------------
// what the fixture is built to demonstrate
// ---------------------------------------------------------------------------

/// Renamed: workspace-local, reached only from ordinary code, pinned by no rule.
const RENAMED: &[&str] = &[
    "internal_fold",
    "pick_transport",
    "establish_session",
    "PROTOCOL_TAG",
    "mint",
];

/// Must survive, because a rule or a language-level constraint says so.
const PINNED: &[&str] = &["main", "exported_checksum", "pinned_by_comment"];

/// Must survive, because rust-analyzer cannot rewrite the reference.
///
/// Every one of these is reached from inside a `format!` or `println!` call in
/// the fixture. Renaming the definition while leaving the macro argument alone
/// would produce source that does not compile — see the module docs on
/// `sourceveil_core::rust`.
const PINNED_BY_MACRO_REFERENCE: &[&str] =
    &["describe", "transport_name", "DEFAULT_PORT", "redact"];

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_cargo-obfuscator"))
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/simple-rust")
        .canonicalize()
        .expect("fixture directory")
}

fn transform(input: &Path, output: &Path, seed: &str) -> Output {
    Command::new(binary())
        .arg("transform")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .args(["--seed", seed])
        .output()
        .expect("spawning cargo-obfuscator")
}

fn assert_succeeded(result: &Output) {
    assert!(
        result.status.success(),
        "transform failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr),
    );
}

/// One transform of the fixture, shared by every read-only assertion.
static SHARED: OnceLock<(TempDir, PathBuf)> = OnceLock::new();

fn shared() -> &'static Path {
    &SHARED
        .get_or_init(|| {
            let tmp = TempDir::new().expect("temp dir");
            let out = tmp.path().join("generated");
            assert_succeeded(&transform(&fixture(), &out, "20240917"));
            (tmp, out)
        })
        .1
}

/// Every generated text file, keyed by path relative to the root.
///
/// `.obfuscator/` is excluded because `report.json` records wall-clock
/// durations, which legitimately differ between runs; everything that affects
/// the *build* is included.
fn source_tree(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for entry in walk(root) {
        let rel = entry
            .strip_prefix(root)
            .expect("path under root")
            .to_string_lossy()
            .to_string();
        if rel.starts_with(".obfuscator") || rel.starts_with("target") {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&entry) {
            out.insert(rel, text);
        }
    }
    out
}

fn walk(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("reading {rel}: {e}"))
}

/// The concatenation of every generated source file.
fn all_source(root: &Path) -> String {
    source_tree(root)
        .into_values()
        .collect::<Vec<_>>()
        .join("\n")
}

fn mapping(root: &Path) -> serde_json::Value {
    let path = root.join(".obfuscator/mapping.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("mapping.json"))
        .expect("valid json")
}

fn report(root: &Path) -> serde_json::Value {
    let path = root.join(".obfuscator/report.json");
    serde_json::from_str(&std::fs::read_to_string(&path).expect("report.json")).expect("valid json")
}

/// How many symbols were kept for a given reason.
fn skipped_count(root: &Path, reason: &str) -> u64 {
    report(root)["skipped_by_reason"][reason]
        .as_u64()
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// the main event
// ---------------------------------------------------------------------------

#[test]
fn transform_renames_symbols_and_the_result_still_compiles() {
    let out = shared();
    let source = all_source(out);

    for name in PINNED {
        assert!(
            source.contains(name),
            "`{name}` is pinned by a keep rule or an ABI attribute but was renamed away"
        );
    }

    for name in RENAMED {
        assert!(
            !source.contains(name),
            "`{name}` should have been renamed but is still present in the output"
        );
    }

    // The strongest statement the tool can make about its own output.
    let result = Command::new("cargo")
        .arg("check")
        .arg("--locked")
        .arg("--all-targets")
        .current_dir(out)
        .output()
        .expect("spawning cargo");
    assert!(
        result.status.success(),
        "generated tree at {} does not compile\n--- stderr ---\n{}",
        out.display(),
        String::from_utf8_lossy(&result.stderr),
    );
}

/// The rule that keeps the output compilable.
///
/// Without it the fixture produces `format!("{} via {} on {}", …, transport_name(..), DEFAULT_PORT)`
/// with `transport_name` and `DEFAULT_PORT` renamed at their definitions and
/// not at this call, which does not compile.
#[test]
fn macro_referenced_symbols_are_kept_and_reported() {
    let out = shared();
    let source = all_source(out);

    for name in PINNED_BY_MACRO_REFERENCE {
        assert!(
            source.contains(name),
            "`{name}` is referenced from inside a macro token tree, where \
             rust-analyzer cannot rewrite it; leaving it renamed would break the build"
        );
    }

    assert!(
        skipped_count(out, "macro-call-reference") >= PINNED_BY_MACRO_REFERENCE.len() as u64,
        "the report must say how many symbols the macro rule cost"
    );

    // And the reason must be attached to the right symbols, not merely counted.
    let skipped = report(out);
    for entry in skipped["skipped"].as_array().expect("skipped array") {
        let path = entry["symbol_path"].as_str().unwrap_or_default();
        if PINNED_BY_MACRO_REFERENCE.iter().any(|n| path.ends_with(n)) {
            assert_eq!(
                entry["reason"].as_str(),
                Some("macro-call-reference"),
                "`{path}` was kept, but for the wrong stated reason: {entry}"
            );
        }
    }
}

#[test]
fn rename_reaches_across_module_and_file_boundaries() {
    let out = shared();
    let main_rs = read(out, "src/main.rs");
    let auth_mod = read(out, "src/auth/mod.rs");
    let token_rs = read(out, "src/auth/token.rs");

    // `establish_session` is defined in auth/mod.rs, called from main.rs, and
    // returns a type defined in auth/token.rs. All three files must agree.
    assert!(!main_rs.contains("establish_session"));
    assert!(!auth_mod.contains("establish_session"));
    assert!(!token_rs.contains("Session"));
    assert!(
        auth_mod.contains("mod token;"),
        "module declarations must survive"
    );

    // `mint` is defined in token.rs and called from auth/mod.rs.
    assert!(!token_rs.contains("mint"));
    assert!(
        !auth_mod.contains("token::mint"),
        "cross-file call not renamed"
    );
}

#[test]
fn ffi_and_keep_rules_pin_exactly_what_they_should() {
    let out = shared();
    let main_rs = read(out, "src/main.rs");

    assert!(
        main_rs.contains("exported_checksum"),
        "a #[no_mangle] symbol is the C ABI; renaming it silently changes the linkage"
    );
    assert!(
        main_rs.contains("fn main()"),
        "`main` is the process entry point"
    );
    assert!(
        main_rs.contains("pinned_by_comment"),
        "// obfuscator:keep must pin the item below it"
    );
}

#[test]
fn the_input_tree_is_never_written_to() {
    let before = source_tree(&fixture());
    let _ = shared();
    let after = source_tree(&fixture());

    assert_eq!(
        before, after,
        "the transform modified the input tree; output must be a separate copy"
    );
}

#[test]
fn the_mapping_records_what_was_renamed() {
    let out = shared();
    let parsed = mapping(out);

    let symbols = parsed["symbols"].as_object().expect("symbols object");
    let paths: Vec<&str> = symbols.keys().map(String::as_str).collect();

    for name in RENAMED {
        assert!(
            paths.iter().any(|k| k.ends_with(name)),
            "mapping is missing the rename of `{name}`; it has {paths:?}"
        );
    }
    // Function renames are not the whole story: types, variants and methods
    // have to be recorded too, or a stack trace cannot be read back.
    for name in ["Session", "Transport::Tls", "Session::new"] {
        assert!(
            paths.iter().any(|k| k.ends_with(name)),
            "mapping is missing the rename of `{name}`; it has {paths:?}"
        );
    }

    assert_eq!(parsed["seed"].as_u64(), Some(20240917));

    // Nothing recorded in the mapping may still be findable in the output —
    // that is what the leak-scan stage asserts during the transform, and this
    // is the same claim checked independently.
    let source = all_source(out);
    for original in paths {
        let short = original.rsplit("::").next().expect("symbol name");
        if short.len() >= 4 {
            assert!(
                !source.contains(short),
                "`{short}` was recorded as renamed but still appears in the output"
            );
        }
    }
}

#[test]
fn no_source_maps_reach_the_output() {
    let out = shared();
    for path in walk(out) {
        let rel = path
            .strip_prefix(out)
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert!(
            !rel.ends_with(".map"),
            "a source map reached the generated tree: {rel}"
        );
    }
}

// ---------------------------------------------------------------------------
// build diversification
// ---------------------------------------------------------------------------

#[test]
fn seeds_are_reproducible_and_actually_diversify() {
    let tmp = TempDir::new().unwrap();
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");
    let other = tmp.path().join("other");

    for (out, seed) in [(&first, "424242"), (&second, "424242"), (&other, "424243")] {
        assert_succeeded(&transform(&fixture(), out, seed));
    }

    assert_eq!(
        source_tree(&first),
        source_tree(&second),
        "same source + same seed must produce identical output, or a release \
         cannot be rebuilt"
    );
    assert_ne!(
        source_tree(&first),
        source_tree(&other),
        "two builds from different seeds are byte-identical, so the seed is not \
         reaching the name generator"
    );
}

// ---------------------------------------------------------------------------
// refusal to do the wrong thing
// ---------------------------------------------------------------------------

#[test]
fn refuses_to_write_into_a_populated_output_directory() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("generated");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("pre-existing.txt"), "do not clobber me").unwrap();

    let result = transform(&fixture(), &out, "1");
    assert!(!result.status.success(), "should have refused");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("already exists and is not empty"),
        "unhelpful error: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        out.join("pre-existing.txt").is_file(),
        "the pre-existing file was destroyed anyway"
    );
}

// ---------------------------------------------------------------------------
// serde wire format
// ---------------------------------------------------------------------------
//
// The rename pass must not change what the program writes to the network or to
// disk. Compiling is not evidence of that — the two builds compile either way.
// The only proof is to run the original and the transformed program and compare
// their output, which is what these tests do.

fn serde_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/serde-safety")
        .canonicalize()
        .expect("serde fixture directory")
}

/// Run a crate in `root` and return its stdout.
fn run_crate(root: &Path) -> String {
    let result = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .current_dir(root)
        .output()
        .expect("spawning cargo run");
    assert!(
        result.status.success(),
        "{} failed to run\n--- stderr ---\n{}",
        root.display(),
        String::from_utf8_lossy(&result.stderr),
    );
    String::from_utf8_lossy(&result.stdout).to_string()
}

/// The wire format of the untransformed fixture. Everything below is compared
/// against this.
static WIRE_FORMAT: OnceLock<String> = OnceLock::new();

fn original_wire_format() -> &'static str {
    WIRE_FORMAT.get_or_init(|| run_crate(&serde_fixture()))
}

/// Transform the serde fixture, optionally under a named profile.
fn transform_serde(profile: Option<&str>, seed: &str) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("temp dir");
    let out = tmp.path().join("generated");

    let mut cmd = Command::new(binary());
    cmd.arg("transform")
        .arg("--input")
        .arg(serde_fixture())
        .arg("--output")
        .arg(&out)
        .args(["--seed", seed]);

    if let Some(profile) = profile {
        let config = tmp.path().join("obfuscator.toml");
        std::fs::write(&config, format!("version = 1\nprofile = {profile:?}\n"))
            .expect("writing config");
        cmd.arg("--config").arg(&config);
    }

    let result = cmd.output().expect("spawning cargo-obfuscator");
    assert_succeeded(&result);
    (tmp, out)
}

/// Every name in the fixture that is a wire-format key.
const SERDE_KEYS: &[&str] = &[
    // plain model
    "user_name",
    "device_id",
    "internal_scratch",
    // rename_all = "camelCase"
    "session_token",
    "expires_at",
    // externally tagged enum
    "Connected",
    "Disconnected",
    "reason_code",
    // internally tagged enum
    "Started",
    "Stopped",
    "started_at",
    // explicit per-field rename
    "modern_name",
    "legacy_name",
];

/// The one entry in [`SERDE_KEYS`] that is not an identifier.
///
/// `legacy_name` is the string *value* of `#[serde(rename = "legacy_name")]`.
/// It is a wire key that has to survive, but it is never a rename candidate, so
/// it can never appear among the `serde-model` skips.
const SERDE_KEY_STRING_VALUES: &[&str] = &["legacy_name"];

/// Names that are ordinary Rust identifiers and must keep moving.
const NON_SERDE_FIELDS: &[&str] = &["scratch_buffer", "retry_count"];

#[test]
fn serde_wire_format_survives_the_default_profile() {
    let (_tmp, out) = transform_serde(None, "20240917");
    assert_eq!(
        run_crate(&out),
        original_wire_format(),
        "the generated program serialises differently from the original"
    );
}

#[test]
fn serde_wire_format_survives_the_balanced_profile() {
    // `balanced` is the profile that actually turns field rename on, so this is
    // the case where a missing serde rule would do real damage.
    let (_tmp, out) = transform_serde(Some("balanced"), "20240917");

    assert_eq!(
        run_crate(&out),
        original_wire_format(),
        "the generated program serialises differently from the original"
    );

    let model = read(&out, "src/model.rs");
    for key in SERDE_KEYS {
        assert!(
            model.contains(key),
            "`{key}` is a serde wire-format key but was renamed"
        );
    }
    for field in NON_SERDE_FIELDS {
        assert!(
            !model.contains(field),
            "`{field}` is not part of any serde model, so `balanced` should have renamed it"
        );
    }

    // And the report must say why the difference exists, not just that it does.
    let identifier_keys = SERDE_KEYS.len() - SERDE_KEY_STRING_VALUES.len();
    assert!(
        skipped_count(&out, "serde-model") >= identifier_keys as u64,
        "every wire-format identifier should be accounted for as a serde-model skip"
    );
}

/// Serde members are pinned even under `safe`, where fields are off but enum
/// variants are renamed by default — a variant name is a JSON key too.
#[test]
fn serde_enum_variants_are_pinned_under_the_safe_profile() {
    let (_tmp, out) = transform_serde(None, "20240917");
    let model = read(&out, "src/model.rs");
    for variant in ["Connected", "Disconnected", "Started", "Stopped"] {
        assert!(
            model.contains(variant),
            "variant `{variant}` is an externally-tagged key and was renamed"
        );
    }
    assert!(
        skipped_count(&out, "serde-model") >= 4,
        "the four serde variants should be reported as serde-model skips"
    );
}

/// The fixture is only meaningful if it still demonstrates obfuscation.
#[test]
fn serde_fixture_still_renames_its_non_serde_types() {
    let (_tmp, out) = transform_serde(Some("balanced"), "20240917");
    let model = read(&out, "src/model.rs");
    assert!(
        !model.contains("RuntimeState"),
        "a non-serde type must still be renamed, or this fixture proves nothing"
    );
}
