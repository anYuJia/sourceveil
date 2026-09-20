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

use std::collections::{BTreeMap, BTreeSet};
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

/// Referenced from inside `format!`/`println!`; the standard-macro semantic
/// shell must resolve and rewrite both definition and call-site token.
const REFERENCED_BY_STANDARD_MACRO: &[&str] =
    &["describe", "transport_name", "DEFAULT_PORT", "redact"];

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_cargo-obfuscator"))
}

#[test]
fn cargo_subcommand_and_direct_entrypoints_expose_comment_flag() {
    for args in [
        vec!["transform", "--help"],
        vec!["obfuscator", "transform", "--help"],
    ] {
        let result = Command::new(binary()).args(args).output().unwrap();
        assert_succeeded(&result);
        assert!(String::from_utf8(result.stdout)
            .unwrap()
            .contains("--strip-comments"));
    }
}

#[test]
fn closure_bindings_and_strip_comments_work_through_the_cli() {
    let tmp = TempDir::new().unwrap();
    let input = tmp.path().join("input");
    std::fs::create_dir_all(input.join("src")).unwrap();
    std::fs::write(input.join("Cargo.toml"), "# manifest comment\n[package]\nname='closure_fixture'\nversion='0.1.0'\nedition='2024'\n[workspace]\n").unwrap();
    let source = r#"//! remove doc comment
struct Cookie { value: String }
fn main(){
    // remove local comment
    let cookies=[Cookie{value:"hello".into()}];
    let result=cookies.iter().map(|cookie| {let item=&cookie.value;format!("{item}")}).collect::<Vec<_>>();
    println!("{}",result.join(";"));
}"#;
    std::fs::write(input.join("src/main.rs"), source).unwrap();
    std::fs::write(
        input.join("web.js"),
        "/*! Copyright fixture */\nconst url='https://example.com';// remove\n",
    )
    .unwrap();
    let config = tmp.path().join("config.toml");
    std::fs::write(
        &config,
        r#"profile='safe'
[rename]
locals=true
params=true
functions=false
types=false
traits=false
enums=false
consts=false
statics=false
modules=false
fields=false
[build]
verify=true
verify_stages=['cargo-check','leak-scan']
"#,
    )
    .unwrap();
    let output = tmp.path().join("output");
    let result = Command::new(binary())
        .args(["transform", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .arg("--config")
        .arg(&config)
        .args(["--seed", "43", "--strip-comments"])
        .output()
        .unwrap();
    assert_succeeded(&result);
    let transformed = read(&output, "src/main.rs");
    assert!(!transformed.contains("|cookie|"));
    assert!(!transformed.contains("let item"));
    assert!(!transformed.contains("remove"));
    assert!(!transformed.contains("{item}"));
    assert_eq!(read(&input, "src/main.rs"), source);
    assert!(read(&output, "web.js").contains("https://example.com"));
    assert!(read(&output, "SOURCEVEIL_NOTICES.txt").contains("Copyright fixture"));
    assert!(
        report(&output)["comments"]["comments_removed"]
            .as_u64()
            .unwrap()
            >= 4
    );
    let run = Command::new("cargo")
        .args(["run", "--quiet", "--offline"])
        .current_dir(&output)
        .output()
        .unwrap();
    assert_succeeded(&run);
    assert_eq!(String::from_utf8(run.stdout).unwrap(), "hello\n");
}

#[test]
fn inferred_fields_methods_and_shadowed_names_use_definition_indexed_edits() {
    let tmp = TempDir::new().unwrap();
    let input = tmp.path().join("input");
    std::fs::create_dir_all(input.join("src")).unwrap();
    std::fs::write(
        input.join("Cargo.toml"),
        "[workspace]\n[package]\nname='semantic_members'\nversion='0.1.0'\nedition='2024'\n",
    )
    .unwrap();
    let source = r#"mod config { pub fn marker()->i32 { 2 } }
struct Client { config:i32, state:i32 }
impl Client {
    fn new(config:i32)->Self { Self { config, state:config+1 } }
    fn validate(&self)->i32 { self.config+self.state }
}
fn main(){
    let config=3;
    let client=Client::new(config);
    println!("{}",client.validate()+client.config+config::marker());
}"#;
    std::fs::write(input.join("src/main.rs"), source).unwrap();
    let config = tmp.path().join("obfuscator.toml");
    std::fs::write(
        &config,
        "version=1\nprofile='aggressive'\n[build]\nverify_stages=['cargo-check']\nload_out_dirs=false\n",
    )
    .unwrap();
    let out = tmp.path().join("output");
    let transformed = Command::new(binary())
        .args(["transform", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(&out)
        .arg("--config")
        .arg(&config)
        .args(["--seed", "91"])
        .output()
        .unwrap();
    assert_succeeded(&transformed);
    let generated = all_source(&out);
    for original in ["Client", "config", "state", "new", "validate", "client"] {
        assert!(
            !generated.contains(original),
            "definition-indexed rename left `{original}` behind:\n{generated}"
        );
    }
    let run = Command::new("cargo")
        .args(["run", "--quiet", "--offline"])
        .current_dir(&out)
        .output()
        .unwrap();
    assert_succeeded(&run);
    assert_eq!(String::from_utf8(run.stdout).unwrap(), "12\n");
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

#[test]
fn standard_macro_references_are_semantically_renamed() {
    let out = shared();
    let source = all_source(out);

    for name in REFERENCED_BY_STANDARD_MACRO {
        assert!(
            !source.contains(name),
            "`{name}` survived even though its standard-macro reference is semantically resolvable"
        );
        assert!(
            symbol_mapping_contains(out, name),
            "`{name}` has no mapping entry"
        );
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
fn module_file_rename_moves_a_directory_transactionally() {
    let tmp = TempDir::new().expect("temp dir");
    let out = tmp.path().join("generated");
    let config = tmp.path().join("obfuscator.toml");
    std::fs::write(
        &config,
        r#"
version = 1
profile = "safe"

[rename]
module_files = true

[build]
verify = false
"#,
    )
    .expect("writing module-file config");

    let result = Command::new(binary())
        .args(["transform", "--input"])
        .arg(fixture())
        .args(["--output"])
        .arg(&out)
        .args(["--config"])
        .arg(&config)
        .args(["--seed", "4242", "--no-verify"])
        .output()
        .expect("spawning cargo-obfuscator");
    assert_succeeded(&result);

    let parsed = mapping(&out);
    let new_module = parsed["symbols"]
        .as_object()
        .expect("symbols mapping")
        .iter()
        .find_map(|(old, new)| {
            old.ends_with("::auth")
                .then(|| new.as_str().expect("module replacement").to_string())
        })
        .expect("auth module should be renamed");
    let new_child_module = parsed["symbols"]
        .as_object()
        .expect("symbols mapping")
        .iter()
        .find_map(|(old, new)| {
            old.ends_with("::auth::token")
                .then(|| new.as_str().expect("child module replacement").to_string())
        })
        .expect("nested token module should be renamed");
    let moved_dir = out.join("src").join(&new_module);
    assert!(moved_dir.join("mod.rs").is_file());
    assert!(moved_dir.join(format!("{new_child_module}.rs")).is_file());
    assert!(
        !moved_dir.join("token.rs").exists(),
        "old nested module filename survived"
    );
    assert!(
        !out.join("src/auth").exists(),
        "old module directory survived"
    );
    assert!(read(&out, "src/main.rs").contains(&format!("mod {new_module};")));

    let check = Command::new("cargo")
        .args(["check", "--locked", "--all-targets"])
        .current_dir(&out)
        .output()
        .expect("checking module-file output");
    assert!(
        check.status.success(),
        "module-file output failed to compile\n{}",
        String::from_utf8_lossy(&check.stderr)
    );
}

#[test]
fn path_dependency_policy_is_closed_world_and_explicit() {
    let input = tauri_fixture("workspace-path-dependency");

    let transform_with = |dependency_line: &str| {
        let tmp = TempDir::new().expect("temp dir");
        let out = tmp.path().join("generated");
        let config = tmp.path().join("obfuscator.toml");
        std::fs::write(
            &config,
            format!(
                "version = 1\nprofile = \"safe\"\n\n[project]\nrust_root = \"app\"\n\n[dependencies]\n{dependency_line}\n\n[build]\nverify = false\n"
            ),
        )
        .expect("writing dependency config");
        let result = Command::new(binary())
            .args(["transform", "--input"])
            .arg(&input)
            .args(["--output"])
            .arg(&out)
            .args(["--config"])
            .arg(&config)
            .args(["--seed", "7001", "--no-verify"])
            .output()
            .expect("spawning cargo-obfuscator");
        assert_succeeded(&result);
        (tmp, out)
    };

    let (_external_tmp, external) = transform_with("\"helper-lib\" = \"external\"");
    let external_source = read(&external, "helper/src/lib.rs");
    assert!(external_source.contains("private_calculation"));
    assert!(
        report(&external)["skipped_by_reason"]["dependency-external"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );

    let (_private_tmp, private) = transform_with("\"helper-lib\" = \"private-obfuscate\"");
    let private_source = read(&private, "helper/src/lib.rs");
    assert!(!private_source.contains("private_calculation"));
    assert!(private_source.contains("pub fn public_api"));
    let private_check = Command::new("cargo")
        .args(["check", "--locked"])
        .current_dir(private.join("app"))
        .output()
        .expect("checking path dependency output");
    assert!(
        private_check.status.success(),
        "path dependency output failed to compile\n{}",
        String::from_utf8_lossy(&private_check.stderr)
    );

    let (_wrapper_tmp, wrapper) = transform_with("\"helper-lib\" = \"wrapper\"");
    let wrapper_main = read(&wrapper, "app/src/main.rs");
    let wrapper_module = std::fs::read_dir(wrapper.join("app/src"))
        .expect("wrapper source directory")
        .flatten()
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("sv_") && name.ends_with(".rs"))
        })
        .expect("generated dependency wrapper");
    let wrapper_name = wrapper_module
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("wrapper module name");
    assert!(wrapper_main.contains(&format!("mod {wrapper_name};")));
    assert!(wrapper_main.contains(&format!("crate::{wrapper_name}::public_api")));
    assert!(mapping(&wrapper)["dependency_wrappers"]
        .as_object()
        .is_some_and(|m| m.contains_key("helper-lib")));
    let wrapper_check = Command::new("cargo")
        .args(["check", "--locked"])
        .current_dir(wrapper.join("app"))
        .output()
        .expect("checking dependency wrapper output");
    assert!(
        wrapper_check.status.success(),
        "dependency wrapper output failed to compile\n{}",
        String::from_utf8_lossy(&wrapper_check.stderr)
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
// runtime string protection
// ---------------------------------------------------------------------------

fn string_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/string-protection")
        .canonicalize()
        .expect("string fixture directory")
}

fn no_std_string_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/no-std-string")
        .canonicalize()
        .expect("no_std string fixture directory")
}

fn transform_strings_from(input: &Path, seed: &str) -> (TempDir, PathBuf) {
    let tmp = TempDir::new().expect("temp dir");
    let out = tmp.path().join("generated");
    let config = tmp.path().join("obfuscator.toml");
    std::fs::write(
        &config,
        "version = 1\nprofile = \"balanced\"\n\n[strings]\nall = true\nui = true\n",
    )
    .expect("writing balanced config");

    let result = Command::new(binary())
        .arg("transform")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(&out)
        .arg("--config")
        .arg(&config)
        .args(["--seed", seed])
        .output()
        .expect("spawning cargo-obfuscator");
    assert_succeeded(&result);
    (tmp, out)
}

fn transform_strings(seed: &str) -> (TempDir, PathBuf) {
    transform_strings_from(&string_fixture(), seed)
}

fn protected_payloads(root: &Path) -> Vec<String> {
    let marker = "let mut __b = ::std::vec![";
    let source = read(root, "src/main.rs");
    let mut payloads = Vec::new();
    let mut rest = source.as_str();
    while let Some(start) = rest.find(marker) {
        let bytes = &rest[start + marker.len()..];
        let Some(end) = bytes.find("];") else {
            break;
        };
        payloads.push(bytes[..end].to_string());
        rest = &bytes[end + 2..];
    }
    payloads.sort();
    payloads
}

#[test]
fn all_mode_protects_runtime_strings_without_changing_behaviour() {
    let original = run_crate(&string_fixture());
    let (_tmp, out) = transform_strings("20240917");

    assert_eq!(
        run_crate(&out),
        original,
        "runtime string protection changed program behaviour"
    );

    let source = all_source(&out);
    for protected in ["license-check", "device-validation"] {
        assert!(
            !source.contains(&format!("\"{protected}\"")),
            "protected plaintext {protected:?} remains as a Rust literal"
        );
        assert!(
            mapping(&out)["strings"].get(protected).is_some(),
            "{protected:?} is missing from mapping.strings"
        );
    }

    for protected in [
        "document",
        "navigate",
        "Accept",
        "text/html,application/xhtml+xml",
        r#"webid=(\d+)"#,
        "0",
    ] {
        assert!(
            !source.contains(&format!("\"{protected}\""))
                && !source.contains(&format!("r#\"{protected}\"#")),
            "all mode left runtime plaintext {protected:?} in generated Rust"
        );
    }
    for generic in ["document", "navigate", "Accept"] {
        assert!(
            mapping(&out)["strings"].get(generic).is_none(),
            "generic all-mode value {generic:?} must not make an unreliable global binary promise"
        );
    }

    for protected in [
        "Cookie 无效: ",
        "indexed ",
        " named ",
        "raw {label} ",
        "Request failed: ",
    ] {
        assert!(
            !source.contains(protected),
            "format literal fragment {protected:?} remains in generated source"
        );
        assert!(
            mapping(&out)["strings"].get(protected).is_some(),
            "format fragment {protected:?} is missing from mapping.strings"
        );
    }

    // Compile-time values cannot become runtime decoder expressions. They are
    // now re-spelled as equivalent Unicode escapes after the transaction, so
    // the source carries no plaintext while the mapping remains conservative.
    let kept = "compile-time-protocol";
    assert!(
        !source.contains(kept),
        "{kept:?} must not remain as compile-time plaintext"
    );
    assert!(source.contains("\\u{63}\\u{6f}\\u{6d}"));
    assert!(
        mapping(&out)["strings"].get(kept).is_none(),
        "a kept plaintext must not be advertised as protected"
    );
    for protected in ["macro-protocol-name", "mixed-protocol"] {
        assert!(
            !source.contains(protected),
            "proven formatting-macro expression {protected:?} stayed plaintext"
        );
    }
    assert!(
        mapping(&out)["strings"].get("mixed-protocol").is_some(),
        "fully protected macro/runtime value is missing from the strict mapping"
    );
    assert!(
        !source.contains("nested-protocol"),
        "all mode should protect both the direct value and its larger format fragment"
    );
    assert!(
        mapping(&out)["strings"].get("nested-protocol").is_none(),
        "the conservative substring proof must not overclaim an unmapped value"
    );

    let string_report = &report(&out)["strings"];
    assert!(
        string_report["values_protected"].as_u64().unwrap_or(0) >= 2,
        "report did not count protected values: {string_report}"
    );
    assert!(
        string_report["values_protected_unmapped"]
            .as_u64()
            .unwrap_or(0)
            >= 3,
        "report did not separate protected generic values from the strict mapping: {string_report}"
    );
    assert!(
        string_report["kept_unsafe_context"].as_u64().unwrap_or(0) >= 1,
        "report did not expose compile-time keeps: {string_report}"
    );
    assert!(
        string_report["kept_external_collision"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "report did not expose nested plaintext collisions: {string_report}"
    );
}

#[test]
fn no_std_crates_keep_runtime_string_literals() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("generated");
    let config = tmp.path().join("obfuscator.toml");
    std::fs::write(&config, "version = 1\nprofile = \"balanced\"\n").unwrap();
    let result = Command::new(binary())
        .args(["transform", "--input"])
        .arg(no_std_string_fixture())
        .args(["--output"])
        .arg(&out)
        .args(["--config"])
        .arg(&config)
        .args(["--seed", "20240917", "--no-verify"])
        .output()
        .unwrap();
    assert_succeeded(&result);

    let source = read(&out, "src/lib.rs");
    assert!(source.contains("\"no-std-protocol\""));
    assert!(mapping(&out)["strings"].as_object().unwrap().is_empty());
    assert!(report(&out)["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning.as_str().unwrap().contains("no_std")));
}

#[test]
fn string_protection_is_deterministic_per_seed() {
    let (_a_tmp, a) = transform_strings("77");
    let (_b_tmp, b) = transform_strings("77");
    assert_eq!(source_tree(&a), source_tree(&b));

    let (_c_tmp, c) = transform_strings("78");
    assert_ne!(
        read(&a, "src/main.rs"),
        read(&c, "src/main.rs"),
        "different release seeds should diversify encoded string bytes"
    );
}

#[test]
fn protected_strings_are_absent_from_the_release_binary() {
    let (_tmp, out) = transform_strings("20240917");
    let build = Command::new("cargo")
        .args(["build", "--release", "--manifest-path"])
        .arg(out.join("Cargo.toml"))
        .output()
        .expect("building transformed string fixture");
    assert!(
        build.status.success(),
        "release build failed\n{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let binary_name = if cfg!(windows) {
        "string-protection-fixture.exe"
    } else {
        "string-protection-fixture"
    };
    let artifact = out.join("target/release").join(binary_name);
    let scan = Command::new(binary())
        .args(["scan-binary", "--binary"])
        .arg(&artifact)
        .args(["--mapping"])
        .arg(out.join(".obfuscator/mapping.json"))
        .output()
        .expect("scanning transformed release binary");
    assert!(
        scan.status.success(),
        "protected string leaked into release binary\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );
}

#[test]
fn string_identity_survives_checkout_and_unrelated_source_changes() {
    let tmp = TempDir::new().unwrap();
    let first_input = tmp.path().join("first-input");
    let second_input = tmp.path().join("second-input");
    copy_tree(&string_fixture(), &first_input);
    copy_tree(&string_fixture(), &second_input);

    let (_first_tmp, first) = transform_strings_from(&first_input, "991");
    let (_second_tmp, second) = transform_strings_from(&second_input, "991");
    assert_eq!(
        protected_payloads(&first),
        protected_payloads(&second),
        "checkout path must not affect protected string bytes"
    );

    let main = second_input.join("src/main.rs");
    let mut source = std::fs::read_to_string(&main).unwrap();
    source.insert_str(0, "fn unrelated_item() -> u32 { 7 }\n\n");
    std::fs::write(&main, source).unwrap();
    let (_third_tmp, third) = transform_strings_from(&second_input, "991");
    assert_eq!(
        protected_payloads(&first),
        protected_payloads(&third),
        "adding an unrelated item must not re-encode existing occurrences"
    );
}

// ---------------------------------------------------------------------------
// serde wire format
// ---------------------------------------------------------------------------
//
// Compiling is not evidence that a source transform preserved serde. These
// tests execute both programs and compare the protocol bytes they actually
// produce, including payloads deserialised under the old contract.

fn serde_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/serde-safety")
        .canonicalize()
        .expect("serde fixture directory")
}

fn serde_transform_fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/serde-transform")
        .canonicalize()
        .expect("serde transform fixture directory")
}

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

static WIRE_FORMAT: OnceLock<String> = OnceLock::new();

fn original_wire_format() -> &'static str {
    WIRE_FORMAT.get_or_init(|| run_crate(&serde_fixture()))
}

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

fn symbol_mapping_contains(root: &Path, leaf: &str) -> bool {
    mapping(root)["symbols"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.keys())
        .any(|path| path.rsplit("::").next() == Some(leaf))
}

#[test]
fn serde_wire_format_survives_the_default_profile() {
    let (_tmp, out) = transform_serde(None, "20240917");
    assert_eq!(
        run_crate(&out),
        original_wire_format(),
        "the generated safe-profile program changed the serde protocol"
    );

    // Safe owns serde members but deliberately leaves them alone.
    for member in ["user_name", "Connected", "Started", "value_field"] {
        assert!(
            !symbol_mapping_contains(&out, member),
            "safe unexpectedly renamed serde member {member}"
        );
    }
}

#[test]
fn balanced_renames_supported_serde_members_without_changing_wire_bytes() {
    let (_tmp, out) = transform_serde(Some("balanced"), "20240917");

    assert_eq!(
        run_crate(&out),
        original_wire_format(),
        "balanced changed serialize/deserialize behaviour"
    );

    for member in [
        "user_name",
        "device_id",
        "session_token",
        "Connected",
        "Disconnected",
        "reason_code",
        "Started",
        "Stopped",
        "AdjacentEvent",
        "value_field",
        "modern_name",
        "r#type",
        "raw_value",
    ] {
        if member == "AdjacentEvent" {
            // The container type is handled by the ordinary symbol pass, not
            // the serde member pass.
            continue;
        }
        assert!(
            symbol_mapping_contains(&out, member),
            "balanced did not rename supported serde member {member}"
        );
    }

    let model = read(&out, "src/model.rs");
    for wire in [
        "\"user_name\"",
        "\"device_id\"",
        "\"sessionToken\"",
        "\"Connected\"",
        "\"Disconnected\"",
        "\"reason_code\"",
        "\"Started\"",
        "\"Stopped\"",
        "\"outValue\"",
        "\"in_value\"",
        "\"current_name\"",
        "\"old_name\"",
        "\"userName\"",
        "\"type\"",
    ] {
        assert!(
            !model.contains(wire),
            "wire contract {wire} remained as plaintext in transformed source"
        );
    }
    assert!(
        model.contains("\\u{75}\\u{73}\\u{65}\\u{72}"),
        "wire contracts should be represented by equivalent escaped literals"
    );

    assert_eq!(
        skipped_count(&out, "serde-unsupported"),
        0,
        "the supported serde corpus must not fall back to a blanket pin"
    );

    let retry_count_definitions = mapping(&out)["symbols"]
        .as_object()
        .unwrap()
        .keys()
        .filter(|path| path.rsplit("::").next() == Some("retry_count"))
        .count();
    assert_eq!(
        retry_count_definitions, 2,
        "same-spelled fields in separate structs must both be renamed"
    );
}

#[test]
fn serde_fixture_still_obfuscates_non_serde_fields() {
    let (_tmp, out) = transform_serde(Some("balanced"), "20240917");
    for field in ["scratch_buffer", "retry_count"] {
        assert!(
            symbol_mapping_contains(&out, field),
            "ordinary Rust field {field} should still be renamed"
        );
    }
}

#[test]
fn aggressive_handles_the_full_serde_attribute_corpus() {
    let tmp = TempDir::new().unwrap();
    let input = serde_transform_fixture();
    let out = tmp.path().join("generated");
    let result = Command::new(binary())
        .args(["transform", "--input"])
        .arg(&input)
        .arg("--output")
        .arg(&out)
        .arg("--config")
        .arg(input.join("obfuscator.toml"))
        .args(["--seed", "20240917"])
        .output()
        .unwrap();
    assert_succeeded(&result);

    for symbol in [
        "PlainStruct",
        "RenameAllStruct",
        "TransparentStruct",
        "UntaggedEnum",
        "TimestampDef",
        "Meter",
        "hex_u32",
        "serialize",
        "deserialize",
        "user_name",
        "metadata",
        "ignored",
        "write_only",
        "read_only",
        "millis",
        "flags",
    ] {
        assert!(
            symbol_mapping_contains(&out, symbol),
            "full serde corpus did not rename {symbol}"
        );
    }
    assert_eq!(skipped_count(&out, "serde-unsupported"), 0);
    assert!(report(&out)["verification"]
        .as_array()
        .unwrap()
        .iter()
        .any(|stage| stage["stage"] == "cargo-check" && stage["passed"] == true));
    let generated = all_source(&out);
    assert!(generated.contains("serialize_with ="));
    assert!(generated.contains("deserialize_with ="));
    assert!(!generated.contains("//!"));
    assert!(!generated.contains("// ---"));
}

// ---------------------------------------------------------------------------
// Tauri IPC
// ---------------------------------------------------------------------------
//
// A command's name lives in four places at once — the Rust definition, the
// `generate_handler!` list, the frontend `invoke("...")` call, and any Rust
// allow-list or match arm. These tests run the real binary over a real Tauri 2
// project and check that all four agree afterwards.

fn tauri_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

fn transform_tauri(name: &str, seed: &str, verify: bool) -> (TempDir, PathBuf, Output) {
    let tmp = TempDir::new().expect("temp dir");
    let out = tmp.path().join("generated");

    let mut cmd = Command::new(binary());
    cmd.arg("transform")
        .arg("--input")
        .arg(tauri_fixture(name))
        .arg("--output")
        .arg(&out)
        .args(["--seed", seed]);
    if !verify {
        cmd.arg("--no-verify");
    }

    let result = cmd.output().expect("spawning cargo-obfuscator");
    (tmp, out, result)
}

static TAURI_STATIC: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
static TAURI_DYNAMIC: OnceLock<(TempDir, PathBuf)> = OnceLock::new();

fn static_tauri() -> &'static Path {
    &TAURI_STATIC
        .get_or_init(|| {
            let (tmp, out, result) = transform_tauri("tauri-ipc-static", "20240917", true);
            assert_succeeded(&result);
            (tmp, out)
        })
        .1
}

fn dynamic_tauri() -> &'static Path {
    &TAURI_DYNAMIC
        .get_or_init(|| {
            let (tmp, out, result) = transform_tauri("tauri-ipc-dynamic", "20240917", true);
            assert_succeeded(&result);
            (tmp, out)
        })
        .1
}

/// The integration corpus is a real Tauri 2 project, not a hand-written
/// parser fixture: the generated tree is checked with Cargo and its shipped
/// frontend is built before the protocol assertions below run.
#[test]
fn real_tauri_integration_fixture_is_verified_end_to_end() {
    let out = static_tauri();
    assert!(out.join("src-tauri/Cargo.toml").is_file());
    assert!(out.join("src-tauri/tauri.conf.json").is_file());
    assert!(out.join("frontend/dist").is_dir());
    assert!(read(out, "src-tauri/Cargo.toml").contains("tauri"));

    let generated_report = report(out);
    let verification = generated_report["verification"]
        .as_array()
        .expect("verification stages");
    for stage in verification {
        assert_eq!(stage["passed"], true, "verification failed: {stage}");
    }
    assert!(
        verification
            .iter()
            .any(|stage| stage["stage"] == "cargo-check"),
        "real Tauri fixture must pass cargo-check: {verification:?}"
    );
    assert!(
        verification
            .iter()
            .any(|stage| stage["stage"] == "npm-build"),
        "real Tauri fixture must build its shipped frontend: {verification:?}"
    );

    let release = Command::new("cargo")
        .args(["build", "--release", "--locked"])
        .current_dir(out.join("src-tauri"))
        .output()
        .expect("building the transformed Tauri release library");
    assert!(
        release.status.success(),
        "transformed Tauri release build failed\n{}",
        String::from_utf8_lossy(&release.stderr)
    );
    let release_dir = out.join("src-tauri/target/release");
    let artifact = ["libtauri_ipc_static_lib.rlib", "tauri_ipc_static_lib.lib"]
        .iter()
        .map(|name| release_dir.join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| panic!("release artifact missing under {}", release_dir.display()));
    let scan = Command::new(binary())
        .args(["scan-binary", "--binary"])
        .arg(&artifact)
        .args(["--mapping"])
        .arg(out.join(".obfuscator/mapping.json"))
        .output()
        .expect("scanning transformed Tauri release artifact");
    assert!(
        scan.status.success(),
        "transformed Tauri binary leak scan failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&scan.stdout),
        String::from_utf8_lossy(&scan.stderr)
    );
}

#[test]
fn frontend_semantic_rename_keeps_protocol_and_property_names() {
    let tmp = TempDir::new().expect("temp dir");
    let out = tmp.path().join("generated");
    let config = tmp.path().join("obfuscator.toml");
    std::fs::write(
        &config,
        r#"
version = 1
profile = "safe"

[project]
frontend_root = "frontend"
frontend_source = "src"

[rename]
functions = false
types = false
traits = false
enums = false
consts = false
statics = false
modules = false
fields = false

[strings]
enabled = false

[tauri]
commands = false
events = false

[frontend]
enabled = true
rename_private_identifiers = true

[build]
verify = false
"#,
    )
    .expect("writing frontend config");

    let result = Command::new(binary())
        .args(["transform", "--input"])
        .arg(tauri_fixture("tauri-ipc-static"))
        .args(["--output"])
        .arg(&out)
        .args(["--config"])
        .arg(&config)
        .args(["--seed", "1", "--no-verify"])
        .output()
        .expect("spawning cargo-obfuscator");
    assert_succeeded(&result);

    let ipc = read(&out, "frontend/src/ipc.ts");
    let wrapper = read(&out, "frontend/src/wrapper.ts");
    assert!(!ipc.contains("SYNC_COMMAND"));
    assert!(ipc.contains("export async function getUserInfo"));
    assert!(
        ipc.contains("{ userId:"),
        "object shorthand key must stay stable while its value is renamed"
    );
    assert!(
        ipc.contains("{ key:"),
        "destructuring shorthand key must stay stable while its binding is renamed"
    );
    assert!(!wrapper.contains("command: string"));
    assert!(!wrapper.contains("args?: Record"));
    assert!(wrapper.contains("invoke<T>("));

    let parsed_mapping = mapping(&out);
    let frontend_mapping = parsed_mapping["frontend_symbols"]
        .as_object()
        .expect("frontend_symbols mapping");
    assert!(frontend_mapping
        .keys()
        .any(|key| key.contains("SYNC_COMMAND")));
    assert!(frontend_mapping.keys().any(|key| key.contains("::userId@")));

    let frontend_report = &report(&out)["frontend"];
    assert!(frontend_report["symbols_renamed"].as_u64().unwrap_or(0) >= 3);
    assert_eq!(
        frontend_report["kept_by_reason"]["object-shorthand"]
            .as_u64()
            .unwrap_or(0),
        0
    );
}

#[test]
fn frontend_string_protection_covers_jsx_templates_and_defaults() {
    let tmp = TempDir::new().expect("temp dir");
    let input = tmp.path().join("input");
    std::fs::create_dir_all(input.join("frontend/src")).expect("frontend source");
    std::fs::write(
        input.join("Cargo.toml"),
        "[package]\nname = 'frontend_string_fixture'\nversion = '0.1.0'\nedition = '2024'\n",
    )
    .unwrap();
    std::fs::create_dir_all(input.join("src")).unwrap();
    std::fs::write(input.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(
        input.join("frontend/src/view.tsx"),
        r#"type Mode = "replace" | "append";
interface Props { title?: string }
export function View({ title = "默认标题" }: Props) {
  const mode: Mode = "replace";
  const text = `前缀 ${"嵌套"}`;
  return <button title="提示" data-label="标签">{title}{text}{mode}</button>;
}
"#,
    )
    .unwrap();

    let config = tmp.path().join("obfuscator.toml");
    std::fs::write(
        &config,
        r#"version = 1
profile = "safe"
[project]
frontend_root = "frontend"
frontend_source = "src"
[rename]
functions = false
types = false
traits = false
enums = false
consts = false
statics = false
modules = false
fields = false
[strings]
enabled = true
all = false
frontend = true
[comments]
strip = true
[tauri]
commands = false
events = false
[build]
verify = false
"#,
    )
    .unwrap();

    let output = tmp.path().join("generated");
    let result = Command::new(binary())
        .args(["transform", "--input"])
        .arg(&input)
        .args(["--output"])
        .arg(&output)
        .args(["--config"])
        .arg(&config)
        .args(["--seed", "101", "--no-verify"])
        .output()
        .expect("spawning cargo-obfuscator");
    assert_succeeded(&result);

    let transformed = read(&output, "frontend/src/view.tsx");
    assert!(!transformed.contains("默认标题"));
    assert!(!transformed.contains("前缀"));
    assert!(!transformed.contains("嵌套"));
    assert!(!transformed.contains("提示"));
    assert!(!transformed.contains("标签"));
    assert!(transformed.contains("__sv_decode_"));
    assert!(transformed.contains(r#"type Mode = "replace" | "append""#));

    let parsed_mapping = mapping(&output);
    assert!(
        parsed_mapping["frontend_strings"]
            .as_object()
            .unwrap()
            .len()
            >= 5
    );
    let report_json = report(&output);
    let frontend_report = &report_json["frontend"];
    assert_eq!(report_json["files"]["frontend_scanned"].as_u64(), Some(1));
    assert!(
        frontend_report["string_occurrences_protected"]
            .as_u64()
            .unwrap_or(0)
            >= 5
    );
}

/// Command names appearing in `generate_handler![...]`.
fn handler_list(root: &Path) -> BTreeSet<String> {
    let lib = read(root, "src-tauri/src/lib.rs");
    let mut out = BTreeSet::new();
    let mut rest = lib.as_str();
    while let Some(start) = rest.find("generate_handler![") {
        rest = &rest[start + "generate_handler![".len()..];
        let Some(end) = rest.find(']') else { break };
        for entry in rest[..end].split(',') {
            if let Some(name) = entry.trim().rsplit("::").next() {
                if !name.is_empty() {
                    out.insert(name.to_string());
                }
            }
        }
        rest = &rest[end..];
    }
    out
}

/// Which of `candidates` the *shipped* frontend names.
///
/// Read from `dist`, not from `src`, because built output is what actually
/// runs — and because it is the one place a missed rewrite becomes a runtime
/// failure rather than a compile error. Intersected with the mapping's own
/// names rather than collecting every string literal, because a bundle is full
/// of strings that are not commands.
fn shipped_frontend_commands(root: &Path, candidates: &BTreeSet<String>) -> BTreeSet<String> {
    let dist = root.join("frontend/dist");
    let mut out = BTreeSet::new();
    for path in walk(&dist) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for quote in ['"', '\'', '`'] {
            for part in text.split(quote).skip(1).step_by(2) {
                let name = part.trim();
                if candidates.contains(name) {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

#[test]
fn tauri_commands_move_together_across_both_languages() {
    let out = static_tauri();
    let commands = report(out)["commands"].clone();

    assert_eq!(commands["discovered"].as_u64(), Some(4));
    assert_eq!(commands["renamed"].as_u64(), Some(4));
    assert_eq!(
        commands["kept"].as_array().map(|k| k.len()),
        Some(0),
        "nothing should have been kept: {commands}"
    );

    let mapping = mapping(out);
    let renamed: BTreeMap<String, String> = mapping["commands"]
        .as_object()
        .expect("commands mapping")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
        .collect();
    assert_eq!(renamed.len(), 4, "{renamed:?}");
    assert!(renamed.contains_key("get_user_info"));
    assert!(
        renamed.contains_key("probe_vault_health"),
        "the short-form attribute must be found"
    );

    // The handler list, the shipped frontend, and the mapping have to name the
    // same set. Any disagreement is a command that fails at runtime.
    let new_names: BTreeSet<String> = renamed.values().cloned().collect();
    let candidates: BTreeSet<String> = renamed
        .keys()
        .cloned()
        .chain(new_names.iter().cloned())
        .collect();

    assert_eq!(
        handler_list(out),
        new_names,
        "the Rust handler list does not name exactly the new commands"
    );
    assert_eq!(
        shipped_frontend_commands(out, &candidates),
        new_names,
        "the shipped frontend does not name exactly the new commands — an old \
         name still ships, or a new one never reached the bundle"
    );

    // The original names must be gone from both sides.
    let rust = read(out, "src-tauri/src/lib.rs") + &read(out, "src-tauri/src/commands.rs");
    for original in renamed.keys() {
        assert!(
            !rust.contains(&format!("fn {original}")),
            "`{original}` is still defined in the generated Rust"
        );
    }
}

/// The Rust allow-list and the match arm are part of the same protocol.
#[test]
fn tauri_rust_command_literals_are_rewritten() {
    let out = static_tauri();
    let allow = read(out, "src-tauri/src/allow.rs");
    // The three the fixture actually lists. probe_vault_health is reached through the
    // handler list and the frontend wrapper, not through the allow-list.
    let renamed: BTreeMap<String, String> = mapping(out)["commands"]
        .as_object()
        .expect("commands mapping")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
        .collect();

    for original in ["get_user_info", "activate_license", "sync_state"] {
        assert!(
            !allow.contains(&format!("\"{original}\"")),
            "`{original}` survived in the Rust allow-list"
        );
        let new = &renamed[original];
        assert!(
            allow.contains(&format!("\"{new}\"")),
            "the allow-list should name `{new}`"
        );
    }
    assert!(
        allow.contains("invoke.message.command()"),
        "the dispatch shape must be left alone"
    );
}

#[test]
fn tauri_dynamic_invoke_keeps_the_whole_namespace() {
    let out = dynamic_tauri();
    let commands = report(out)["commands"].clone();

    assert_eq!(commands["discovered"].as_u64(), Some(4));
    assert_eq!(
        commands["renamed"].as_u64(),
        Some(0),
        "one dynamic call must keep every command: {commands}"
    );
    assert_eq!(
        commands["kept_by_reason"]["dynamic-frontend-command-reference"].as_u64(),
        Some(4)
    );

    // The mapping must record nothing, or a stack trace would be misread.
    assert!(
        mapping(out)["commands"]
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true),
        "no command was renamed, so the mapping must be empty"
    );

    // And the reason has to be findable: a developer needs the file and line.
    let report = report(out);
    let kept = serde_json::to_string(&report["commands"]["kept"]).unwrap();
    assert!(kept.contains("dynamic.ts"), "{kept}");
    assert!(
        report["warnings"]
            .as_array()
            .map(|w| w.iter().any(|w| w
                .as_str()
                .is_some_and(|s| s.contains("dynamic.ts:") && s.contains("obfuscation disabled"))))
            .unwrap_or(false),
        "the warning must point at the dynamic call: {}",
        report["warnings"]
    );
}

/// The generic symbol rename must not rename a command a second time.
#[test]
fn tauri_commands_are_owned_by_the_command_pass() {
    let out = static_tauri();
    let symbols = mapping(out)["symbols"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    for key in symbols.keys() {
        for command in [
            "get_user_info",
            "activate_license",
            "sync_state",
            "probe_vault_health",
        ] {
            assert!(
                !key.ends_with(&format!("::{command}")),
                "`{command}` was also renamed by the symbol pass as `{key}`"
            );
        }
    }
}

#[test]
fn the_command_mapping_is_reproducible_and_seeded() {
    // No verification: this is about the names, and a cargo check of the Tauri
    // tree costs more than the assertion is worth.
    let (_t1, first, r1) = transform_tauri("tauri-ipc-static", "5150", false);
    let (_t2, second, r2) = transform_tauri("tauri-ipc-static", "5150", false);
    let (_t3, other, r3) = transform_tauri("tauri-ipc-static", "5151", false);
    for r in [&r1, &r2, &r3] {
        assert_succeeded(r);
    }

    let commands = |root: &Path| mapping(root)["commands"].clone();
    assert_eq!(
        commands(&first),
        commands(&second),
        "same seed, same mapping"
    );
    assert_ne!(
        commands(&first),
        commands(&other),
        "different seed, different mapping"
    );
}

// ---------------------------------------------------------------------------
// Mapping stability
// ---------------------------------------------------------------------------
//
// A mapping is the answer key for crash reports, and a release has to be
// rebuildable from its own tag. Both properties die if a name depends on
// anything except its own identity — and the failure is quiet: the build
// succeeds, the output is correct, and the mapping has silently churned.

/// Transform an arbitrary directory without the verification pipeline.
///
/// These tests are about names, and a `cargo check` of the Tauri tree costs
/// more than the assertion is worth.
fn transform_quietly(input: &Path, output: &Path, seed: &str) {
    let result = Command::new(binary())
        .arg("transform")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .args(["--seed", seed])
        .arg("--no-verify")
        .output()
        .expect("spawning cargo-obfuscator");
    assert_succeeded(&result);
}

fn copy_tree(from: &Path, to: &Path) {
    for entry in walk(from) {
        let rel = entry.strip_prefix(from).expect("path under root");
        if rel.to_string_lossy().starts_with("target")
            || rel.to_string_lossy().starts_with("node_modules")
        {
            continue;
        }
        let target = to.join(rel);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::copy(&entry, &target).expect("copy");
    }
}

/// One new function, at the top of the first file the walker reaches.
///
/// Position matters: candidates are enumerated in file order, so this lands in
/// the middle of the sequence rather than at the end. Under a shared name
/// stream that is exactly what renames everything after it.
fn add_unrelated_function(root: &Path) {
    let path = root.join("src-tauri/src/commands.rs");
    let mut text = std::fs::read_to_string(&path).expect("read commands.rs");
    text.insert_str(0, "pub fn aaa_added_later() -> u32 {\n    7\n}\n\n");
    std::fs::write(&path, text).expect("write commands.rs");
}

#[test]
fn adding_an_unrelated_item_moves_no_other_name() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("project");
    copy_tree(&tauri_fixture("tauri-ipc-static"), &project);

    let before_root = tmp.path().join("before");
    transform_quietly(&project, &before_root, "777");
    let before = mapping(&before_root);

    add_unrelated_function(&project);

    let after_root = tmp.path().join("after");
    transform_quietly(&project, &after_root, "777");
    let after = mapping(&after_root);

    for section in ["symbols", "commands", "events"] {
        let (Some(a), Some(b)) = (
            before.get(section).and_then(|v| v.as_object()),
            after.get(section).and_then(|v| v.as_object()),
        ) else {
            continue;
        };
        for (key, name) in a {
            if let Some(other) = b.get(key) {
                assert_eq!(
                    other, name,
                    "`{key}` in `{section}` was renamed differently because an unrelated \
                     function was added elsewhere in the project"
                );
            }
        }
    }
}

/// The same property across domains: nothing in the symbol pass can move a
/// command name, because the two never consulted the same stream.
#[test]
fn domains_do_not_disturb_each_other() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("project");
    copy_tree(&tauri_fixture("tauri-ipc-static"), &project);

    let before_root = tmp.path().join("before");
    transform_quietly(&project, &before_root, "31337");
    let before = mapping(&before_root)["commands"].clone();

    // A pile of new symbols, well before every command in candidate order.
    let path = project.join("src-tauri/src/commands.rs");
    let mut text = std::fs::read_to_string(&path).expect("read");
    text.insert_str(
        0,
        "pub fn aaa_one() -> u32 { 1 }\npub fn aab_two() -> u32 { 2 }\npub fn aac_three() -> u32 { 3 }\n\n",
    );
    std::fs::write(&path, text).expect("write");

    let after_root = tmp.path().join("after");
    transform_quietly(&project, &after_root, "31337");
    let after = mapping(&after_root)["commands"].clone();

    assert_eq!(
        before, after,
        "command names moved because unrelated symbols were added"
    );
}

// ---------------------------------------------------------------------------
// Tauri events
// ---------------------------------------------------------------------------
//
// An event has no registry: nothing lists every event the way
// `generate_handler!` lists every command. A rename is only safe when the graph
// is closed — at least one producer and one consumer, both inside the generated
// workspace — so most of what these tests check is what was *refused*.

static EVENTS_STATIC: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
static EVENTS_DYNAMIC: OnceLock<(TempDir, PathBuf)> = OnceLock::new();

fn events_static() -> &'static Path {
    &EVENTS_STATIC
        .get_or_init(|| {
            let (tmp, out, result) = transform_tauri("tauri-events-static", "20240917", true);
            assert_succeeded(&result);
            (tmp, out)
        })
        .1
}

fn events_dynamic() -> &'static Path {
    &EVENTS_DYNAMIC
        .get_or_init(|| {
            let (tmp, out, result) = transform_tauri("tauri-events-dynamic", "20240917", true);
            assert_succeeded(&result);
            (tmp, out)
        })
        .1
}

fn event_map(root: &Path) -> BTreeMap<String, String> {
    mapping(root)["events"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Every event name mentioned to the Tauri event API in a Rust file.
fn rust_event_literals(root: &Path) -> BTreeSet<String> {
    let text = read(root, "src-tauri/src/events.rs");
    let mut out = BTreeSet::new();
    for call in [
        ".emit(",
        ".emit_to(",
        ".emit_filter(",
        ".listen(",
        ".listen_any(",
        ".once(",
    ] {
        let mut rest = text.as_str();
        while let Some(at) = rest.find(call) {
            rest = &rest[at + call.len()..];
            // Skip the window label on `emit_to`.
            let rest_after_label = if call == ".emit_to(" {
                match rest.find(',') {
                    Some(comma) => &rest[comma + 1..],
                    None => rest,
                }
            } else {
                rest
            };
            let trimmed = rest_after_label.trim_start();
            if let Some(stripped) = trimmed.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    out.insert(stripped[..end].to_string());
                }
            }
        }
    }
    out
}

/// The string a `const NAME = "..."` holds.
fn const_value(source: &str, name: &str) -> String {
    let needle = format!("const {name} = \"");
    source
        .find(&needle)
        .and_then(|at| {
            let rest = &source[at + needle.len()..];
            rest.find('"').map(|end| rest[..end].to_string())
        })
        .unwrap_or_default()
}

/// Quoted strings on a line, in order.
fn quoted_strings(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('"') else { break };
        out.push(rest[..end].to_string());
        rest = &rest[end + 1..];
    }
    out
}

/// Every event name passed to the Tauri event API in the frontend source.
///
/// The decoys — `socket.emit`, `emitter.once` — are excluded by name, because
/// leaving them out is exactly what this test is about.
fn frontend_event_literals(root: &Path) -> BTreeSet<String> {
    let text = read(root, "frontend/src/events.ts");
    let mut out = BTreeSet::new();

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("//") || line.starts_with("interface") || line.starts_with("declare") {
            continue;
        }
        if line.contains("socket.") || line.contains("emitter.") {
            continue;
        }
        let is_tauri_call = ["emit(", "emitTo(", "listen", "once("]
            .iter()
            .any(|call| line.contains(call));
        if !is_tauri_call {
            continue;
        }

        let strings = quoted_strings(line);
        // `emitTo("main", "name", ...)` — the label comes first.
        let name = if line.contains("emitTo(") {
            strings.get(1)
        } else {
            strings.first()
        };
        if let Some(name) = name {
            out.insert(name.clone());
        }
        if line.contains("listen(EVENT") {
            out.insert(const_value(&text, "EVENT"));
        }
    }
    out
}

#[test]
fn tauri_events_move_together_across_both_languages() {
    let out = events_static();
    let report = report(out)["events"].clone();

    assert_eq!(report["discovered"].as_u64(), Some(11));
    assert_eq!(report["renamed"].as_u64(), Some(9));
    assert_eq!(
        report["kept"].as_array().map(|k| k.len()),
        Some(2),
        "only the two events that reach outside the workspace should be kept: {report}"
    );

    let renamed = event_map(out);
    assert_eq!(renamed.len(), 9, "{renamed:?}");

    // The cross-language events have to be named identically on both sides.
    // Anything else is an event that fires into the void. Events that only one
    // language participates in are checked on that side alone.
    let rust = rust_event_literals(out);
    let frontend = frontend_event_literals(out);

    let cross_language = [
        "download-progress",
        "session-updated",
        "open-file",
        "frontend-ready",
        "sync-state",
        "startup-complete",
    ];
    for original in cross_language {
        let new_name = &renamed[original];
        assert!(
            rust.contains(new_name),
            "`{original}` was renamed to `{new_name}` but the Rust side does not use it"
        );
        assert!(
            frontend.contains(new_name),
            "`{original}` was renamed to `{new_name}` but the frontend does not use it"
        );
    }

    // Rust to Rust, and frontend to frontend: one side each.
    assert!(rust.contains(&renamed["rust-internal-tick"]));
    assert!(frontend.contains(&renamed["fe-internal-refresh"]));

    // Neither side may still name a renamed event by its old name.
    for original in renamed.keys() {
        assert!(
            !rust.iter().any(|n| n == original),
            "`{original}` still appears on the Rust side"
        );
    }
}

/// The two events that reach outside the workspace, and why.
#[test]
fn events_with_only_one_end_inside_the_workspace_are_kept() {
    let out = events_static();
    let report = report(out);
    let kept = &report["events"]["kept_by_reason"];

    assert_eq!(kept["external-event-source"].as_u64(), Some(1));
    assert_eq!(kept["external-event-consumer"].as_u64(), Some(1));

    let events = event_map(out);
    assert!(
        !events.contains_key("plugin-status"),
        "a listener with no producer may be fed by a plugin"
    );
    assert!(
        !events.contains_key("telemetry-ping"),
        "a producer with no listener may be consumed elsewhere"
    );
}

/// `emit` and `listen` are ordinary method names.
#[test]
fn calls_that_are_not_the_tauri_event_api_are_untouched() {
    let out = events_static();
    let frontend = read(out, "frontend/src/events.ts");
    let rust = read(out, "src-tauri/src/events.rs");

    assert!(
        frontend.contains(r#"socket.emit("plugin-status")"#),
        "a socket bus is not the Tauri event API"
    );
    assert!(
        frontend.contains(r#"emitter.once("telemetry-ping")"#),
        "an emitter is not the Tauri event API"
    );
    assert!(
        rust.contains(r#""plugin-status""#) && rust.contains(r#""telemetry-ping""#),
        "a local bus is not the Tauri event API"
    );

    // `emitTo`'s first argument is a window label, and this phase does not
    // rename window labels.
    assert!(
        frontend.contains(r#"emitTo("main", "#),
        "the target label was modified"
    );
    assert!(
        rust.contains(r#"emit_to("main", "#),
        "the target label was modified"
    );
}

#[test]
fn tauri_dynamic_event_keeps_the_whole_namespace() {
    let out = events_dynamic();
    let report = report(out);

    assert_eq!(report["events"]["discovered"].as_u64(), Some(11));
    assert_eq!(
        report["events"]["renamed"].as_u64(),
        Some(0),
        "a runtime-computed name could be any event"
    );
    assert_eq!(
        report["events"]["kept_by_reason"]["dynamic-event-reference"].as_u64(),
        Some(11)
    );
    assert!(
        event_map(out).is_empty(),
        "nothing was renamed, so nothing is mapped"
    );

    // Both directions have to be named, with a line, or the report is not
    // actionable.
    let warnings = serde_json::to_string(&report["warnings"]).unwrap();
    assert!(warnings.contains("events.ts:"), "{warnings}");
    assert!(warnings.contains("events.rs:"), "{warnings}");
    assert!(
        warnings.contains("event obfuscation disabled"),
        "{warnings}"
    );
}

#[test]
fn the_event_mapping_is_reproducible_and_seeded() {
    let (_t1, first, r1) = transform_tauri("tauri-events-static", "8181", false);
    let (_t2, second, r2) = transform_tauri("tauri-events-static", "8181", false);
    let (_t3, other, r3) = transform_tauri("tauri-events-static", "8182", false);
    for r in [&r1, &r2, &r3] {
        assert_succeeded(r);
    }

    assert_eq!(
        event_map(&first),
        event_map(&second),
        "same seed, same mapping"
    );
    assert_ne!(
        event_map(&first),
        event_map(&other),
        "different seed, different mapping"
    );

    // The whole point of the domain separator: the two namespaces are
    // independent, so neither can move because the other changed.
    let commands = |root: &Path| mapping(root)["commands"].clone();
    assert_eq!(commands(&first), commands(&second));
}

// ---------------------------------------------------------------------------
// serde wire names
// ---------------------------------------------------------------------------
//
// `sourceveil_core::serde::case` reimplements serde's `rename_all` rules,
// because `serde_derive` is a proc-macro crate whose internals are not API. A
// second reading of serde's source is not evidence that the port is right, so
// the rules are checked against serde itself: the fixture in
// `tests/fixtures/serde-wire` serialises one struct and one enum per rule, and
// every key it actually produced is compared with the one SourceVeil computes.

/// The keys of a JSON object, in the order they appear.
fn object_keys_in_order(json: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = json;
    while let Some(start) = rest.find('"') {
        rest = &rest[start + 1..];
        let Some(end) = rest.find('"') else { break };
        let key = rest[..end].to_string();
        rest = &rest[end + 1..];
        if rest.trim_start().starts_with(':') {
            out.push(key);
        }
    }
    out
}

/// One `field`/`variant` case from the oracle's output.
struct OracleCase {
    kind: String,
    rule: String,
    wire_names: Vec<String>,
}

fn run_wire_oracle() -> Vec<OracleCase> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/serde-wire")
        .canonicalize()
        .expect("serde-wire fixture");

    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .current_dir(&root)
        .output()
        .expect("spawning cargo run");
    assert!(
        output.status.success(),
        "the oracle fixture failed to run:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let mut cases: Vec<OracleCase> = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(rest) = line
            .strip_prefix("field ")
            .or_else(|| line.strip_prefix("variant "))
        else {
            continue;
        };
        let kind = if line.starts_with("field ") {
            "field"
        } else {
            "variant"
        };
        let Some(json) = lines.next() else { break };
        let json = json.trim();

        // A field case prints an object; a variant case prints one string.
        //
        // The keys are read in order from the raw text rather than through
        // `serde_json::Value`, whose object is a map and would hand them back
        // sorted — which is not what serde wrote and not what a peer sees.
        let wire_names = if kind == "field" {
            object_keys_in_order(json)
        } else {
            serde_json::from_str::<Vec<String>>(json).expect("an array of wire names")
        };

        // `Rest WaitingForLogin` on a variant line is a value, not a rule.
        let rule = rest.split(' ').next_back().unwrap_or_default().to_string();
        cases.push(OracleCase {
            kind: kind.to_string(),
            rule,
            wire_names,
        });
    }
    cases
}

#[test]
fn the_ported_rename_rules_match_serde_itself() {
    use sourceveil_core::serde::case::RenameRule;

    let cases = run_wire_oracle();
    // One per rule per kind: eight `rename_all` spellings, on a field and on a
    // variant. A variant case carries every variant of that enum.
    assert_eq!(
        cases.len(),
        16,
        "expected a case per rule per kind, got {}",
        cases.len()
    );

    // The names the fixture declares, in declaration order.
    const FIELDS: &[&str] = &["user_name", "http_port"];
    const VARIANTS: &[&str] = &["WaitingForLogin", "HTTPServer", "Idle"];

    let mut checked = 0;
    for case in &cases {
        let rule = RenameRule::parse(&case.rule)
            .unwrap_or_else(|e| panic!("the oracle used a rule we do not know: {e}"));

        let expected: Vec<String> = if case.kind == "field" {
            FIELDS.iter().map(|f| rule.apply_to_field(f)).collect()
        } else {
            VARIANTS.iter().map(|v| rule.apply_to_variant(v)).collect()
        };

        assert_eq!(
            case.wire_names, expected,
            "{} under `{}`: serde produced {:?}, SourceVeil computes {:?}",
            case.kind, case.rule, case.wire_names, expected
        );
        checked += 1;
    }
    assert_eq!(checked, cases.len());

    // And the trap this whole module exists for, stated as a test: on a field
    // `lowercase` is the identity and on a variant it is not, so a single
    // shared implementation would disagree with serde here.
    assert_eq!(
        RenameRule::parse("lowercase")
            .unwrap()
            .apply_to_field("user_name"),
        "user_name"
    );
    assert_eq!(
        RenameRule::parse("lowercase")
            .unwrap()
            .apply_to_variant("WaitingForLogin"),
        "waitingforlogin"
    );
}
