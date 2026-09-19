//! Runtime string-literal protection.
//!
//! This pass is intentionally narrower than "encrypt every string". It only
//! rewrites ordinary runtime Rust string expressions whose type can remain
//! \`&'static str\`. Compile-time contexts (attributes, macro token trees,
//! const/static initialisers, patterns, ABI strings, const fn bodies) are left
//! alone.
//!
//! A protected value is transformed only when *every* occurrence selected for
//! protection is safe. That makes the mapping honest: once a value appears in
//! \`mapping.strings\`, source/binary leak scans may require the original
//! plaintext to be gone.
//!
//! The runtime representation uses a per-occurrence HMAC-derived seed and a
//! tiny xorshift64* stream. This is obfuscation, not cryptographic secrecy: the
//! decoder and seed ship in the client. Its purpose is to remove plaintext from
//! static string tables and break the strings -> XREF shortcut.

use crate::edits::{replace, Contribution, EditPlan};
use crate::plan::{DependenciesPlan, StringsPlan};
use crate::rust::analysis::RustAnalysis;
use crate::rust::rename::crate_for_file;
use crate::scanner::{is_root_like, path_starts_with, CrateGraph};
use aho_corasick::AhoCorasick;
use anyhow::Result;
use hmac::{Hmac, Mac};
use ra_ap_syntax::ast::{self, AstNode, AstToken, HasAttrs};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

const STREAM_MULTIPLIER: u64 = 0x2545_F491_4F6C_DD1D;

#[derive(Debug, Clone, Default)]
pub struct StringOutcome {
    pub files_scanned: usize,
    pub values_discovered: usize,
    pub occurrences_discovered: usize,
    pub values_protected: usize,
    pub occurrences_protected: usize,
    pub kept_unsafe_context: usize,
    pub kept_external_collision: usize,
    pub kept_conflict: usize,
    pub files_edited: BTreeSet<PathBuf>,
    /// Original plaintext -> representation marker.
    pub mapping: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
struct Occurrence {
    file: PathBuf,
    source: String,
    start: u32,
    end: u32,
    safe: bool,
}

pub struct StringRequest<'a> {
    pub input_root: &'a Path,
    pub copied: &'a BTreeSet<PathBuf>,
    pub graph: &'a CrateGraph,
    pub plan: &'a StringsPlan,
    pub dependencies: &'a DependenciesPlan,
    pub seed: u64,
    /// Tauri commands/events (renamed or kept). The string pass must never
    /// reinterpret those protocol values as ordinary literals.
    pub reserved_protocol_values: &'a HashSet<String>,
}

pub fn run(
    analysis: &RustAnalysis,
    req: &StringRequest<'_>,
    edits: &mut EditPlan,
) -> Result<StringOutcome> {
    let mut out = StringOutcome::default();
    if !req.plan.enabled {
        return Ok(out);
    }

    // First find no_std crates. A block-local OnceLock relies on std, so these
    // crates are deliberately out of scope rather than made to compile by
    // smuggling std into them.
    let mut no_std_crates = HashSet::new();
    let mut parsed_files = Vec::new();
    for (file_id, path) in analysis.rust_files() {
        let Ok(rel) = path.strip_prefix(req.input_root) else {
            continue;
        };
        if !req.copied.contains(rel) {
            continue;
        }
        let Some((parsed, source)) = analysis.parse(file_id) else {
            continue;
        };
        if has_no_std_attribute(&parsed) {
            if let Some(krate) = crate_for_file(req.graph, &path) {
                no_std_crates.insert(krate.name.clone());
            }
        }
        parsed_files.push((path, parsed, source));
    }

    // Keep every decoded Rust literal, including values that are not selected
    // for protection. The binary scanner is deliberately a raw byte scanner:
    // protecting `token-name` cannot be claimed as complete when an unrelated
    // literal such as `missing token-name in response` will compile the same
    // bytes back into the artifact.
    let rust_literal_values = parsed_files
        .iter()
        .flat_map(|(_, parsed, _)| {
            parsed
                .syntax()
                .descendants_with_tokens()
                .filter_map(|element| element.into_token())
                .filter_map(ast::String::cast)
                .filter_map(|token| syn::parse_str::<syn::LitStr>(token.text()).ok())
                .map(|literal| literal.value())
        })
        .collect::<BTreeSet<_>>();

    let mut by_value: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();

    for (path, parsed, source) in parsed_files {
        let Some(krate) = crate_for_file(req.graph, &path) else {
            continue;
        };
        if !is_root_like(req.graph, &krate.name)
            && matches!(
                req.dependencies.mode_for(&krate.name),
                crate::config::DependencyMode::External | crate::config::DependencyMode::Wrapper
            )
        {
            continue;
        }
        if no_std_crates.contains(&krate.name) {
            continue;
        }
        out.files_scanned += 1;

        for token in parsed
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .filter_map(ast::String::cast)
        {
            let text = token.text();
            let Ok(lit) = syn::parse_str::<syn::LitStr>(text) else {
                continue;
            };
            let value = lit.value();
            if classify(&value, req.plan).is_none() {
                continue;
            }
            // A retained wire value such as `Audio132K` also retains `132K`
            // as raw bytes. The final binary scanner intentionally searches
            // substrings, so exact equality is not a sufficient reservation.
            if collides_with_reserved_protocol(&value, req.reserved_protocol_values) {
                continue;
            }

            let range = token.syntax().text_range();
            let start = u32::from(range.start());
            let end = u32::from(range.end());
            let safe = !forbidden_context(token.syntax());

            by_value.entry(value).or_default().push(Occurrence {
                file: path.clone(),
                source: source.clone(),
                start,
                end,
                safe,
            });
        }
    }

    out.values_discovered = by_value.len();
    out.occurrences_discovered = by_value.values().map(Vec::len).sum();

    // The mapping is a promise that a protected plaintext vanished from the
    // generated tree. A value may be a safe runtime literal in Rust and still
    // be required verbatim by Cargo metadata, a Tauri config, or frontend
    // source. Reserve those cross-file collisions before staging any edit;
    // otherwise source/binary verification would correctly reject a mapping
    // that could never be satisfied.
    let copied_texts = copied_non_rust_texts(req);
    by_value.retain(|value, _| {
        let collision = copied_texts.iter().any(|text| text.contains(value));
        if collision {
            out.kept_external_collision += 1;
        }
        !collision
    });

    // A proper substring in another Rust literal is also a plaintext
    // collision. This check uses decoded literal values, so raw strings and
    // escaped source spellings are treated exactly as rustc treats them. Be
    // conservative even when the containing literal is itself selectable:
    // values are committed independently, and mapping one must never depend on
    // a later transaction also succeeding.
    by_value.retain(|value, _| {
        let collision = has_rust_literal_collision(value, &rust_literal_values);
        if collision {
            out.kept_external_collision += 1;
        }
        !collision
    });

    // Registry/git/external path dependencies are intentionally not copied or
    // rewritten, but Rust literals, byte strings, identifiers, generated JS,
    // and bundled assets from those packages can all reach the same final
    // artifact. Scan their raw source bytes before promising that a plaintext
    // is absent. This intentionally prefers a conservative keep over a mapping
    // entry that the final raw-byte scanner cannot verify.
    let candidate_values = by_value.keys().cloned().collect::<BTreeSet<_>>();
    let dependency_collisions =
        external_dependency_plaintext_collisions(req.graph, req.input_root, &candidate_values)?;
    by_value.retain(|value, _| {
        let collision = dependency_collisions.contains(value);
        if collision {
            out.kept_external_collision += 1;
        }
        !collision
    });

    for (value, mut occurrences) in by_value {
        // One unsafe occurrence keeps this plaintext globally. Otherwise
        // mapping.strings would promise the leak scanner that it disappeared
        // when it did not.
        if occurrences.iter().any(|occ| !occ.safe) {
            out.kept_unsafe_context += 1;
            tracing::debug!(
                value = %value,
                occurrences = occurrences.len(),
                "keeping string because at least one occurrence is compile-time/ambiguous"
            );
            continue;
        }

        // rust-analyzer's file iteration order is an implementation detail.
        // Sort before assigning ordinals so identical inputs produce the same
        // per-occurrence identity on every host.
        occurrences.sort_by(|left, right| {
            left.file
                .cmp(&right.file)
                .then_with(|| left.start.cmp(&right.start))
        });

        let mut contributions_by_file: BTreeMap<PathBuf, (String, Vec<ra_ap_ide::Indel>)> =
            BTreeMap::new();
        let mut occurrence_ordinals: BTreeMap<String, u64> = BTreeMap::new();

        for occ in &occurrences {
            let file_identity = relative_file_identity(req.input_root, &occ.file);
            let ordinal = occurrence_ordinals
                .entry(file_identity.clone())
                .or_default();
            let stream_seed = derive_stream_seed(req.seed, &file_identity, &value, *ordinal);
            *ordinal += 1;
            let encoded = encode(value.as_bytes(), stream_seed);
            let replacement = protected_expression(&encoded, stream_seed);

            let entry = contributions_by_file
                .entry(occ.file.clone())
                .or_insert_with(|| (occ.source.clone(), Vec::new()));
            entry.1.push(replace(occ.start, occ.end, replacement));
        }

        let contributions: Vec<Contribution<'_>> = contributions_by_file
            .iter()
            .map(|(path, (source, indels))| Contribution::new(path, source, indels.clone()))
            .collect();

        match edits.stage_transaction(contributions) {
            Ok(applied) => {
                out.values_protected += 1;
                out.occurrences_protected += applied;
                out.files_edited
                    .extend(contributions_by_file.keys().cloned());
                out.mapping
                    .insert(value, "runtime-xorshift64star".to_string());
            }
            Err(error) => {
                out.kept_conflict += 1;
                tracing::debug!(%error, "keeping string because its edit transaction conflicted");
            }
        }
    }

    if !no_std_crates.is_empty() {
        out.warnings.push(format!(
            "string protection skipped {} no_std crate(s): {}",
            no_std_crates.len(),
            {
                let mut names: Vec<_> = no_std_crates.into_iter().collect();
                names.sort();
                names.join(", ")
            }
        ));
    }

    Ok(out)
}

fn copied_non_rust_texts(req: &StringRequest<'_>) -> Vec<String> {
    const TEXT_EXTENSIONS: &[&str] = &[
        "cjs", "css", "html", "js", "json", "jsx", "mjs", "svelte", "toml", "ts", "tsx", "vue",
    ];

    req.copied
        .iter()
        .filter(|relative| {
            relative
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| TEXT_EXTENSIONS.contains(&extension))
        })
        .filter_map(|relative| std::fs::read_to_string(req.input_root.join(relative)).ok())
        .collect()
}

fn has_rust_literal_collision(value: &str, literals: &BTreeSet<String>) -> bool {
    literals
        .iter()
        .any(|literal| literal != value && literal.contains(value))
}

fn collides_with_reserved_protocol(value: &str, reserved: &HashSet<String>) -> bool {
    reserved.iter().any(|protocol| protocol.contains(value))
}

pub(crate) fn external_dependency_plaintext_collisions(
    graph: &CrateGraph,
    input_root: &Path,
    candidates: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    if candidates.is_empty() {
        return Ok(BTreeSet::new());
    }

    let patterns = candidates.iter().cloned().collect::<Vec<_>>();
    let matcher = AhoCorasick::new(&patterns)?;
    let mut roots = BTreeSet::new();
    for root in graph
        .dependency_source_dirs
        .iter()
        .chain(graph.dependency_manifest_dirs.values())
    {
        if !path_starts_with(root, input_root) {
            roots.insert(root.clone());
        }
    }

    let mut collisions = BTreeSet::new();
    for root in roots {
        for entry in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_entry(|entry| {
                !entry.file_type().is_dir()
                    || !matches!(
                        entry.file_name().to_string_lossy().as_ref(),
                        "target" | ".git" | ".hg" | ".svn"
                    )
            })
            .filter_map(|entry| entry.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(bytes) = std::fs::read(entry.path()) else {
                continue;
            };
            if entry.path().extension().is_some_and(|value| value == "rs") {
                scan_rust_dependency_values(&bytes, &matcher, &patterns, &mut collisions);
            } else {
                record_plaintext_matches(&bytes, &matcher, &patterns, &mut collisions);
            }
        }
    }

    // Some dependencies construct static data from numeric byte tables. The
    // Brotli dictionary is a real example: Chinese and ASCII words are written
    // as `0xe9, 0x98, ...` in Rust source and only become searchable plaintext
    // in the compiled rlib. rust-analyzer's loading check has already produced
    // dependency artifacts by this point, so inspect only resolved external
    // library artifacts, never the workspace crate that still contains the
    // candidate literals by definition.
    if let Some(target_dir) = &graph.target_directory {
        for entry in walkdir::WalkDir::new(target_dir)
            .into_iter()
            .filter_entry(|entry| {
                !entry.file_type().is_dir()
                    || !matches!(
                        entry.file_name().to_string_lossy().as_ref(),
                        "incremental" | ".fingerprint" | "build" | "examples"
                    )
            })
            .filter_map(|entry| entry.ok())
        {
            if !entry.file_type().is_file() || !is_external_dependency_artifact(entry.path(), graph)
            {
                continue;
            }
            let Ok(bytes) = std::fs::read(entry.path()) else {
                continue;
            };
            record_plaintext_matches(&bytes, &matcher, &patterns, &mut collisions);
        }
    }

    Ok(collisions)
}

fn record_plaintext_matches(
    bytes: &[u8],
    matcher: &AhoCorasick,
    patterns: &[String],
    collisions: &mut BTreeSet<String>,
) {
    for found in matcher.find_overlapping_iter(bytes) {
        collisions.insert(patterns[found.pattern().as_usize()].clone());
    }
}

fn scan_rust_dependency_values(
    bytes: &[u8],
    matcher: &AhoCorasick,
    patterns: &[String],
    collisions: &mut BTreeSet<String>,
) {
    // Most dependency files contain neither a candidate spelling nor a static
    // byte table. Avoid constructing a full syntax tree for all of crates.io;
    // parsing only plausible files keeps this proof linear in bytes read
    // instead of linear in the complete dependency AST.
    let has_raw_candidate = matcher.is_match(bytes);
    let may_have_u8_table = bytes.windows(3).any(|window| window == b"[u8")
        && encoded_integer_stream_may_match(bytes, matcher);
    if !has_raw_candidate && !may_have_u8_table {
        return;
    }

    let Ok(source) = std::str::from_utf8(bytes) else {
        return;
    };
    let parsed = ast::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2021).tree();

    // Rust comments (including rustdoc examples) are not linked data. Decode
    // actual string/byte/C-string tokens instead of searching the raw `.rs`
    // text so examples do not conservatively pin unrelated application
    // protocols.
    if has_raw_candidate {
        for value in parsed
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .filter_map(ast::AnyString::cast)
            .filter_map(|literal| literal.value().ok().map(|value| value.into_owned()))
        {
            record_plaintext_matches(value.as_bytes(), matcher, patterns, collisions);
        }
    }

    // A dependency may spell linked bytes as numeric array elements rather
    // than a literal. Reconstruct plain u8 arrays so data such as Brotli's
    // static dictionary participates in the same collision proof.
    if may_have_u8_table {
        for array in parsed
            .syntax()
            .descendants()
            .filter_map(ast::ArrayExpr::cast)
        {
            if array.semicolon_token().is_some() {
                continue;
            }
            let values = array
                .exprs()
                .map(|expression| parse_u8_literal(&expression))
                .collect::<Option<Vec<_>>>();
            if let Some(values) = values.filter(|values| !values.is_empty()) {
                record_plaintext_matches(&values, matcher, patterns, collisions);
            }
        }
    }
}

/// Cheap prefilter for Rust numeric byte tables.
///
/// Parsing a large generated dependency file into a syntax tree is expensive.
/// Extract its integer literals first and only parse when their byte stream can
/// actually contain one of the candidate plaintexts. A false positive merely
/// causes a parse; the AST array check remains the authority.
fn encoded_integer_stream_may_match(source: &[u8], matcher: &AhoCorasick) -> bool {
    let mut stream = Vec::new();
    let mut cursor = 0;
    while cursor < source.len() {
        if !source[cursor].is_ascii_digit()
            || (cursor > 0
                && (source[cursor - 1].is_ascii_alphanumeric() || source[cursor - 1] == b'_'))
        {
            cursor += 1;
            continue;
        }

        let start = cursor;
        let (radix, prefix) =
            if source[start..].starts_with(b"0x") || source[start..].starts_with(b"0X") {
                (16, 2)
            } else if source[start..].starts_with(b"0o") || source[start..].starts_with(b"0O") {
                (8, 2)
            } else if source[start..].starts_with(b"0b") || source[start..].starts_with(b"0B") {
                (2, 2)
            } else {
                (10, 0)
            };
        cursor += prefix;
        let digits_start = cursor;
        while cursor < source.len()
            && (source[cursor] == b'_' || (source[cursor] as char).is_digit(radix))
        {
            cursor += 1;
        }
        if cursor == digits_start {
            cursor = start + 1;
            continue;
        }
        let digits = source[digits_start..cursor]
            .iter()
            .copied()
            .filter(|byte| *byte != b'_')
            .collect::<Vec<_>>();
        let value = std::str::from_utf8(&digits)
            .ok()
            .and_then(|digits| u16::from_str_radix(digits, radix).ok())
            .and_then(|value| u8::try_from(value).ok());
        // NUL is not valid in any protected protocol value and safely breaks
        // a run when the integer is not a byte (for example an array length).
        stream.push(value.unwrap_or(0));
    }
    matcher.is_match(&stream)
}

fn parse_u8_literal(expression: &ast::Expr) -> Option<u8> {
    if expression.syntax().kind() != ra_ap_syntax::SyntaxKind::LITERAL {
        return None;
    }
    let token = expression
        .syntax()
        .children_with_tokens()
        .filter_map(|element| element.into_token())
        .find(|token| token.kind() == ra_ap_syntax::SyntaxKind::INT_NUMBER)?;
    let compact = token.text().replace('_', "");
    let (radix, digits) = if let Some(value) = compact.strip_prefix("0x") {
        (16, value)
    } else if let Some(value) = compact.strip_prefix("0o") {
        (8, value)
    } else if let Some(value) = compact.strip_prefix("0b") {
        (2, value)
    } else {
        (10, compact.as_str())
    };
    let valid = |character: char| character.is_digit(radix);
    let end = digits
        .find(|character| !valid(character))
        .unwrap_or(digits.len());
    (end > 0)
        .then(|| u8::from_str_radix(&digits[..end], radix).ok())
        .flatten()
}

fn is_external_dependency_artifact(path: &Path, graph: &CrateGraph) -> bool {
    if path
        .parent()
        .and_then(Path::file_name)
        .is_none_or(|name| name != "deps")
    {
        return false;
    }

    let extension = path.extension().and_then(|value| value.to_str());
    if !matches!(
        extension,
        Some("rlib" | "a" | "lib" | "so" | "dylib" | "dll")
    ) {
        return false;
    }

    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let extension = extension.expect("the artifact extension was checked above");
    let without_extension = file_name
        .strip_suffix(&format!(".{extension}"))
        .unwrap_or(file_name);
    let base = without_extension
        .strip_prefix("lib")
        .unwrap_or(without_extension);
    graph
        .dependency_artifact_stems
        .iter()
        .any(|stem| base == stem || base.starts_with(&format!("{stem}-")))
}

fn has_no_std_attribute(parsed: &ast::SourceFile) -> bool {
    parsed
        .attrs()
        .filter(|attr| attr.kind().is_inner())
        .flat_map(|attr| attr.skip_cfg_attrs().into_iter())
        .any(|meta| meta.simple_name().is_some_and(|name| name == "no_std"))
}

fn relative_file_identity(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Which configured class owns this value.
///
/// The default balanced profile only enables \`internal\`, and this deliberately
/// recognises machine-like semantic strings rather than every piece of copy.
fn classify(value: &str, plan: &StringsPlan) -> Option<&'static str> {
    if value.len() < 4 || value.len() > 1024 || value.contains('\0') {
        return None;
    }

    let lower = value.to_ascii_lowercase();
    let endpoint = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://");
    if endpoint {
        return plan.endpoints.then_some("endpoint");
    }

    let looks_ui = value.chars().any(char::is_whitespace) || !value.is_ascii();
    if looks_ui {
        return plan.ui.then_some("ui");
    }

    if !plan.internal {
        return None;
    }

    let has_alpha = value.bytes().any(|b| b.is_ascii_alphabetic());
    let has_semantic_separator = value
        .bytes()
        .any(|b| matches!(b, b'_' | b'-' | b':' | b'/' | b'.'));
    let protocol_style = has_alpha
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));

    (has_alpha && (has_semantic_separator || protocol_style)).then_some("internal")
}

/// Contexts where replacing a literal expression with a runtime block would
/// change whether the source is const-evaluable, pattern syntax, ABI syntax, or
/// macro/attribute input.
fn forbidden_context(token: &ra_ap_syntax::SyntaxToken) -> bool {
    let mut current = token.parent();
    while let Some(node) = current {
        let kind = format!("{:?}", node.kind());

        if matches!(
            kind.as_str(),
            "ATTR"
                | "TOKEN_TREE"
                | "CONST"
                | "STATIC"
                | "ABI"
                | "EXTERN_CRATE"
                | "CONST_ARG"
                | "CONST_PARAM"
                | "ARRAY_TYPE"
        ) || kind.ends_with("_PAT")
        {
            return true;
        }

        if kind.starts_with("ASM_")
            || kind.starts_with("FORMAT_ARGS_")
            || kind == "INCLUDE_BYTES_EXPR"
        {
            return true;
        }

        if kind == "BLOCK_EXPR"
            && ast::BlockExpr::cast(node.clone()).is_some_and(|block| block.const_token().is_some())
        {
            return true;
        }

        if kind == "FN" {
            if ast::Fn::cast(node).is_some_and(|function| function.const_token().is_some()) {
                return true;
            }
            // Once a normal runtime function owns the literal, outer item
            // syntax cannot make the expression const.
            return false;
        }

        current = node.parent();
    }
    false
}

fn derive_stream_seed(build_seed: u64, file_identity: &str, value: &str, ordinal: u64) -> u64 {
    let mut mac = Hmac::<Sha256>::new_from_slice(&build_seed.to_be_bytes())
        .expect("HMAC accepts every key length");
    mac.update(b"protected-string\0");
    mac.update(file_identity.as_bytes());
    mac.update(b"\0");
    mac.update(value.as_bytes());
    mac.update(b"\0");
    mac.update(&ordinal.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    // xorshift's all-zero state is absorbing.
    u64::from_be_bytes(bytes) | 1
}

fn next_stream_byte(state: &mut u64) -> u8 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    (state.wrapping_mul(STREAM_MULTIPLIER) >> 56) as u8
}

fn encode(value: &[u8], seed: u64) -> Vec<u8> {
    let mut state = seed;
    value
        .iter()
        .map(|byte| byte ^ next_stream_byte(&mut state))
        .collect()
}

fn protected_expression(encoded: &[u8], seed: u64) -> String {
    let bytes = encoded
        .iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\
static __SV: ::std::sync::OnceLock<::std::string::String> = ::std::sync::OnceLock::new();\
__SV.get_or_init(|| {{\
let mut __b = ::std::vec![{bytes}];\
let mut __s: u64 = ::std::hint::black_box(0x{seed:016x});\
for __x in &mut __b {{\
__s ^= __s >> 12;\
__s ^= __s << 25;\
__s ^= __s >> 27;\
*__x ^= (__s.wrapping_mul(0x{STREAM_MULTIPLIER:016x}) >> 56) as u8;\
}}\
::std::string::String::from_utf8_lossy(&__b).into_owned()\
}}).as_str()\
}}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::StringsPlan;

    fn balanced_strings() -> StringsPlan {
        StringsPlan {
            enabled: true,
            internal: true,
            ..Default::default()
        }
    }

    #[test]
    fn encoding_roundtrips_with_the_runtime_stream() {
        let original = b"license-check";
        let seed = 0x1234_5678_9abc_def1;
        let mut encoded = encode(original, seed);
        let mut state = seed;
        for byte in &mut encoded {
            *byte ^= next_stream_byte(&mut state);
        }
        assert_eq!(encoded, original);
    }

    #[test]
    fn string_seed_is_stable_and_identity_specific() {
        assert_eq!(
            derive_stream_seed(7, "src/lib.rs", "license-check", 0),
            derive_stream_seed(7, "src/lib.rs", "license-check", 0)
        );
        assert_ne!(
            derive_stream_seed(7, "src/lib.rs", "license-check", 0),
            derive_stream_seed(7, "src/lib.rs", "license-check", 1)
        );
        assert_ne!(
            derive_stream_seed(7, "src/lib.rs", "license-check", 0),
            derive_stream_seed(7, "src/other.rs", "license-check", 0)
        );
        assert_ne!(
            derive_stream_seed(7, "src/lib.rs", "license-check", 0),
            derive_stream_seed(7, "src/lib.rs", "other-value", 0)
        );
    }

    #[test]
    fn file_identity_is_relative_and_separator_stable() {
        assert_eq!(
            relative_file_identity(
                Path::new("/checkout/one"),
                Path::new("/checkout/one/src/lib.rs")
            ),
            "src/lib.rs"
        );
        assert_eq!(
            relative_file_identity(
                Path::new("/checkout/two"),
                Path::new("/checkout/two/src/lib.rs")
            ),
            "src/lib.rs"
        );
    }

    fn forbidden_for(source: &str, value: &str) -> bool {
        let file =
            ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2021).tree();
        file.syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .filter_map(ast::String::cast)
            .find_map(|token| {
                let literal = syn::parse_str::<syn::LitStr>(token.text()).ok()?;
                (literal.value() == value).then(|| forbidden_context(token.syntax()))
            })
            .unwrap_or_else(|| panic!("string literal {value:?} not found in {source:?}"))
    }

    #[test]
    fn compile_time_and_ambiguous_contexts_are_kept() {
        let cases = [
            (
                "#![ no_std ]\nconst VALUE: &str = \"const-protocol\";",
                "const-protocol",
            ),
            (
                "#[cfg(feature = \"cfg-protocol\")] fn f() {}",
                "cfg-protocol",
            ),
            (
                "static VALUE: &str = \"static-protocol\";",
                "static-protocol",
            ),
            (
                "pub(crate) const fn f() -> &'static str { \"const-fn-protocol\" }",
                "const-fn-protocol",
            ),
            (
                "pub const unsafe fn f() -> &'static str { \"unsafe-const-fn\" }",
                "unsafe-const-fn",
            ),
            (
                "fn f() { let _ = match \"scrutinee\" { \"match-protocol\" => 1, _ => 0 }; }",
                "match-protocol",
            ),
            (
                "fn f() { let _: [u8; \"array-length-protocol\".len()] = []; }",
                "array-length-protocol",
            ),
            (
                "struct S<const N: usize>; type T = S<{ \"const-generic-protocol\".len() }>;",
                "const-generic-protocol",
            ),
            (
                "fn f() -> &'static str { const { \"inline-const-protocol\" } }",
                "inline-const-protocol",
            ),
            (
                "fn f() { format_args!(\"format-protocol\"); }",
                "format-protocol",
            ),
            (
                "fn f() { include_bytes!(\"include-protocol\"); }",
                "include-protocol",
            ),
        ];
        for (source, value) in cases {
            assert!(
                forbidden_for(source, value),
                "context was treated as runtime: {source}"
            );
        }
        assert!(!forbidden_for(
            "fn f() -> &'static str { let value = \"runtime-protocol\"; value }",
            "runtime-protocol"
        ));
    }

    #[test]
    fn no_std_detection_reads_inner_ast_attributes() {
        for source in [
            "#![no_std]\nfn f() {}",
            "#![ no_std ]\nfn f() {}",
            "#![cfg_attr(feature = \"std\", no_std)]\nfn f() {}",
        ] {
            let file =
                ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2021).tree();
            assert!(has_no_std_attribute(&file), "missed no_std in {source:?}");
        }
        let file = ra_ap_syntax::SourceFile::parse(
            "#[no_std]\nfn f() {}",
            ra_ap_syntax::Edition::Edition2021,
        )
        .tree();
        assert!(!has_no_std_attribute(&file));
    }

    #[test]
    fn default_internal_classification_is_machine_like() {
        let plan = balanced_strings();
        assert_eq!(classify("license-check", &plan), Some("internal"));
        assert_eq!(classify("HOLE_PUNCH_REQUEST", &plan), Some("internal"));
        assert_eq!(classify("state.value", &plan), Some("internal"));
        assert_eq!(classify("Connected", &plan), None);
        assert_eq!(classify("Cancel download", &plan), None);
        assert_eq!(classify("确定", &plan), None);
    }

    #[test]
    fn endpoint_and_ui_are_explicit_classes() {
        let mut plan = balanced_strings();
        assert_eq!(classify("https://example.invalid/api", &plan), None);
        plan.endpoints = true;
        assert_eq!(
            classify("https://example.invalid/api", &plan),
            Some("endpoint")
        );

        assert_eq!(classify("Download complete", &plan), None);
        plan.ui = true;
        assert_eq!(classify("Download complete", &plan), Some("ui"));
    }

    #[test]
    fn generated_expression_contains_no_plaintext() {
        let value = "device-validation";
        let seed = 11;
        let expression = protected_expression(&encode(value.as_bytes(), seed), seed);
        assert!(!expression.contains(value));
        assert!(expression.contains("OnceLock"));
        assert!(expression.contains("black_box"));
    }

    #[test]
    fn copied_metadata_is_treated_as_a_plaintext_collision() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"shared-runtime-name\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("README.md"),
            "shared-runtime-name is documentation only",
        )
        .unwrap();
        let copied = BTreeSet::from([PathBuf::from("Cargo.toml"), PathBuf::from("README.md")]);
        let graph = CrateGraph::default();
        let strings = balanced_strings();
        let dependencies = DependenciesPlan::default();
        let reserved = HashSet::new();
        let request = StringRequest {
            input_root: tmp.path(),
            copied: &copied,
            graph: &graph,
            plan: &strings,
            dependencies: &dependencies,
            seed: 7,
            reserved_protocol_values: &reserved,
        };

        let texts = copied_non_rust_texts(&request);
        assert!(texts
            .iter()
            .any(|text| text.contains("shared-runtime-name")));
        assert!(!texts.iter().any(|text| text.contains("documentation only")));
    }

    #[test]
    fn a_value_inside_a_larger_rust_literal_is_a_plaintext_collision() {
        let literals = BTreeSet::from([
            "aweme_detail".to_string(),
            "No aweme_detail in response".to_string(),
            "bytes=0-1048575".to_string(),
        ]);

        for value in ["aweme_detail", "bytes=0-"] {
            assert!(has_rust_literal_collision(value, &literals));
        }
        assert!(!has_rust_literal_collision("unrelated", &literals));
    }

    #[test]
    fn a_string_inside_a_retained_wire_value_is_reserved() {
        let reserved = HashSet::from(["Audio132K".to_string(), "download://progress".to_string()]);
        assert!(collides_with_reserved_protocol("132K", &reserved));
        assert!(collides_with_reserved_protocol("progress", &reserved));
        assert!(!collides_with_reserved_protocol("private-token", &reserved));
    }

    #[test]
    fn external_dependency_sources_are_plaintext_collisions() {
        let tmp = tempfile::tempdir().unwrap();
        let input = tmp.path().join("input");
        let dependency = tmp.path().join("registry-dependency");
        std::fs::create_dir_all(dependency.join("src")).unwrap();
        std::fs::write(
            dependency.join("src/lib.rs"),
            r#"
/// A documentation-only-token example must not pin an application value.
pub const MIME: &str = "application/octet-stream";
pub static TABLE: [u8; 9] = [
    0x68, 0x65, 0x78, 0x2d, 0x74, 0x6f, 0x6b, 0x65, 0x6e,
];
"#,
        )
        .unwrap();
        std::fs::create_dir_all(dependency.join("guest-js")).unwrap();
        std::fs::write(
            dependency.join("guest-js/index.ts"),
            "this.downloadedBytes = undefined;",
        )
        .unwrap();

        let mut graph = CrateGraph::default();
        graph.dependency_source_dirs.insert(dependency);
        let strings = balanced_strings();
        let dependencies = DependenciesPlan::default();
        let copied = BTreeSet::new();
        let reserved = HashSet::new();
        let request = StringRequest {
            input_root: &input,
            copied: &copied,
            graph: &graph,
            plan: &strings,
            dependencies: &dependencies,
            seed: 7,
            reserved_protocol_values: &reserved,
        };
        let candidates = BTreeSet::from([
            ".downloaded".to_string(),
            "application/octet-stream".to_string(),
            "documentation-only-token".to_string(),
            "hex-token".to_string(),
            "private-runtime-token".to_string(),
        ]);

        let collisions = external_dependency_plaintext_collisions(
            request.graph,
            request.input_root,
            &candidates,
        )
        .unwrap();
        assert_eq!(
            collisions,
            BTreeSet::from([
                ".downloaded".to_string(),
                "application/octet-stream".to_string(),
                "hex-token".to_string()
            ])
        );
    }

    #[test]
    fn compiled_dependency_byte_tables_are_plaintext_collisions() {
        let tmp = tempfile::tempdir().unwrap();
        let deps = tmp.path().join("target/debug/deps");
        std::fs::create_dir_all(&deps).unwrap();
        std::fs::write(
            deps.join("libbyte_table_dep-123456.rlib"),
            b"archive-prefix compiled-only-token archive-suffix",
        )
        .unwrap();
        std::fs::write(
            deps.join("libworkspace_root-123456.rlib"),
            b"workspace-only-token",
        )
        .unwrap();

        let mut graph = CrateGraph {
            target_directory: Some(tmp.path().join("target")),
            ..Default::default()
        };
        graph
            .dependency_artifact_stems
            .insert("byte_table_dep".into());
        let candidates = BTreeSet::from([
            "compiled-only-token".to_string(),
            "workspace-only-token".to_string(),
        ]);

        let collisions = external_dependency_plaintext_collisions(
            &graph,
            &tmp.path().join("input"),
            &candidates,
        )
        .unwrap();
        assert_eq!(
            collisions,
            BTreeSet::from(["compiled-only-token".to_string()])
        );
    }

    #[test]
    fn numeric_table_prefilter_finds_encoded_bytes_without_parsing_unrelated_tables() {
        let matcher = AhoCorasick::new(["hex-token", "not-present"]).unwrap();
        assert!(encoded_integer_stream_may_match(
            b"static X: [u8; 9] = [0x68,0x65,0x78,0x2d,0x74,0x6f,0x6b,0x65,0x6e];",
            &matcher
        ));
        assert!(!encoded_integer_stream_may_match(
            b"static X: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];",
            &matcher
        ));
    }
}
