//! Runtime string-literal protection.
//!
//! This pass rewrites selected runtime Rust string expressions whose type can
//! remain \`&'static str\`, plus the literal text pieces of structurally proven
//! formatting macros. With `strings.all`, every non-empty runtime literal is a
//! candidate; the narrower classes remain available for balanced builds.
//! Format placeholders stay in a compile-time literal and each visible text
//! piece becomes a generated named argument whose value is decoded at runtime.
//! Other macro token trees and compile-time contexts (attributes, const/static
//! initialisers, patterns, ABI strings and const fn bodies) are left alone.
//!
//! Rewrite eligibility and global plaintext proof are deliberately separate.
//! Every safe occurrence is transformed even when the same spelling must stay
//! in a compile-time context, copied asset, protocol, or dependency. A value is
//! entered into `mapping.strings` only when no retained collision is known, so
//! source/binary leak scans may still treat every mapped plaintext as fatal.
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
use ra_ap_syntax::{
    ast::{self, AstNode, AstToken, HasAttrs, HasName},
    SyntaxKind,
};
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::{Path, PathBuf};

const STREAM_MULTIPLIER: u64 = 0x2545_F491_4F6C_DD1D;
/// Raw-byte leak scans are not meaningful for one-to-three-byte strings: a
/// match is overwhelmingly likely to be incidental machine code or metadata.
/// Those literals are still protected, but are not advertised in the strict
/// global mapping.
const MIN_VERIFIABLE_PLAINTEXT_LEN: usize = 4;

#[derive(Debug, Clone, Default)]
pub struct StringOutcome {
    pub files_scanned: usize,
    pub values_discovered: usize,
    pub occurrences_discovered: usize,
    pub values_protected: usize,
    /// Protected values for which the pass can promise that no known retained
    /// plaintext remains. This is also the number eligible for the mapping.
    pub values_mapped: usize,
    /// Values whose safe occurrences were protected but whose plaintext is
    /// retained or may collide elsewhere, so they are intentionally unmapped.
    pub values_protected_unmapped: usize,
    pub occurrences_protected: usize,
    pub occurrences_kept_unsafe: usize,
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
    kind: OccurrenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct LiteralId {
    file: PathBuf,
    start: u32,
    end: u32,
}

#[derive(Debug, Clone)]
enum OccurrenceKind {
    Ordinary,
    Format {
        template: LiteralId,
        fragment: usize,
    },
}

#[derive(Debug, Clone)]
enum FormatPart {
    Literal { fragment: usize, value: String },
    Argument(String),
}

#[derive(Debug, Clone)]
struct FormatTemplate {
    id: LiteralId,
    file: PathBuf,
    source: String,
    literal_start: u32,
    literal_end: u32,
    insert_at: u32,
    trailing_comma: bool,
    parts: Vec<FormatPart>,
    used_identifiers: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct RustLiteralRecord {
    id: LiteralId,
    value: String,
}

#[derive(Debug, Clone)]
struct PreparedFormatFragment {
    expression: String,
    stream_seed: u64,
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
    // for protection. Records retain their source identity so a formatting
    // literal can remove its own visible pieces without treating the original
    // `text {placeholder}` template as an external collision.
    let rust_literals = parsed_files
        .iter()
        .flat_map(|(path, parsed, _)| {
            parsed
                .syntax()
                .descendants_with_tokens()
                .filter_map(|element| element.into_token())
                .filter_map(ast::String::cast)
                .filter_map(|token| {
                    let literal = syn::parse_str::<syn::LitStr>(token.text()).ok()?;
                    let range = token.syntax().text_range();
                    Some(RustLiteralRecord {
                        id: LiteralId {
                            file: path.clone(),
                            start: u32::from(range.start()),
                            end: u32::from(range.end()),
                        },
                        value: literal.value(),
                    })
                })
        })
        .collect::<Vec<_>>();

    let shadowed_format_macros = collect_shadowed_format_macros(&parsed_files);
    let mut by_value: BTreeMap<String, Vec<Occurrence>> = BTreeMap::new();
    let mut format_templates = BTreeMap::new();

    for (path, parsed, source) in &parsed_files {
        let Some(krate) = crate_for_file(req.graph, path) else {
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

        // A format macro requires a compile-time literal, so replacing the
        // whole expression is invalid Rust. For macro shapes whose format
        // argument position is known, split the literal output from the
        // placeholders and register each visible fragment independently.
        for (template, safe) in
            discover_format_templates(parsed, path, source, &shadowed_format_macros)
        {
            for part in &template.parts {
                let FormatPart::Literal { fragment, value } = part else {
                    continue;
                };
                if classify(value.as_str(), req.plan).is_none() {
                    continue;
                }
                by_value.entry(value.clone()).or_default().push(Occurrence {
                    file: path.clone(),
                    source: source.clone(),
                    start: template.literal_start,
                    end: template.literal_end,
                    safe,
                    kind: OccurrenceKind::Format {
                        template: template.id.clone(),
                        fragment: *fragment,
                    },
                });
            }
            format_templates.insert(template.id.clone(), template);
        }

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
            let range = token.syntax().text_range();
            let id = LiteralId {
                file: path.clone(),
                start: u32::from(range.start()),
                end: u32::from(range.end()),
            };
            // Proven format literals are represented by their visible pieces
            // above. Treating the complete string as an ordinary unsafe token
            // would pin every one of those pieces forever.
            if format_templates.contains_key(&id) {
                continue;
            }
            if classify(&value, req.plan).is_none() {
                continue;
            }
            let start = u32::from(range.start());
            let end = u32::from(range.end());
            let safe = !forbidden_runtime_context(token.syntax(), &shadowed_format_macros);

            by_value.entry(value).or_default().push(Occurrence {
                file: path.clone(),
                source: source.clone(),
                start,
                end,
                safe,
                kind: OccurrenceKind::Ordinary,
            });
        }
    }

    out.values_discovered = by_value.len();
    out.occurrences_discovered = by_value.values().map(Vec::len).sum();

    // Rewriting and proof are separate decisions. Safe runtime occurrences are
    // always rewritten. The proof set below only decides whether the value may
    // be advertised in mapping.strings as globally absent plaintext.
    let mut proof_blocked = BTreeSet::new();
    let mut external_collisions = BTreeSet::new();

    // A retained wire value such as `Audio132K` also retains `132K` as raw
    // bytes. This prevents a strict mapping promise, but must not prevent a
    // separate runtime occurrence from being encoded.
    let mut mapping_plan = req.plan.clone();
    mapping_plan.all = false;
    for value in by_value.keys() {
        // `all` deliberately admits generic words such as "navigate" and
        // "document". Those are worth removing from application source, but
        // raw final binaries may independently contain them in the toolchain,
        // platform libraries, or dependency metadata. Keep strict mapping
        // membership limited to the explicit semantic classes; otherwise one
        // incidental substring would turn a successful protection pass into a
        // false binary-leak failure.
        let generic_all_value = req.plan.all && classify(value, &mapping_plan).is_none();
        if value.len() < MIN_VERIFIABLE_PLAINTEXT_LEN || generic_all_value {
            proof_blocked.insert(value.clone());
        }
        if collides_with_reserved_protocol(value, req.reserved_protocol_values) {
            proof_blocked.insert(value.clone());
            external_collisions.insert(value.clone());
        }
    }

    // A value may also be required verbatim by Cargo/Tauri configuration or
    // frontend source. Keep transforming its Rust runtime sites, but withhold
    // it from the strict mapping.
    let copied_texts = copied_non_rust_texts(req);
    for value in by_value.keys() {
        if copied_texts.iter().any(|text| text.contains(value)) {
            proof_blocked.insert(value.clone());
            external_collisions.insert(value.clone());
        }
    }

    // An unsafe occurrence remains plaintext, but no longer pins independent
    // safe occurrences of the same value.
    let unsafe_values = by_value
        .iter()
        .filter(|(_, occurrences)| occurrences.iter().any(|occurrence| !occurrence.safe))
        .map(|(value, _)| value.clone())
        .collect::<BTreeSet<_>>();
    out.kept_unsafe_context = unsafe_values.len();
    out.occurrences_kept_unsafe = by_value
        .values()
        .flatten()
        .filter(|occurrence| !occurrence.safe)
        .count();
    proof_blocked.extend(unsafe_values);

    for (value, occurrences) in &by_value {
        if occurrences.iter().any(|occurrence| !occurrence.safe) {
            tracing::debug!(
                value = %value,
                occurrences = occurrences.len(),
                "protecting safe string occurrences while retaining compile-time/ambiguous sites"
            );
        }
    }

    // A proper substring in another retained Rust literal is also a plaintext
    // collision. Formatting literals are modelled as their runtime literal
    // pieces plus unchanged placeholders; only an exact selected piece owned
    // by this value is ignored.
    let rust_collisions = by_value
        .iter()
        .filter(|(value, occurrences)| {
            has_rust_literal_collision(value, occurrences, &rust_literals, &format_templates)
        })
        .map(|(value, _)| value.clone())
        .collect::<BTreeSet<_>>();
    for value in rust_collisions {
        proof_blocked.insert(value.clone());
        external_collisions.insert(value);
    }

    // Registry/git/external path dependencies are intentionally not copied or
    // rewritten, but Rust literals, byte strings, identifiers, generated JS,
    // and bundled assets from those packages can all reach the same final
    // artifact. Scan their raw source bytes before promising that a plaintext
    // is absent. This intentionally prefers a conservative keep over a mapping
    // entry that the final raw-byte scanner cannot verify.
    let candidate_values = by_value
        .keys()
        .filter(|value| !proof_blocked.contains(*value))
        .cloned()
        .collect::<BTreeSet<_>>();
    let dependency_collisions =
        external_dependency_plaintext_collisions(req.graph, req.input_root, &candidate_values)?;
    proof_blocked.extend(dependency_collisions.iter().cloned());
    external_collisions.extend(dependency_collisions);
    out.kept_external_collision = external_collisions.len();

    // Only safe occurrences participate in edit transactions. Values that
    // exist exclusively in compile-time/opaque contexts remain discovered and
    // reported, but naturally have no rewrite component.
    for occurrences in by_value.values_mut() {
        occurrences.retain(|occurrence| occurrence.safe);
    }
    by_value.retain(|_, occurrences| !occurrences.is_empty());

    // rust-analyzer's file iteration order is an implementation detail. Sort
    // before assigning ordinals so identical inputs produce the same
    // per-occurrence identity on every host.
    for occurrences in by_value.values_mut() {
        occurrences.sort_by(occurrence_order);
    }

    // One macro rewrite owns one literal replacement and one argument-list
    // insertion. Values sharing that macro must commit together. Connected
    // components retain a per-value failure boundary for unrelated literals.
    let mut values_by_template: BTreeMap<LiteralId, BTreeSet<String>> = BTreeMap::new();
    for (value, occurrences) in &by_value {
        for occurrence in occurrences {
            if let OccurrenceKind::Format { template, .. } = &occurrence.kind {
                values_by_template
                    .entry(template.clone())
                    .or_default()
                    .insert(value.clone());
            }
        }
    }

    let starts = by_value.keys().cloned().collect::<Vec<_>>();
    let mut visited = BTreeSet::new();
    for start in starts {
        if visited.contains(&start) {
            continue;
        }
        let mut component = BTreeSet::new();
        let mut queue = VecDeque::from([start]);
        while let Some(value) = queue.pop_front() {
            if !visited.insert(value.clone()) {
                continue;
            }
            component.insert(value.clone());
            for occurrence in &by_value[&value] {
                let OccurrenceKind::Format { template, .. } = &occurrence.kind else {
                    continue;
                };
                if let Some(neighbours) = values_by_template.get(template) {
                    queue.extend(neighbours.iter().cloned());
                }
            }
        }

        let mut contributions_by_file: BTreeMap<PathBuf, (String, Vec<ra_ap_ide::Indel>)> =
            BTreeMap::new();
        let mut prepared_formats: BTreeMap<LiteralId, BTreeMap<usize, PreparedFormatFragment>> =
            BTreeMap::new();
        let mut protected_occurrences = 0;

        for value in &component {
            let mut occurrence_ordinals: BTreeMap<String, u64> = BTreeMap::new();
            for occurrence in &by_value[value] {
                let file_identity = relative_file_identity(req.input_root, &occurrence.file);
                let ordinal = occurrence_ordinals
                    .entry(file_identity.clone())
                    .or_default();
                let stream_seed = derive_stream_seed(req.seed, &file_identity, value, *ordinal);
                *ordinal += 1;
                let encoded = encode(value.as_bytes(), stream_seed);
                let expression = protected_expression(&encoded, stream_seed);
                protected_occurrences += 1;

                match &occurrence.kind {
                    OccurrenceKind::Ordinary => {
                        let entry = contributions_by_file
                            .entry(occurrence.file.clone())
                            .or_insert_with(|| (occurrence.source.clone(), Vec::new()));
                        entry
                            .1
                            .push(replace(occurrence.start, occurrence.end, expression));
                    }
                    OccurrenceKind::Format { template, fragment } => {
                        prepared_formats
                            .entry(template.clone())
                            .or_default()
                            .insert(
                                *fragment,
                                PreparedFormatFragment {
                                    expression,
                                    stream_seed,
                                },
                            );
                    }
                }
            }
        }

        for (id, selected) in prepared_formats {
            let template = &format_templates[&id];
            let entry = contributions_by_file
                .entry(template.file.clone())
                .or_insert_with(|| (template.source.clone(), Vec::new()));
            entry.1.extend(format_template_edits(template, &selected));
        }

        let contributions: Vec<Contribution<'_>> = contributions_by_file
            .iter()
            .map(|(path, (source, indels))| Contribution::new(path, source, indels.clone()))
            .collect();

        match edits.stage_transaction(contributions) {
            Ok(_) => {
                out.values_protected += component.len();
                out.occurrences_protected += protected_occurrences;
                out.files_edited
                    .extend(contributions_by_file.keys().cloned());
                for value in component {
                    if proof_blocked.contains(&value) {
                        out.values_protected_unmapped += 1;
                    } else {
                        out.values_mapped += 1;
                        out.mapping
                            .insert(value, "runtime-xorshift64star".to_string());
                    }
                }
            }
            Err(error) => {
                out.kept_conflict += component.len();
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

fn collect_shadowed_format_macros(
    parsed_files: &[(PathBuf, ast::SourceFile, String)],
) -> HashSet<String> {
    let mut shadowed = HashSet::new();
    for (_, parsed, _) in parsed_files {
        for definition in parsed
            .syntax()
            .descendants()
            .filter_map(ast::MacroRules::cast)
        {
            if let Some(name) = definition.name() {
                let text = name.text().to_string();
                if is_known_runtime_macro_name(&text) {
                    shadowed.insert(text);
                }
            }
        }

        // Macro imports share the macro namespace with prelude macros. It is
        // intentionally conservative to skip even `use std::format`: a
        // qualified `std::format!` remains provable, while guessing what an
        // unqualified import resolves to could append arguments to an opaque
        // macro DSL.
        for import in parsed.syntax().descendants().filter_map(ast::UseTree::cast) {
            if import.use_tree_list().is_some() || import.star_token().is_some() {
                continue;
            }
            let imported = import
                .rename()
                .and_then(|rename| rename.name())
                .map(|name| name.text().to_string())
                .or_else(|| {
                    import
                        .path()?
                        .segment()?
                        .name_ref()
                        .map(|name| name.text().to_string())
                });
            if imported.as_deref().is_some_and(is_known_runtime_macro_name) {
                let imported = imported.expect("the imported name was checked");
                // These macros have a documented format-string grammar. An
                // explicit import from `anyhow` proves their identity just as
                // a `std::format!` qualification would. A local macro_rules!
                // definition was collected above and still wins.
                let trusted_anyhow_import =
                    matches!(imported.as_str(), "anyhow" | "bail" | "ensure")
                        && import
                            .syntax()
                            .ancestors()
                            .find_map(ast::Use::cast)
                            .is_some_and(|item| {
                                let compact = item.syntax().text().to_string().replace(' ', "");
                                compact.starts_with("useanyhow::")
                                    || compact.starts_with("pubuseanyhow::")
                            });
                if !trusted_anyhow_import {
                    shadowed.insert(imported);
                }
            }
        }
    }
    shadowed
}

fn is_supported_unqualified_format_macro(name: &str) -> bool {
    matches!(
        name,
        "format"
            | "format_args"
            | "format_args_nl"
            | "print"
            | "println"
            | "eprint"
            | "eprintln"
            | "write"
            | "writeln"
            | "panic"
            | "todo"
            | "unreachable"
            | "unimplemented"
            | "assert"
            | "debug_assert"
            | "assert_eq"
            | "assert_ne"
            | "debug_assert_eq"
            | "debug_assert_ne"
            | "anyhow"
            | "bail"
            | "ensure"
    )
}

fn is_known_runtime_macro_name(name: &str) -> bool {
    is_supported_unqualified_format_macro(name) || matches!(name, "vec" | "dbg" | "matches")
}

fn format_macro_argument_path(path: &str, shadowed: &HashSet<String>) -> Option<(usize, bool)> {
    let compact = path.replace(' ', "");
    let parts = compact
        .split("::")
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let name = *parts.last()?;

    let standard = match name {
        "format" | "format_args" | "format_args_nl" | "print" | "println" | "eprint"
        | "eprintln" | "panic" | "todo" | "unreachable" | "unimplemented" => Some(0),
        "write" | "writeln" => Some(1),
        "assert" | "debug_assert" => Some(1),
        "assert_eq" | "assert_ne" | "debug_assert_eq" | "debug_assert_ne" => Some(2),
        _ => None,
    };
    if let Some(index) = standard {
        let proven_path = (parts.len() == 1 && !shadowed.contains(name))
            || (parts.len() == 2 && matches!(parts[0], "std" | "core" | "alloc"));
        return proven_path.then_some((index, false));
    }

    let anyhow_index = match name {
        "anyhow" | "bail" => Some(0),
        "ensure" => Some(1),
        _ => None,
    };
    if let Some(index) = anyhow_index {
        let proven_path = (parts.len() == 1 && !shadowed.contains(name))
            || (parts.len() == 2 && parts[0] == "anyhow");
        return proven_path.then_some((index, false));
    }

    let log_index = match name {
        "error" | "warn" | "info" | "debug" | "trace" => Some(0),
        "log" => Some(1),
        _ => None,
    };
    (parts.len() == 2 && parts[0] == "log").then_some((log_index?, true))
}

fn discover_format_templates(
    parsed: &ast::SourceFile,
    path: &Path,
    source: &str,
    shadowed: &HashSet<String>,
) -> Vec<(FormatTemplate, bool)> {
    let mut templates = Vec::new();
    for call in parsed
        .syntax()
        .descendants()
        .filter_map(ast::MacroCall::cast)
    {
        let safe = !forbidden_format_context(&call, shadowed);
        if let Some(template) = format_template(&call, path, source, shadowed) {
            templates.push((template, safe));
        }
        if transparent_runtime_macro(&call, shadowed) {
            if let Some(token_tree) = call.token_tree() {
                discover_nested_format_templates(
                    &token_tree,
                    path,
                    source,
                    shadowed,
                    safe,
                    &mut templates,
                );
            }
        }
    }
    templates
}

fn discover_nested_format_templates(
    token_tree: &ast::TokenTree,
    path: &Path,
    source: &str,
    shadowed: &HashSet<String>,
    safe: bool,
    templates: &mut Vec<(FormatTemplate, bool)>,
) {
    let elements = token_tree
        .syntax()
        .children_with_tokens()
        .filter(|element| !element.kind().is_trivia())
        .collect::<Vec<_>>();
    for (index, element) in elements.iter().enumerate() {
        let Some(nested) = element
            .as_node()
            .and_then(|node| ast::TokenTree::cast(node.clone()))
        else {
            continue;
        };
        if let Some(macro_path) = nested_macro_path(&elements, index) {
            if let Some(template) =
                format_template_from_tree(&macro_path, &nested, path, source, shadowed)
            {
                templates.push((template, safe));
            }
            // An opaque macro owns the grammar of its complete token tree. Do
            // not discover format-looking tokens inside it. Proven expression
            // containers retain ordinary Rust expression semantics and may be
            // traversed recursively.
            if transparent_runtime_macro_path(&macro_path, shadowed) {
                discover_nested_format_templates(&nested, path, source, shadowed, safe, templates);
            }
        } else {
            // Parentheses/brackets/braces used only for grouping inside a
            // transparent macro do not introduce a new macro grammar.
            discover_nested_format_templates(&nested, path, source, shadowed, safe, templates);
        }
    }
}

fn nested_macro_path(
    elements: &[ra_ap_syntax::SyntaxElement],
    token_tree_index: usize,
) -> Option<String> {
    if token_tree_index < 2 || elements[token_tree_index - 1].to_string() != "!" {
        return None;
    }
    let name = elements[token_tree_index - 2].as_token()?;
    if name.kind() != SyntaxKind::IDENT {
        return None;
    }
    if token_tree_index >= 4 && elements[token_tree_index - 3].to_string() == "::" {
        let prefix = elements[token_tree_index - 4].as_token()?;
        if prefix.kind() == SyntaxKind::IDENT {
            return Some(format!("{}::{}", prefix.text(), name.text()));
        }
    }
    Some(name.text().to_string())
}

fn format_template(
    call: &ast::MacroCall,
    path: &Path,
    source: &str,
    shadowed: &HashSet<String>,
) -> Option<FormatTemplate> {
    let macro_path = call.path()?.syntax().text().to_string();
    let token_tree = call.token_tree()?;
    format_template_from_tree(&macro_path, &token_tree, path, source, shadowed)
}

fn format_template_from_tree(
    macro_path: &str,
    token_tree: &ast::TokenTree,
    path: &Path,
    source: &str,
    shadowed: &HashSet<String>,
) -> Option<FormatTemplate> {
    let (mut format_index, log_macro) = format_macro_argument_path(macro_path, shadowed)?;
    let tree_range = token_tree.syntax().text_range();
    let inner = token_tree
        .syntax()
        .children_with_tokens()
        .filter(|element| {
            !element.kind().is_trivia()
                && element.text_range().start() > tree_range.start()
                && element.text_range().end() < tree_range.end()
        })
        .collect::<Vec<_>>();
    let trailing_comma = inner
        .last()
        .is_some_and(|element| element.kind() == SyntaxKind::COMMA);
    let mut arguments = vec![Vec::new()];
    for element in inner {
        if element.kind() == SyntaxKind::COMMA {
            arguments.push(Vec::new());
        } else {
            arguments.last_mut()?.push(element);
        }
    }

    // `log::info!(target: "name", "...")` and
    // `log::log!(target: "name", level, "...")` carry a metadata argument
    // in front of the ordinary format position.
    if log_macro
        && arguments.first().is_some_and(|argument| {
            argument.len() >= 2
                && argument[0].kind() == SyntaxKind::IDENT
                && argument[0].to_string() == "target"
                && argument[1].kind() == SyntaxKind::COLON
        })
    {
        format_index += 1;
    }

    let argument = arguments.get(format_index)?;
    if argument.len() != 1 {
        return None;
    }
    let token = argument[0]
        .as_token()
        .cloned()
        .and_then(ast::String::cast)?;
    let literal = syn::parse_str::<syn::LitStr>(token.text()).ok()?;
    let parts = split_format_literal(&literal.value())?;
    let range = token.syntax().text_range();
    let id = LiteralId {
        file: path.to_path_buf(),
        start: u32::from(range.start()),
        end: u32::from(range.end()),
    };
    let insert_at = u32::from(token_tree.syntax().last_token()?.text_range().start());
    let used_identifiers = token_tree
        .syntax()
        .descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| token.kind() == SyntaxKind::IDENT)
        .map(|token| token.text().to_string())
        .collect();

    Some(FormatTemplate {
        id,
        file: path.to_path_buf(),
        source: source.to_string(),
        literal_start: u32::from(range.start()),
        literal_end: u32::from(range.end()),
        insert_at,
        trailing_comma,
        parts,
        used_identifiers,
    })
}

fn split_format_literal(value: &str) -> Option<Vec<FormatPart>> {
    use rustc_parse_format::{ParseMode, Parser, Piece};

    // rustc's parser is the grammar authority. The small scanner below exists
    // only to retain the exact decoded `{...}` spelling for reconstruction.
    let mut parser = Parser::new(value, None, None, false, ParseMode::Format);
    let expected_arguments = parser
        .by_ref()
        .filter(|piece| matches!(piece, Piece::NextArgument(_)))
        .count();
    if !parser.errors.is_empty() {
        return None;
    }

    let bytes = value.as_bytes();
    let mut parts = Vec::new();
    let mut literal = String::new();
    let mut cursor = 0;
    let mut fragment = 0;
    let mut arguments = 0;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' if bytes.get(cursor + 1) == Some(&b'{') => {
                literal.push('{');
                cursor += 2;
            }
            b'}' if bytes.get(cursor + 1) == Some(&b'}') => {
                literal.push('}');
                cursor += 2;
            }
            b'{' => {
                if !literal.is_empty() {
                    parts.push(FormatPart::Literal {
                        fragment,
                        value: std::mem::take(&mut literal),
                    });
                    fragment += 1;
                }
                let close = value[cursor + 1..].find('}')? + cursor + 1;
                if value[cursor + 1..close].contains('{') {
                    return None;
                }
                parts.push(FormatPart::Argument(value[cursor..=close].to_string()));
                arguments += 1;
                cursor = close + 1;
            }
            b'}' => return None,
            _ => {
                let character = value[cursor..].chars().next()?;
                literal.push(character);
                cursor += character.len_utf8();
            }
        }
    }
    if !literal.is_empty() {
        parts.push(FormatPart::Literal {
            fragment,
            value: literal,
        });
    }
    (arguments == expected_arguments).then_some(parts)
}

fn append_format_literal(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '{' => output.push_str("{{"),
            '}' => output.push_str("}}"),
            _ => output.push(character),
        }
    }
}

fn format_template_edits(
    template: &FormatTemplate,
    selected: &BTreeMap<usize, PreparedFormatFragment>,
) -> Vec<ra_ap_ide::Indel> {
    let mut skeleton = String::new();
    let mut generated = Vec::new();
    let mut used = template.used_identifiers.clone();
    for part in &template.parts {
        match part {
            FormatPart::Literal { fragment, value } => {
                if let Some(prepared) = selected.get(fragment) {
                    let name =
                        unique_format_argument_name(prepared.stream_seed, *fragment, &mut used);
                    skeleton.push('{');
                    skeleton.push_str(&name);
                    skeleton.push('}');
                    generated.push((name, prepared.expression.clone()));
                } else {
                    append_format_literal(value, &mut skeleton);
                }
            }
            FormatPart::Argument(argument) => skeleton.push_str(argument),
        }
    }

    let literal = format!("{skeleton:?}");
    debug_assert!(syn::parse_str::<syn::LitStr>(&literal).is_ok());
    let arguments = generated
        .into_iter()
        .map(|(name, expression)| format!("{name}={expression}"))
        .collect::<Vec<_>>()
        .join(",");
    let insertion = if template.trailing_comma {
        format!(" {arguments}")
    } else {
        format!(",{arguments}")
    };
    vec![
        replace(template.literal_start, template.literal_end, literal),
        replace(template.insert_at, template.insert_at, insertion),
    ]
}

fn unique_format_argument_name(
    stream_seed: u64,
    fragment: usize,
    used: &mut BTreeSet<String>,
) -> String {
    let base = format!("__sv_fmt_{stream_seed:016x}_{fragment:x}");
    if used.insert(base.clone()) {
        return base;
    }
    for nonce in 1u64.. {
        let candidate = format!("{base}_{nonce:x}");
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("the generated format argument namespace is finite")
}

fn occurrence_order(left: &Occurrence, right: &Occurrence) -> std::cmp::Ordering {
    left.file
        .cmp(&right.file)
        .then_with(|| left.start.cmp(&right.start))
        .then_with(|| left.end.cmp(&right.end))
        .then_with(|| match (&left.kind, &right.kind) {
            (OccurrenceKind::Ordinary, OccurrenceKind::Ordinary) => std::cmp::Ordering::Equal,
            (OccurrenceKind::Ordinary, OccurrenceKind::Format { .. }) => std::cmp::Ordering::Less,
            (OccurrenceKind::Format { .. }, OccurrenceKind::Ordinary) => {
                std::cmp::Ordering::Greater
            }
            (
                OccurrenceKind::Format {
                    template: left_template,
                    fragment: left_fragment,
                },
                OccurrenceKind::Format {
                    template: right_template,
                    fragment: right_fragment,
                },
            ) => left_template
                .cmp(right_template)
                .then_with(|| left_fragment.cmp(right_fragment)),
        })
}

fn has_rust_literal_collision(
    value: &str,
    occurrences: &[Occurrence],
    literals: &[RustLiteralRecord],
    templates: &BTreeMap<LiteralId, FormatTemplate>,
) -> bool {
    let ordinary_sites = occurrences
        .iter()
        .filter(|occurrence| occurrence.safe && matches!(occurrence.kind, OccurrenceKind::Ordinary))
        .map(|occurrence| LiteralId {
            file: occurrence.file.clone(),
            start: occurrence.start,
            end: occurrence.end,
        })
        .collect::<BTreeSet<_>>();
    let format_sites = occurrences
        .iter()
        .filter(|occurrence| occurrence.safe)
        .filter_map(|occurrence| match &occurrence.kind {
            OccurrenceKind::Format { template, fragment } => Some((template.clone(), *fragment)),
            OccurrenceKind::Ordinary => None,
        })
        .collect::<BTreeSet<_>>();

    literals.iter().any(|literal| {
        if let Some(template) = templates.get(&literal.id) {
            return template.parts.iter().any(|part| match part {
                FormatPart::Literal {
                    fragment,
                    value: literal_piece,
                } => {
                    literal_piece.contains(value)
                        && !(literal_piece == value
                            && format_sites.contains(&(literal.id.clone(), *fragment)))
                }
                FormatPart::Argument(argument) => argument.contains(value),
            });
        }

        literal.value.contains(value)
            && !(literal.value == value && ordinary_sites.contains(&literal.id))
    })
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
/// `all` selects every non-empty runtime value. The default balanced profile
/// only enables `internal`, which deliberately recognises machine-like
/// semantic strings rather than every piece of copy.
fn classify(value: &str, plan: &StringsPlan) -> Option<&'static str> {
    if value.is_empty() {
        return None;
    }
    if plan.all {
        return Some("all");
    }
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
#[cfg(test)]
fn forbidden_context(token: &ra_ap_syntax::SyntaxToken) -> bool {
    forbidden_ancestors(token.parent(), None)
}

/// Ordinary literals inside a small set of proven expression-oriented macros
/// retain normal Rust expression grammar. This covers formatting arguments,
/// assertions, `anyhow` errors, `vec!` elements and `dbg!` arguments without
/// guessing at arbitrary macro DSLs such as `serde_json::json!` object keys or
/// `matches!` patterns.
fn forbidden_runtime_context(
    token: &ra_ap_syntax::SyntaxToken,
    shadowed: &HashSet<String>,
) -> bool {
    forbidden_ancestors(
        token.parent(),
        Some((shadowed, MacroTransparency::OrdinaryExpression)),
    )
}

/// A supported format literal necessarily lives in its own `TOKEN_TREE`.
/// Start above the macro call so that owning tree is allowed, while an outer
/// opaque macro, attribute, const item, or const function still rejects the
/// runtime decoder. A small set of proven expression-container macros may
/// surround it; their input grammar accepts the rewritten inner macro call.
fn forbidden_format_context(call: &ast::MacroCall, shadowed: &HashSet<String>) -> bool {
    forbidden_ancestors(
        call.syntax().parent(),
        Some((shadowed, MacroTransparency::NestedFormat)),
    )
}

#[derive(Debug, Clone, Copy)]
enum MacroTransparency {
    NestedFormat,
    OrdinaryExpression,
}

fn forbidden_ancestors(
    mut current: Option<ra_ap_syntax::SyntaxNode>,
    transparent_macros: Option<(&HashSet<String>, MacroTransparency)>,
) -> bool {
    while let Some(node) = current {
        let kind = format!("{:?}", node.kind());

        if kind == "TOKEN_TREE" {
            if let Some((shadowed, mode)) = transparent_macros {
                let outer = node.parent().and_then(ast::MacroCall::cast);
                if let Some(outer) = outer.filter(|outer| match mode {
                    MacroTransparency::NestedFormat => transparent_runtime_macro(outer, shadowed),
                    MacroTransparency::OrdinaryExpression => {
                        transparent_expression_macro(outer, shadowed)
                    }
                }) {
                    current = outer.syntax().parent();
                    continue;
                }
            }
            return true;
        }

        if matches!(
            kind.as_str(),
            "ATTR"
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

fn transparent_runtime_macro(call: &ast::MacroCall, shadowed: &HashSet<String>) -> bool {
    let Some(path) = call.path() else {
        return false;
    };
    transparent_runtime_macro_path(&path.syntax().text().to_string(), shadowed)
}

fn transparent_expression_macro(call: &ast::MacroCall, shadowed: &HashSet<String>) -> bool {
    let Some(path) = call.path() else {
        return false;
    };
    transparent_expression_macro_path(&path.syntax().text().to_string(), shadowed)
}

fn transparent_expression_macro_path(path: &str, shadowed: &HashSet<String>) -> bool {
    if format_macro_argument_path(path, shadowed).is_some() {
        return true;
    }
    let compact = path.replace(' ', "");
    let parts = compact
        .split("::")
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let Some(name) = parts.last().copied() else {
        return false;
    };
    matches!(name, "vec" | "dbg")
        && ((parts.len() == 1 && !shadowed.contains(name))
            || (parts.len() == 2 && matches!(parts[0], "std" | "core" | "alloc")))
}

fn transparent_runtime_macro_path(path: &str, shadowed: &HashSet<String>) -> bool {
    if format_macro_argument_path(path, shadowed).is_some() {
        return true;
    }
    let compact = path.replace(' ', "");
    let parts = compact
        .split("::")
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let Some(name) = parts.last().copied() else {
        return false;
    };
    if matches!(name, "vec" | "dbg" | "matches") {
        return (parts.len() == 1 && !shadowed.contains(name))
            || (parts.len() == 2 && matches!(parts[0], "std" | "core" | "alloc"));
    }
    parts == ["serde_json", "json"]
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

    fn forbidden_runtime_for(source: &str, value: &str) -> bool {
        let file =
            ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2021).tree();
        file.syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .filter_map(ast::String::cast)
            .find_map(|token| {
                let literal = syn::parse_str::<syn::LitStr>(token.text()).ok()?;
                (literal.value() == value)
                    .then(|| forbidden_runtime_context(token.syntax(), &HashSet::new()))
            })
            .unwrap_or_else(|| panic!("string literal {value:?} not found in {source:?}"))
    }

    #[test]
    fn proven_macro_expression_arguments_are_runtime_contexts() {
        for (source, value) in [
            (
                r#"fn f() { println!("{}", "print-value"); }"#,
                "print-value",
            ),
            (
                r#"fn f() { let _ = vec!["vector-value"]; }"#,
                "vector-value",
            ),
            (
                r#"fn f() { assert_eq!("left-value", "right-value"); }"#,
                "right-value",
            ),
            (
                r#"fn f() { let _ = anyhow!("error text: {}", "detail-value"); }"#,
                "detail-value",
            ),
        ] {
            assert!(
                !forbidden_runtime_for(source, value),
                "proven expression argument was kept: {source}"
            );
        }

        for (source, value) in [
            (
                r#"fn f(v: &str) { let _ = matches!(v, "pattern-value"); }"#,
                "pattern-value",
            ),
            (
                r#"fn f() { let _ = serde_json::json!({ "wire-key": 1 }); }"#,
                "wire-key",
            ),
        ] {
            assert!(
                forbidden_runtime_for(source, value),
                "macro DSL literal was incorrectly treated as an expression: {source}"
            );
        }
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
    fn all_classification_includes_plain_short_raw_and_nul_strings() {
        let mut plan = balanced_strings();
        plan.all = true;
        for value in [
            "document",
            "navigate",
            "Accept",
            "text/html,application/xhtml+xml",
            r#"webid=(\d+)"#,
            "0",
            "\0",
            &"x".repeat(2048),
        ] {
            assert_eq!(classify(value, &plan), Some("all"), "missed {value:?}");
        }
        assert_eq!(classify("", &plan), None);
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

    fn one_format_template(source: &str) -> Option<FormatTemplate> {
        let parsed =
            ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2021).tree();
        let call = parsed
            .syntax()
            .descendants()
            .find_map(ast::MacroCall::cast)?;
        format_template(
            &call,
            Path::new("/input/src/main.rs"),
            source,
            &HashSet::new(),
        )
    }

    #[test]
    fn format_parser_preserves_placeholders_and_decodes_literal_braces() {
        let parts = split_format_literal(
            "Cookie 无效: {0:>8}; {name}; {value:width$.precision$}; {{label}}",
        )
        .unwrap();
        let rendered = parts
            .iter()
            .map(|part| match part {
                FormatPart::Literal { value, .. } => format!("L:{value}"),
                FormatPart::Argument(value) => format!("A:{value}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            [
                "L:Cookie 无效: ",
                "A:{0:>8}",
                "L:; ",
                "A:{name}",
                "L:; ",
                "A:{value:width$.precision$}",
                "L:; {label}",
            ]
        );
    }

    #[test]
    fn format_macro_rewrite_keeps_the_compile_time_skeleton() {
        let source = r###"fn f(error: u32, name: &str, width: usize, precision: usize) {
    let _ = format!(r#"Cookie 无效: {}; indexed {0:>8}; {name}; {{label}} {error:width$.precision$}"#, error);
}"###;
        let template = one_format_template(source).unwrap();
        let selected = template
            .parts
            .iter()
            .filter_map(|part| {
                let FormatPart::Literal { fragment, value } = part else {
                    return None;
                };
                let seed = 100 + *fragment as u64;
                Some((
                    *fragment,
                    PreparedFormatFragment {
                        expression: protected_expression(&encode(value.as_bytes(), seed), seed),
                        stream_seed: seed,
                    },
                ))
            })
            .collect::<BTreeMap<_, _>>();
        let rewritten =
            crate::edits::apply_indels(source, &format_template_edits(&template, &selected))
                .unwrap();

        assert!(!rewritten.contains("Cookie 无效"));
        for placeholder in ["{}", "{0:>8}", "{name}", "{error:width$.precision$}"] {
            assert!(rewritten.contains(placeholder), "lost {placeholder:?}");
        }
        assert!(rewritten.contains("OnceLock"));
        assert!(rewritten.contains("__sv_fmt_"));
    }

    #[test]
    fn anyhow_and_assert_message_literals_are_format_templates() {
        for source in [
            r#"fn f(error: u32) { let _ = anyhow!("Request failed: {}", error); }"#,
            r#"fn f(ok: bool, error: u32) { assert!(ok, "Request failed: {}", error); }"#,
            r#"fn f(left: u32, right: u32) { assert_eq!(left, right, "Mismatch: {left}"); }"#,
        ] {
            let template = one_format_template(source)
                .unwrap_or_else(|| panic!("format template not recognised: {source}"));
            assert!(template.parts.iter().any(|part| matches!(
                part,
                FormatPart::Literal { value, .. }
                    if value == "Request failed: " || value == "Mismatch: "
            )));
        }
    }

    #[test]
    fn shadowed_format_macro_is_not_rewritten() {
        let source = r#"
macro_rules! format { ($value:expr) => { $value } }
fn f() { let _ = format!("Cookie 无效: {}"); }
"#;
        let parsed =
            ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2021).tree();
        let parsed_files = vec![(
            PathBuf::from("/input/src/main.rs"),
            parsed.clone(),
            source.into(),
        )];
        let shadowed = collect_shadowed_format_macros(&parsed_files);
        let call = parsed
            .syntax()
            .descendants()
            .filter_map(ast::MacroCall::cast)
            .find(|call| {
                call.path()
                    .is_some_and(|path| path.syntax().text() == "format")
            })
            .unwrap();
        assert!(
            format_template(&call, Path::new("/input/src/main.rs"), source, &shadowed,).is_none()
        );
    }

    #[test]
    fn format_macro_inside_vec_is_a_runtime_context() {
        let source = r#"fn f(error: u32) { let _ = vec![format!("Cookie 无效: {}", error)]; }"#;
        let parsed =
            ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2021).tree();
        let templates = discover_format_templates(
            &parsed,
            Path::new("/input/src/main.rs"),
            source,
            &HashSet::new(),
        );
        assert_eq!(templates.len(), 1);
        assert!(
            templates[0].1,
            "nested format macro was treated as const/opaque"
        );
        assert!(templates[0].0.parts.iter().any(|part| matches!(
            part,
            FormatPart::Literal { value, .. } if value == "Cookie 无效: "
        )));
    }

    #[test]
    fn format_looking_tokens_inside_an_opaque_macro_are_kept() {
        let source = r#"
macro_rules! opaque { ($($token:tt)*) => { () } }
fn f(error: u32) { opaque!(format!("Cookie 无效: {}", error)); }
"#;
        let parsed =
            ra_ap_syntax::SourceFile::parse(source, ra_ap_syntax::Edition::Edition2021).tree();
        let templates = discover_format_templates(
            &parsed,
            Path::new("/input/src/main.rs"),
            source,
            &HashSet::new(),
        );
        assert!(templates.is_empty());
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
        let path = PathBuf::from("/input/src/main.rs");
        let literals = [
            "aweme_detail",
            "No aweme_detail in response",
            "bytes=0-1048575",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, value)| RustLiteralRecord {
            id: LiteralId {
                file: path.clone(),
                start: index as u32,
                end: index as u32 + 1,
            },
            value: value.to_string(),
        })
        .collect::<Vec<_>>();
        let exact = Occurrence {
            file: path,
            source: String::new(),
            start: 0,
            end: 1,
            safe: true,
            kind: OccurrenceKind::Ordinary,
        };

        assert!(has_rust_literal_collision(
            "aweme_detail",
            &[exact],
            &literals,
            &BTreeMap::new(),
        ));
        assert!(has_rust_literal_collision(
            "bytes=0-",
            &[],
            &literals,
            &BTreeMap::new(),
        ));
        assert!(!has_rust_literal_collision(
            "unrelated",
            &[],
            &literals,
            &BTreeMap::new(),
        ));
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
