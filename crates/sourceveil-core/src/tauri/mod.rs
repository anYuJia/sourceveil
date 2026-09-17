//! The Tauri command pass.
//!
//! A command's name lives in four places at once:
//!
//! ```text
//! Rust definition          #[tauri::command] async fn get_user_info()
//! registration             tauri::generate_handler![commands::get_user_info]
//! frontend call            invoke("get_user_info")
//! Rust dispatch            match invoke.message.command() { "get_user_info" => .. }
//! ```
//!
//! They are one protocol, so they are changed as one transaction. Committing
//! three of the four leaves a project that either does not compile or — worse —
//! compiles, starts, and silently refuses every call to that command.
//!
//! ## Everything here fails closed
//!
//! Each command is decided independently, and any doubt keeps it:
//!
//! - **One dynamic frontend call keeps the whole namespace.** `invoke(name)`
//!   computes a name at runtime, so it might be *any* command. There is no way
//!   to rename "the statically referenced ones" and leave the rest.
//! - A command not found in a handler list is kept: it might be registered in a
//!   way this pass cannot see.
//! - A handler list this pass cannot read completely keeps every command in it.
//! - A command name appearing as a Rust or frontend string in a context this
//!   pass does not recognise is kept, because the same string might be a log
//!   message rather than a command.
//!
//! Every one of those is reported with a file, a line and a reason.

pub mod handler;
pub mod literals;

use crate::frontend::{self, IpcAnalysis, Span};
use crate::names::{NameCase, NameGenerator};
use crate::plan::Plan;
use crate::rust::analysis::RustAnalysis;
use crate::rust::candidates::attribute_names;
use crate::rust::rename::{self, resolve_change_edits};
use crate::scanner::CrateGraph;
use anyhow::Result;
use ra_ap_ide::FileId;
use ra_ap_syntax::ast::{self, AstNode, HasName};
use ra_ap_syntax::{SyntaxKind, TextRange};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// What the pass needs to know about the project.
pub struct CommandRequest<'a> {
    pub input_root: &'a Path,
    /// Workspace-relative paths of files present in the output tree.
    pub copied: &'a BTreeSet<PathBuf>,
    pub plan: &'a Plan,
    pub graph: &'a CrateGraph,
    /// Where the frontend lives, if the project has one.
    pub frontend_root: Option<&'a Path>,
    /// Extra callee names understood to be `invoke`.
    pub invoke_names: &'a [String],
}

#[derive(Debug, Default)]
pub struct CommandOutcome {
    pub discovered: usize,
    pub renamed: usize,
    pub kept: Vec<KeptCommand>,
    /// Original command name -> replacement, for `mapping.json`.
    pub mapping: BTreeMap<String, String>,
    /// Definition sites this pass owns, so the symbol rename pass skips them.
    pub claimed: HashSet<(PathBuf, TextRange)>,
    pub refs: CommandRefCounts,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CommandRefCounts {
    pub frontend_static: usize,
    pub frontend_dynamic: usize,
    pub handler: usize,
    pub rust_literals: usize,
}

#[derive(Debug, Clone)]
pub struct KeptCommand {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub reason: CommandKeepReason,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKeepReason {
    /// No frontend was found, so nothing can be shown to be in sync.
    NoFrontend,
    /// A frontend `invoke(expr)` that is not a compile-time constant.
    DynamicFrontendReference,
    /// The name appears as a frontend string outside an invoke call.
    AmbiguousFrontendLiteral,
    /// The name appears as a Rust string this pass cannot classify.
    AmbiguousRustLiteral,
    /// Not listed in any handler list this pass could read.
    MissingHandlerEntry,
    /// A handler list that could not be parsed completely.
    UnparseableHandlerList,
    /// A `#[command]` attribute that could not be shown to come from Tauri.
    UnresolvedAttribute,
    /// Another pass already scheduled an overlapping edit.
    EditConflict,
    /// rust-analyzer would not produce an edit set for the definition.
    Unresolvable,
}

impl CommandKeepReason {
    pub fn as_str(self) -> &'static str {
        match self {
            CommandKeepReason::NoFrontend => "no-frontend",
            CommandKeepReason::DynamicFrontendReference => "dynamic-frontend-command-reference",
            CommandKeepReason::AmbiguousFrontendLiteral => "unresolved-frontend-reference",
            CommandKeepReason::AmbiguousRustLiteral => "ambiguous-rust-literal",
            CommandKeepReason::MissingHandlerEntry => "unresolved-command-handler",
            CommandKeepReason::UnparseableHandlerList => "unparseable-handler-list",
            CommandKeepReason::UnresolvedAttribute => "unresolved-command-attribute",
            CommandKeepReason::EditConflict => "edit-conflict",
            CommandKeepReason::Unresolvable => "unresolvable",
        }
    }
}

impl std::fmt::Display for CommandKeepReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl CommandOutcome {
    fn keep(
        &mut self,
        command: &DiscoveredCommand,
        reason: CommandKeepReason,
        detail: Option<String>,
    ) {
        self.kept.push(KeptCommand {
            name: command.name.clone(),
            file: command.file.display().to_string(),
            line: command.line,
            reason,
            detail,
        });
    }
}

/// A `#[tauri::command]` function.
#[derive(Debug, Clone)]
struct DiscoveredCommand {
    name: String,
    file: PathBuf,
    file_id: FileId,
    name_range: TextRange,
    line: u32,
}

/// A read-only view of one workspace Rust file.
struct RustFile {
    path: PathBuf,
    file_id: FileId,
    text: String,
}

/// A `generate_handler!` entry, with the file it lives in.
struct HandlerRef {
    command: String,
    file: PathBuf,
    span: TextRange,
}

pub fn run(
    analysis: &RustAnalysis,
    req: &CommandRequest<'_>,
    names: &mut NameGenerator,
    plan: &mut crate::edits::EditPlan,
) -> Result<CommandOutcome> {
    let mut out = CommandOutcome::default();

    let files = workspace_files(analysis, req.graph);
    let mut commands = Vec::new();
    for file in &files {
        let (found, unresolved) = discover(analysis, file, req.input_root);
        commands.extend(found);
        for (name, line) in unresolved {
            // A `#[command]` we could not show comes from Tauri. Reported
            // against the attribute rather than against a command, because
            // there is no command here we are entitled to name.
            out.warnings.push(format!(
                "{}:{}: `#[{name}]` could not be resolved to a Tauri command macro; \
                 the item is left alone",
                file.path.display(),
                line
            ));
        }
    }

    out.discovered = commands.len();
    if commands.is_empty() {
        return Ok(out);
    }
    tracing::info!(commands = commands.len(), "discovered tauri commands");

    // ---- the frontend side ------------------------------------------------
    let Some(frontend_root) = req.frontend_root else {
        for command in &commands {
            out.keep(
                command,
                CommandKeepReason::NoFrontend,
                Some("no frontend root was detected, so nothing can be shown to be in sync".into()),
            );
        }
        return Ok(out);
    };

    let ipc = frontend::analyze(frontend_root, req.invoke_names)?;
    out.refs.frontend_static = ipc.static_refs.len();
    out.refs.frontend_dynamic = ipc.dynamic_refs.len();
    out.warnings.extend(ipc.warnings.iter().cloned());

    if !ipc.dynamic_refs.is_empty() {
        // Every command, not just the ones that look involved: the dynamic
        // expression could evaluate to any of them.
        for command in &commands {
            out.keep(
                command,
                CommandKeepReason::DynamicFrontendReference,
                Some(describe_dynamic_refs(&ipc)),
            );
        }
        out.warnings.push(format!(
            "Tauri command obfuscation disabled: the frontend has {} dynamic invoke \
             argument(s), and a runtime-computed name could refer to any command. Make \
             them static to enable command renaming.\n{}",
            ipc.dynamic_refs.len(),
            describe_dynamic_refs(&ipc)
        ));
        return Ok(out);
    }

    // ---- the Rust side ----------------------------------------------------
    let (handlers, unparseable) = collect_handlers(&files);
    out.refs.handler = handlers.len();

    if !unparseable.is_empty() {
        let detail = unparseable.join("\n");
        out.warnings.push(format!(
            "a generate_handler! list could not be read completely, so no command could be \
             shown to be registered:\n{detail}"
        ));
        for command in &commands {
            out.keep(
                command,
                CommandKeepReason::UnparseableHandlerList,
                Some(detail.clone()),
            );
        }
        return Ok(out);
    }

    let command_names: BTreeSet<String> = commands.iter().map(|c| c.name.clone()).collect();
    let mut rust_literals = literals::LiteralScan::default();
    for file in &files {
        let Some((parsed, _)) = analysis.parse(file.file_id) else {
            continue;
        };
        rust_literals.extend(literals::scan_file(
            &file.path,
            parsed.syntax(),
            &command_names,
        ));
    }
    out.refs.rust_literals = rust_literals.recognized.len();

    let mut texts: BTreeMap<PathBuf, String> = files
        .iter()
        .map(|f| (f.path.clone(), f.text.clone()))
        .collect();
    texts.extend(ipc.file_texts.iter().map(|(k, v)| (k.clone(), v.clone())));

    // Files must be indexed by path, not by position in a vector, because an
    // edit set spans several of them.
    let mut handler_by_path: BTreeMap<PathBuf, Vec<&HandlerRef>> = BTreeMap::new();
    for handler in &handlers {
        handler_by_path
            .entry(handler.file.clone())
            .or_default()
            .push(handler);
    }

    for command in &commands {
        if let Err((reason, detail)) = decide(
            command,
            &ipc,
            &handlers,
            &rust_literals,
            req.input_root,
            req.copied,
        ) {
            out.keep(command, reason, detail);
            continue;
        }

        match rename_command(
            analysis,
            req,
            command,
            &ipc,
            &handler_by_path,
            &rust_literals,
            &texts,
            names,
            plan,
        ) {
            Ok(new_name) => {
                out.renamed += 1;
                out.mapping.insert(command.name.clone(), new_name);
                out.claimed
                    .insert((command.file.clone(), command.name_range));
            }
            Err((reason, detail)) => out.keep(command, reason, detail),
        }
    }

    tracing::info!(
        renamed = out.renamed,
        kept = out.kept.len(),
        "tauri command pass complete"
    );
    Ok(out)
}

/// The gates, checked before any edit is computed.
fn decide(
    command: &DiscoveredCommand,
    ipc: &IpcAnalysis,
    handlers: &[HandlerRef],
    rust_literals: &literals::LiteralScan,
    input_root: &Path,
    copied: &BTreeSet<PathBuf>,
) -> std::result::Result<(), (CommandKeepReason, Option<String>)> {
    // The frontend must reach this command only through literals we can edit.
    let editable: HashSet<Span> = ipc
        .static_refs
        .iter()
        .filter(|r| r.command == command.name)
        .map(|r| r.span)
        .collect();
    let strays: Vec<String> = ipc
        .literals
        .iter()
        .filter(|l| l.value == command.name && !editable.contains(&l.span))
        .map(|l| format!("{}:{}", l.file.display(), line_in_texts(l, &ipc.file_texts)))
        .collect();
    if !strays.is_empty() {
        return Err((
            CommandKeepReason::AmbiguousFrontendLiteral,
            Some(format!(
                "the name also appears in the frontend outside an invoke call, where its \
                 purpose cannot be determined: {}",
                strays.join(", ")
            )),
        ));
    }

    // Registration: without an entry we can rewrite, we cannot show how the
    // command is reached.
    if !handlers.iter().any(|h| h.command == command.name) {
        return Err((
            CommandKeepReason::MissingHandlerEntry,
            Some(
                "no generate_handler! entry names this command, so how it is registered \
                 could not be established"
                    .into(),
            ),
        ));
    }

    // A Rust string spelling the command name, in a context this pass does not
    // recognise, might be a dispatch table — or might be a log line.
    let unrecognised: Vec<String> = rust_literals
        .unclassified_for(&command.name)
        .map(|r| format!("offset {}", u32::from(r.span.start())))
        .collect();
    if !unrecognised.is_empty() {
        return Err((
            CommandKeepReason::AmbiguousRustLiteral,
            Some(format!(
                "a Rust string literal spells this name outside a recognised dispatch or \
                 command-set context, so its purpose cannot be determined ({})",
                unrecognised.join(", ")
            )),
        ));
    }

    // Every file the rename would touch has to be one we copied and can write.
    let rel = command
        .file
        .strip_prefix(input_root)
        .map(|p| p.to_path_buf())
        .unwrap_or_default();
    if !copied.contains(&rel) {
        return Err((
            CommandKeepReason::Unresolvable,
            Some(format!(
                "{} is not part of the generated tree",
                rel.display()
            )),
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rename_command(
    analysis: &RustAnalysis,
    req: &CommandRequest<'_>,
    command: &DiscoveredCommand,
    ipc: &IpcAnalysis,
    handler_by_path: &BTreeMap<PathBuf, Vec<&HandlerRef>>,
    rust_literals: &literals::LiteralScan,
    texts: &BTreeMap<PathBuf, String>,
    names: &mut NameGenerator,
    plan: &mut crate::edits::EditPlan,
) -> std::result::Result<String, (CommandKeepReason, Option<String>)> {
    let new_name = names
        .generate(NameCase::Snake)
        .map_err(|e| (CommandKeepReason::Unresolvable, Some(e.to_string())))?;

    let change = rename::propose_rename(analysis, command.file_id, command.name_range, &new_name)
        .map_err(|skip| (CommandKeepReason::Unresolvable, skip.1))?;
    let by_file = resolve_change_edits(analysis, req.input_root, req.copied, &change)
        .map_err(|skip| (CommandKeepReason::Unresolvable, skip.1))?;

    let mut pending: Vec<(PathBuf, Vec<ra_ap_ide::Indel>)> = by_file.into_iter().collect();

    // The registration list, which rust-analyzer's reference search does not
    // reach inside a macro token tree.
    for (path, entries) in handler_by_path {
        let indels: Vec<_> = entries
            .iter()
            .filter(|h| h.command == command.name)
            .map(|h| {
                crate::edits::replace(
                    u32::from(h.span.start()),
                    u32::from(h.span.end()),
                    new_name.clone(),
                )
            })
            .collect();
        if !indels.is_empty() {
            pending.push((path.clone(), indels));
        }
    }

    // The frontend call site.
    let frontend: Vec<_> = ipc
        .static_refs
        .iter()
        .filter(|r| r.command == command.name)
        .collect();
    for reference in &frontend {
        // Keep the original quote style; the span covers the quotes.
        let replacement = format!("{q}{new_name}{q}", q = reference.quote);
        pending.push((
            reference.file.clone(),
            vec![crate::edits::replace(
                reference.span.start,
                reference.span.end,
                replacement,
            )],
        ));
    }

    // Rust-side dispatch arms and allow-lists.
    let literal_refs: Vec<_> = rust_literals.recognized_for(&command.name).collect();
    let mut by_source: BTreeMap<PathBuf, Vec<_>> = BTreeMap::new();
    for reference in literal_refs {
        by_source
            .entry(reference.file.clone())
            .or_default()
            .push(reference);
    }
    for (path, references) in by_source {
        let indels = references
            .into_iter()
            .map(|r| {
                crate::edits::replace(
                    u32::from(r.span.start()),
                    u32::from(r.span.end()),
                    format!("\"{new_name}\""),
                )
            })
            .collect();
        pending.push((path, indels));
    }

    // Every file in the transaction must have a snapshot. A file we never read
    // cannot be edited against.
    let mut contributions = Vec::with_capacity(pending.len());
    for (path, indels) in &pending {
        let Some(text) = texts.get(path).map(String::as_str) else {
            return Err((
                CommandKeepReason::Unresolvable,
                Some(format!("no analysed text for {}", path.display())),
            ));
        };
        contributions.push(crate::edits::Contribution::new(path, text, indels.clone()));
    }

    match plan.stage_transaction(contributions) {
        Ok(_) => Ok(new_name),
        Err(e) => Err((CommandKeepReason::EditConflict, Some(e.to_string()))),
    }
}

/// Multiline description of every dynamic invoke argument, for the report.
fn describe_dynamic_refs(ipc: &IpcAnalysis) -> String {
    ipc.dynamic_refs
        .iter()
        .map(|r| format!("  {}:{}  {}", r.file.display(), r.line, r.expression))
        .collect::<Vec<_>>()
        .join("\n")
}

fn workspace_files(analysis: &RustAnalysis, graph: &CrateGraph) -> Vec<RustFile> {
    let mut out = Vec::new();
    for (file_id, path) in analysis.rust_files() {
        if rename::crate_for_file(graph, &path).is_none() {
            continue;
        }
        let Some((_, text)) = analysis.parse(file_id) else {
            continue;
        };
        out.push(RustFile {
            path,
            file_id,
            text,
        });
    }
    out
}

/// Every `#[tauri::command]` in one file, plus the short-form attributes that
/// could not be resolved.
fn discover(
    analysis: &RustAnalysis,
    file: &RustFile,
    input_root: &Path,
) -> (Vec<DiscoveredCommand>, Vec<(String, u32)>) {
    let mut found = Vec::new();
    let mut unresolved = Vec::new();

    let Some((parsed, _)) = analysis.parse(file.file_id) else {
        return (found, unresolved);
    };

    for node in parsed.syntax().descendants() {
        if node.kind() != SyntaxKind::FN {
            continue;
        }
        let Some(function) = ast::Fn::cast(node.clone()) else {
            continue;
        };
        let Some(name_node) = function.name() else {
            continue;
        };

        let attributes = attribute_names(&node);
        let full_path = attributes.iter().any(|a| a == "tauri::command");
        let short_form = attributes.iter().any(|a| a == "command");

        if !full_path && !short_form {
            continue;
        }

        // `#[command]` alone is ambiguous: clap has one too. It is only
        // accepted when the attribute resolves into the Tauri macro crate.
        if !full_path && !resolves_to_tauri(analysis, &node, file.file_id, input_root) {
            unresolved.push((
                "command".to_string(),
                line_of(&file.text, node.text_range()),
            ));
            continue;
        }

        let name = name_node.syntax().text().to_string();
        found.push(DiscoveredCommand {
            name,
            file: file.path.clone(),
            file_id: file.file_id,
            name_range: name_node.syntax().text_range(),
            line: line_of(&file.text, node.text_range()),
        });
    }

    (found, unresolved)
}

/// Does the short-form attribute on this item resolve into `tauri`?
///
/// Answered by name resolution rather than by guessing from the import list.
/// Anything that cannot be resolved answers `false`, which keeps the command.
fn resolves_to_tauri(
    analysis: &RustAnalysis,
    item: &ra_ap_syntax::SyntaxNode,
    file_id: FileId,
    input_root: &Path,
) -> bool {
    use ra_ap_ide::{FilePosition, GotoDefinitionConfig};

    let Some(attribute) = item.children().filter_map(ast::Attr::cast).find(|attr| {
        let names = attribute_names_from_attr(attr);
        names.iter().any(|a| a == "command")
    }) else {
        return false;
    };

    // The attribute's child is a `PATH_META` holding the `PATH`, not a `PATH`
    // directly, so this searches descendants rather than children.
    let Some(path) = attribute
        .syntax()
        .descendants()
        .find(|c| c.kind() == SyntaxKind::PATH)
    else {
        return false;
    };

    let config = GotoDefinitionConfig {
        ra_fixture: ra_ap_ide::RaFixtureConfig::default(),
    };
    let position = FilePosition {
        file_id,
        offset: path.text_range().start(),
    };

    let resolved = analysis.analysis().goto_definition(position, &config);
    match &resolved {
        Ok(Some(info)) => tracing::debug!(
            targets = info.info.len(),
            offset = u32::from(position.offset),
            "short-form attribute resolved"
        ),
        Ok(None) => tracing::debug!(
            offset = u32::from(position.offset),
            "short-form attribute: no definition found"
        ),
        Err(e) => tracing::debug!(?e, "short-form attribute: request cancelled"),
    }
    let Ok(Some(info)) = resolved else {
        return false;
    };

    info.info.iter().any(|target| {
        let Some(path) = analysis.file_path(target.file_id) else {
            return false;
        };
        tracing::debug!(attribute = "command", resolved = %path.display(), "resolved short-form attribute");
        defines_tauri_macro(&path, input_root)
    })
}

/// Attribute paths of a single attribute node.
///
/// [`candidates::attribute_names`] works on the item that carries the
/// attributes; this is the same normalisation for the attribute alone.
fn attribute_names_from_attr(attr: &ast::Attr) -> Vec<String> {
    let text = attr.syntax().text().to_string();
    let inner = text
        .trim_start_matches("#!")
        .trim_start_matches('#')
        .trim_start()
        .trim_start_matches('[')
        .trim_end()
        .trim_end_matches(']')
        .trim();
    let name = inner
        .split(['(', '=', ' ', '\n', '\t'])
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let mut out = vec![name.clone()];
    if let Some(last) = name.rsplit("::").next() {
        if last != name {
            out.push(last.to_string());
        }
    }
    out
}

/// Does this path name the Tauri crate or its macro crate?
///
/// Two things are being asked at once, and both matter. The definition has to
/// live outside the project being transformed — otherwise a project with its
/// own `tauri`-named crate would resolve to itself — and it has to be a Tauri
/// package. `tauri-macros` is where `#[command]` is actually defined; the
/// `tauri` crate re-exports it, and name resolution may stop at either.
fn defines_tauri_macro(path: &Path, input_root: &Path) -> bool {
    if path.starts_with(input_root) {
        return false;
    }
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        name == "tauri"
            || name.starts_with("tauri-macros-")
            || name
                .split_once('-')
                .is_some_and(|(head, tail)| head == "tauri" && tail.starts_with(char::is_numeric))
    })
}

/// Every `generate_handler!` entry in the workspace, and the lists that could
/// not be read.
fn collect_handlers(files: &[RustFile]) -> (Vec<HandlerRef>, Vec<String>) {
    let mut entries = Vec::new();
    let mut unparseable = Vec::new();

    for file in files {
        let parsed =
            ra_ap_syntax::SourceFile::parse(&file.text, ra_ap_syntax::Edition::Edition2021);
        let tree = parsed.tree();

        for call in tree.syntax().descendants() {
            if call.kind() != SyntaxKind::MACRO_CALL {
                continue;
            }
            let Some(path) = call.children().find(|c| c.kind() == SyntaxKind::PATH) else {
                continue;
            };
            let path_text = path.text().to_string();
            if !is_generate_handler(&path_text) {
                continue;
            }
            let Some(tree) = call.children().find(|c| c.kind() == SyntaxKind::TOKEN_TREE) else {
                unparseable.push(format!(
                    "{}:{}: generate_handler! without an argument list",
                    file.path.display(),
                    line_of(&file.text, call.text_range())
                ));
                continue;
            };

            match handler::parse_entries(&tree) {
                Ok(parsed_entries) => {
                    for entry in parsed_entries {
                        entries.push(HandlerRef {
                            command: entry.command,
                            file: file.path.clone(),
                            span: entry.name_range,
                        });
                    }
                }
                Err(error) => unparseable.push(format!(
                    "{}:{}: {error}",
                    file.path.display(),
                    line_of(&file.text, call.text_range())
                )),
            }
        }
    }

    (entries, unparseable)
}

/// `tauri::generate_handler` is the spelling that matters. The bare form is
/// accepted too, since a `use tauri::generate_handler;` is common — and if the
/// project has some other macro of that name, the entries simply will not match
/// any discovered command, which keeps them.
fn is_generate_handler(path: &str) -> bool {
    let path = path.trim();
    path == "tauri::generate_handler" || path == "generate_handler"
}

fn line_of(text: &str, range: TextRange) -> u32 {
    let offset = (u32::from(range.start()) as usize).min(text.len());
    1 + text[..offset].matches('\n').count() as u32
}

/// The 1-based line a frontend literal sits on.
fn line_in_texts(reference: &frontend::StringLiteral, texts: &BTreeMap<PathBuf, String>) -> u32 {
    texts
        .get(&reference.file)
        .map(|text| {
            let offset = (reference.span.start as usize).min(text.len());
            1 + text[..offset].matches('\n').count() as u32
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_handler_paths_are_recognised() {
        assert!(is_generate_handler("tauri::generate_handler"));
        assert!(is_generate_handler("generate_handler"));
        assert!(!is_generate_handler("tauri::generate_handler_extra"));
        assert!(!is_generate_handler("serde_json::json"));
    }

    #[test]
    fn the_tauri_macro_crate_is_recognised_by_path() {
        let root = Path::new("/work/app");
        assert!(defines_tauri_macro(
            Path::new("/home/u/.cargo/registry/src/index/tauri-macros-2.11.5/src/command.rs"),
            root
        ));
        assert!(defines_tauri_macro(
            Path::new("/home/u/.cargo/registry/src/index/tauri-2.11.5/src/lib.rs"),
            root
        ));
        assert!(!defines_tauri_macro(
            Path::new("/home/u/.cargo/registry/src/index/clap_derive-4.5.0/src/lib.rs"),
            root
        ));
        // A crate of the project's own must never resolve to Tauri, however it
        // is named.
        assert!(!defines_tauri_macro(
            Path::new("/work/app/tauri-ipc-static/src/commands.rs"),
            root
        ));
    }

    #[test]
    fn keep_reasons_have_stable_names() {
        // The report is read in CI logs; these strings are the contract.
        assert_eq!(
            CommandKeepReason::DynamicFrontendReference.as_str(),
            "dynamic-frontend-command-reference"
        );
        assert_eq!(
            CommandKeepReason::AmbiguousRustLiteral.as_str(),
            "ambiguous-rust-literal"
        );
        assert_eq!(
            CommandKeepReason::MissingHandlerEntry.as_str(),
            "unresolved-command-handler"
        );
        assert_eq!(
            CommandKeepReason::AmbiguousFrontendLiteral.as_str(),
            "unresolved-frontend-reference"
        );
        assert_eq!(CommandKeepReason::EditConflict.as_str(), "edit-conflict");
    }
}
