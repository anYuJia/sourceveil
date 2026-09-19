//! The Tauri event pass.
//!
//! Unlike a command, an event has no registry. `generate_handler!` lists every
//! command; nothing lists every event. A name can be emitted in Rust, listened
//! for in TypeScript, relayed back to another window, or produced by a plugin
//! this tool never sees:
//!
//! ```text
//! Rust      -> Frontend        app.emit("download-progress", ..)
//! Frontend  -> Rust            listen("download-progress", ..)
//! Frontend  -> Frontend        emit(..) / listen(..)
//! Rust      -> Rust            emit(..) / listen(..)
//! ```
//!
//! So a rename is only safe when the *graph* is closed: at least one producer
//! and at least one consumer, both inside the generated workspace. An event
//! with only a listener might be produced by a plugin; one with only a producer
//! might be consumed by a page this tool cannot see. Either way the name is
//! somebody else's protocol too, and it stays.
//!
//! ## Provenance, again
//!
//! `emit`, `listen` and `once` are ordinary method names. Rust has event buses
//! too. So a call is only considered once name resolution places its method in
//! the Tauri crate — the same standard the frontend analysis applies to its
//! imports.

use crate::frontend::collect_sources;
use crate::frontend::events::{self, EventAnalysis, EventNameRef, EventRole};
use crate::names::{NameCase, NameDeriver, SeedDomain};
use crate::plan::Plan;
use crate::rust::analysis::RustAnalysis;
use crate::rust::rename;
use crate::scanner::{is_root_like, CrateGraph};
use anyhow::Result;
use ra_ap_ide::{FileId, FilePosition, GotoDefinitionConfig, Indel};
use ra_ap_syntax::ast::{self, AstNode, HasArgList};
use ra_ap_syntax::{SyntaxKind, TextRange};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub struct EventRequest<'a> {
    pub input_root: &'a Path,
    pub copied: &'a BTreeSet<PathBuf>,
    pub plan: &'a Plan,
    pub graph: &'a CrateGraph,
    pub frontend_root: Option<&'a Path>,
}

#[derive(Debug, Default)]
pub struct EventOutcome {
    pub discovered: usize,
    pub renamed: usize,
    pub kept: Vec<KeptEvent>,
    pub mapping: BTreeMap<String, String>,
    pub refs: EventRefCounts,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct EventRefCounts {
    pub rust_emit: usize,
    pub rust_listen: usize,
    pub frontend_emit: usize,
    pub frontend_listen: usize,
    pub dynamic: usize,
    pub external_source: usize,
    pub external_consumer: usize,
}

#[derive(Debug, Clone)]
pub struct KeptEvent {
    pub name: String,
    pub file: String,
    pub line: u32,
    pub reason: EventKeepReason,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKeepReason {
    /// Emitted but never listened for inside the workspace: something outside
    /// it may be the consumer.
    ExternalEventConsumer,
    /// Listened for but never emitted inside the workspace: a plugin, the
    /// framework, or another page may be the producer.
    ExternalEventSource,
    /// A name computed at runtime, which could be any event.
    DynamicEventReference,
    /// A name this pass could not classify.
    UnresolvedEventReference,
    /// A framework or plugin event, which is not this project's protocol.
    FrameworkEvent,
    /// The original bytes also occur outside the exact producer/consumer
    /// edits or in a linked dependency artifact.
    PlaintextCollision,
    /// Another pass already scheduled an overlapping edit.
    EditConflict,
    /// rust-analyzer would not produce an edit set.
    Unresolvable,
}

impl EventKeepReason {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKeepReason::ExternalEventConsumer => "external-event-consumer",
            EventKeepReason::ExternalEventSource => "external-event-source",
            EventKeepReason::DynamicEventReference => "dynamic-event-reference",
            EventKeepReason::UnresolvedEventReference => "unresolved-event-reference",
            EventKeepReason::FrameworkEvent => "framework-event",
            EventKeepReason::PlaintextCollision => "plaintext-substring-collision",
            EventKeepReason::EditConflict => "edit-conflict",
            EventKeepReason::Unresolvable => "unresolvable",
        }
    }
}

impl std::fmt::Display for EventKeepReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which Rust event API a call goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustEventApi {
    Emit,
    EmitTo,
    EmitFilter,
    Listen,
    ListenAny,
    Once,
}

impl RustEventApi {
    fn by_method(name: &str) -> Option<Self> {
        Some(match name {
            "emit" => RustEventApi::Emit,
            "emit_to" => RustEventApi::EmitTo,
            "emit_filter" => RustEventApi::EmitFilter,
            "listen" => RustEventApi::Listen,
            "listen_any" => RustEventApi::ListenAny,
            "once" => RustEventApi::Once,
            _ => return None,
        })
    }

    /// Which argument holds the event name.
    ///
    /// `emit_to(target, name, payload)` is why this exists. Its first argument
    /// is a window label; renaming a label is not this phase's business, and
    /// treating argument zero as the name would corrupt the target.
    fn name_argument(self) -> usize {
        match self {
            RustEventApi::EmitTo => 1,
            _ => 0,
        }
    }

    fn role(self) -> EventRole {
        match self {
            RustEventApi::Emit | RustEventApi::EmitTo | RustEventApi::EmitFilter => {
                EventRole::Producer
            }
            RustEventApi::Listen | RustEventApi::ListenAny | RustEventApi::Once => {
                EventRole::Consumer
            }
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            RustEventApi::Emit => "emit",
            RustEventApi::EmitTo => "emit_to",
            RustEventApi::EmitFilter => "emit_filter",
            RustEventApi::Listen => "listen",
            RustEventApi::ListenAny => "listen_any",
            RustEventApi::Once => "once",
        }
    }
}

/// One Rust event API call.
#[derive(Debug, Clone)]
struct RustEventRef {
    file: PathBuf,
    line: u32,
    api: RustEventApi,
    role: EventRole,
    /// The literal to rewrite, quotes included, when the name is static.
    static_name: Option<(String, TextRange)>,
    /// The argument as written, when it is not.
    expression: Option<String>,
}

impl RustEventRef {
    fn name(&self) -> Option<&str> {
        self.static_name.as_ref().map(|(name, _)| name.as_str())
    }
}

pub fn run(
    analysis: &RustAnalysis,
    req: &EventRequest<'_>,
    names: &mut NameDeriver,
    plan: &mut crate::edits::EditPlan,
) -> Result<EventOutcome> {
    let mut out = EventOutcome::default();

    // ---- the Rust side ----------------------------------------------------
    let files = workspace_files(analysis, req.graph, req.plan);
    let mut rust_refs: Vec<RustEventRef> = Vec::new();
    for file in &files {
        rust_refs.extend(collect_rust_refs(analysis, file, req.input_root));
    }

    // ---- the frontend side ------------------------------------------------
    let (sources, read_warnings) = match req.frontend_root {
        Some(root) => collect_sources(root),
        None => (Vec::new(), Vec::new()),
    };
    out.warnings.extend(read_warnings);
    let ipc = events::analyze(&sources, req.frontend_root.unwrap_or(req.input_root))?;
    out.warnings.extend(ipc.warnings.iter().cloned());
    let mut texts: BTreeMap<PathBuf, String> = files
        .iter()
        .map(|f| (f.path.clone(), f.text.clone()))
        .collect();
    texts.extend(sources.iter().map(|s| (s.path.clone(), s.text.clone())));

    for call in &ipc.calls {
        match call.role {
            EventRole::Producer => out.refs.frontend_emit += 1,
            EventRole::Consumer => out.refs.frontend_listen += 1,
        }
    }
    for reference in &rust_refs {
        match reference.role {
            EventRole::Producer => out.refs.rust_emit += 1,
            EventRole::Consumer => out.refs.rust_listen += 1,
        }
    }

    // ---- the gate ---------------------------------------------------------
    let rust_dynamic: Vec<&RustEventRef> = rust_refs
        .iter()
        .filter(|r| r.expression.is_some())
        .collect();
    let frontend_dynamic: Vec<&events::EventCall> = ipc.dynamic().collect();
    out.refs.dynamic = rust_dynamic.len() + frontend_dynamic.len();

    if !rust_dynamic.is_empty() || !frontend_dynamic.is_empty() {
        let detail = describe_dynamic(&rust_dynamic, &frontend_dynamic);
        let names = event_names(&rust_refs, &ipc);
        // Counted before the gate, so the report says how much was at stake
        // rather than reporting a namespace that looks empty.
        out.discovered = names.len();
        for name in names {
            out.kept.push(KeptEvent {
                name,
                file: String::new(),
                line: 0,
                reason: EventKeepReason::DynamicEventReference,
                detail: Some(
                    "the event namespace contains a runtime-computed name, which could be \
                     any event"
                        .into(),
                ),
            });
        }
        out.warnings.push(format!(
            "Tauri event obfuscation disabled: {} runtime-computed event name(s) could refer \
             to any event. Make them static to enable event renaming.\n{detail}",
            out.refs.dynamic
        ));
        return Ok(out);
    }

    // ---- the graph --------------------------------------------------------
    let mut graph: BTreeMap<String, Graph> = BTreeMap::new();
    for reference in &rust_refs {
        if let Some(name) = reference.name() {
            graph.entry(name.to_string()).or_default().producers +=
                usize::from(reference.role == EventRole::Producer);
            graph.entry(name.to_string()).or_default().consumers +=
                usize::from(reference.role == EventRole::Consumer);
        }
    }
    for call in &ipc.calls {
        if let EventNameRef::Static { value, .. } = &call.name {
            let entry = graph.entry(value.clone()).or_default();
            match call.role {
                EventRole::Producer => entry.producers += 1,
                EventRole::Consumer => entry.consumers += 1,
            }
        }
    }

    out.discovered = graph.len();
    if graph.is_empty() {
        return Ok(out);
    }
    tracing::info!(events = graph.len(), "discovered tauri events");

    // Event channels must not collide with a command name or with each other,
    // and both sets are properties of the source rather than of the walk.
    for command in &req.plan.tauri.invoke_names {
        names.reserve(command.clone());
    }
    for name in graph.keys() {
        names.reserve(name.clone());
    }

    let event_names = graph.keys().cloned().collect::<BTreeSet<_>>();
    let external_plaintext_collisions = crate::strings::external_dependency_plaintext_collisions(
        req.graph,
        req.input_root,
        &event_names,
    )?;

    // ---- one transaction per event ----------------------------------------
    for (name, edges) in &graph {
        if external_plaintext_collisions.contains(name) {
            out.kept.push(KeptEvent {
                name: name.clone(),
                file: String::new(),
                line: 0,
                reason: EventKeepReason::PlaintextCollision,
                detail: Some(
                    "the original event bytes also occur in an external dependency source or \
                     compiled library artifact; the strict final-binary scan could not prove \
                     their provenance"
                        .into(),
                ),
            });
            continue;
        }
        if let Some(reason) = keep_reason(name, edges) {
            out.kept.push(KeptEvent {
                name: name.clone(),
                file: String::new(),
                line: 0,
                reason,
                detail: None,
            });
            if reason == EventKeepReason::ExternalEventSource {
                out.refs.external_source += 1;
            }
            if reason == EventKeepReason::ExternalEventConsumer {
                out.refs.external_consumer += 1;
            }
            continue;
        }

        match rename_event(name, &rust_refs, &ipc, &texts, req, names, plan) {
            Ok(new_name) => {
                out.renamed += 1;
                out.mapping.insert(name.clone(), new_name);
            }
            Err((reason, detail)) => out.kept.push(KeptEvent {
                name: name.clone(),
                file: String::new(),
                line: 0,
                reason,
                detail,
            }),
        }
    }

    tracing::info!(
        renamed = out.renamed,
        kept = out.kept.len(),
        "tauri event pass complete"
    );
    Ok(out)
}

#[derive(Debug, Default, Clone, Copy)]
struct Graph {
    producers: usize,
    consumers: usize,
}

/// The internal-event rule.
fn keep_reason(name: &str, edges: &Graph) -> Option<EventKeepReason> {
    // `tauri://window-created` and friends are the framework's protocol, not
    // this project's. Renaming one would break the framework rather than hide
    // anything.
    if name.contains("://") || name.starts_with("tauri") {
        return Some(EventKeepReason::FrameworkEvent);
    }
    match (edges.producers, edges.consumers) {
        (0, _) => Some(EventKeepReason::ExternalEventSource),
        (_, 0) => Some(EventKeepReason::ExternalEventConsumer),
        _ => None,
    }
}

fn event_names(rust_refs: &[RustEventRef], ipc: &EventAnalysis) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for reference in rust_refs {
        if let Some(name) = reference.name() {
            names.insert(name.to_string());
        }
    }
    for call in &ipc.calls {
        if let EventNameRef::Static { value, .. } = &call.name {
            names.insert(value.clone());
        }
    }
    names.into_iter().collect()
}

#[allow(clippy::too_many_arguments)]
fn rename_event(
    name: &str,
    rust_refs: &[RustEventRef],
    ipc: &EventAnalysis,
    texts: &BTreeMap<PathBuf, String>,
    _req: &EventRequest<'_>,
    names: &mut NameDeriver,
    plan: &mut crate::edits::EditPlan,
) -> std::result::Result<String, (EventKeepReason, Option<String>)> {
    let new_name = names
        .derive(SeedDomain::TauriEvent, name, NameCase::Channel)
        .map_err(|e| (EventKeepReason::Unresolvable, Some(e.to_string())))?;

    let mut pending: BTreeMap<PathBuf, Vec<Indel>> = BTreeMap::new();

    for reference in rust_refs.iter().filter(|r| r.name() == Some(name)) {
        let (_, range) = reference
            .static_name
            .as_ref()
            .expect("a dynamic reference keeps the whole namespace");
        push(
            &mut pending,
            &reference.file,
            crate::edits::replace(
                u32::from(range.start()),
                u32::from(range.end()),
                format!("\"{new_name}\""),
            ),
        );
    }

    for call in ipc
        .calls
        .iter()
        .filter(|c| matches!(&c.name, EventNameRef::Static { value, .. } if value == name))
    {
        let EventNameRef::Static { span, quote, .. } = &call.name else {
            continue;
        };
        push(
            &mut pending,
            &call.file,
            crate::edits::replace(span.start, span.end, format!("{quote}{new_name}{quote}")),
        );
    }

    let pending_for_scan = pending
        .iter()
        .map(|(path, edits)| (path.clone(), edits.clone()))
        .collect::<Vec<_>>();
    let collisions = super::uncovered_plaintext_occurrences(name, texts, &pending_for_scan);
    if !collisions.is_empty() {
        return Err((
            EventKeepReason::PlaintextCollision,
            Some(format!(
                "the original event bytes also occur outside the exact producer/consumer \
                 edits; the strict final-binary scan could not establish provenance: {}",
                collisions.join(", ")
            )),
        ));
    }

    let mut contributions = Vec::with_capacity(pending.len());
    for (path, indels) in &pending {
        let Some(text) = texts.get(path).map(String::as_str) else {
            return Err((
                EventKeepReason::Unresolvable,
                Some(format!("no analysed text for {}", path.display())),
            ));
        };
        contributions.push(crate::edits::Contribution::new(path, text, indels.clone()));
    }

    match plan.stage_transaction(contributions) {
        Ok(_) => Ok(new_name),
        Err(e) => Err((EventKeepReason::EditConflict, Some(e.to_string()))),
    }
}

fn push(pending: &mut BTreeMap<PathBuf, Vec<Indel>>, path: &Path, indel: Indel) {
    pending.entry(path.to_path_buf()).or_default().push(indel);
}

fn describe_dynamic(rust: &[&RustEventRef], frontend: &[&events::EventCall]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for reference in rust {
        lines.push(format!(
            "  {}:{}  .{}({})",
            reference.file.display(),
            reference.line,
            reference.api.as_str(),
            reference.expression.as_deref().unwrap_or("")
        ));
    }
    for call in frontend {
        if let EventNameRef::Dynamic { expression } = &call.name {
            lines.push(format!(
                "  {}:{}  {}({expression}, ...)",
                call.file.display(),
                call.line,
                call.callee
            ));
        }
    }
    lines.sort();
    lines.join("\n")
}

struct RustFile {
    path: PathBuf,
    file_id: FileId,
    text: String,
}

fn workspace_files(
    analysis: &RustAnalysis,
    graph: &CrateGraph,
    plan: &crate::plan::Plan,
) -> Vec<RustFile> {
    let mut out = Vec::new();
    for (file_id, path) in analysis.rust_files() {
        let Some(krate) = rename::crate_for_file(graph, &path) else {
            continue;
        };
        if !is_root_like(graph, &krate.name)
            && plan.dependencies.mode_for(&krate.name) != crate::config::DependencyMode::Obfuscate
        {
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

/// Every method call in one file that name resolution places in the Tauri crate.
fn collect_rust_refs(
    analysis: &RustAnalysis,
    file: &RustFile,
    input_root: &Path,
) -> Vec<RustEventRef> {
    let mut out = Vec::new();
    let parsed =
        ra_ap_syntax::SourceFile::parse(&file.text, ra_ap_syntax::Edition::Edition2021).tree();

    for node in parsed.syntax().descendants() {
        if node.kind() != SyntaxKind::METHOD_CALL_EXPR {
            continue;
        }
        let Some(call) = ast::MethodCallExpr::cast(node.clone()) else {
            continue;
        };
        let Some(name_ref) = call.name_ref() else {
            continue;
        };
        let method = name_ref.syntax().text().to_string();
        let Some(api) = RustEventApi::by_method(&method) else {
            continue;
        };

        // Not the method name alone: `foo.emit(..)` is a common shape on types
        // that have nothing to do with Tauri.
        if !resolves_to_tauri(
            analysis,
            file.file_id,
            name_ref.syntax().text_range(),
            input_root,
        ) {
            continue;
        }

        let Some(arg_list) = call.arg_list() else {
            continue;
        };
        let args: Vec<ast::Expr> = arg_list.args().collect();
        let Some(argument) = args.get(api.name_argument()) else {
            continue;
        };

        let line = line_of(&file.text, node.text_range());
        let static_name = string_literal(argument);
        let expression = static_name
            .is_none()
            .then(|| argument.syntax().text().to_string());

        out.push(RustEventRef {
            file: file.path.clone(),
            line,
            api,
            role: api.role(),
            static_name,
            expression,
        });
    }

    out
}

/// The value and span of a string literal argument.
///
/// Read off the token rather than through the AST enum: what matters is that
/// the argument is exactly one string literal, and `LITERAL` holding a single
/// `STRING` token is that and nothing else.
fn string_literal(expr: &ast::Expr) -> Option<(String, TextRange)> {
    let node = expr.syntax();
    if node.kind() != SyntaxKind::LITERAL {
        return None;
    }
    let token = node
        .children_with_tokens()
        .filter_map(|element| element.into_token())
        .find(|token| token.kind() == SyntaxKind::STRING)?;
    let value = crate::tauri::literals::string_value(token.text())?;
    Some((value, node.text_range()))
}

/// Does this method name resolve into the Tauri crate?
fn resolves_to_tauri(
    analysis: &RustAnalysis,
    file_id: FileId,
    range: TextRange,
    input_root: &Path,
) -> bool {
    let config = GotoDefinitionConfig {
        ra_fixture: ra_ap_ide::RaFixtureConfig::default(),
    };
    let position = FilePosition {
        file_id,
        offset: range.start(),
    };

    let Ok(Some(info)) = analysis.analysis().goto_definition(position, &config) else {
        return false;
    };
    info.info.iter().any(|target| {
        analysis
            .file_path(target.file_id)
            .map(|path| super::is_tauri_api_path(&path, input_root))
            .unwrap_or(false)
    })
}

fn line_of(text: &str, range: TextRange) -> u32 {
    let offset = (u32::from(range.start()) as usize).min(text.len());
    1 + text[..offset].matches('\n').count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::events::EventApi;

    fn graph(producers: usize, consumers: usize) -> Graph {
        Graph {
            producers,
            consumers,
        }
    }

    #[test]
    fn an_event_with_both_ends_inside_the_workspace_may_move() {
        assert_eq!(keep_reason("download-progress", &graph(1, 1)), None);
        assert_eq!(keep_reason("download-progress", &graph(3, 2)), None);
    }

    /// A listener with no producer may be fed by a plugin or another page.
    #[test]
    fn a_listener_only_event_is_kept() {
        assert_eq!(
            keep_reason("plugin-status", &graph(0, 2)),
            Some(EventKeepReason::ExternalEventSource)
        );
    }

    /// An emitter with no listener may be consumed outside the workspace.
    #[test]
    fn a_producer_only_event_is_kept() {
        assert_eq!(
            keep_reason("telemetry-ping", &graph(1, 0)),
            Some(EventKeepReason::ExternalEventConsumer)
        );
    }

    #[test]
    fn framework_channels_are_never_touched() {
        for name in [
            "tauri://window-created",
            "tauri://close-requested",
            "tauri-update",
        ] {
            assert_eq!(
                keep_reason(name, &graph(1, 1)),
                Some(EventKeepReason::FrameworkEvent),
                "{name}"
            );
        }
    }

    #[test]
    fn plaintext_collision_reason_has_a_stable_report_name() {
        assert_eq!(
            EventKeepReason::PlaintextCollision.as_str(),
            "plaintext-substring-collision"
        );
    }

    #[test]
    fn the_name_argument_differs_for_emit_to() {
        assert_eq!(RustEventApi::Emit.name_argument(), 0);
        assert_eq!(RustEventApi::EmitFilter.name_argument(), 0);
        assert_eq!(RustEventApi::EmitTo.name_argument(), 1);
        assert_eq!(RustEventApi::Listen.name_argument(), 0);
        assert_eq!(RustEventApi::ListenAny.name_argument(), 0);
        assert_eq!(RustEventApi::Once.name_argument(), 0);
    }

    #[test]
    fn roles_are_split_by_api() {
        for api in [
            RustEventApi::Emit,
            RustEventApi::EmitTo,
            RustEventApi::EmitFilter,
        ] {
            assert_eq!(api.role(), EventRole::Producer, "{api:?}");
        }
        for api in [
            RustEventApi::Listen,
            RustEventApi::ListenAny,
            RustEventApi::Once,
        ] {
            assert_eq!(api.role(), EventRole::Consumer, "{api:?}");
        }
        assert_eq!(EventApi::EmitTo.name_argument(), 1);
    }
}
