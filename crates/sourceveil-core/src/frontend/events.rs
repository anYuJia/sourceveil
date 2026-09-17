//! Event channel analysis: which event names the frontend emits and listens
//! for, and where that cannot be determined.
//!
//! ## Why provenance is not optional here
//!
//! `invoke` is a name almost nothing else uses. `emit`, `listen` and `once` are
//! the opposite: socket.io, Node's `EventEmitter`, every store library and half
//! the DOM use them. A pass that matched on the callee name would rewrite
//! `socket.emit("download-progress")` in a project that also happens to use
//! Tauri, which is a silent break.
//!
//! So a call is only considered at all when its callee traces back to
//! `@tauri-apps/api/event` through an import in the same file — including an
//! aliased import, a namespace import, and a receiver bound from
//! `getCurrentWebviewWindow()`.

use super::{line_of, parse, quote_at, slice, SourceFile, Span};
use anyhow::Result;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, BindingIdentifier, BindingPattern, CallExpression, Expression,
    ImportDeclarationSpecifier, Program, Statement, VariableDeclaration,
};
use oxc_ast_visit::{walk, Visit};
use oxc_span::GetSpan;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The Tauri module that carries the event API.
const EVENT_MODULE: &str = "@tauri-apps/api/event";
/// The Tauri module that hands back a window receiver.
const WEBVIEW_WINDOW_MODULE: &str = "@tauri-apps/api/webviewWindow";

/// Which event API a call goes through, and which argument holds the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventApi {
    /// `emit(name, payload)` — the name is the first argument.
    Emit,
    /// `emitTo(target, name, payload)` — the first argument is a window label,
    /// which this phase does not touch.
    EmitTo,
    Listen,
    Once,
}

impl EventApi {
    /// Which argument is the event name.
    ///
    /// `emitTo` is why this exists. Its first argument is a window label, and
    /// renaming a label is not something this pass does — treating argument
    /// zero as the name would corrupt the target.
    pub fn name_argument(self) -> usize {
        match self {
            EventApi::EmitTo => 1,
            EventApi::Emit | EventApi::Listen | EventApi::Once => 0,
        }
    }

    /// Is this call announcing an event, or waiting for one?
    pub fn role(self) -> EventRole {
        match self {
            EventApi::Emit | EventApi::EmitTo => EventRole::Producer,
            EventApi::Listen | EventApi::Once => EventRole::Consumer,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            EventApi::Emit => "emit",
            EventApi::EmitTo => "emitTo",
            EventApi::Listen => "listen",
            EventApi::Once => "once",
        }
    }

    /// The Rust spelling, for the report.
    pub fn rust_name(self) -> &'static str {
        match self {
            EventApi::Emit => "emit",
            EventApi::EmitTo => "emit_to",
            EventApi::Listen => "listen",
            EventApi::Once => "once",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventRole {
    Producer,
    Consumer,
}

/// The event name at one call site.
#[derive(Debug, Clone)]
pub enum EventNameRef {
    /// The literal as written, or a constant this analysis proved.
    Static {
        value: String,
        /// The literal to replace, quotes included.
        span: Span,
        quote: char,
        /// True when the literal is a constant's initialiser rather than the
        /// argument itself.
        via_constant: bool,
    },
    /// Anything else — the call might name any event.
    Dynamic { expression: String },
}

/// One call into the Tauri event API.
#[derive(Debug, Clone)]
pub struct EventCall {
    pub file: PathBuf,
    pub line: u32,
    pub api: EventApi,
    pub role: EventRole,
    /// The callee as written, so aliases are visible in the report.
    pub callee: String,
    pub name: EventNameRef,
}

#[derive(Debug, Default)]
pub struct EventAnalysis {
    pub files_scanned: usize,
    /// Every call whose callee resolved to the Tauri event API.
    pub calls: Vec<EventCall>,
    /// String literals equal to an event name, outside a recognised call.
    /// Collected by the pass once it knows the event names.
    pub warnings: Vec<String>,
}

impl EventAnalysis {
    pub fn dynamic(&self) -> impl Iterator<Item = &EventCall> {
        self.calls
            .iter()
            .filter(|c| matches!(c.name, EventNameRef::Dynamic { .. }))
    }
}

/// Analyse every frontend source file.
pub fn analyze(sources: &[SourceFile], _root: &Path) -> Result<EventAnalysis> {
    let mut out = EventAnalysis::default();

    for file in sources {
        let allocator = Allocator::default();
        let Some(program) = parse(&allocator, &file.text, &file.path) else {
            out.warnings.push(format!(
                "could not parse {}; its event calls are not analysed",
                file.path.display()
            ));
            continue;
        };

        let imports = Imports::collect(&program);
        if imports.is_empty() {
            // No Tauri event import in this file, so nothing in it can be a
            // Tauri event call. `socket.emit` and `emitter.once` live here.
            continue;
        }
        out.files_scanned += 1;

        let mut collector = EventCollector {
            file: file.path.clone(),
            source: &file.text,
            imports: &imports,
            wins: BTreeSet::new(),
            constants: BTreeMap::new(),
            shadowed: BTreeSet::new(),
            bindings: BTreeSet::new(),
            calls: Vec::new(),
        };
        collector.visit_program(&program);
        out.calls.extend(collector.calls);
    }

    // Source order, so the report reads like the file and the edits come out
    // the same way on every run.
    out.calls.sort_by(|a, b| {
        (&a.file, a.line, a.api.as_str(), &a.callee).cmp(&(
            &b.file,
            b.line,
            b.api.as_str(),
            &b.callee,
        ))
    });
    Ok(out)
}

/// What each local name in a file actually refers to.
#[derive(Debug, Default)]
struct Imports {
    /// Local name -> the event API it names, through however many aliases.
    functions: BTreeMap<String, EventApi>,
    /// Local names bound to the whole event module: `import * as events`.
    namespaces: BTreeSet<String>,
    /// Local names bound to the webview-window factory.
    window_factories: BTreeSet<String>,
}

impl Imports {
    fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.namespaces.is_empty() && self.window_factories.is_empty()
    }

    fn collect(program: &Program<'_>) -> Self {
        let mut out = Imports::default();

        for statement in &program.body {
            let Statement::ImportDeclaration(import) = statement else {
                continue;
            };
            let from = import.source.value.as_str();

            let Some(specifiers) = &import.specifiers else {
                continue;
            };
            for specifier in specifiers.iter() {
                match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(named) => {
                        let imported = named.imported.name();
                        let local = named.local.name.to_string();
                        if from == EVENT_MODULE {
                            if let Some(api) = api_by_name(imported.as_str()) {
                                out.functions.insert(local, api);
                            }
                        } else if from == WEBVIEW_WINDOW_MODULE
                            && imported.as_str() == "getCurrentWebviewWindow"
                        {
                            out.window_factories.insert(local);
                        }
                    }
                    // `import * as events from "@tauri-apps/api/event"`, used
                    // as `events.emit(...)`.
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(ns) => {
                        if from == EVENT_MODULE {
                            out.namespaces.insert(ns.local.name.to_string());
                        }
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(_) => {}
                }
            }
        }
        out
    }

    /// The API a bare callee name refers to.
    fn function(&self, name: &str) -> Option<EventApi> {
        self.functions.get(name).copied()
    }

    /// The API a `namespace.name(...)` call refers to.
    fn member(&self, object: &str, property: &str) -> Option<EventApi> {
        self.namespaces
            .contains(object)
            .then(|| api_by_name(property))
            .flatten()
    }
}

fn api_by_name(name: &str) -> Option<EventApi> {
    Some(match name {
        "emit" => EventApi::Emit,
        "emitTo" => EventApi::EmitTo,
        "listen" => EventApi::Listen,
        "once" => EventApi::Once,
        _ => return None,
    })
}

struct EventCollector<'a> {
    file: PathBuf,
    source: &'a str,
    imports: &'a Imports,
    /// Local names holding a `WebviewWindow`.
    wins: BTreeSet<String>,
    /// Module-level `const NAME = "literal"`.
    constants: BTreeMap<String, (String, Span)>,
    /// Names bound more than once in this file. The constant lookup cannot tell
    /// which binding a use belongs to, so those names are refused.
    shadowed: BTreeSet<String>,
    /// Every name bound anywhere in this file.
    bindings: BTreeSet<String>,
    calls: Vec<EventCall>,
}

impl<'a, 'b> Visit<'b> for EventCollector<'a> {
    fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'b>) {
        if !self.bindings.insert(id.name.to_string()) {
            self.shadowed.insert(id.name.to_string());
        }
        walk::walk_binding_identifier(self, id);
    }

    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'b>) {
        self.note_window_binding(declaration);
        for declarator in &declaration.declarations {
            let BindingPattern::BindingIdentifier(id) = &declarator.id else {
                continue;
            };
            if let Some(Expression::StringLiteral(literal)) = &declarator.init {
                self.constants.insert(
                    id.name.to_string(),
                    (
                        literal.value.to_string(),
                        Span::new(literal.span.start, literal.span.end),
                    ),
                );
            }
        }
        walk::walk_variable_declaration(self, declaration);
    }

    fn visit_call_expression(&mut self, expr: &CallExpression<'b>) {
        if let Some((api, callee)) = self.classify(expr) {
            if let Some(argument) = expr.arguments.get(api.name_argument()) {
                let line = line_of(self.source, expr.span.start);
                self.calls.push(EventCall {
                    file: self.file.clone(),
                    line,
                    api,
                    role: api.role(),
                    callee,
                    name: self.name_of(argument, line),
                });
            }
        }
        walk::walk_call_expression(self, expr);
    }
}

impl<'a> EventCollector<'a> {
    /// Which Tauri API this call goes through, if any.
    ///
    /// Returns `None` for everything that cannot be traced to a Tauri import —
    /// which is the whole point, because `emit` and `listen` are not rare
    /// names.
    fn classify(&self, expr: &CallExpression<'_>) -> Option<(EventApi, String)> {
        match &expr.callee {
            // `emit(...)` / `listen(...)`, however the import was aliased.
            Expression::Identifier(callee) => self
                .imports
                .function(callee.name.as_str())
                .map(|api| (api, callee.name.to_string())),

            // `events.emit(...)` through a namespace import.
            Expression::StaticMemberExpression(member) => {
                let Expression::Identifier(object) = &member.object else {
                    return None;
                };
                let property = member.property.name.as_str();

                // `win.emit(...)` where `win` came from
                // `getCurrentWebviewWindow()`.
                if self.wins.contains(object.name.as_str()) {
                    let api = api_by_name(property)?;
                    return Some((api, format!("{}.{property}", object.name)));
                }

                self.imports
                    .member(object.name.as_str(), property)
                    .map(|api| (api, format!("{}.{property}", object.name)))
            }
            _ => None,
        }
    }

    /// The event name at this argument, if it is a compile-time string.
    fn name_of(&self, argument: &Argument<'_>, _line: u32) -> EventNameRef {
        match argument {
            Argument::StringLiteral(literal) => EventNameRef::Static {
                value: literal.value.to_string(),
                span: Span::new(literal.span.start, literal.span.end),
                quote: quote_at(self.source, literal.span.start),
                via_constant: false,
            },
            // A template literal with no substitutions is still a constant;
            // one with substitutions is exactly the dynamic case.
            Argument::TemplateLiteral(template) if template.expressions.is_empty() => {
                match template.quasis.first() {
                    Some(quasi) => EventNameRef::Static {
                        value: quasi.value.raw.to_string(),
                        span: Span::new(template.span.start, template.span.end),
                        quote: '`',
                        via_constant: false,
                    },
                    None => self.dynamic(argument),
                }
            }
            Argument::Identifier(ident) => match self.constant_for(&ident.name) {
                Some((value, span)) => EventNameRef::Static {
                    value,
                    span,
                    quote: quote_at(self.source, span.start),
                    via_constant: true,
                },
                None => self.dynamic(argument),
            },
            other => self.dynamic(other),
        }
    }

    fn dynamic(&self, argument: &Argument<'_>) -> EventNameRef {
        let span = argument.span();
        EventNameRef::Dynamic {
            expression: slice(self.source, span.start, span.end).to_string(),
        }
    }

    /// A module-level constant this call could be naming.
    ///
    /// Unlike the command analysis this does not audit every use of the
    /// constant. It does not need to: an event name is a *value*, and rewriting
    /// the constant changes it wherever it is read — which is what the caller
    /// wants when the same constant is both emitted and listened for. The one
    /// thing that would be wrong is a shadowed name, so a name bound more than
    /// once in the file is refused.
    fn constant_for(&self, name: &str) -> Option<(String, Span)> {
        if self.shadowed.contains(name) {
            return None;
        }
        let (value, span) = self.constants.get(name)?;
        Some((value.clone(), *span))
    }

    /// Bindings introduced by `getCurrentWebviewWindow()`.
    ///
    /// Only a direct call is accepted. `const win = factory()` where `factory`
    /// is anything else is not provably a window, and guessing is how a pass
    /// starts rewriting somebody else's event bus.
    ///
    /// Recorded during the walk rather than by a pre-pass over the module body,
    /// because the binding almost always sits inside the function that uses
    /// it:
    ///
    /// ```ts
    /// export async function resized() {
    ///   const win = getCurrentWebviewWindow();
    ///   await win.emit("window-resized", { .. });
    /// }
    /// ```
    ///
    /// The visitor walks in source order, so the binding is known before the
    /// call that follows it.
    fn note_window_binding(&mut self, declaration: &VariableDeclaration<'_>) {
        for declarator in &declaration.declarations {
            let (BindingPattern::BindingIdentifier(id), Some(Expression::CallExpression(call))) =
                (&declarator.id, &declarator.init)
            else {
                continue;
            };
            let Expression::Identifier(callee) = &call.callee else {
                continue;
            };
            if self.imports.window_factories.contains(callee.name.as_str()) {
                self.wins.insert(id.name.to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_src(src: &str) -> EventAnalysis {
        let sources = vec![SourceFile {
            path: PathBuf::from("events.ts"),
            text: src.to_string(),
        }];
        analyze(&sources, Path::new(".")).unwrap()
    }

    fn names(a: &EventAnalysis) -> Vec<(EventApi, EventRole, String)> {
        a.calls
            .iter()
            .map(|c| {
                let name = match &c.name {
                    EventNameRef::Static { value, .. } => value.clone(),
                    EventNameRef::Dynamic { expression } => format!("<{expression}>"),
                };
                (c.api, c.role, name)
            })
            .collect()
    }

    const IMPORT: &str = r#"import { emit, emitTo, listen, once } from "@tauri-apps/api/event";"#;

    #[test]
    fn a_direct_import_is_recognised() {
        let a = analyze_src(&format!(
            "{IMPORT}\nemit(\"download-started\", payload);\nlisten(\"download-started\", h);"
        ));
        assert_eq!(
            names(&a),
            vec![
                (
                    EventApi::Emit,
                    EventRole::Producer,
                    "download-started".into()
                ),
                (
                    EventApi::Listen,
                    EventRole::Consumer,
                    "download-started".into()
                ),
            ]
        );
    }

    /// The whole reason provenance exists.
    #[test]
    fn an_untraced_callee_is_not_a_tauri_call() {
        let a = analyze_src(
            r#"
            const socket = connect();
            socket.emit("download-started");
            emitter.once("open-file");
            store.listen("sync-state");
            "#,
        );
        assert!(a.calls.is_empty(), "{:?}", names(&a));
    }

    /// Even in a file that does use the Tauri event API, a receiver that did
    /// not come from Tauri is left alone.
    #[test]
    fn an_untraced_receiver_beside_a_tauri_import_is_still_not_tauri() {
        let a = analyze_src(&format!(
            r#"{IMPORT}
            const socket = connect();
            socket.emit("download-started");
            emit("real-event", payload);
            "#
        ));
        assert_eq!(
            names(&a),
            vec![(EventApi::Emit, EventRole::Producer, "real-event".into())],
            "{:?}",
            names(&a)
        );
    }

    #[test]
    fn an_aliased_import_is_followed() {
        let a = analyze_src(
            r#"
            import { emit as fire, listen as on } from "@tauri-apps/api/event";
            fire("download-started");
            on("download-started", h);
            "#,
        );
        assert_eq!(names(&a).len(), 2, "{:?}", names(&a));
        assert_eq!(a.calls[1].callee, "on");
    }

    #[test]
    fn a_namespace_import_is_followed() {
        let a = analyze_src(
            r#"
            import * as events from "@tauri-apps/api/event";
            events.emit("download-started");
            events.listen("download-started", h);
            "#,
        );
        assert_eq!(names(&a).len(), 2, "{:?}", names(&a));
        assert_eq!(a.calls[0].callee, "events.emit");
    }

    /// `emitTo`'s first argument is a window label. Reading argument zero would
    /// corrupt the target rather than rename the event.
    #[test]
    fn emit_to_takes_its_name_from_the_second_argument() {
        let a = analyze_src(&format!(
            "{IMPORT}\nemitTo(\"main\", \"session-updated\", payload);"
        ));
        assert_eq!(
            names(&a),
            vec![(
                EventApi::EmitTo,
                EventRole::Producer,
                "session-updated".into()
            )]
        );
        let span = match &a.calls[0].name {
            EventNameRef::Static { span, .. } => *span,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            &"import { emit, emitTo, listen, once } from \"@tauri-apps/api/event\";\nemitTo(\"main\", \"session-updated\", payload);"
                [span.start as usize..span.end as usize],
            "\"session-updated\"",
            "the span must cover the second argument, not the label"
        );
    }

    #[test]
    fn a_window_bound_from_the_tauri_factory_is_followed() {
        let a = analyze_src(
            r#"
            import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
            const win = getCurrentWebviewWindow();
            win.emit("download-progress", payload);
            win.listen("download-progress", h);
            win.once("startup-complete", h);
            "#,
        );
        assert_eq!(names(&a).len(), 3, "{:?}", names(&a));
        assert!(a.calls.iter().all(|c| c.callee.starts_with("win.")));
    }

    /// A binding from anything else is not provably a window.
    #[test]
    fn a_window_bound_from_something_else_is_not_followed() {
        let a = analyze_src(
            r#"
            import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";
            function factory() { return getCurrentWebviewWindow(); }
            const win = factory();
            win.emit("download-progress", payload);
            "#,
        );
        assert!(a.calls.is_empty(), "{:?}", names(&a));
    }

    #[test]
    fn a_constant_event_name_is_resolved() {
        let a = analyze_src(&format!(
            r#"{IMPORT}
            const EVENT = "open-file";
            listen(EVENT, h);
            "#
        ));
        assert_eq!(
            names(&a),
            vec![(EventApi::Listen, EventRole::Consumer, "open-file".into())]
        );
        assert!(matches!(
            a.calls[0].name,
            EventNameRef::Static {
                via_constant: true,
                ..
            }
        ));
    }

    #[test]
    fn a_shadowed_constant_is_not_resolved() {
        let a = analyze_src(&format!(
            r#"{IMPORT}
            const EVENT = "outer";
            function f() {{
                const EVENT = "inner";
                listen(EVENT, h);
            }}
            "#
        ));
        assert!(matches!(a.calls[0].name, EventNameRef::Dynamic { .. }));
    }

    #[test]
    fn dynamic_arguments_are_recorded() {
        let a = analyze_src(&format!(
            r#"{IMPORT}
            listen(eventName, h);
            emit(`${{group}}-${{action}}`, payload);
            once(prefix + suffix, h);
            "#
        ));
        let dynamic: Vec<&EventCall> = a.dynamic().collect();
        assert_eq!(dynamic.len(), 3, "{:?}", names(&a));
        assert_eq!(dynamic[0].line, 2);
    }

    #[test]
    fn a_substitution_free_template_is_a_constant() {
        let a = analyze_src(&format!("{IMPORT}\nlisten(`plain-event`, h);"));
        assert_eq!(
            names(&a),
            vec![(EventApi::Listen, EventRole::Consumer, "plain-event".into())]
        );
    }

    /// A file with no Tauri import is skipped entirely, so `socket.emit` costs
    /// nothing even to look at.
    #[test]
    fn a_file_without_a_tauri_import_is_skipped() {
        let a = analyze_src("socket.emit('x');");
        assert_eq!(a.files_scanned, 0);
        assert!(a.calls.is_empty());
    }
}
