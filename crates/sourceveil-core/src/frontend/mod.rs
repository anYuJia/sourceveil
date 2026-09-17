//! Frontend analysis, for the parts of the IPC contract that live in
//! TypeScript.
//!
//! Only what the Tauri command pass needs: which strings are passed to
//! `invoke`, and — just as important — where a call *cannot* be resolved to a
//! string, because that is the case that decides whether the whole command
//! namespace is safe to touch.
//!
//! ## Why the unresolved case is fatal rather than skipped
//!
//! `invoke(commandName)` computes a command name at runtime. Nothing static can
//! enumerate what it might be, so it might be *any* command. Renaming the Rust
//! handlers while such a call exists means the frontend asks for a name that no
//! longer exists. There is no way to rename "the commands that are statically
//! referenced" and leave the rest — every command is potentially the dynamic
//! one. So one dynamic call keeps the entire namespace, and the report says
//! exactly where it is.

use anyhow::Result;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, BindingIdentifier, BindingPattern, CallExpression, Expression, Program,
    VariableDeclaration,
};
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::{GetSpan, SourceType};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// Byte range in a frontend file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    fn new(start: u32, end: u32) -> Self {
        Self { start, end }
    }
}

/// A command name that must be rewritten, and the literal that spells it.
#[derive(Debug, Clone)]
pub struct StaticInvoke {
    pub file: PathBuf,
    /// The callee as written: `invoke`, `call`, a project wrapper.
    pub callee: String,
    /// The string literal to replace, quotes included.
    pub span: Span,
    pub command: String,
    /// Quote character of the original, so the rewrite can keep it.
    pub quote: char,
    pub via: InvokeVia,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeVia {
    /// The literal is the argument: `invoke("x")`.
    Literal,
    /// The argument is a module-level constant, and the literal is its
    /// initialiser: `invoke(CMD)`.
    Constant,
}

/// An `invoke(...)` whose argument is not a compile-time string.
#[derive(Debug, Clone)]
pub struct DynamicInvoke {
    pub file: PathBuf,
    /// The callee as written, or empty when there is no call site.
    pub callee: String,
    pub line: u32,
    /// The argument as written, for the report.
    pub expression: String,
}

/// Every string literal in the frontend, kept so that a literal naming a
/// command can be found outside an `invoke` call.
#[derive(Debug, Clone)]
pub struct StringLiteral {
    pub file: PathBuf,
    pub span: Span,
    pub value: String,
}

#[derive(Debug, Default)]
pub struct IpcAnalysis {
    pub files_scanned: usize,
    /// Callee names understood to be `invoke`, including wrappers found in the
    /// project itself.
    pub invoke_names: BTreeSet<String>,
    pub static_refs: Vec<StaticInvoke>,
    pub dynamic_refs: Vec<DynamicInvoke>,
    pub literals: Vec<StringLiteral>,
    /// The text of every file analysed, so a pass staging edits against it can
    /// supply the same snapshot the analysis ran on.
    pub file_texts: BTreeMap<PathBuf, String>,
    pub warnings: Vec<String>,
}

impl IpcAnalysis {}

/// Extensions worth parsing.
const FRONTEND_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"];

/// Directories never walked.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "dist",
    "build",
    "target",
    ".git",
    "coverage",
    "out",
];

/// Names understood to be `invoke` without any local evidence.
const DEFAULT_INVOKE_NAMES: &[&str] = &["invoke", "tauriInvoke"];

/// Analyse every frontend source file below `root`.
pub fn analyze(root: &Path, extra_invoke_names: &[String]) -> Result<IpcAnalysis> {
    let mut out = IpcAnalysis::default();
    out.invoke_names
        .extend(DEFAULT_INVOKE_NAMES.iter().map(|s| s.to_string()));
    out.invoke_names.extend(extra_invoke_names.iter().cloned());

    let files = collect_files(root);

    // First pass: find wrappers, so a project calling its own helper is
    // understood before its call sites are classified.
    let mut parsed_files = Vec::with_capacity(files.len());
    for path in &files {
        let Ok(source) = std::fs::read_to_string(path) else {
            out.warnings
                .push(format!("could not read {}; skipped", path.display()));
            continue;
        };
        parsed_files.push((path.clone(), source));
    }

    let mut wrappers: Vec<Wrapper> = Vec::new();
    for (path, source) in &parsed_files {
        let allocator = Allocator::default();
        let Some(program) = parse(&allocator, source, path) else {
            out.warnings.push(format!(
                "could not parse {}; its invoke calls are not analysed",
                path.display()
            ));
            continue;
        };
        wrappers.extend(find_wrappers(&program, &out.invoke_names, path, source));
    }
    for wrapper in &wrappers {
        out.invoke_names.insert(wrapper.name.clone());
    }

    // Second pass: classify call sites with the full wrapper set known.
    for (path, source) in &parsed_files {
        out.file_texts.insert(path.clone(), source.clone());
        let allocator = Allocator::default();
        let Some(program) = parse(&allocator, source, path) else {
            continue;
        };
        out.files_scanned += 1;

        let mut collector = Collector {
            file: path.clone(),
            source,
            invoke_names: &out.invoke_names,
            static_refs: Vec::new(),
            dynamic_refs: Vec::new(),
            literals: Vec::new(),
            constant_declarations: BTreeMap::new(),
            bindings: HashSet::new(),
            duplicate_bindings: HashSet::new(),
            identifier_refs: Vec::new(),
            invoke_arg_spans: HashSet::new(),
            constant_candidates: Vec::new(),
            current_callee: String::new(),
            function_stack: Vec::new(),
        };

        collector.visit_program(&program);
        collector.resolve_constant_invokes();

        out.static_refs.extend(collector.static_refs);
        out.dynamic_refs.extend(collector.dynamic_refs);
        out.literals.extend(collector.literals);
    }

    // A wrapper that nothing in the analysed tree calls is a hole rather than
    // a convenience. It is reachable from outside this tree — another bundle,
    // a test, a consumer — with a name nothing here can see, so the same
    // reasoning as a dynamic call applies to it.
    for wrapper in &wrappers {
        let called = out.static_refs.iter().any(|r| r.callee == wrapper.name)
            || out.dynamic_refs.iter().any(|r| r.callee == wrapper.name);
        if !called {
            out.dynamic_refs.push(DynamicInvoke {
                file: wrapper.file.clone(),
                callee: wrapper.name.clone(),
                line: wrapper.line,
                expression: format!(
                    "{} — an invoke wrapper with no call site in the analysed tree",
                    wrapper.name
                ),
            });
        }
    }

    // Source order. The report is read by someone walking the file, and the
    // edits have to come out the same way on every run: a constant's
    // initialiser is discovered while resolving a call site, so without this
    // the order depends on when resolution happened to run.
    out.static_refs.sort_by(|a, b| {
        (&a.file, a.span.start, &a.command).cmp(&(&b.file, b.span.start, &b.command))
    });
    out.dynamic_refs
        .sort_by(|a, b| (&a.file, a.line, &a.expression).cmp(&(&b.file, b.line, &b.expression)));
    out.literals
        .sort_by(|a, b| (&a.file, a.span.start).cmp(&(&b.file, b.span.start)));

    Ok(out)
}

fn parse<'a>(allocator: &'a Allocator, source: &'a str, path: &Path) -> Option<Program<'a>> {
    let source_type = SourceType::from_path(path).unwrap_or_default();
    let ret = Parser::new(allocator, source, source_type).parse();
    if !ret.diagnostics.is_empty() {
        return None;
    }
    Some(ret.program)
}

fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                return !SKIP_DIRS.contains(&name.as_ref());
            }
            true
        })
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        if FRONTEND_EXTENSIONS.contains(&ext.as_str()) {
            files.push(entry.path().to_path_buf());
        }
    }
    files.sort();
    files
}

/// A function that forwards its first parameter to an invoke call.
#[derive(Debug, Clone)]
struct Wrapper {
    name: String,
    file: PathBuf,
    line: u32,
}

/// Names of local functions that forward their first parameter to an invoke
/// call, which makes them invoke wrappers in their own right.
///
/// Found through the visitor rather than by matching statement shapes, because
/// `export function call(cmd) { return invoke(cmd); }` is not a
/// `Statement::FunctionDeclaration` — and an exported wrapper is exactly the
/// shape a project is most likely to have.
fn find_wrappers(
    program: &Program<'_>,
    known: &BTreeSet<String>,
    path: &Path,
    source: &str,
) -> Vec<Wrapper> {
    struct Finder<'a> {
        known: &'a BTreeSet<String>,
        found: Vec<String>,
    }

    impl<'a, 'b> Visit<'b> for Finder<'a> {
        fn visit_function(
            &mut self,
            func: &oxc_ast::ast::Function<'b>,
            flags: oxc_syntax::scope::ScopeFlags,
        ) {
            if let (Some(id), Some(first), Some(body)) =
                (&func.id, func.params.items.first(), &func.body)
            {
                if let BindingPattern::BindingIdentifier(param) = &first.pattern {
                    let mut probe = WrapperProbe {
                        param: param.name.as_str(),
                        known: self.known,
                        forwards: false,
                    };
                    probe.visit_function_body(body);
                    if probe.forwards {
                        self.found.push(id.name.to_string());
                    }
                }
            }
            walk::walk_function(self, func, flags);
        }
    }

    let mut finder = Finder {
        known,
        found: Vec::new(),
    };
    finder.visit_program(program);

    finder
        .found
        .into_iter()
        .map(|name| Wrapper {
            line: finder_line_of(source, name.as_str()).unwrap_or(0),
            name,
            file: path.to_path_buf(),
        })
        .collect()
}

/// The line a top-level function is declared on.
///
/// Only used for the report, so a text search is good enough and avoids
/// threading spans out of the visitor.
fn finder_line_of(source: &str, name: &str) -> Option<u32> {
    let needle = format!("function {name}");
    let at = source.find(&needle)?;
    Some(line_of(source, at as u32))
}

/// Does a function body call a known invoke with its own first parameter?
struct WrapperProbe<'a> {
    param: &'a str,
    known: &'a BTreeSet<String>,
    forwards: bool,
}

impl<'a, 'b> Visit<'b> for WrapperProbe<'a> {
    fn visit_call_expression(&mut self, expr: &CallExpression<'b>) {
        if let Expression::Identifier(callee) = &expr.callee {
            if self.known.contains(callee.name.as_str()) {
                if let Some(Argument::Identifier(arg)) = expr.arguments.first() {
                    if arg.name == self.param {
                        self.forwards = true;
                    }
                }
            }
        }
        walk::walk_call_expression(self, expr);
    }
}

/// An `invoke(NAME)` awaiting a decision about whether `NAME` is a command
/// constant.
#[derive(Debug)]
struct ConstantCandidate {
    name: String,
    file: PathBuf,
    callee: String,
    line: u32,
}

struct Collector<'a> {
    file: PathBuf,
    source: &'a str,
    invoke_names: &'a BTreeSet<String>,

    static_refs: Vec<StaticInvoke>,
    dynamic_refs: Vec<DynamicInvoke>,
    literals: Vec<StringLiteral>,

    /// `const NAME = "literal"` anywhere in the file.
    constant_declarations: BTreeMap<String, (Span, String)>,
    /// Every name bound anywhere in the file.
    bindings: HashSet<String>,
    /// Names bound more than once, which this analysis cannot resolve.
    duplicate_bindings: HashSet<String>,

    /// Every identifier *use*, with its span.
    identifier_refs: Vec<(String, Span)>,
    /// Spans of identifiers used as the first argument of an invoke call.
    invoke_arg_spans: HashSet<Span>,
    constant_candidates: Vec<ConstantCandidate>,
    /// Callee of the invoke currently being recorded.
    current_callee: String,
    /// The chain of enclosing function declarations, so the forwarding call
    /// inside a wrapper can be told apart from a call site.
    function_stack: Vec<Option<String>>,
}

impl<'a, 'b> Visit<'b> for Collector<'a> {
    fn visit_function(
        &mut self,
        func: &oxc_ast::ast::Function<'b>,
        flags: oxc_syntax::scope::ScopeFlags,
    ) {
        self.function_stack
            .push(func.id.as_ref().map(|id| id.name.to_string()));
        walk::walk_function(self, func, flags);
        self.function_stack.pop();
    }

    fn visit_call_expression(&mut self, expr: &CallExpression<'b>) {
        if let Expression::Identifier(callee) = &expr.callee {
            if self.invoke_names.contains(callee.name.as_str()) && !self.inside_wrapper() {
                self.record_invoke(expr);
            }
        }
        walk::walk_call_expression(self, expr);
    }

    fn visit_string_literal(&mut self, literal: &oxc_ast::ast::StringLiteral<'b>) {
        self.literals.push(StringLiteral {
            file: self.file.clone(),
            span: Span::new(literal.span.start, literal.span.end),
            value: literal.value.to_string(),
        });
        walk::walk_string_literal(self, literal);
    }

    fn visit_identifier_reference(&mut self, ident: &oxc_ast::ast::IdentifierReference<'b>) {
        self.identifier_refs.push((
            ident.name.to_string(),
            Span::new(ident.span.start, ident.span.end),
        ));
        walk::walk_identifier_reference(self, ident);
    }

    /// Every binding site: `const`, parameters, function and class names,
    /// catch parameters, imports.
    fn visit_binding_identifier(&mut self, id: &BindingIdentifier<'b>) {
        if !self.bindings.insert(id.name.to_string()) {
            self.duplicate_bindings.insert(id.name.to_string());
        }
        walk::walk_binding_identifier(self, id);
    }

    fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'b>) {
        for declarator in &decl.declarations {
            let BindingPattern::BindingIdentifier(id) = &declarator.id else {
                continue;
            };
            if let Some(Expression::StringLiteral(literal)) = &declarator.init {
                self.constant_declarations.insert(
                    id.name.to_string(),
                    (
                        Span::new(literal.span.start, literal.span.end),
                        literal.value.to_string(),
                    ),
                );
            }
        }
        walk::walk_variable_declaration(self, decl);
    }
}

impl<'a> Collector<'a> {
    /// Is this call the forwarding call of a wrapper?
    ///
    /// `function call(cmd: string) { return invoke(cmd); }` contains an
    /// `invoke` whose argument is a parameter, so it can never be resolved to a
    /// constant. Treating it as a dynamic reference would disable command
    /// renaming for the whole project — but it is not a call site, it is the
    /// wrapper's own body. What matters is the wrapper's callers, and those are
    /// analysed normally.
    fn inside_wrapper(&self) -> bool {
        self.function_stack
            .last()
            .and_then(|name| name.as_ref())
            .map(|name| self.invoke_names.contains(name))
            .unwrap_or(false)
    }

    fn record_invoke(&mut self, expr: &CallExpression<'_>) {
        let Some(argument) = expr.arguments.first() else {
            return;
        };
        let callee = match &expr.callee {
            Expression::Identifier(ident) => ident.name.to_string(),
            _ => String::new(),
        };
        self.current_callee = callee.clone();
        let _ = &callee;

        match argument {
            Argument::StringLiteral(literal) => {
                self.static_refs.push(StaticInvoke {
                    file: self.file.clone(),
                    callee: callee.to_string(),
                    span: Span::new(literal.span.start, literal.span.end),
                    command: literal.value.to_string(),
                    quote: quote_at(self.source, literal.span.start),
                    via: InvokeVia::Literal,
                });
            }
            Argument::Identifier(ident) => {
                self.invoke_arg_spans
                    .insert(Span::new(ident.span.start, ident.span.end));
                self.constant_candidates.push(ConstantCandidate {
                    name: ident.name.to_string(),
                    file: self.file.clone(),
                    callee: self.current_callee.clone(),
                    line: line_of(self.source, ident.span.start),
                });
            }
            // A template literal with no substitutions is still a constant.
            Argument::TemplateLiteral(template) if template.expressions.is_empty() => {
                match template.quasis.first() {
                    Some(quasi) => self.static_refs.push(StaticInvoke {
                        file: self.file.clone(),
                        callee: callee.to_string(),
                        span: Span::new(template.span.start, template.span.end),
                        command: quasi.value.raw.to_string(),
                        quote: '`',
                        via: InvokeVia::Literal,
                    }),
                    None => self.push_dynamic(argument),
                }
            }
            other => self.push_dynamic(other),
        }
    }

    fn push_dynamic(&mut self, argument: &Argument<'_>) {
        let span = argument.span();
        self.dynamic_refs.push(DynamicInvoke {
            file: self.file.clone(),
            callee: self.current_callee.clone(),
            line: line_of(self.source, span.start),
            expression: slice(self.source, span.start, span.end).to_string(),
        });
    }

    /// Turn `invoke(CONST)` into an edit on the constant's initialiser — but
    /// only when every use of that constant is as an invoke argument.
    ///
    /// Rewriting the constant changes its value for every other reader too, and
    /// this analysis has no idea what they do with it.
    fn resolve_constant_invokes(&mut self) {
        for candidate in std::mem::take(&mut self.constant_candidates) {
            if let Some(resolved) = self.try_resolve(&candidate) {
                self.static_refs.push(resolved);
            } else {
                self.dynamic_refs.push(DynamicInvoke {
                    file: candidate.file,
                    callee: candidate.callee,
                    line: candidate.line,
                    expression: candidate.name,
                });
            }
        }
    }

    fn try_resolve(&self, candidate: &ConstantCandidate) -> Option<StaticInvoke> {
        if self.duplicate_bindings.contains(&candidate.name) {
            return None;
        }
        let (literal_span, value) = self.constant_declarations.get(&candidate.name)?;

        let uses: Vec<&Span> = self
            .identifier_refs
            .iter()
            .filter(|(name, _)| *name == candidate.name)
            .map(|(_, span)| span)
            .collect();
        if uses.is_empty() {
            return None;
        }
        if !uses.iter().all(|span| self.invoke_arg_spans.contains(span)) {
            return None;
        }

        Some(StaticInvoke {
            file: self.file.clone(),
            callee: self.current_callee.clone(),
            span: *literal_span,
            command: value.clone(),
            quote: quote_at(self.source, literal_span.start),
            via: InvokeVia::Constant,
        })
    }
}

/// The quote character a string literal starts with.
fn quote_at(source: &str, start: u32) -> char {
    source
        .get(start as usize..)
        .and_then(|s| s.chars().next())
        .unwrap_or('"')
}

fn slice(source: &str, start: u32, end: u32) -> &str {
    let (start, end) = (start as usize, (end as usize).min(source.len()));
    if start >= end {
        return "";
    }
    &source[start..end]
}

fn line_of(source: &str, offset: u32) -> u32 {
    let offset = (offset as usize).min(source.len());
    1 + source[..offset].matches('\n').count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_src(src: &str) -> IpcAnalysis {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("ipc.ts"), src).unwrap();
        analyze(tmp.path(), &[]).unwrap()
    }

    #[test]
    fn finds_a_plain_invoke_literal() {
        let a = analyze_src(r#"invoke("get_user_info");"#);
        assert_eq!(a.static_refs.len(), 1);
        assert_eq!(a.static_refs[0].command, "get_user_info");
        assert!(a.dynamic_refs.is_empty());
    }

    #[test]
    fn finds_a_typed_invoke() {
        let a = analyze_src(r#"invoke<Response>("activate_license", { key });"#);
        assert_eq!(a.static_refs.len(), 1);
        assert_eq!(a.static_refs[0].command, "activate_license");
    }

    #[test]
    fn finds_the_tauri_module_spelling() {
        let a = analyze_src(r#"invoke("x");"#);
        assert_eq!(a.static_refs.len(), 1);
    }

    #[test]
    fn a_constant_used_only_for_invoke_is_resolved() {
        let a = analyze_src(
            r#"
            const CMD = "get_secret_status";
            invoke(CMD);
            "#,
        );
        assert!(a.dynamic_refs.is_empty(), "{:?}", a.dynamic_refs);
        assert_eq!(a.static_refs.len(), 1);
        assert_eq!(a.static_refs[0].command, "get_secret_status");
        assert_eq!(a.static_refs[0].via, InvokeVia::Constant);
    }

    #[test]
    fn a_constant_used_elsewhere_is_not_resolved() {
        let a = analyze_src(
            r#"
            const CMD = "get_secret_status";
            invoke(CMD);
            log(CMD);
            "#,
        );
        assert_eq!(a.dynamic_refs.len(), 1, "{:?}", a.static_refs);
        assert!(a.static_refs.is_empty());
    }

    #[test]
    fn a_shadowed_constant_is_not_resolved() {
        let a = analyze_src(
            r#"
            const CMD = "outer";
            function f() {
                const CMD = "inner";
                invoke(CMD);
            }
            "#,
        );
        assert_eq!(a.dynamic_refs.len(), 1, "{:?}", a.static_refs);
    }

    #[test]
    fn dynamic_arguments_are_recorded_with_their_line() {
        let a = analyze_src(
            "invoke(a);\ninvoke(prefix + action);\ninvoke(`${prefix}_${name}`);\ninvoke(commands[t]);",
        );
        assert_eq!(a.dynamic_refs.len(), 4, "{:?}", a.dynamic_refs);
        assert_eq!(a.dynamic_refs[0].line, 1);
        assert_eq!(a.dynamic_refs[1].expression, "prefix + action");
        assert_eq!(a.dynamic_refs[3].expression, "commands[t]");
    }

    #[test]
    fn a_local_wrapper_is_understood() {
        let a = analyze_src(
            r#"
            function call(cmd: string) {
                return invoke(cmd);
            }
            call("get_user_info");
            "#,
        );
        assert_eq!(a.static_refs.len(), 1, "{:?}", a.static_refs);
        assert_eq!(a.static_refs[0].command, "get_user_info");
    }

    #[test]
    fn a_wrapper_that_does_not_forward_is_not_an_invoke() {
        let a = analyze_src(
            r#"
            function other(a: string, b: string) { return invoke(b); }
            other("not_a_command", "x");
            "#,
        );
        assert!(a.static_refs.is_empty(), "{:?}", a.static_refs);
    }

    #[test]
    fn a_substitution_free_template_literal_is_a_constant() {
        let a = analyze_src("invoke(`plain_command`);");
        assert_eq!(a.static_refs.len(), 1, "{:?}", a.dynamic_refs);
        assert_eq!(a.static_refs[0].command, "plain_command");
    }

    #[test]
    fn node_modules_and_dist_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules/pkg")).unwrap();
        std::fs::write(tmp.path().join("node_modules/pkg/a.js"), "invoke('x')").unwrap();
        std::fs::create_dir_all(tmp.path().join("dist")).unwrap();
        std::fs::write(tmp.path().join("dist/b.js"), "invoke('y')").unwrap();
        std::fs::write(tmp.path().join("src.ts"), "invoke('z')").unwrap();
        let a = analyze(tmp.path(), &[]).unwrap();
        assert_eq!(a.files_scanned, 1);
        assert_eq!(a.static_refs[0].command, "z");
    }

    /// The literal span has to cover the quotes: that is what gets replaced.
    #[test]
    fn the_literal_span_covers_the_quotes() {
        let src = r#"invoke("get_user_info");"#;
        let a = analyze_src(src);
        let span = a.static_refs[0].span;
        assert_eq!(
            &src[span.start as usize..span.end as usize],
            r#""get_user_info""#
        );
        assert_eq!(a.static_refs[0].quote, '"');
    }

    #[test]
    fn single_quoted_literals_keep_their_quote() {
        let a = analyze_src("invoke('single');");
        assert_eq!(a.static_refs[0].quote, '\'');
    }

    /// A wrapper's own forwarding call is not a call site, so it must not be
    /// treated as a dynamic reference — that would disable command renaming
    /// for any project that wraps `invoke`.
    #[test]
    fn a_wrapper_body_does_not_count_as_a_dynamic_call() {
        let a = analyze_src(
            r#"
            import { invoke } from "@tauri-apps/api/core";

            export function call<T>(command: string): Promise<T> {
                return invoke<T>(command);
            }

            export function ping(): Promise<string> {
                return call<string>("ping");
            }
            "#,
        );
        assert!(
            a.dynamic_refs.is_empty(),
            "the wrapper's own body should not be dynamic: {:?}",
            a.dynamic_refs
        );
        assert_eq!(a.static_refs.len(), 1, "{:?}", a.static_refs);
        assert_eq!(a.static_refs[0].command, "ping");
    }

    /// A constant that is only ever used inside `invoke` calls is resolvable
    /// even when it is referenced more than once.
    #[test]
    fn a_constant_used_by_several_invokes_is_resolved_once() {
        let a = analyze_src(
            r#"
            const CMD = "shared_command";
            invoke(CMD);
            invoke(CMD, { a: 1 });
            "#,
        );
        assert!(a.dynamic_refs.is_empty(), "{:?}", a.dynamic_refs);
        assert_eq!(a.static_refs.len(), 2);
        assert!(a.static_refs.iter().all(|r| r.via == InvokeVia::Constant));
    }
}
