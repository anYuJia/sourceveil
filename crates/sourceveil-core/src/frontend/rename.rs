//! Scope-aware JavaScript/TypeScript binding rename.
//!
//! This is intentionally a small, conservative pass. OXC's semantic model
//! gives us the binding and every resolved identifier reference; we rewrite
//! only those spans. Member properties (`object.name`), object keys, JSON
//! fields and React props are never identifier references and therefore never
//! enter the edit set. When the syntax makes that distinction ambiguous — for
//! example an object shorthand property — the complete binding is kept.
//!
//! The pass is fail-closed around module boundaries as well. Imports and
//! exports are API surface, not private locals. A top-level binding is eligible
//! only when its declaration and all references are private to this module.
//! Nested function/block bindings are the primary Phase 4 target.

use super::{collect_sources, parse};
use crate::edits::{replace, EditPlan, SourceRef};
use crate::mapping::Mapping;
use crate::names::{NameCase, NameDeriver, SeedDomain};
use crate::report::FrontendStats;
use anyhow::Result;
use oxc_allocator::Allocator;
use oxc_ast::ast::{BindingIdentifier, IdentifierName, IdentifierReference};
use oxc_ast::AstKind;
use oxc_ast_visit::{walk, Visit};
use oxc_semantic::{Semantic, SemanticBuilder, SymbolFlags, SymbolId};
use oxc_span::GetSpan;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Inputs shared by every frontend file in a transform.
pub struct RenameRequest<'a> {
    /// Workspace root, used to make mapping identities independent of the
    /// temporary directory used for a transform.
    pub input_root: &'a Path,
    /// Usually `<frontend>/src`; only files below this directory are parsed.
    pub source_root: &'a Path,
    /// Workspace-relative files that were actually copied to the output.
    pub copied: &'a BTreeSet<PathBuf>,
}

#[derive(Debug, Default)]
pub struct RenameOutcome {
    pub stats: FrontendStats,
    pub mapping: Mapping,
    pub warnings: Vec<String>,
}

/// Rename private lexical bindings in all supported frontend sources.
pub fn run(
    req: &RenameRequest<'_>,
    names: &mut NameDeriver,
    edits: &mut EditPlan,
) -> Result<RenameOutcome> {
    let (sources, read_warnings) = collect_sources(req.source_root);
    let mut outcome = RenameOutcome {
        mapping: Mapping::default(),
        ..Default::default()
    };
    outcome.warnings.extend(read_warnings);
    let mut edited_files = BTreeSet::new();

    // Keep generated frontend names away from every lexical spelling already
    // present in the frontend. This is done before deriving any frontend name
    // (but after the Rust passes have drawn theirs), so a frontend file cannot
    // introduce a shadowing collision.
    for file in &sources {
        let allocator = Allocator::default();
        let Some(program) = parse(&allocator, &file.text, &file.path) else {
            continue;
        };
        let mut collector = IdentifierCollector::default();
        collector.visit_program(&program);
        for name in collector.names {
            names.reserve(name);
        }
    }

    for file in &sources {
        let allocator = Allocator::default();
        let Some(program) = parse(&allocator, &file.text, &file.path) else {
            outcome.warnings.push(format!(
                "could not parse {}; its private bindings are not renamed",
                file.path.display()
            ));
            continue;
        };
        outcome.stats.files_scanned += 1;

        // OXC's semantic graph borrows the arena-backed Program, so both stay
        // alive for the complete decision and staging loop below.
        let program = allocator.alloc(program);
        let built = SemanticBuilder::new().with_build_nodes(true).build(program);
        if !built.diagnostics.is_empty() {
            outcome.warnings.push(format!(
                "could not build a complete semantic model for {}; its private bindings are kept",
                file.path.display()
            ));
            continue;
        }
        let semantic = built.semantic;
        let ids: Vec<SymbolId> = semantic.scoping().symbol_ids().collect();

        let dynamic_scope = contains_dynamic_scope(&file.text);
        for symbol_id in ids {
            let flags = semantic.scoping().symbol_flags(symbol_id);
            if !is_candidate(flags) {
                continue;
            }
            outcome.stats.symbols_discovered += 1;

            let old_name = semantic.scoping().symbol_name(symbol_id).to_string();
            let declaration = semantic.symbol_declaration(symbol_id);
            let declaration_span = semantic.scoping().symbol_span(symbol_id);
            let scope = semantic.symbol_scope(symbol_id);
            let top_level = scope == semantic.scoping().root_scope_id();

            let reason = if dynamic_scope {
                Some("dynamic-scope")
            } else if flags.intersects(SymbolFlags::Import | SymbolFlags::TypeImport) {
                Some("import-binding")
            } else if flags.contains(SymbolFlags::Ambient) {
                Some("ambient-declaration")
            } else if has_property_declaration_ancestor(&semantic, declaration.id()) {
                Some("property-binding")
            } else if top_level && has_export_ancestor(&semantic, declaration.id()) {
                Some("exported-binding")
            } else if has_commonjs_boundary(&file.text) && top_level {
                Some("module-boundary")
            } else if top_level && has_external_reference(&semantic, symbol_id) {
                Some("exported-binding")
            } else if is_in_unsafe_scope(&semantic, scope) {
                Some("dynamic-scope")
            } else if is_object_shorthand(&semantic, declaration.id(), declaration_span)
                || semantic.symbol_references(symbol_id).any(|reference| {
                    is_object_shorthand(
                        &semantic,
                        reference.node_id(),
                        semantic.reference_span(reference),
                    )
                })
            {
                Some("object-shorthand")
            } else {
                None
            };

            if let Some(reason) = reason {
                record_kept(&mut outcome.stats, reason);
                continue;
            }

            let relative = req
                .input_root
                .canonicalize()
                .ok()
                .and_then(|root| file.path.strip_prefix(root).ok())
                .unwrap_or(file.path.as_path());
            let relative = relative.to_string_lossy().replace('\\', "/");
            let identity = format!(
                "frontend::{relative}::{old_name}@{}",
                declaration_span.start
            );
            let new_name = names.derive(SeedDomain::FrontendSymbol, &identity, NameCase::Snake)?;

            let mut spans = BTreeSet::new();
            spans.insert((declaration_span.start, declaration_span.end));
            for reference in semantic.symbol_references(symbol_id) {
                let span = semantic.reference_span(reference);
                spans.insert((span.start, span.end));
            }
            let indels = spans
                .into_iter()
                .map(|(start, end)| replace(start, end, new_name.clone()))
                .collect::<Vec<_>>();

            let Some(rel) = file.path.strip_prefix(req.input_root).ok() else {
                record_kept(&mut outcome.stats, "outside-workspace");
                continue;
            };
            if !req.copied.contains(rel) {
                record_kept(&mut outcome.stats, "not-copied");
                continue;
            }

            match edits.stage(
                SourceRef {
                    path: &file.path,
                    text: &file.text,
                },
                indels,
            ) {
                Ok(applied) => {
                    outcome.stats.symbols_renamed += 1;
                    outcome.stats.edits_applied += applied;
                    edited_files.insert(file.path.clone());
                    outcome.mapping.frontend_symbols.insert(identity, new_name);
                }
                Err(conflict) => {
                    record_kept(&mut outcome.stats, "edit-conflict");
                    outcome.warnings.push(conflict.to_string());
                }
            }
        }
    }

    // `EditPlan` is shared with the Rust/Tauri passes, so count only files this
    // pass actually contributed to by looking at the mapping's source paths.
    outcome.stats.files_edited = edited_files.len();
    Ok(outcome)
}

fn record_kept(stats: &mut FrontendStats, reason: &str) {
    *stats.kept_by_reason.entry(reason.to_string()).or_default() += 1;
}

fn is_candidate(flags: SymbolFlags) -> bool {
    flags.intersects(
        SymbolFlags::Function
            | SymbolFlags::Class
            | SymbolFlags::FunctionScopedVariable
            | SymbolFlags::BlockScopedVariable,
    ) && !flags.intersects(
        SymbolFlags::Import
            | SymbolFlags::TypeImport
            | SymbolFlags::TypeAlias
            | SymbolFlags::Interface
            | SymbolFlags::EnumMember
            | SymbolFlags::RegularEnum
            | SymbolFlags::ConstEnum,
    )
}

fn contains_dynamic_scope(source: &str) -> bool {
    // OXC marks direct-eval/with scopes too; this lexical guard also catches a
    // direct eval in a syntax position whose semantic graph has no descendant
    // scope for the binding (the conservative outcome is to keep the file's
    // bindings).
    source.contains("eval(") || source.contains("eval (") || source.contains("with (")
}

fn has_commonjs_boundary(source: &str) -> bool {
    source.contains("module.exports") || source.contains("exports.")
}

fn is_in_unsafe_scope(semantic: &Semantic<'_>, mut scope: oxc_semantic::ScopeId) -> bool {
    loop {
        let flags = semantic.scoping().scope_flags(scope);
        if flags.intersects(oxc_semantic::ScopeFlags::DirectEval | oxc_semantic::ScopeFlags::With) {
            return true;
        }
        let Some(parent) = semantic.scoping().scope_parent_id(scope) else {
            return false;
        };
        scope = parent;
    }
}

fn has_external_reference(semantic: &Semantic<'_>, symbol_id: SymbolId) -> bool {
    semantic
        .symbol_references(symbol_id)
        .any(|reference| has_export_reference_ancestor(semantic, reference.node_id()))
}

/// A reference in an exported function's body is still a private lexical
/// reference. Only an export specifier/default expression (before crossing a
/// function or class boundary) makes the binding itself part of the module
/// contract.
fn has_export_reference_ancestor(semantic: &Semantic<'_>, node_id: oxc_semantic::NodeId) -> bool {
    for kind in semantic.nodes().ancestor_kinds(node_id) {
        match kind {
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) | AstKind::Class(_) => {
                return false
            }
            AstKind::ExportNamedDeclaration(_)
            | AstKind::ExportFromDeclaration(_)
            | AstKind::ExportDefaultDeclaration(_)
            | AstKind::ExportAllDeclaration(_) => return true,
            _ => {}
        }
    }
    false
}

fn has_export_ancestor(semantic: &Semantic<'_>, node_id: oxc_semantic::NodeId) -> bool {
    semantic.nodes().ancestor_kinds(node_id).any(|kind| {
        matches!(
            kind,
            AstKind::ExportDeclaration(_)
                | AstKind::ExportNamedDeclaration(_)
                | AstKind::ExportFromDeclaration(_)
                | AstKind::ExportDefaultDeclaration(_)
                | AstKind::ExportAllDeclaration(_)
        )
    })
}

fn has_property_declaration_ancestor(
    semantic: &Semantic<'_>,
    node_id: oxc_semantic::NodeId,
) -> bool {
    for kind in semantic.nodes().ancestor_kinds(node_id) {
        match kind {
            // A binding nested in a method body is a normal lexical local;
            // stop before the method's property name is reached.
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_) | AstKind::Class(_) => {
                return false
            }
            AstKind::MethodDefinition(_)
            | AstKind::PropertyDefinition(_)
            | AstKind::AccessorProperty(_) => return true,
            _ => {}
        }
    }
    false
}

fn is_object_shorthand(
    semantic: &Semantic<'_>,
    node_id: oxc_semantic::NodeId,
    span: oxc_span::Span,
) -> bool {
    semantic
        .nodes()
        .ancestor_kinds(node_id)
        .any(|kind| match kind {
            AstKind::ObjectProperty(property) => {
                property.shorthand && property.value.span() == span
            }
            AstKind::BindingProperty(property) => {
                property.shorthand && property.value.span() == span
            }
            _ => false,
        })
}

#[derive(Default)]
struct IdentifierCollector {
    names: BTreeSet<String>,
}

impl<'a> Visit<'a> for IdentifierCollector {
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        self.names.insert(identifier.name.to_string());
        walk::walk_identifier_reference(self, identifier);
    }

    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        self.names.insert(identifier.name.to_string());
        walk::walk_binding_identifier(self, identifier);
    }

    fn visit_identifier_name(&mut self, identifier: &IdentifierName<'a>) {
        self.names.insert(identifier.name.to_string());
        walk::walk_identifier_name(self, identifier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edits::EditPlan;
    use std::collections::{BTreeSet, HashSet};
    use tempfile::tempdir;

    fn run_source(source: &str) -> (String, RenameOutcome) {
        let tmp = tempdir().unwrap();
        let root = tmp.path().join("frontend/src");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("app.ts");
        std::fs::write(&path, source).unwrap();
        let copied = BTreeSet::from([PathBuf::from("frontend/src/app.ts")]);
        let mut names = NameDeriver::new(7, 5, 9, HashSet::new());
        let mut edits = EditPlan::new();
        let outcome = run(
            &RenameRequest {
                input_root: tmp.path(),
                source_root: &root,
                copied: &copied,
            },
            &mut names,
            &mut edits,
        )
        .unwrap();
        let output_root = tmp.path().join("out");
        std::fs::create_dir_all(output_root.join("frontend/src")).unwrap();
        std::fs::copy(&path, output_root.join("frontend/src/app.ts")).unwrap();
        edits.apply(tmp.path(), &output_root).unwrap();
        let out = std::fs::read_to_string(output_root.join("frontend/src/app.ts")).unwrap();
        (out, outcome)
    }

    #[test]
    fn semantic_parse_rejects_exports_and_shorthand() {
        let (out, outcome) = run_source(
            "export const api = 1; function outer() { const local = 2; return { local }; }",
        );
        assert!(outcome.stats.symbols_discovered >= 2);
        assert!(outcome
            .stats
            .kept_by_reason
            .contains_key("exported-binding"));
        assert!(outcome
            .stats
            .kept_by_reason
            .contains_key("object-shorthand"));
        assert!(out.contains("export const api = 1"));
    }

    #[test]
    fn private_bindings_inside_exported_functions_are_eligible() {
        let (out, outcome) =
            run_source("export function api() { const privateValue = 2; return privateValue; }");
        assert!(!out.contains("privateValue"));
        assert!(out.contains("export function api"));
        assert_eq!(outcome.stats.symbols_renamed, 1);
    }

    #[test]
    fn member_properties_and_explicit_object_keys_are_not_renamed() {
        let (out, outcome) = run_source(
            "function build() { const value = 2; const object = { label: value }; return object.label + value; }",
        );
        assert!(!out.contains("const value"));
        assert!(out.contains("label:"));
        assert!(out.contains(".label"));
        assert!(outcome.stats.symbols_renamed >= 2);
    }

    #[test]
    fn method_locals_are_not_mistaken_for_property_names() {
        let (out, outcome) =
            run_source("class Worker { run() { const privateValue = 2; return privateValue; } }");
        assert!(!out.contains("privateValue"));
        assert!(out.contains("run()"));
        assert!(outcome.stats.symbols_renamed >= 2);
    }
}
