//! Runtime string protection for TypeScript/JavaScript sources.
//!
//! The frontend pass is deliberately AST based. Replacing every quoted token
//! with a decoder call would break module specifiers, object keys and JSX
//! attributes whose values are structural (class names, URLs, input types,
//! and so on). We therefore collect only expressions and user-facing JSX
//! values that can legally become an expression at the same position.
//!
//! Every generated file gets a tiny UTF-8 decoder helper. Keeping the helper
//! local makes the transformed tree self-contained and avoids changing import
//! graphs or requiring a runtime package in the generated project.

use super::{collect_sources, parse};
use crate::edits::{replace, EditPlan, SourceRef};
use crate::plan::StringsPlan;
use anyhow::Result;
use oxc_ast::ast::{
    AssignmentPattern, BinaryExpression, ExportAllDeclaration, ExportFromDeclaration, Expression,
    ImportAttribute, ImportDeclaration, ImportExpression, JSXAttribute, JSXAttributeValue, JSXText,
    ObjectPattern, ObjectProperty, PropertyKey, StringLiteral, SwitchCase, TSEnumMemberName,
    TSLiteral, TSLiteralType, TaggedTemplateExpression, TemplateLiteral,
};
use oxc_ast_visit::{walk, Visit};
use oxc_syntax::operator::BinaryOperator;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateKind {
    Expression,
    JsxAttribute,
    JsxText,
    TemplateQuasi,
    ObjectKey,
}

#[derive(Debug, Clone)]
struct Candidate {
    start: u32,
    end: u32,
    value: String,
    kind: CandidateKind,
}

#[derive(Debug, Default)]
struct Collected {
    candidates: Vec<Candidate>,
    /// Values retained in a structural/compile-time context. A value that is
    /// both retained and protected must not be advertised in the strict
    /// mapping, otherwise the leak scanner would correctly reject it.
    retained_values: BTreeSet<String>,
}

struct Collector {
    source: String,
    skip: BTreeSet<(u32, u32)>,
    owned: BTreeSet<(u32, u32)>,
    object_pattern_depth: usize,
    out: Collected,
}

#[derive(Debug, Default)]
pub struct StringOutcome {
    pub files_scanned: usize,
    pub values_discovered: usize,
    pub occurrences_discovered: usize,
    pub occurrences_protected: usize,
    pub occurrences_kept: usize,
    pub files_edited: usize,
    pub mapping: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

pub struct StringRequest<'a> {
    pub input_root: &'a Path,
    pub source_root: &'a Path,
    pub copied: &'a BTreeSet<PathBuf>,
    pub plan: &'a StringsPlan,
    pub seed: u64,
    pub reserved_protocol_values: &'a HashSet<String>,
}

/// Protect frontend runtime strings and JSX text.
pub fn run(req: &StringRequest<'_>, edits: &mut EditPlan) -> Result<StringOutcome> {
    let (sources, read_warnings) = collect_sources(req.source_root);
    let mut out = StringOutcome {
        warnings: read_warnings,
        ..Default::default()
    };

    let mut edited_files = BTreeSet::new();
    for file in sources {
        let Some(relative) = file.path.strip_prefix(req.input_root).ok() else {
            continue;
        };
        if !req.copied.contains(relative) || file.path.to_string_lossy().ends_with(".d.ts") {
            continue;
        }
        let allocator = oxc_allocator::Allocator::default();
        let Some(program) = parse(&allocator, &file.text, &file.path) else {
            out.warnings.push(format!(
                "could not parse {}; frontend strings are kept",
                file.path.display()
            ));
            continue;
        };
        out.files_scanned += 1;

        let mut collector = Collector {
            source: file.text.clone(),
            skip: BTreeSet::new(),
            owned: BTreeSet::new(),
            object_pattern_depth: 0,
            out: Collected::default(),
        };
        collector.visit_program(&program);
        let mut candidates = collector.out.candidates;
        candidates.sort_by_key(|candidate| (candidate.start, candidate.end));
        candidates.dedup_by_key(|candidate| (candidate.start, candidate.end));

        let mut by_value = BTreeMap::<String, usize>::new();
        for candidate in &candidates {
            if eligible(
                candidate.value.as_str(),
                req.plan,
                req.reserved_protocol_values,
            ) {
                *by_value.entry(candidate.value.clone()).or_default() += 1;
            }
        }
        out.values_discovered += by_value.len();
        out.occurrences_discovered += by_value.values().sum::<usize>();
        if by_value.is_empty() {
            continue;
        }

        let helper = helper_name(&file.path, req.seed, &file.text);
        let typescript = matches!(
            file.path
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("ts" | "tsx" | "mts" | "cts")
        );
        let mut indels = Vec::new();
        let mut value_occurrences = BTreeMap::<String, usize>::new();
        for candidate in candidates {
            if !eligible(
                candidate.value.as_str(),
                req.plan,
                req.reserved_protocol_values,
            ) {
                continue;
            }
            let ordinal = value_occurrences
                .entry(candidate.value.clone())
                .or_default();
            let key = derive_key(req.seed, &file.path, candidate.value.as_str(), *ordinal);
            *ordinal += 1;
            let call = decode_call(&helper, &candidate.value, key, typescript);
            let replacement = match candidate.kind {
                CandidateKind::Expression => call,
                CandidateKind::JsxAttribute => format!("{{{call}}}"),
                CandidateKind::JsxText => jsx_text_replacement(&file.text, &candidate, &call),
                CandidateKind::TemplateQuasi => format!("${{{call}}}"),
                CandidateKind::ObjectKey => format!("[{call}]"),
            };
            indels.push(replace(candidate.start, candidate.end, replacement));
            out.occurrences_protected += 1;

            // A compact marker is enough for diagnostics and keeps the
            // reversible value in the existing mapping section. The encoded
            // bytes are intentionally not exposed as source plaintext.
            out.mapping
                .entry(candidate.value)
                .or_insert_with(|| format!("frontend-decoded:{key:08x}"));
        }

        // A helper is inserted only when this file has a real replacement. It
        // is placed after a hashbang and directive prologue so both remain
        // valid JavaScript semantics.
        if !indels.is_empty() {
            let at = helper_insert_at(&file.text, &program);
            indels.push(replace(at, at, helper_source(&helper, typescript)));
            match edits.stage(
                SourceRef {
                    path: &file.path,
                    text: &file.text,
                },
                indels,
            ) {
                Ok(_) => {
                    edited_files.insert(file.path.clone());
                }
                Err(conflict) => {
                    out.occurrences_kept += by_value.values().sum::<usize>();
                    out.warnings.push(conflict.to_string());
                }
            }
        }

        // Only globally safe values belong in the strict mapping. Structural
        // occurrences are retained by design (for example object keys), so
        // remove those values after staging the independent safe occurrences.
        for value in collector.out.retained_values {
            out.mapping.remove(&value);
        }
    }

    out.files_edited = edited_files.len();
    Ok(out)
}

fn eligible(value: &str, plan: &StringsPlan, reserved: &HashSet<String>) -> bool {
    if value.is_empty() || reserved.contains(value) {
        return false;
    }
    plan.frontend
        || plan.all
        || (plan.ui && value.chars().any(|c| c.is_alphabetic() && !c.is_ascii()))
        || (plan.endpoints && (value.starts_with("http://") || value.starts_with("https://")))
        || (plan.internal && value.len() >= 4)
}

fn helper_name(path: &Path, seed: u64, source: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(path.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut name = format!(
        "__sv_decode_{:08x}",
        u32::from_le_bytes(digest[0..4].try_into().unwrap())
    );
    let mut nonce = 0u32;
    while source.contains(&name) {
        nonce = nonce.wrapping_add(1);
        name = format!(
            "__sv_decode_{:08x}_{nonce:x}",
            u32::from_le_bytes(digest[0..4].try_into().unwrap())
        );
    }
    name
}

fn derive_key(seed: u64, path: &Path, value: &str, ordinal: usize) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update((ordinal as u64).to_le_bytes());
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut key = u32::from_le_bytes(digest[0..4].try_into().unwrap());
    if key == 0 {
        key = 0xa341_316c;
    }
    key
}

fn encode(value: &str, mut key: u32) -> Vec<u8> {
    if key == 0 {
        key = 0xa341_316c;
    }
    value
        .as_bytes()
        .iter()
        .map(|byte| {
            key ^= key << 13;
            key ^= key >> 17;
            key ^= key << 5;
            byte ^ (key as u8)
        })
        .collect()
}

fn decode_call(helper: &str, value: &str, key: u32, _typescript: bool) -> String {
    let bytes = encode(value, key)
        .into_iter()
        .map(|byte| format!("0x{byte:02x}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("{helper}([{bytes}],0x{key:08x})")
}

fn helper_source(name: &str, typescript: bool) -> String {
    if typescript {
        format!(
            "const {name}=(a: number[],k: number): any=>{{let x=k>>>0;for(let i=0;i<a.length;i++){{x^=x<<13;x^=x>>>17;x^=x<<5;a[i]^=x&255}}return new TextDecoder().decode(new Uint8Array(a))}};\n"
        )
    } else {
        format!(
            "const {name}=(a,k)=>{{let x=k>>>0;for(let i=0;i<a.length;i++){{x^=x<<13;x^=x>>>17;x^=x<<5;a[i]^=x&255}}return new TextDecoder().decode(new Uint8Array(a))}};\n"
        )
    }
}

fn helper_insert_at(source: &str, program: &oxc_ast::ast::Program<'_>) -> u32 {
    let mut at = program.hashbang.as_ref().map(|h| h.span.end).unwrap_or(0);
    for directive in &program.directives {
        at = at.max(directive.span.end);
    }
    if at > 0 && source.as_bytes().get(at as usize) == Some(&b'\n') {
        at += 1;
    }
    at
}

fn jsx_text_replacement(_source: &str, _candidate: &Candidate, call: &str) -> String {
    format!("{{{call}}}")
}

impl<'b> Visit<'b> for Collector {
    fn visit_string_literal(&mut self, literal: &StringLiteral<'b>) {
        let span = (literal.span.start, literal.span.end);
        if self.skip.contains(&span) {
            if !self.owned.contains(&span) {
                self.out.retained_values.insert(literal.value.to_string());
            }
        } else {
            let end = self
                .source
                .get(span.1 as usize..)
                .and_then(|suffix| {
                    let leading = suffix.len() - suffix.trim_start().len();
                    let rest = &suffix[leading..];
                    rest.strip_prefix("as const")
                        .filter(|tail| {
                            !tail.chars().next().is_some_and(|character| {
                                character.is_alphanumeric() || character == '_'
                            })
                        })
                        .map(|_| span.1 + leading as u32 + "as const".len() as u32)
                })
                .unwrap_or(span.1);
            self.out.candidates.push(Candidate {
                start: span.0,
                end,
                value: literal.value.to_string(),
                kind: CandidateKind::Expression,
            });
        }
    }

    fn visit_directive(&mut self, directive: &oxc_ast::ast::Directive<'b>) {
        self.skip.insert((
            directive.expression.span.start,
            directive.expression.span.end,
        ));
        walk::walk_directive(self, directive);
    }

    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'b>) {
        self.skip
            .insert((declaration.source.span.start, declaration.source.span.end));
        walk::walk_import_declaration(self, declaration);
    }

    fn visit_export_from_declaration(&mut self, declaration: &ExportFromDeclaration<'b>) {
        self.skip
            .insert((declaration.source.span.start, declaration.source.span.end));
        walk::walk_export_from_declaration(self, declaration);
    }

    fn visit_export_all_declaration(&mut self, declaration: &ExportAllDeclaration<'b>) {
        self.skip
            .insert((declaration.source.span.start, declaration.source.span.end));
        walk::walk_export_all_declaration(self, declaration);
    }

    fn visit_import_expression(&mut self, expression: &ImportExpression<'b>) {
        if let Some(span) = string_or_template_span(&expression.source) {
            self.skip.insert(span);
        }
        walk::walk_import_expression(self, expression);
    }

    fn visit_import_attribute(&mut self, attribute: &ImportAttribute<'b>) {
        self.skip
            .insert((attribute.value.span.start, attribute.value.span.end));
        walk::walk_import_attribute(self, attribute);
    }

    fn visit_ts_literal_type(&mut self, literal: &TSLiteralType<'b>) {
        match &literal.literal {
            TSLiteral::StringLiteral(value) => {
                self.skip.insert((value.span.start, value.span.end));
            }
            TSLiteral::TemplateLiteral(value) => {
                self.skip.insert((value.span.start, value.span.end));
            }
            _ => {}
        }
        walk::walk_ts_literal_type(self, literal);
    }

    fn visit_ts_enum_member_name(&mut self, name: &TSEnumMemberName<'b>) {
        match name {
            TSEnumMemberName::String(value) | TSEnumMemberName::ComputedString(value) => {
                self.skip.insert((value.span.start, value.span.end));
            }
            TSEnumMemberName::ComputedTemplateString(value) => {
                self.skip.insert((value.span.start, value.span.end));
            }
            TSEnumMemberName::Identifier(_) => {}
        }
        walk::walk_ts_enum_member_name(self, name);
    }

    fn visit_object_property(&mut self, property: &ObjectProperty<'b>) {
        if !property.computed {
            if let PropertyKey::StringLiteral(literal) = &property.key {
                let span = (literal.span.start, literal.span.end);
                self.skip.insert(span);
                self.owned.insert(span);
                self.out.candidates.push(Candidate {
                    start: span.0,
                    end: span.1,
                    value: literal.value.to_string(),
                    kind: CandidateKind::ObjectKey,
                });
            } else if let PropertyKey::StaticIdentifier(identifier) = &property.key {
                let value = identifier.name.to_string();
                if value.chars().any(|character| !character.is_ascii()) && !property.shorthand {
                    let span = (identifier.span.start, identifier.span.end);
                    self.out.candidates.push(Candidate {
                        start: span.0,
                        end: span.1,
                        value,
                        kind: CandidateKind::ObjectKey,
                    });
                }
            }

            if property
                .key
                .static_name()
                .is_some_and(|name| literal_contract_key(name.as_ref()))
            {
                self.mark_contract_expression(&property.value);
            }
        }
        walk::walk_object_property(self, property);
    }

    fn visit_jsx_attribute(&mut self, attribute: &JSXAttribute<'b>) {
        if let Some(JSXAttributeValue::StringLiteral(literal)) = &attribute.value {
            let span = (literal.span.start, literal.span.end);
            let value = literal.value.to_string();
            self.skip.insert(span);
            self.owned.insert(span);
            self.out.candidates.push(Candidate {
                start: span.0,
                end: span.1,
                value,
                kind: CandidateKind::JsxAttribute,
            });
        }
        walk::walk_jsx_attribute(self, attribute);
    }

    fn visit_jsx_text(&mut self, text: &JSXText<'b>) {
        let value = text.value.to_string();
        if !value.trim().is_empty() {
            self.out.candidates.push(Candidate {
                start: text.span.start,
                end: text.span.end,
                value,
                kind: CandidateKind::JsxText,
            });
        }
    }

    fn visit_tagged_template_expression(&mut self, expression: &TaggedTemplateExpression<'b>) {
        self.skip
            .insert((expression.quasi.span.start, expression.quasi.span.end));
        walk::walk_tagged_template_expression(self, expression);
    }

    fn visit_template_literal(&mut self, literal: &TemplateLiteral<'b>) {
        let span = (literal.span.start, literal.span.end);
        if self.skip.contains(&span) {
            walk::walk_template_literal(self, literal);
            return;
        }
        for quasi in &literal.quasis {
            let value = quasi
                .value
                .cooked
                .as_ref()
                .unwrap_or(&quasi.value.raw)
                .to_string();
            if !value.is_empty() {
                self.out.candidates.push(Candidate {
                    start: quasi.span.start,
                    end: quasi.span.end,
                    value,
                    kind: CandidateKind::TemplateQuasi,
                });
            }
        }
        // Quasis are independent edits. Descend into interpolation
        // expressions so nested literals such as `${condition ? "中文" : ""}`
        // are protected as well.
        walk::walk_template_literal(self, literal);
    }

    fn visit_switch_case(&mut self, case: &SwitchCase<'b>) {
        // A switch test is commonly a discriminant of a generated union
        // (for example `payload.event` or `result.type`). Replacing the test
        // with a decoder call widens it to `any` and prevents TypeScript from
        // narrowing the consequent branch. Keep the literal but still walk
        // the body, where ordinary runtime strings remain eligible.
        if let Some(test) = &case.test {
            self.mark_string_expression(test);
        }
        walk::walk_switch_case(self, case);
    }

    fn visit_binary_expression(&mut self, expression: &BinaryExpression<'b>) {
        // Equality checks are another TypeScript narrowing form. Preserve
        // direct literal operands (including `as const` wrappers) so the
        // generated source retains the original literal type.
        if matches!(
            expression.operator,
            BinaryOperator::Equality
                | BinaryOperator::Inequality
                | BinaryOperator::StrictEquality
                | BinaryOperator::StrictInequality
                | BinaryOperator::In
        ) {
            if should_retain_comparison_operand(&expression.left, &expression.right) {
                self.mark_string_expression(&expression.left);
            }
            if should_retain_comparison_operand(&expression.right, &expression.left) {
                self.mark_string_expression(&expression.right);
            }
        }
        walk::walk_binary_expression(self, expression);
    }

    fn visit_assignment_pattern(&mut self, pattern: &AssignmentPattern<'b>) {
        // Defaults in destructuring inherit the declared property type. A
        // decoder call is typed as `any`, which widens discriminants such as
        // `activeResultType = "all"` and later breaks indexed access. Keep the
        // literal in this type-sensitive position. Ordinary parameter
        // defaults remain runtime strings and are still protected.
        if self.object_pattern_depth > 0 && is_ascii_string_expression(&pattern.right) {
            self.mark_string_expression(&pattern.right);
        }
        walk::walk_assignment_pattern(self, pattern);
    }

    fn visit_object_pattern(&mut self, pattern: &ObjectPattern<'b>) {
        self.object_pattern_depth = self.object_pattern_depth.saturating_add(1);
        walk::walk_object_pattern(self, pattern);
        self.object_pattern_depth = self.object_pattern_depth.saturating_sub(1);
    }
}

impl Collector {
    fn mark_string_expression<'b>(&mut self, expression: &Expression<'b>) {
        match expression {
            Expression::StringLiteral(literal) => {
                let span = (literal.span.start, literal.span.end);
                self.skip.insert(span);
                self.out.retained_values.insert(literal.value.to_string());
            }
            Expression::TemplateLiteral(literal) => {
                self.skip.insert((literal.span.start, literal.span.end));
            }
            Expression::TSAsExpression(expression) => {
                self.mark_string_expression(&expression.expression);
            }
            Expression::TSTypeAssertion(expression) => {
                self.mark_string_expression(&expression.expression);
            }
            _ => {}
        }
    }

    fn mark_contract_expression<'b>(&mut self, expression: &Expression<'b>) {
        match expression {
            Expression::StringLiteral(literal) => {
                let span = (literal.span.start, literal.span.end);
                self.skip.insert(span);
                self.out.retained_values.insert(literal.value.to_string());
            }
            Expression::TemplateLiteral(literal) => {
                self.skip.insert((literal.span.start, literal.span.end));
            }
            Expression::TSAsExpression(expression) => {
                self.mark_contract_expression(&expression.expression);
            }
            Expression::TSTypeAssertion(expression) => {
                self.mark_contract_expression(&expression.expression);
            }
            _ => {}
        }
    }
}

fn literal_contract_key(name: &str) -> bool {
    matches!(
        name,
        "id" | "type"
            | "state"
            | "status"
            | "kind"
            | "mode"
            | "view"
            | "tab"
            | "filter"
            | "key"
            | "event"
            | "media_kind"
            | "media_type"
    )
}

fn is_ascii_string_expression(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::StringLiteral(literal) => literal.value.is_ascii(),
        Expression::TemplateLiteral(literal) => literal
            .quasis
            .iter()
            .all(|quasi| quasi.value.raw.is_ascii()),
        Expression::TSAsExpression(expression) => {
            is_ascii_string_expression(&expression.expression)
        }
        Expression::TSTypeAssertion(expression) => {
            is_ascii_string_expression(&expression.expression)
        }
        _ => false,
    }
}

fn should_retain_comparison_operand(expression: &Expression<'_>, other: &Expression<'_>) -> bool {
    if !is_string_expression(expression) {
        return false;
    }
    if is_ascii_string_expression(expression) {
        return true;
    }
    static_member_name(other).is_some_and(literal_contract_key)
}

fn is_string_expression(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::StringLiteral(_)
            | Expression::TemplateLiteral(_)
            | Expression::TSAsExpression(_)
            | Expression::TSTypeAssertion(_)
    )
}

fn static_member_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression.as_member_expression()? {
        oxc_ast::ast::MemberExpression::StaticMemberExpression(member) => {
            Some(member.property.name.as_str())
        }
        _ => None,
    }
}

fn string_or_template_span(expression: &oxc_ast::ast::Expression<'_>) -> Option<(u32, u32)> {
    match expression {
        oxc_ast::ast::Expression::StringLiteral(literal) => {
            Some((literal.span.start, literal.span.end))
        }
        oxc_ast::ast::Expression::TemplateLiteral(literal) => {
            Some((literal.span.start, literal.span.end))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edits::EditPlan;
    use crate::plan::StringsPlan;
    use std::collections::HashSet;

    #[test]
    fn utf8_encoding_is_reversible() {
        let value = "中文文本";
        let key = 0x1234_5678;
        let encoded = encode(value, key);
        assert_ne!(encoded, value.as_bytes());
        assert_eq!(encoded.len(), value.len());
    }

    #[test]
    fn transforms_jsx_and_runtime_literals_but_keeps_type_literals() {
        let input = tempfile::tempdir().unwrap();
        let source_root = input.path().join("frontend/src");
        std::fs::create_dir_all(&source_root).unwrap();
        let path = source_root.join("view.tsx");
        std::fs::write(
            &path,
            r#"import React from "react";
type Mode = "replace" | "append";
export function withDefault(title = "默认提示") { return title; }
export function View() {
  const mode: Mode = "replace";
  return <button title="提示" className="stable">开始 {mode}</button>;
}
"#,
        )
        .unwrap();
        let copied = [PathBuf::from("frontend/src/view.tsx")]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let plan = StringsPlan {
            enabled: true,
            all: true,
            frontend: true,
            ..Default::default()
        };
        let mut edits = EditPlan::new();
        let outcome = run(
            &StringRequest {
                input_root: input.path(),
                source_root: &source_root,
                copied: &copied,
                plan: &plan,
                seed: 7,
                reserved_protocol_values: &HashSet::new(),
            },
            &mut edits,
        )
        .unwrap();
        assert!(outcome.occurrences_protected >= 2);
        let output = input.path().join("out");
        std::fs::create_dir_all(output.join("frontend/src")).unwrap();
        std::fs::copy(&path, output.join("frontend/src/view.tsx")).unwrap();
        edits.apply(input.path(), &output).unwrap();
        let rewritten = std::fs::read_to_string(output.join("frontend/src/view.tsx")).unwrap();
        assert!(!rewritten.contains("提示"));
        assert!(!rewritten.contains("默认提示"));
        assert!(rewritten.contains("type Mode = \"replace\" | \"append\""));
        let allocator = oxc_allocator::Allocator::default();
        let parsed = parse(&allocator, &rewritten, &path).expect("rewritten TSX remains parseable");
        assert!(parsed.body.len() >= 2);
    }
}
