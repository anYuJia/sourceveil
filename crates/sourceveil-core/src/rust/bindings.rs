//! Lexical binding rewriting, including closures and standard macro expressions.
//! Macro shells are replaced by same-length tuple/array shells for analysis
//! only. Source bytes and format strings are never reparsed as arbitrary text.

use super::{
    candidates::{self, Candidate, FileContext},
    ItemKind,
};
use crate::{
    edits::{Contribution, EditPlan},
    names::{NameCase, NameDeriver, SeedDomain},
    plan::Plan,
    report::{RenameStats, SkipReason, SkippedSymbol},
    scanner::{is_root_like, CrateGraph},
};
use anyhow::{bail, Context, Result};
use ra_ap_ide::{Indel, TextSize};
use ra_ap_syntax::{
    ast::{self, AstNode, AstToken, HasLoopBody, HasName, IsString},
    Edition, SourceFile, SyntaxElement, SyntaxKind, SyntaxNode, TextRange,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

#[derive(Default)]
pub struct Outcome {
    pub stats: RenameStats,
    pub files_scanned: usize,
    pub mapping: BTreeMap<String, String>,
    pub skipped: Vec<SkippedSymbol>,
}

/// Group the semantic pass' already-applied spellings by their original leaf
/// identifier. Rust represents `Type { field }` and `Type { field: field }`
/// with the same source token for both the field and lexical value. A field
/// rename can therefore leave the generated shorthand token carrying the new
/// field spelling before this lexical pass runs. Keeping this reverse index
/// lets us expand that token without guessing from source text.
fn renamed_spellings(symbols: &BTreeMap<String, String>) -> BTreeMap<String, HashSet<String>> {
    let mut spellings: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for (path, replacement) in symbols {
        let Some(leaf) = path.rsplit("::").next() else {
            continue;
        };
        if leaf.contains('@') {
            continue;
        }
        let leaf = leaf.strip_prefix("r#").unwrap_or(leaf);
        if leaf != replacement {
            spellings
                .entry(leaf.to_owned())
                .or_default()
                .insert(replacement.clone());
        }
    }
    spellings
}

pub fn run(
    root: &Path,
    input_root: &Path,
    graph: &CrateGraph,
    plan: &Plan,
    seed: u64,
    renamed_symbols: &BTreeMap<String, String>,
) -> Result<Outcome> {
    let mut sources = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| {
            e.depth() == 0
                || !e.file_type().is_dir()
                || !matches!(
                    e.file_name().to_str(),
                    Some("target" | "node_modules" | ".git" | ".obfuscator")
                )
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file() || entry.path().extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let relative = entry.path().strip_prefix(root)?;
        let original_path = input_root.join(relative);
        let Some(krate) = super::rename::crate_for_file(graph, &original_path) else {
            continue;
        };
        if !is_root_like(graph, &krate.name)
            && !matches!(
                plan.dependencies.mode_for(&krate.name),
                crate::config::DependencyMode::Obfuscate
                    | crate::config::DependencyMode::PrivateObfuscate
            )
        {
            continue;
        }
        if crate::copier::build_globset(&plan.keep.files)?.is_match(relative) {
            continue;
        }
        sources.push((
            entry.path().to_owned(),
            std::fs::read_to_string(entry.path())?,
        ));
    }
    let mut names = NameDeriver::new(
        seed,
        plan.rename.name_len.0,
        plan.rename.name_len.1,
        HashSet::new(),
    );
    let mut shadowed_macros = HashSet::new();
    let mut possible_constants = HashSet::from(["None".to_owned()]);
    for (_, source) in &sources {
        let tree = SourceFile::parse(source, Edition::Edition2024).tree();
        for token in tree
            .syntax()
            .descendants_with_tokens()
            .filter_map(|e| e.into_token())
        {
            if token.kind() == SyntaxKind::IDENT {
                names.reserve(token.text());
            }
        }
        for node in tree
            .syntax()
            .descendants()
            .filter_map(ast::MacroRules::cast)
        {
            if let Some(name) = node.name() {
                shadowed_macros.insert(name.text().to_string());
            }
        }
        for node in tree.syntax().descendants() {
            if let Some(import) = ast::UseTree::cast(node.clone()) {
                if import.use_tree_list().is_none() && import.star_token().is_none() {
                    if let Some(name) = import
                        .rename()
                        .and_then(|r| r.name())
                        .map(|n| n.text().to_string())
                        .or_else(|| {
                            import
                                .path()?
                                .segment()?
                                .name_ref()
                                .map(|n| n.text().to_string())
                        })
                    {
                        possible_constants.insert(name);
                    }
                }
            } else if matches!(
                node.kind(),
                SyntaxKind::CONST | SyntaxKind::STATIC | SyntaxKind::STRUCT | SyntaxKind::VARIANT
            ) {
                possible_constants.extend(
                    node.children()
                        .filter(|n| n.kind() == SyntaxKind::NAME)
                        .map(|n| n.text().to_string()),
                );
            }
        }
    }
    let keep_patterns = crate::copier::build_globset(&plan.keep.patterns)?;
    let renamed_spellings = renamed_spellings(renamed_symbols);
    let mut outcome = Outcome {
        files_scanned: sources.len(),
        ..Default::default()
    };
    let mut pending = Vec::new();
    for (path, source) in sources {
        let relative = path.strip_prefix(root)?;
        let source_tree = SourceFile::parse(&source, Edition::Edition2024).tree();
        let parsed = expanded(&source, &shadowed_macros)?;
        let mut edits = EditPlan::default();
        let select = SelectIndex::analyze(
            &source,
            &source_tree,
            &path,
            relative,
            &shadowed_macros,
            &possible_constants,
            &renamed_spellings,
            plan,
            &keep_patterns,
            &mut names,
            &mut edits,
            &mut outcome,
        )?;
        // Closures hidden in an arbitrary macro DSL cannot be traversed as
        // Rust AST. Surface that boundary instead of silently missing them.
        for node in parsed
            .tree
            .syntax()
            .descendants()
            .filter(|n| matches!(n.kind(), SyntaxKind::MACRO_CALL | SyntaxKind::MACRO_RULES))
        {
            if ast::MacroCall::cast(node.clone())
                .is_some_and(|call| select.calls.contains(&call.syntax().text_range()))
            {
                continue;
            }
            if node
                .descendants_with_tokens()
                .filter_map(|t| t.into_token())
                .any(|t| matches!(t.kind(), SyntaxKind::PIPE | SyntaxKind::PIPE2))
            {
                let offset = usize::from(node.text_range().start());
                outcome.skipped.push(SkippedSymbol{
                    name:"opaque-macro-body".into(),symbol_path:format!("{}::macro@{offset}",relative.display()),file:relative.display().to_string(),
                    line:source[..offset].bytes().filter(|b|*b==b'\n').count() as u32+1,
                    reason:SkipReason::MacroGenerated,detail:Some("opaque macro contains pipe tokens that may form closures; macro body was not rewritten".into()),
                });
            }
        }
        let ctx = FileContext {
            path: &path,
            text: &source,
            crate_name: "bindings",
            module_prefix: &[],
        };
        let candidates: Vec<_> = candidates::collect(&parsed.tree, &ctx)
            .into_iter()
            .filter(|c| matches!(c.kind, ItemKind::Local | ItemKind::Param))
            .collect();
        let index = BindingIndex::new(
            &parsed.tree,
            &candidates,
            &possible_constants,
            &select.calls,
        );
        for candidate in &candidates {
            if !candidate.kind.enabled_in(&plan.rename) {
                continue;
            }
            // `IdentPat` also represents a bare constant or unit variant in
            // pattern position. BindingIndex excludes those deliberately;
            // they are not failed binding-renames and need no report entry.
            if !index
                .bindings
                .iter()
                .any(|binding| binding.definition == candidate.name_range)
            {
                continue;
            }
            let reason = if candidate.inline_keep {
                Some((SkipReason::InlineKeepComment, "explicit inline keep rule"))
            } else if parameter_contract(candidate, &parsed.tree, plan) {
                Some((
                    SkipReason::IntrinsicAttribute,
                    "function parameter is part of an attribute-driven framework contract",
                ))
            } else if plan.keep.symbols.contains(&candidate.name)
                || keep_patterns.is_match(&candidate.name)
            {
                Some((SkipReason::KeepRule, "explicit keep rule"))
            } else if index.opaque_reference(candidate, &parsed.tree, &select.calls) {
                Some((SkipReason::MacroCallReference,"binding occurs inside an unsupported/shadowed macro or has no executable scope"))
            } else {
                None
            };
            if let Some((reason, detail)) = reason {
                outcome.skipped.push(SkippedSymbol {
                    name: candidate.name.clone(),
                    symbol_path: candidate.path.clone(),
                    file: relative.display().to_string(),
                    line: candidate.line,
                    reason,
                    detail: Some(detail.into()),
                });
                continue;
            }
            let identity = format!("{}::{}", relative.display(), candidate.path);
            let case = if candidate.name.starts_with('_') {
                NameCase::HiddenSnake
            } else {
                NameCase::Snake
            };
            let replacement = names.derive(SeedDomain::RustSymbol, &identity, case)?;
            let mut changes: Vec<_> = index
                .edits(candidate, &parsed, &replacement, &renamed_spellings)
                .into_iter()
                .map(|mut edit| {
                    let delta = TextSize::from(
                        parsed
                            .shifted_expressions
                            .iter()
                            .filter(|range| range.contains(edit.delete.start()))
                            .count() as u32,
                    );
                    edit.delete += delta;
                    edit
                })
                .collect();
            changes.extend(select.edits_for_outer(candidate, &index, &replacement));
            changes
                .sort_by_key(|edit| (edit.delete.start(), edit.delete.end(), edit.insert.clone()));
            changes
                .dedup_by(|left, right| left.delete == right.delete && left.insert == right.insert);
            if changes.is_empty() {
                continue;
            }
            let count = changes.len();
            edits
                .stage_transaction(vec![Contribution::new(&path, &source, changes)])
                .with_context(|| {
                    format!(
                        "staging closure/local binding {} in {}",
                        candidate.name,
                        path.display()
                    )
                })?;
            outcome.stats.bump(candidate.kind);
            outcome.stats.edits_applied += count;
            outcome.mapping.insert(identity, replacement);
        }
        if !edits.is_empty() {
            let changes = edits.pending_edits(&path).unwrap();
            let mut output = source.clone();
            let mut changes = changes.to_vec();
            changes.sort_by_key(|i| std::cmp::Reverse((i.delete.start(), i.delete.end())));
            for change in changes {
                output.replace_range(
                    usize::from(change.delete.start())..usize::from(change.delete.end()),
                    &change.insert,
                );
            }
            pending.push((path, output));
            outcome.stats.files_edited += 1;
        }
    }
    for (path, output) in pending {
        std::fs::write(path, output)?;
    }
    Ok(outcome)
}

/// References and embedded bindings recovered from `tokio::select!` and the
/// equivalent futures macros. Their branch grammar is not ordinary Rust, so a
/// normal syntax walk sees only an opaque token tree. Each branch is rebuilt
/// as a temporary Rust function from exact source slices; the binding resolver
/// then applies the same shadowing, shorthand-field, closure, and format-string
/// rules used for the rest of the file.
#[derive(Default)]
struct SelectIndex {
    calls: HashSet<TextRange>,
    outer: Vec<SelectOuterReference>,
}

#[derive(Clone)]
struct SelectOuterReference {
    name: String,
    range: TextRange,
    shorthand: Option<(TextRange, String)>,
    at: TextSize,
    function: Option<TextRange>,
}

#[derive(Clone, Copy)]
struct SelectPiece {
    synthetic: TextRange,
    source: TextRange,
}

impl SelectPiece {
    fn map_range(self, range: TextRange) -> Option<TextRange> {
        let within = if range.is_empty() {
            self.synthetic.start() <= range.start() && range.start() <= self.synthetic.end()
        } else {
            self.synthetic.contains_range(range)
        };
        if !within {
            return None;
        }
        let delta = range.start() - self.synthetic.start();
        Some(TextRange::at(self.source.start() + delta, range.len()))
    }
}

#[derive(Clone, Copy)]
struct SelectBranch {
    pattern: Option<TextRange>,
    future: Option<TextRange>,
    condition: Option<TextRange>,
    handler: TextRange,
    /// Non-Rust macro grammar preceding the future (`PAT =`) or, for an
    /// `else` branch, the complete `else =>` prefix.
    prefix: TextRange,
    /// The optional `, if` prefix; the condition itself remains executable
    /// Rust in the semantic shell.
    guard_prefix: Option<TextRange>,
    arrow: Option<TextRange>,
    separator: Option<TextRange>,
}

impl SelectIndex {
    #[allow(clippy::too_many_arguments)]
    fn analyze(
        source: &str,
        tree: &ast::SourceFile,
        path: &Path,
        relative: &Path,
        shadowed_macros: &HashSet<String>,
        possible_constants: &HashSet<String>,
        renamed_spellings: &BTreeMap<String, HashSet<String>>,
        plan: &Plan,
        keep_patterns: &globset::GlobSet,
        names: &mut NameDeriver,
        edits: &mut EditPlan,
        outcome: &mut Outcome,
    ) -> Result<Self> {
        let mut result = Self::default();
        for call in tree.syntax().descendants().filter_map(ast::MacroCall::cast) {
            if !is_select_macro(&call) {
                continue;
            }
            let Some(branches) = select_branches(&call) else {
                continue;
            };
            result.calls.insert(call.syntax().text_range());
            let function = enclosing_function(call.syntax());
            let at = call.syntax().text_range().start();

            for branch in branches {
                let (synthetic, pieces) = select_branch_source(source, branch);
                let expanded = expanded(&synthetic, shadowed_macros)?;
                let ctx = FileContext {
                    path,
                    text: &synthetic,
                    crate_name: "select",
                    module_prefix: &[],
                };
                let candidates: Vec<_> = candidates::collect(&expanded.tree, &ctx)
                    .into_iter()
                    .filter(|candidate| {
                        matches!(candidate.kind, ItemKind::Local | ItemKind::Param)
                            && map_select_range(
                                &pieces,
                                source_range(&expanded, candidate.name_range),
                            )
                            .is_some()
                    })
                    .collect();
                let index = BindingIndex::new(
                    &expanded.tree,
                    &candidates,
                    possible_constants,
                    &HashSet::new(),
                );

                for candidate in &candidates {
                    let Some(definition) =
                        map_select_range(&pieces, source_range(&expanded, candidate.name_range))
                    else {
                        continue;
                    };
                    if !candidate.kind.enabled_in(&plan.rename) {
                        continue;
                    }
                    if !index
                        .bindings
                        .iter()
                        .any(|binding| binding.definition == candidate.name_range)
                    {
                        continue;
                    }
                    let reason = if candidate.inline_keep {
                        Some((SkipReason::InlineKeepComment, "explicit inline keep rule"))
                    } else if plan.keep.symbols.contains(&candidate.name)
                        || keep_patterns.is_match(&candidate.name)
                    {
                        Some((SkipReason::KeepRule, "explicit keep rule"))
                    } else if index.opaque_reference(candidate, &expanded.tree, &HashSet::new()) {
                        Some((
                            SkipReason::MacroCallReference,
                            "select branch binding occurs inside an unsupported nested macro",
                        ))
                    } else {
                        None
                    };
                    if let Some((reason, detail)) = reason {
                        outcome.skipped.push(SkippedSymbol {
                            name: candidate.name.clone(),
                            symbol_path: format!(
                                "{}::select@{}::{}@{}",
                                relative.display(),
                                u32::from(at),
                                candidate.name,
                                u32::from(definition.start())
                            ),
                            file: relative.display().to_string(),
                            line: line_of(source, definition.start()),
                            reason,
                            detail: Some(detail.into()),
                        });
                        continue;
                    }

                    let identity = format!(
                        "{}::select@{}::{}@{}",
                        relative.display(),
                        u32::from(at),
                        candidate.name,
                        u32::from(definition.start())
                    );
                    let case = if candidate.name.starts_with('_') {
                        NameCase::HiddenSnake
                    } else {
                        NameCase::Snake
                    };
                    let replacement = names.derive(SeedDomain::RustSymbol, &identity, case)?;
                    let mut changes = Vec::new();
                    for edit in index.edits(candidate, &expanded, &replacement, renamed_spellings) {
                        let source_edit = source_range(&expanded, edit.delete);
                        let Some(delete) = map_select_range(&pieces, source_edit) else {
                            continue;
                        };
                        changes.push(Indel {
                            delete,
                            insert: edit.insert,
                        });
                    }
                    changes.sort_by_key(|edit| {
                        (edit.delete.start(), edit.delete.end(), edit.insert.clone())
                    });
                    changes.dedup_by(|left, right| {
                        left.delete == right.delete && left.insert == right.insert
                    });
                    if changes.is_empty() {
                        continue;
                    }
                    let count = changes.len();
                    edits
                        .stage_transaction(vec![Contribution::new(path, source, changes)])
                        .with_context(|| {
                            format!(
                                "staging select binding {} in {}",
                                candidate.name,
                                path.display()
                            )
                        })?;
                    outcome.stats.bump(candidate.kind);
                    outcome.stats.edits_applied += count;
                    outcome.mapping.insert(identity, replacement);
                }

                for token in expanded
                    .tree
                    .syntax()
                    .descendants_with_tokens()
                    .filter_map(|element| element.into_token())
                    .filter(|token| token.kind() == SyntaxKind::IDENT)
                {
                    let range = token.text_range();
                    if expanded.labels.contains(&range) {
                        continue;
                    }
                    let Some(mapped) = map_select_range(&pieces, source_range(&expanded, range))
                    else {
                        continue;
                    };
                    let parent = token.parent().unwrap();
                    let is_reference = parent
                        .ancestors()
                        .find_map(ast::PathExpr::cast)
                        .is_some_and(|expression| expression.syntax().text_range() == range);
                    if !is_reference
                        || index
                            .resolve(token.text(), range.start(), enclosing_function(&parent))
                            .is_some()
                    {
                        continue;
                    }
                    let shorthand = select_shorthand(&parent, &pieces, &expanded, token.text());
                    result.outer.push(SelectOuterReference {
                        name: token.text().to_string(),
                        range: mapped,
                        shorthand,
                        at,
                        function,
                    });
                }
                for capture in &expanded.format_refs {
                    let function_in_branch = expanded
                        .tree
                        .syntax()
                        .token_at_offset(capture.at)
                        .right_biased()
                        .and_then(|token| token.parent())
                        .and_then(|parent| enclosing_function(&parent));
                    if index
                        .resolve(&capture.name, capture.at, function_in_branch)
                        .is_some()
                    {
                        continue;
                    }
                    let Some(range) =
                        map_select_range(&pieces, source_range(&expanded, capture.range))
                    else {
                        continue;
                    };
                    result.outer.push(SelectOuterReference {
                        name: capture.name.clone(),
                        range,
                        shorthand: None,
                        at,
                        function,
                    });
                }
            }
        }
        result.outer.sort_by(|left, right| {
            left.range
                .start()
                .cmp(&right.range.start())
                .then(left.range.end().cmp(&right.range.end()))
                .then(left.name.cmp(&right.name))
        });
        result
            .outer
            .dedup_by(|left, right| left.range == right.range && left.name == right.name);
        Ok(result)
    }

    fn edits_for_outer(
        &self,
        candidate: &Candidate,
        index: &BindingIndex,
        replacement: &str,
    ) -> Vec<Indel> {
        let mut edits = Vec::new();
        for reference in &self.outer {
            if reference.name != candidate.name
                || index.resolve(&candidate.name, reference.at, reference.function)
                    != Some(candidate.name_range)
            {
                continue;
            }
            if let Some((at, field)) = &reference.shorthand {
                edits.push(Indel {
                    delete: *at,
                    insert: format!("{field}: "),
                });
            }
            edits.push(Indel {
                delete: reference.range,
                insert: replacement.to_string(),
            });
        }
        edits
    }
}

fn select_shorthand(
    parent: &SyntaxNode,
    pieces: &[SelectPiece],
    expanded: &Expanded,
    field: &str,
) -> Option<(TextRange, String)> {
    let record = parent.ancestors().find(|node| {
        matches!(
            node.kind(),
            SyntaxKind::RECORD_EXPR_FIELD | SyntaxKind::RECORD_PAT_FIELD
        )
    })?;
    if record
        .children_with_tokens()
        .any(|element| element.kind() == SyntaxKind::COLON)
    {
        return None;
    }
    let at = source_range(expanded, TextRange::empty(record.text_range().start()));
    map_select_range(pieces, at).map(|range| (range, field.to_string()))
}

fn map_select_range(pieces: &[SelectPiece], range: TextRange) -> Option<TextRange> {
    pieces.iter().find_map(|piece| piece.map_range(range))
}

fn line_of(source: &str, at: TextSize) -> u32 {
    source[..usize::from(at)]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count() as u32
        + 1
}

fn select_branch_source(source: &str, branch: SelectBranch) -> (String, Vec<SelectPiece>) {
    let mut synthetic = "fn __sv(){".to_string();
    let mut pieces = Vec::new();
    if let Some(future) = branch.future {
        synthetic.push_str("let _=(");
        push_select_piece(&mut synthetic, &mut pieces, source, future);
        synthetic.push_str(");");
    }
    if let Some(condition) = branch.condition {
        synthetic.push_str("if(");
        push_select_piece(&mut synthetic, &mut pieces, source, condition);
        synthetic.push_str("){}");
    }
    if let Some(pattern) = branch.pattern {
        synthetic.push_str("if let ");
        push_select_piece(&mut synthetic, &mut pieces, source, pattern);
        synthetic.push_str("=loop{}{");
        push_select_piece(&mut synthetic, &mut pieces, source, branch.handler);
        synthetic.push('}');
    } else {
        synthetic.push_str("if true{");
        push_select_piece(&mut synthetic, &mut pieces, source, branch.handler);
        synthetic.push('}');
    }
    synthetic.push('}');
    (synthetic, pieces)
}

fn push_select_piece(
    synthetic: &mut String,
    pieces: &mut Vec<SelectPiece>,
    source: &str,
    range: TextRange,
) {
    let start = TextSize::from(synthetic.len() as u32);
    synthetic.push_str(&source[usize::from(range.start())..usize::from(range.end())]);
    pieces.push(SelectPiece {
        synthetic: TextRange::at(start, range.len()),
        source: range,
    });
}

fn is_select_macro(call: &ast::MacroCall) -> bool {
    let Some(path) = call.path() else {
        return false;
    };
    let path = path.syntax().text().to_string().replace(' ', "");
    matches!(
        path.as_str(),
        "tokio::select" | "futures::select" | "futures_util::select"
    )
}

fn select_branches(call: &ast::MacroCall) -> Option<Vec<SelectBranch>> {
    let token_tree = call.token_tree()?;
    let tree_range = token_tree.syntax().text_range();
    let elements: Vec<SyntaxElement> = token_tree
        .syntax()
        .children_with_tokens()
        .filter(|element| {
            !element.kind().is_trivia()
                && element.text_range().start() > tree_range.start()
                && element.text_range().end() < tree_range.end()
        })
        .collect();
    let mut cursor = 0usize;
    if elements
        .get(cursor)
        .is_some_and(|element| element.to_string() == "biased")
        && elements
            .get(cursor + 1)
            .is_some_and(|element| element.kind() == SyntaxKind::SEMICOLON)
    {
        cursor += 2;
    }
    let mut branches = Vec::new();
    while cursor < elements.len() {
        while elements
            .get(cursor)
            .is_some_and(|element| element.kind() == SyntaxKind::COMMA)
        {
            cursor += 1;
        }
        if cursor >= elements.len() {
            break;
        }
        // Inside an unexpanded token tree `=>` is represented by the two raw
        // tokens `=` and `>` rather than the parser-level `FAT_ARROW` kind.
        let arrow = (cursor..elements.len().saturating_sub(1)).find(|index| {
            elements[*index].kind() == SyntaxKind::EQ
                && elements[*index + 1].kind() == SyntaxKind::R_ANGLE
        })?;
        let handler_index = arrow + 2;
        let handler_first = elements.get(handler_index)?;
        let (handler, next) = if handler_first
            .as_node()
            .and_then(|node| ast::TokenTree::cast(node.clone()))
            .is_some_and(|tree| {
                tree.syntax()
                    .first_token()
                    .is_some_and(|token| token.kind() == SyntaxKind::L_CURLY)
            }) {
            (handler_first.text_range(), handler_index + 1)
        } else {
            let end = (handler_index..elements.len())
                .find(|index| elements[*index].kind() == SyntaxKind::COMMA)
                .unwrap_or(elements.len());
            if end == handler_index {
                return None;
            }
            (
                TextRange::new(
                    elements[handler_index].text_range().start(),
                    elements[end - 1].text_range().end(),
                ),
                end,
            )
        };

        if elements[cursor].to_string() == "else" {
            let separator = elements
                .get(next)
                .filter(|element| element.kind() == SyntaxKind::COMMA)
                .map(SyntaxElement::text_range);
            branches.push(SelectBranch {
                pattern: None,
                future: None,
                condition: None,
                handler,
                prefix: TextRange::new(
                    elements[cursor].text_range().start(),
                    elements[arrow + 1].text_range().end(),
                ),
                guard_prefix: None,
                arrow: None,
                separator,
            });
            cursor = next;
            continue;
        }

        let equals = (cursor..arrow).find(|index| elements[*index].kind() == SyntaxKind::EQ)?;
        if equals == cursor || equals + 1 == arrow {
            return None;
        }
        let guard_comma = (equals + 1..arrow).find(|index| {
            elements[*index].kind() == SyntaxKind::COMMA
                && elements
                    .get(*index + 1)
                    .is_some_and(|element| element.to_string() == "if")
        });
        let future_end = guard_comma.unwrap_or(arrow);
        if future_end == equals + 1 {
            return None;
        }
        let condition = guard_comma.map(|comma| {
            TextRange::new(
                elements[comma + 2].text_range().start(),
                elements[arrow - 1].text_range().end(),
            )
        });
        let future = TextRange::new(
            elements[equals + 1].text_range().start(),
            elements[future_end - 1].text_range().end(),
        );
        let separator = elements
            .get(next)
            .filter(|element| element.kind() == SyntaxKind::COMMA)
            .map(SyntaxElement::text_range);
        branches.push(SelectBranch {
            pattern: Some(TextRange::new(
                elements[cursor].text_range().start(),
                elements[equals - 1].text_range().end(),
            )),
            future: Some(future),
            condition,
            handler,
            prefix: TextRange::new(elements[cursor].text_range().start(), future.start()),
            guard_prefix: guard_comma.map(|comma| {
                TextRange::new(
                    elements[comma].text_range().start(),
                    elements[comma + 2].text_range().start(),
                )
            }),
            arrow: Some(TextRange::new(
                elements[arrow].text_range().start(),
                elements[arrow + 1].text_range().end(),
            )),
            separator,
        });
        cursor = next;
    }
    (!branches.is_empty()).then_some(branches)
}

fn mask_analysis_range(bytes: &[u8], range: TextRange, changes: &mut Vec<(TextSize, u8)>) {
    let start = usize::from(range.start());
    let end = usize::from(range.end());
    for (offset, byte) in bytes[start..end].iter().enumerate() {
        let at = start + offset;
        if !matches!(*byte, b'\n' | b'\r') {
            changes.push((TextSize::from(at as u32), b' '));
        }
    }
}

fn possible_constant_names(tree: &ast::SourceFile) -> HashSet<String> {
    let mut names = HashSet::from(["None".to_string()]);
    for node in tree.syntax().descendants() {
        if let Some(import) = ast::UseTree::cast(node.clone()) {
            if import.use_tree_list().is_none() && import.star_token().is_none() {
                if let Some(name) = import
                    .rename()
                    .and_then(|rename| rename.name())
                    .map(|name| name.text().to_string())
                    .or_else(|| {
                        import
                            .path()?
                            .segment()?
                            .name_ref()
                            .map(|name| name.text().to_string())
                    })
                {
                    names.insert(name);
                }
            }
        } else if matches!(
            node.kind(),
            SyntaxKind::CONST | SyntaxKind::STATIC | SyntaxKind::STRUCT | SyntaxKind::VARIANT
        ) {
            names.extend(
                node.children()
                    .filter(|child| child.kind() == SyntaxKind::NAME)
                    .map(|child| child.text().to_string()),
            );
        }
    }
    names
}

fn select_local_ranges(
    source: &str,
    branches: &[SelectBranch],
    shadowed_macros: &HashSet<String>,
    possible_constants: &HashSet<String>,
) -> Result<Vec<TextRange>> {
    let mut ranges = Vec::new();
    for branch in branches {
        let (synthetic, pieces) = select_branch_source(source, *branch);
        let expanded = expanded(&synthetic, shadowed_macros)?;
        let ctx = FileContext {
            path: Path::new("select-analysis.rs"),
            text: &synthetic,
            crate_name: "select",
            module_prefix: &[],
        };
        let candidates: Vec<_> = candidates::collect(&expanded.tree, &ctx)
            .into_iter()
            .filter(|candidate| {
                matches!(candidate.kind, ItemKind::Local | ItemKind::Param)
                    && map_select_range(&pieces, source_range(&expanded, candidate.name_range))
                        .is_some()
            })
            .collect();
        let index = BindingIndex::new(
            &expanded.tree,
            &candidates,
            possible_constants,
            &HashSet::new(),
        );
        for candidate in &candidates {
            if !index
                .bindings
                .iter()
                .any(|binding| binding.definition == candidate.name_range)
            {
                continue;
            }
            for edit in index.edits(
                candidate,
                &expanded,
                "__sourceveil_binding",
                &BTreeMap::new(),
            ) {
                if edit.delete.is_empty() {
                    continue;
                }
                if let Some(range) = map_select_range(&pieces, source_range(&expanded, edit.delete))
                {
                    ranges.push(range);
                }
            }
        }
    }
    ranges.sort_by_key(|range| (range.start(), range.end()));
    ranges.dedup();
    Ok(ranges)
}

struct Expanded {
    tree: ast::SourceFile,
    format_refs: Vec<FormatRef>,
    labels: HashSet<TextRange>,
    shifted_expressions: Vec<TextRange>,
}
struct FormatRef {
    name: String,
    range: TextRange,
    at: TextSize,
}

pub(crate) struct MacroAnalysisSource {
    pub text: String,
    shifted_expressions: Vec<TextRange>,
}

impl MacroAnalysisSource {
    /// Map a range in the real source into the same-length analysis shell.
    /// Most macro arguments keep their offsets. `matches!` moves only its
    /// scrutinee one byte left, and nested calls can accumulate that shift.
    pub fn analysis_range(&self, source: TextRange) -> TextRange {
        for delta in 0..=self.shifted_expressions.len() {
            let delta = TextSize::from(delta as u32);
            let Some(start) = source.start().checked_sub(delta) else {
                continue;
            };
            let Some(end) = source.end().checked_sub(delta) else {
                continue;
            };
            let candidate = TextRange::new(start, end);
            let mapped = TextSize::from(
                self.shifted_expressions
                    .iter()
                    .filter(|shifted| shifted.contains(candidate.start()))
                    .count() as u32,
            );
            if candidate + mapped == source {
                return candidate;
            }
        }
        source
    }
}

pub(crate) fn macro_analysis_source(
    source: &str,
    shadowed: &HashSet<String>,
) -> Result<MacroAnalysisSource> {
    let parsed = expanded(source, shadowed)?;
    Ok(MacroAnalysisSource {
        text: parsed.tree.syntax().text().to_string(),
        shifted_expressions: parsed.shifted_expressions,
    })
}

/// Identifier-shaped tokens inside supported macro DSLs that are metadata,
/// not Rust references (for example a `json!` object key or `target:` in a
/// log macro). The semantic rename pass uses this set when deciding whether an
/// unresolved macro token is a real safety boundary.
pub(crate) fn macro_label_ranges(
    source: &str,
    shadowed: &HashSet<String>,
) -> Result<HashSet<TextRange>> {
    let parsed = expanded(source, shadowed)?;
    Ok(parsed
        .labels
        .iter()
        .map(|range| source_range(&parsed, *range))
        .collect())
}

/// Implicit named captures embedded in supported format-string macros, mapped
/// back to their exact source spans. rust-analyzer can resolve these spans to
/// definitions even though `rename` does not always include the call-site
/// edit.
pub(crate) fn macro_format_references(
    source: &str,
    shadowed: &HashSet<String>,
) -> Result<Vec<(String, TextRange)>> {
    let parsed = expanded(source, shadowed)?;
    Ok(parsed
        .format_refs
        .iter()
        .map(|reference| {
            (
                reference.name.clone(),
                source_range(&parsed, reference.range),
            )
        })
        .collect())
}

fn source_range(expanded: &Expanded, range: TextRange) -> TextRange {
    let delta = TextSize::from(
        expanded
            .shifted_expressions
            .iter()
            .filter(|shifted| shifted.contains(range.start()))
            .count() as u32,
    );
    range + delta
}

fn parameter_contract(candidate: &Candidate, tree: &ast::SourceFile, plan: &Plan) -> bool {
    if candidate.kind != ItemKind::Param {
        return false;
    }
    let Some(parent) = tree
        .syntax()
        .token_at_offset(candidate.name_range.start())
        .right_biased()
        .and_then(|t| t.parent())
    else {
        return false;
    };
    let Some(container) = parent
        .ancestors()
        .find(|n| matches!(n.kind(), SyntaxKind::CLOSURE_EXPR | SyntaxKind::FN))
    else {
        return false;
    };
    container.kind() == SyntaxKind::FN
        && candidates::attribute_names(&container).iter().any(|attr| {
            attr == "command" || attr == "tauri::command" || plan.keep.attributes.contains(attr)
        })
}

pub(crate) fn macro_kind(
    call: &ast::MacroCall,
    shadowed: &HashSet<String>,
) -> Option<(bool, Option<usize>)> {
    let path = call.path()?.syntax().text().to_string().replace(' ', "");
    let parts: Vec<_> = path.split("::").filter(|s| !s.is_empty()).collect();
    let name = *parts.last()?;
    if shadowed.contains(name)
        || (parts.len() > 1
            && !matches!(parts[0], "std" | "core" | "alloc")
            && !(parts == ["serde_json", "json"])
            && !(parts.len() == 2
                && parts[0] == "log"
                && matches!(name, "info" | "warn" | "error" | "debug" | "trace" | "log"))
            && !(parts.len() == 2
                && parts[0] == "anyhow"
                && matches!(name, "anyhow" | "bail" | "ensure"))
            && !(parts.len() == 2 && matches!(parts[0], "tokio" | "futures") && name == "join"))
    {
        return None;
    }
    Some(match name {
        "vec" => (true, None),
        // These macros evaluate a comma-separated list of ordinary Rust
        // expressions. A tuple is an exact syntax-analysis shell for them.
        "join" if matches!(parts.as_slice(), ["tokio" | "futures", "join"]) => (false, None),
        "dbg" => (false, None),
        "json" => (false, None),
        "matches" => (false, None),
        "info" | "warn" | "error" | "debug" | "trace" | "anyhow" | "bail" => (false, Some(0)),
        "log" | "ensure" => (false, Some(1)),
        "format" | "format_args" | "format_args_nl" | "print" | "println" | "eprint"
        | "eprintln" | "panic" => (false, Some(0)),
        "write" | "writeln" | "assert" | "debug_assert" => (false, Some(1)),
        "assert_eq" | "assert_ne" | "debug_assert_eq" | "debug_assert_ne" => (false, Some(2)),
        _ => return None,
    })
}

fn expanded(source: &str, shadowed: &HashSet<String>) -> Result<Expanded> {
    let mut bytes = source.as_bytes().to_vec();
    let mut format_refs = Vec::new();
    let mut labels = HashSet::new();
    let mut shifted_expressions = Vec::new();
    for _ in 0..128 {
        let text = std::str::from_utf8(&bytes)?;
        let tree = SourceFile::parse(text, Edition::Edition2024).tree();
        let mut changes = Vec::new();
        let mut json_changes = Vec::new();
        let mut matches_moves = Vec::new();
        for call in tree.syntax().descendants().filter_map(ast::MacroCall::cast) {
            if is_select_macro(&call) {
                let Some(branches) = select_branches(&call) else {
                    continue;
                };
                let Some(token_tree) = call.token_tree() else {
                    continue;
                };
                // Erase the macro path while retaining its braces as an
                // ordinary block. Every future, precondition and handler stays
                // at the exact same byte offset, so rust-analyzer can resolve
                // item/field references inside this macro DSL.
                mask_analysis_range(
                    &bytes,
                    TextRange::new(
                        call.syntax().text_range().start(),
                        token_tree.syntax().text_range().start(),
                    ),
                    &mut json_changes,
                );
                let token_elements: Vec<_> = token_tree
                    .syntax()
                    .children_with_tokens()
                    .filter(|element| !element.kind().is_trivia())
                    .collect();
                if token_elements.len() >= 4
                    && token_elements[1].to_string() == "biased"
                    && token_elements[2].kind() == SyntaxKind::SEMICOLON
                {
                    mask_analysis_range(
                        &bytes,
                        TextRange::new(
                            token_elements[1].text_range().start(),
                            token_elements[2].text_range().end(),
                        ),
                        &mut json_changes,
                    );
                }
                let possible_constants = possible_constant_names(&tree);
                labels.extend(select_local_ranges(
                    text,
                    &branches,
                    shadowed,
                    &possible_constants,
                )?);
                for branch in branches {
                    mask_analysis_range(&bytes, branch.prefix, &mut json_changes);
                    if let Some(guard) = branch.guard_prefix {
                        mask_analysis_range(&bytes, guard, &mut json_changes);
                        json_changes.push((guard.start(), b';'));
                    }
                    if let Some(arrow) = branch.arrow {
                        mask_analysis_range(&bytes, arrow, &mut json_changes);
                        json_changes.push((arrow.start(), b';'));
                    }
                    if let Some(separator) = branch.separator {
                        mask_analysis_range(&bytes, separator, &mut json_changes);
                    }
                }
                continue;
            }
            let Some((array, mut format_index)) = macro_kind(&call, shadowed) else {
                continue;
            };
            let Some(tt) = call.token_tree() else {
                continue;
            };
            let range = tt.syntax().text_range();
            let start = call.path().unwrap().syntax().text_range().start();
            if call
                .path()
                .unwrap()
                .segment()
                .and_then(|s| s.name_ref())
                .is_some_and(|n| n.text() == "matches")
            {
                let Some(comma) = matches_separator(&tt) else {
                    continue;
                };
                // An analysis-only match arm without a body still exposes
                // the complete scrutinee, pattern and guard AST, including
                // closures and guard bindings. All source offsets stay fixed.
                changes.push((start, range, false));
                for (i, byte) in b"match".iter().enumerate() {
                    json_changes.push((start + TextSize::from(i as u32), *byte));
                }
                json_changes.push((range.start(), b' '));
                json_changes.push((comma, b'{'));
                json_changes.push((range.end() - TextSize::from(1), b'}'));
                matches_moves.push((range.start(), comma));
                continue;
            }
            if call
                .path()
                .unwrap()
                .segment()
                .and_then(|s| s.name_ref())
                .is_some_and(|n| n.text() == "json")
            {
                let inner: Vec<_> = tt
                    .syntax()
                    .children_with_tokens()
                    .filter(|el| {
                        el.text_range().start() > range.start()
                            && el.text_range().end() < range.end()
                            && !el.kind().is_trivia()
                    })
                    .collect();
                json_value(&inner, &mut json_changes, &mut labels);
            }
            let mut args: Vec<Vec<ra_ap_syntax::SyntaxElement>> = vec![Vec::new()];
            for el in tt.syntax().children_with_tokens().skip(1) {
                if el.text_range().end() == range.end() {
                    break;
                }
                if el.kind() == SyntaxKind::COMMA {
                    args.push(Vec::new());
                } else if !el.kind().is_trivia() {
                    args.last_mut().unwrap().push(el);
                }
            }
            let mut explicit = HashSet::new();
            if let Some(arg) = args.first().filter(|arg| {
                arg.len() >= 3
                    && arg[0].to_string() == "target"
                    && arg[1].kind() == SyntaxKind::COLON
            }) {
                // log!(target: "name", ...) uses a metadata prefix rather
                // than a Rust named argument. Erase just that prefix for AST.
                for at in
                    usize::from(arg[0].text_range().start())..usize::from(arg[1].text_range().end())
                {
                    json_changes.push((TextSize::from(at as u32), b' '));
                }
                labels.insert(arg[0].text_range());
                format_index = format_index.map(|index| index + 1);
            }
            if let Some(index) = format_index {
                for arg in args.iter().skip(index + 1) {
                    if arg.len() >= 2
                        && arg[0].kind() == SyntaxKind::IDENT
                        && arg[1].kind() == SyntaxKind::EQ
                    {
                        explicit.insert(arg[0].to_string());
                        labels.insert(arg[0].text_range());
                    }
                }
                if let Some(arg) = args.get(index).filter(|a| a.len() == 1) {
                    if let Some(token) =
                        arg[0].as_token().and_then(|t| ast::String::cast(t.clone()))
                    {
                        for (name, range) in format_names(&token)? {
                            if !explicit.contains(&name) {
                                format_refs.push(FormatRef {
                                    name,
                                    range,
                                    at: token.syntax().text_range().start(),
                                });
                            }
                        }
                    }
                }
            }
            changes.push((start, range, array));
        }
        if changes.is_empty() && json_changes.is_empty() && matches_moves.is_empty() {
            return Ok(Expanded {
                tree,
                format_refs,
                labels,
                shifted_expressions,
            });
        }
        for (start, range, array) in changes {
            for byte in &mut bytes[usize::from(start)..usize::from(range.start())] {
                if !matches!(*byte, b'\n' | b'\r') {
                    *byte = b' ';
                }
            }
            bytes[usize::from(range.start())] = if array { b'[' } else { b'(' };
            bytes[usize::from(range.end()) - 1] = if array { b']' } else { b')' };
        }
        for (at, byte) in json_changes {
            bytes[usize::from(at)] = byte;
        }
        for (open, comma) in matches_moves {
            // The shorter `match` keyword leaves one spare byte before the
            // scrutinee. Shift only that expression one byte left to fit
            // parentheses: bare closures otherwise swallow the arm as a
            // struct literal. Translate its edit spans back on output.
            bytes.copy_within(usize::from(open) + 1..usize::from(comma), usize::from(open));
            bytes[usize::from(open) - 1] = b'(';
            bytes[usize::from(comma) - 1] = b')';
            shifted_expressions.push(TextRange::new(open, comma - TextSize::from(1)));
        }
    }
    bail!("standard macro nesting exceeds the binding-analysis limit")
}

fn matches_separator(tt: &ast::TokenTree) -> Option<TextSize> {
    let text = tt.syntax().text().to_string();
    let inner = &text[1..text.len() - 1];
    let prefix = "fn __sv(){let _=(";
    let parsed = SourceFile::parse(&format!("{prefix}{inner});}}"), Edition::Edition2024).tree();
    let tuple = parsed
        .syntax()
        .descendants()
        .find_map(ast::TupleExpr::cast)?;
    let first = tuple.fields().next()?;
    let end = usize::from(first.syntax().text_range().end()).checked_sub(prefix.len())?;
    let original = tt.syntax().text_range().start() + TextSize::from((end + 1) as u32);
    tt.syntax()
        .children_with_tokens()
        .find(|el| el.kind() == SyntaxKind::COMMA && el.text_range().start() >= original)
        .map(|el| el.text_range().start())
}

// JSON object punctuation is converted only in the analysis copy. Each JSON
// value remains a Rust expression, exposing closures without touching keys.
fn json_value(
    elements: &[ra_ap_syntax::SyntaxElement],
    changes: &mut Vec<(TextSize, u8)>,
    labels: &mut HashSet<TextRange>,
) {
    if elements.len() != 1 {
        return;
    }
    let value = &elements[0];
    if value.kind() == SyntaxKind::IDENT && value.to_string() == "null" {
        labels.insert(value.text_range());
        return;
    }
    let Some(tree) = value.as_node().cloned().and_then(ast::TokenTree::cast) else {
        return;
    };
    let Some(first) = tree.syntax().first_token() else {
        return;
    };
    let object = first.kind() == SyntaxKind::L_CURLY;
    if !object && first.kind() != SyntaxKind::L_BRACK {
        return;
    }
    let range = tree.syntax().text_range();
    if object {
        changes.push((range.start(), b'['));
        changes.push((range.end() - TextSize::from(1), b']'));
    }
    let inner: Vec<_> = tree
        .syntax()
        .children_with_tokens()
        .filter(|el| {
            el.text_range().start() > range.start()
                && el.text_range().end() < range.end()
                && !el.kind().is_trivia()
        })
        .collect();
    let mut value_start = 0;
    let mut key = object;
    for (i, el) in inner.iter().enumerate() {
        if object && key && el.kind() == SyntaxKind::COLON {
            // A JSON object key is protocol data, not a Rust reference. Mark
            // every identifier in that key so the semantic macro-reference
            // index does not accidentally associate it with an unrelated
            // field or local of the same spelling.
            for key_element in &inner[value_start..i] {
                if let Some(token) = key_element.as_token() {
                    if token.kind() == SyntaxKind::IDENT {
                        labels.insert(token.text_range());
                    }
                } else if let Some(node) = key_element.as_node() {
                    labels.extend(
                        node.descendants_with_tokens()
                            .filter_map(|element| element.into_token())
                            .filter(|token| token.kind() == SyntaxKind::IDENT)
                            .map(|token| token.text_range()),
                    );
                }
            }
            changes.push((el.text_range().start(), b','));
            key = false;
            value_start = i + 1;
        } else if el.kind() == SyntaxKind::COMMA {
            if !key {
                json_value(&inner[value_start..i], changes, labels);
            }
            key = object;
            value_start = i + 1;
        }
    }
    if !key {
        json_value(&inner[value_start..], changes, labels);
    }
}

pub(crate) fn format_names(token: &ast::String) -> Result<Vec<(String, TextRange)>> {
    use rustc_parse_format::{Count, ParseMode, Parser, Piece, Position};
    let value = token
        .value()
        .map_err(|_| anyhow::anyhow!("invalid format string literal"))?;
    let text = token.text();
    let style = token
        .is_raw()
        .then(|| text.bytes().skip(1).take_while(|b| *b == b'#').count());
    let mut parser = Parser::new(
        &value,
        style,
        Some(text.to_string()),
        false,
        ParseMode::Format,
    );
    let mut refs = Vec::new();
    for piece in parser.by_ref() {
        let Piece::NextArgument(arg) = piece else {
            continue;
        };
        if let Position::ArgumentNamed(name) = arg.position {
            refs.push((name.to_string(), arg.position_span));
        }
        for count in [arg.format.width, arg.format.precision] {
            if let Count::CountIsName(name, range) = count {
                refs.push((name.to_string(), range));
            }
        }
    }
    if !parser.errors.is_empty() {
        return Ok(Vec::new());
    }
    let offset = token.syntax().text_range().start();
    Ok(refs
        .into_iter()
        .map(|(name, range)| {
            (
                name,
                TextRange::new(
                    TextSize::from(range.start as u32),
                    TextSize::from(range.end as u32),
                ) + offset,
            )
        })
        .collect())
}

struct Binding {
    definition: TextRange,
    name: String,
    visible: TextRange,
    owner: TextRange,
    function: Option<TextRange>,
}

#[derive(Clone)]
struct BindingToken {
    text: String,
    range: TextRange,
    path_expr: bool,
    shorthand: Option<TextRange>,
    function: Option<TextRange>,
    resolved: Option<TextRange>,
}

struct BindingIndex {
    bindings: Vec<Binding>,
    by_name: HashMap<String, Vec<usize>>,
    by_definition: HashMap<TextRange, usize>,
    tokens_by_name: HashMap<String, Vec<BindingToken>>,
    opaque_bindings: HashSet<TextRange>,
}

impl BindingIndex {
    fn new(
        tree: &ast::SourceFile,
        candidates: &[Candidate],
        possible_constants: &HashSet<String>,
        supported_macro_calls: &HashSet<TextRange>,
    ) -> Self {
        let mut bindings = Vec::new();
        for pat in tree.syntax().descendants().filter_map(ast::IdentPat::cast) {
            let Some(name) = pat.name() else {
                continue;
            };
            let definition = name.syntax().text_range();
            if !candidates.iter().any(|c| c.name_range == definition) {
                continue;
            }
            // A bare pattern may denote a constant/unit variant, not a new
            // lexical variable. Do not let a syntax-only pass rebind it.
            if possible_constants.contains(name.text()) && pat.syntax().text_range() == definition {
                continue;
            }
            let Some((visible, owner)) = visibility(pat.syntax()) else {
                continue;
            };
            bindings.push(Binding {
                definition,
                name: name.text().to_string(),
                visible,
                owner,
                function: enclosing_function(pat.syntax()),
            });
        }
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_definition = HashMap::new();
        for (index, binding) in bindings.iter().enumerate() {
            by_name.entry(binding.name.clone()).or_default().push(index);
            by_definition.insert(binding.definition, index);
        }
        let mut tokens_by_name: HashMap<String, Vec<BindingToken>> = HashMap::new();
        for token in tree
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .filter(|token| token.kind() == SyntaxKind::IDENT)
        {
            let range = token.text_range();
            let parent = token.parent().unwrap();
            let record = parent.ancestors().find(|node| {
                matches!(
                    node.kind(),
                    SyntaxKind::RECORD_EXPR_FIELD | SyntaxKind::RECORD_PAT_FIELD
                )
            });
            let shorthand = record.as_ref().and_then(|node| {
                (!node
                    .children_with_tokens()
                    .any(|element| element.kind() == SyntaxKind::COLON))
                .then_some(node.text_range())
            });
            let path_expr = parent
                .ancestors()
                .find_map(ast::PathExpr::cast)
                .is_some_and(|expression| expression.syntax().text_range() == range);
            tokens_by_name
                .entry(token.text().to_string())
                .or_default()
                .push(BindingToken {
                    text: token.text().to_string(),
                    range,
                    path_expr,
                    shorthand,
                    function: enclosing_function(&parent),
                    resolved: None,
                });
        }
        let mut index = Self {
            bindings,
            by_name,
            by_definition,
            tokens_by_name,
            opaque_bindings: HashSet::new(),
        };
        index.resolve_token_bindings();
        index.opaque_bindings = index.compute_opaque_bindings(tree, supported_macro_calls);
        index
    }

    fn resolve_token_bindings(&mut self) {
        let tokens: Vec<(String, TextSize, Option<TextRange>)> = self
            .tokens_by_name
            .values()
            .flatten()
            .map(|token| (token.text.clone(), token.range.start(), token.function))
            .collect();
        let mut resolved = HashMap::new();
        for (name, at, function) in tokens {
            resolved.insert(
                (name.clone(), at, function),
                self.resolve_by_name_at(&name, at, function),
            );
        }
        for token in self.tokens_by_name.values_mut().flatten() {
            token.resolved = resolved
                .get(&(token.text.clone(), token.range.start(), token.function))
                .copied()
                .flatten();
        }
    }

    fn resolve_by_name_at(
        &self,
        name: &str,
        at: TextSize,
        function: Option<TextRange>,
    ) -> Option<TextRange> {
        self.by_name
            .get(name)?
            .iter()
            .copied()
            .filter_map(|index| {
                let binding = &self.bindings[index];
                (binding.visible.contains(at) && binding.function == function).then_some(binding)
            })
            .max_by_key(|binding| {
                (
                    binding.visible.start(),
                    std::cmp::Reverse(binding.visible.len()),
                    std::cmp::Reverse(binding.definition.start()),
                )
            })
            .map(|binding| binding.definition)
    }

    fn resolve(&self, name: &str, at: TextSize, function: Option<TextRange>) -> Option<TextRange> {
        self.resolve_by_name_at(name, at, function)
    }
    fn opaque_reference(
        &self,
        c: &Candidate,
        tree: &ast::SourceFile,
        supported_macro_calls: &HashSet<TextRange>,
    ) -> bool {
        let _ = (tree, supported_macro_calls);
        !self.by_definition.contains_key(&c.name_range)
            || self.opaque_bindings.contains(&c.name_range)
    }

    /// Resolve macro-body references once per syntax tree instead of walking
    /// every macro for every local/parameter candidate.
    fn compute_opaque_bindings(
        &self,
        tree: &ast::SourceFile,
        supported_macro_calls: &HashSet<TextRange>,
    ) -> HashSet<TextRange> {
        let mut opaque = HashSet::new();
        for definition in tree
            .syntax()
            .descendants()
            .filter_map(ast::MacroRules::cast)
        {
            let at = definition.syntax().text_range().start();
            let function = enclosing_function(definition.syntax());
            for token in definition
                .syntax()
                .descendants_with_tokens()
                .filter_map(|element| element.into_token())
                .filter(|token| token.kind() == SyntaxKind::IDENT)
            {
                if let Some(binding) = self.resolve(token.text(), at, function) {
                    opaque.insert(binding);
                }
            }
        }
        for call in tree.syntax().descendants().filter_map(ast::MacroCall::cast) {
            let call_range = call.syntax().text_range();
            if supported_macro_calls.contains(&call_range) {
                continue;
            }
            let Some(tt) = call.token_tree() else {
                continue;
            };
            let at = call_range.start();
            let function = enclosing_function(call.syntax());
            let bindings_at_call: HashMap<String, TextRange> = self
                .by_name
                .keys()
                .filter_map(|name| {
                    self.resolve(name, at, function)
                        .map(|binding| (name.clone(), binding))
                })
                .collect();
            if bindings_at_call.is_empty() {
                continue;
            }
            for token in tt
                .syntax()
                .descendants_with_tokens()
                .filter_map(|element| element.into_token())
            {
                if token.kind() == SyntaxKind::IDENT {
                    if let Some(binding) = bindings_at_call.get(token.text()) {
                        opaque.insert(*binding);
                    }
                }
                if let Some(lit) = ast::String::cast(token) {
                    if let Ok(refs) = format_names(&lit) {
                        for (name, _) in refs {
                            if let Some(binding) = bindings_at_call.get(name.as_str()) {
                                opaque.insert(*binding);
                            }
                        }
                    }
                }
            }
        }
        opaque
    }

    fn edits(
        &self,
        c: &Candidate,
        expanded: &Expanded,
        new: &str,
        renamed_spellings: &BTreeMap<String, HashSet<String>>,
    ) -> Vec<Indel> {
        let Some(binding) = self.bindings.iter().find(|b| b.definition == c.name_range) else {
            return vec![];
        };
        // Or-patterns bind one variable with several declaration tokens.
        let representative = self
            .bindings
            .iter()
            .filter(|b| b.owner == binding.owner && b.name == binding.name)
            .map(|b| b.definition.start())
            .min();
        if representative != Some(c.name_range.start()) {
            return vec![];
        }
        let mut edits = Vec::new();
        let renamed = renamed_spellings.get(c.name.trim_start_matches("r#"));
        let mut token_names = vec![c.name.clone()];
        if let Some(names) = renamed {
            token_names.extend(names.iter().filter(|name| *name != &c.name).cloned());
        }
        let mut seen = HashSet::new();
        for token in token_names
            .iter()
            .filter_map(|name| self.tokens_by_name.get(name))
            .flatten()
            .filter(|token| seen.insert(token.range))
        {
            let range = token.range;
            let any_definition = self.by_definition.contains_key(&range);
            let definition = self.by_definition.get(&range).is_some_and(|index| {
                let candidate = &self.bindings[*index];
                candidate.owner == binding.owner && candidate.name == binding.name
            });
            let shorthand = token.shorthand.is_some();
            let renamed_shorthand = shorthand && token.text != c.name && renamed.is_some();
            let resolved = token.resolved.or_else(|| {
                renamed_shorthand
                    .then(|| self.resolve(&c.name, range.start(), token.function))
                    .flatten()
            });
            let reference = (token.path_expr && resolved == Some(c.name_range))
                || ((shorthand || renamed_shorthand)
                    && !any_definition
                    && resolved == Some(c.name_range));
            if !(definition || reference) || expanded.labels.contains(&range) {
                continue;
            }
            if let Some(record) = token.shorthand.filter(|_| shorthand) {
                let start = record.start();
                edits.push(Indel {
                    delete: TextRange::empty(start),
                    // A preceding semantic field rename can already have
                    // changed a shorthand token from `field` to
                    // `hidden_field`. Preserve that current field spelling
                    // on the left and rename only the lexical value/pattern
                    // binding on the right.
                    insert: format!("{}: ", token.text),
                });
            }
            edits.push(Indel {
                delete: range,
                insert: new.to_owned(),
            });
        }
        for capture in &expanded.format_refs {
            if capture.name != c.name.trim_start_matches("r#") {
                continue;
            }
            let function = expanded
                .tree
                .syntax()
                .token_at_offset(capture.at)
                .right_biased()
                .and_then(|t| t.parent())
                .and_then(|p| enclosing_function(&p));
            if self.resolve(&c.name, capture.at, function) == Some(c.name_range) {
                edits.push(Indel {
                    delete: capture.range,
                    insert: new.to_owned(),
                });
            }
        }
        edits
    }
}

fn enclosing_function(node: &SyntaxNode) -> Option<TextRange> {
    node.ancestors()
        .find(|n| n.kind() == SyntaxKind::FN)
        .map(|n| n.text_range())
}

fn visibility(pat: &SyntaxNode) -> Option<(TextRange, TextRange)> {
    for owner in pat.ancestors() {
        let range = owner.text_range();
        match owner.kind() {
            SyntaxKind::PARAM => {
                let container = owner
                    .ancestors()
                    .find(|n| matches!(n.kind(), SyntaxKind::CLOSURE_EXPR | SyntaxKind::FN))?;
                let body = if let Some(closure) = ast::ClosureExpr::cast(container.clone()) {
                    closure.body()?.syntax().text_range()
                } else {
                    ast::Fn::cast(container)?.body()?.syntax().text_range()
                };
                return Some((body, range));
            }
            SyntaxKind::LET_STMT => {
                let block = owner
                    .ancestors()
                    .find(|n| n.kind() == SyntaxKind::STMT_LIST)?;
                return Some((TextRange::new(range.end(), block.text_range().end()), range));
            }
            SyntaxKind::FOR_EXPR => {
                let body = ast::ForExpr::cast(owner)?
                    .loop_body()?
                    .syntax()
                    .text_range();
                return Some((body, range));
            }
            SyntaxKind::MATCH_ARM => return Some((range, range)),
            SyntaxKind::LET_EXPR => {
                let control = owner
                    .ancestors()
                    .find(|n| matches!(n.kind(), SyntaxKind::IF_EXPR | SyntaxKind::WHILE_EXPR))?;
                let body = if let Some(if_expr) = ast::IfExpr::cast(control.clone()) {
                    if_expr.then_branch()?.syntax().text_range()
                } else {
                    ast::WhileExpr::cast(control)?
                        .loop_body()?
                        .syntax()
                        .text_range()
                };
                return Some((TextRange::new(range.end(), body.end()), range));
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::Config, scanner::CrateInfo};
    use std::process::Command;

    fn transform(source: &str) -> (tempfile::TempDir, String, Outcome) {
        transform_with_symbols(source, &BTreeMap::new())
    }

    fn transform_with_symbols(
        source: &str,
        renamed_symbols: &BTreeMap<String, String>,
    ) -> (tempfile::TempDir, String, Outcome) {
        let temp = tempfile::tempdir().unwrap();
        let src = temp.path().join("src");
        std::fs::create_dir(&src).unwrap();
        let file = src.join("main.rs");
        std::fs::write(&file, source).unwrap();
        let mut graph = CrateGraph::default();
        graph.workspace.insert(
            "app".into(),
            CrateInfo {
                name: "app".into(),
                manifest_dir: temp.path().to_owned(),
                src_dir: Some(src),
                crate_types: Default::default(),
                is_proc_macro: false,
                is_library: false,
            },
        );
        let config = Config::parse("profile='aggressive'").unwrap();
        let outcome = run(
            temp.path(),
            temp.path(),
            &graph,
            &Plan::resolve(&config).unwrap(),
            32,
            renamed_symbols,
        )
        .unwrap();
        let output = std::fs::read_to_string(file).unwrap();
        (temp, output, outcome)
    }

    fn execute(root: &Path, source: &str, label: &str) -> String {
        let input = root.join(format!("{label}.rs"));
        let binary = root.join(label);
        std::fs::write(&input, source).unwrap();
        let mut compiler = Command::new("rustc");
        if source.contains("serde_json::") {
            let executable = std::env::current_exe().unwrap();
            let deps = executable.parent().unwrap();
            let library = std::fs::read_dir(deps)
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.path())
                .find(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("libserde_json-")
                        && p.extension().is_some_and(|e| e == "rlib")
                })
                .unwrap();
            compiler
                .arg("-L")
                .arg(format!("dependency={}", deps.display()))
                .arg("--extern")
                .arg(format!("serde_json={}", library.display()));
        }
        let result = compiler
            .args(["--edition=2024", "-Dwarnings"])
            .arg(&input)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{source}",
            String::from_utf8_lossy(&result.stderr)
        );
        let result = Command::new(binary).output().unwrap();
        assert!(result.status.success());
        String::from_utf8(result.stdout).unwrap()
    }

    #[test]
    fn every_closure_shape_preserves_execution_and_loses_binding_names() {
        let source = r##"
struct Cookie { cookie: String }
impl Cookie { fn name(&self)->&str { &self.cookie } fn value(&self)->&str { "value" } }
fn main() {
    let cookies = [Cookie { cookie: "name".into() }];
    let result = cookies.iter().map(|cookie| format!("{}={}", cookie.name(), cookie.value())).collect::<Vec<_>>();
    let item = "outer";
    let nested = move |cookie: &str| {
        let item = cookie.trim();
        let same = (|item| format!("{item:>width$}", width=7))(item);
        format!("{item}/{same}")
    };
    let pair = |(mut cookie, item): (i32,i32)| { cookie += item; let item = cookie + 1; item };
    let borrowed = |&cookie: &i32| cookie + 1;
    let members = |Cookie { cookie }: Cookie| cookie;
    let array = |[cookie, item]: [i32;2]| cookie + item;
    let inline = vec![|cookie| cookie + 1, |cookie| cookie + 2];
    let width = 4; let precision = 2; let cookie = 1.25;
    let formatted = format!("{{cookie}} {cookie:>width$.precision$}");
    let r#type = 3;
    let raw = format!(r#"{type}"#);
    let async_closure = async move |cookie: i32| { let item = cookie + 1; item };
    let future = async_closure(3); drop(future);
    println!("{:?}|{}|{}|{}|{}|{}|{}|{}|{}|{}", result,nested("inner"),item,pair((1,2)),borrowed(&1),members(Cookie{cookie:"ok".into()}),array([1,2]),inline[0](3),formatted,raw);
}
"##;
        let (tmp, out, result) = transform(source);
        assert_eq!(
            execute(tmp.path(), source, "before"),
            execute(tmp.path(), &out, "after")
        );
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert!(!out.contains("|cookie"));
        assert!(!out.contains("|item"));
        assert!(!out.contains("let cookies"));
        assert!(!out.contains("let item"));
        assert!(
            out.contains("cookie:"),
            "struct field is a separate namespace"
        );
        assert!(
            out.contains("{{cookie}}"),
            "escaped braces are ordinary output text"
        );
        assert!(result.stats.params >= 10);
    }

    #[test]
    fn shadowing_initializers_match_arms_loops_and_nested_functions() {
        let source = r#"fn main(){
            let cookie=10;
            let outer=|cookie| {let cookie=cookie+1; {let cookie=5; println!("{cookie}");} cookie};
            let cookie=outer(cookie);
            for cookie in [cookie,2] {println!("{cookie}");}
            let answer=match Some(cookie){Some(cookie) if cookie>2=>cookie, _=>0};
            if let Some(cookie)=Some(answer) {println!("{cookie}");} else {println!("{cookie}");}
            fn other(){let cookie=99;println!("{cookie}");} other();
            let named=format!("{cookie}",cookie="label"); println!("{cookie} {named}");
        }"#;
        let (tmp, out, result) = transform(source);
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert_eq!(
            execute(tmp.path(), source, "before"),
            execute(tmp.path(), &out, "after")
        );
        assert!(out.contains("cookie=\"label\""));
    }

    #[test]
    fn record_expression_shorthand_keeps_field_and_renames_the_local() {
        let source = r#"struct Holder{cover:String} fn main(){let cover="x".to_string();let value=Holder{cover};println!("{}",value.cover);}"#;
        let (tmp, out, result) = transform(source);
        assert!(result.skipped.is_empty(), "{:?}\n{out}", result.skipped);
        assert_eq!(
            execute(tmp.path(), source, "before"),
            execute(tmp.path(), &out, "after")
        );
        assert!(!out.contains("let cover"));
        assert!(!out.contains("Holder{cover}"));
        assert!(out.contains("Holder{cover:"), "{out}");
    }

    #[test]
    fn record_shorthand_recovers_after_a_preceding_field_rename() {
        let source = r#"struct Holder{hidden_field:String} fn main(){let cover="x".to_string();let value=Holder{hidden_field};println!("{}",value.hidden_field);}"#;
        let symbols =
            BTreeMap::from([("app::Holder::cover".to_owned(), "hidden_field".to_owned())]);
        let (tmp, out, result) = transform_with_symbols(source, &symbols);
        assert!(result.skipped.is_empty(), "{:?}\n{out}", result.skipped);
        assert!(!out.contains("let cover"));
        assert!(out.contains("Holder{hidden_field:"), "{out}");
        execute(tmp.path(), &out, "after");
    }

    #[test]
    fn custom_macro_is_reported_without_pinning_unrelated_closures() {
        let source = r#"macro_rules! custom {($x:expr)=>{$x}} fn main(){let cookie=1;let used=custom!(cookie);let closure=|cookie|cookie+1;println!("{}",closure(used));}"#;
        let (tmp, out, result) = transform(source);
        assert_eq!(
            execute(tmp.path(), source, "before"),
            execute(tmp.path(), &out, "after")
        );
        assert_eq!(result.skipped.len(), 1);
        assert!(out.contains("let cookie=1"));
        assert!(!out.contains("|cookie|"));
    }

    #[test]
    fn patterns_captures_and_all_standard_format_macros_compile() {
        let source = r#"use std::fmt::Write;
        fn main(){
            let cookie=2;
            macro_rules! captured {()=>{cookie}}
            let value=captured!();
            let callback=|cookie:i32| {
                let text=format!("{cookie}");
                let mut buffer=String::new();
                write!(&mut buffer,"{text}").unwrap();
                writeln!(&mut buffer,"{}",(|item|item+1)(cookie)).unwrap();
                assert_eq!(text,cookie.to_string(),"{text}");
                debug_assert!(cookie>0,"{cookie}");
                let mut count=Some(cookie);
                while let Some(item)=count {count=None;assert!(item>0,"{item}");}
                let branch=match Some(cookie){Some(item @ 1..=10)|Some(item @ 20..=30)=>item,_=>0};
                if let Some(item)=Some(branch) && item>0 {println!("{item}");}
                let pair=|ref item: i32| *item;
                let records=|Holder{ref cookie}: Holder| cookie.len();
                let Holder{cookie}=Holder{cookie:buffer};
                println!("{cookie} {} {}",pair(branch),records(Holder{cookie:text}));
            };
            callback(value);
        }
        struct Holder{cookie:String}"#;
        let (tmp, out, result) = transform(source);
        assert_eq!(
            execute(tmp.path(), source, "before"),
            execute(tmp.path(), &out, "after")
        );
        assert_eq!(result.skipped.len(), 1, "{:?}", result.skipped);
        assert!(!out.contains("|cookie|"));
        assert!(!out.contains("ref item"));
    }

    #[test]
    fn framework_parameter_kept_but_its_closure_is_renamed() {
        let (_, out, result) =
            transform("#[tauri::command] fn command(cookie:i32)->i32{(|cookie|cookie+1)(cookie)}");
        assert!(out.contains("fn command(cookie:i32)"));
        assert!(!out.contains("|cookie|"));
        assert_eq!(result.skipped.len(), 1);
        assert_eq!(result.skipped[0].reason, SkipReason::IntrinsicAttribute);
    }

    #[test]
    fn constant_patterns_are_not_misclassified_as_variables() {
        let source = r#"const LIMIT:i32=2;fn main(){let closure=|cookie|match cookie{LIMIT=>10,item=>item};println!("{} {}",closure(2),closure(3));}"#;
        let (tmp, out, _) = transform(source);
        assert_eq!(
            execute(tmp.path(), source, "before"),
            execute(tmp.path(), &out, "after")
        );
        assert!(out.contains("LIMIT=>10"));
        assert!(!out.contains("|cookie|"));
    }

    #[test]
    fn json_values_include_nested_closures_without_renaming_keys() {
        let source = r#"fn main(){let cookies=[1,2];let null=7;let data=serde_json::json!({"cookie":cookies.iter().map(|cookie|{let item=cookie+1;item}).collect::<Vec<_>>(),"nested":[{"item":(|item|format!("{item}"))(null),"none":null}],"value":(null)});println!("{data}");}"#;
        let (tmp, out, result) = transform(source);
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert_eq!(
            execute(tmp.path(), source, "before"),
            execute(tmp.path(), &out, "after")
        );
        assert!(!out.contains("|cookie|"));
        assert!(!out.contains("|item|"));
        assert!(out.contains("\"cookie\":"));
        assert!(out.contains("\"none\":null"));
    }

    #[test]
    fn module_paths_do_not_pin_closure_names_and_log_macros_are_traversed() {
        let source = r#"mod cookie {pub struct Marker;}
        use cookie::Marker;
        fn main(){let _marker=Marker;let cookies=[1];log::info!(target: "cookie", "{:?}",cookies.iter().map(|cookie|{let item=cookie+1;format!("{item}")}).collect::<Vec<_>>());}"#;
        let (_, out, result) = transform(source);
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert!(!out.contains("|cookie|"));
        assert!(!out.contains("let item"));
        assert!(out.contains("target: \"cookie\""));
        assert!(out.contains("use cookie::Marker"));
        assert!(SourceFile::parse(&out, Edition::Edition2024)
            .errors()
            .is_empty());
    }

    #[test]
    fn matches_scrutinee_patterns_guards_and_nested_closures_keep_scope() {
        let source = r#"fn main(){let cookie=2;let callback=|cookie|matches!(Some(cookie),Some(item) if (|item|item>1)(item));let other=matches!(|cookie,item|cookie+item,operation if operation(1,2)==3);println!("{} {} {}",callback(cookie),other,matches!(cookie,1|2));}"#;
        let (tmp, out, result) = transform(source);
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert_eq!(
            execute(tmp.path(), source, "before"),
            execute(tmp.path(), &out, "after")
        );
        assert!(!out.contains("|cookie"));
        assert!(!out.contains("|item"));
    }

    #[test]
    fn tokio_select_branches_outer_refs_and_nested_bindings_are_all_renamed() {
        let source = r#"fn demo(){
            let mut outer_receiver=receiver();
            let outer_limit=3;
            loop {
                let selected=tokio::select! {
                    branch_result = outer_receiver.recv() => {
                        let closure=|closure_cookie| closure_cookie+outer_limit;
                        match branch_result { Some(nested_item)=>closure(nested_item), None=>break }
                    }
                    _ = sleeper(), if outer_limit>0 => { continue; }
                };
                consume(selected);
            }
        }"#;
        let (_, out, result) = transform(source);
        assert!(result.skipped.is_empty(), "{:?}\n{out}", result.skipped);
        for original in [
            "outer_receiver",
            "outer_limit",
            "selected",
            "branch_result",
            "closure_cookie",
            "nested_item",
        ] {
            assert!(
                !out.contains(original),
                "`{original}` survived select rewriting:\n{out}"
            );
        }
        assert!(SourceFile::parse(&out, Edition::Edition2024)
            .errors()
            .is_empty());
    }

    #[test]
    fn tokio_select_semantic_shell_keeps_offsets_and_labels_branch_locals() {
        let source = r#"fn demo(){let outer=1;let _=tokio::select!{
            branch_value = async { helper(outer) } => {
                let rendered=format!("{branch_value}");
                consume(branch_value,rendered)
            },
            else => { fallback(outer) }
        };}"#;
        let shadowed = HashSet::new();
        let shell = macro_analysis_source(source, &shadowed).unwrap();
        assert_eq!(shell.text.len(), source.len());
        assert!(
            SourceFile::parse(&shell.text, Edition::Edition2024)
                .errors()
                .is_empty(),
            "{}",
            shell.text
        );
        assert!(!shell.text.contains("tokio::select"));
        assert!(shell.text.contains("helper(outer)"));
        assert!(shell.text.contains("fallback(outer)"));

        let labels = macro_label_ranges(source, &shadowed).unwrap();
        let parsed = SourceFile::parse(source, Edition::Edition2024).tree();
        let branch_ranges: Vec<_> = parsed
            .syntax()
            .descendants_with_tokens()
            .filter_map(|element| element.into_token())
            .filter(|token| token.kind() == SyntaxKind::IDENT && token.text() == "branch_value")
            .map(|token| token.text_range())
            .collect();
        // The third occurrence lives inside the format string and is tracked
        // by `macro_format_references`, not as an IDENT token.
        assert_eq!(branch_ranges.len(), 2);
        assert!(branch_ranges.iter().all(|range| labels.contains(range)));
    }
}
