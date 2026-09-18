//! Dependency-boundary wrappers.
//!
//! A registry or path dependency is normally an external contract and stays
//! untouched. When a user explicitly selects `mode = "wrapper"`, this pass
//! creates a small, private module in each root crate and rewrites only
//! semantically-resolved crate-root paths to go through it. The dependency's
//! public API remains unchanged; the wrapper is the obfuscation boundary and
//! is generated from the same seeded name domain as every other transform.

use crate::edits::{replace, EditPlan, FileCreate, SourceRef};
use crate::names::{NameCase, NameDeriver, SeedDomain};
use crate::plan::Plan;
use crate::rust::analysis::RustAnalysis;
use crate::rust::rename::{crate_for_file, is_inside_macro_token_tree};
use crate::scanner::{is_root_like, strip_prefix_path, CrateGraph};
use anyhow::Result;
use ra_ap_ide::{FileId, FilePosition, GotoDefinitionConfig};
use ra_ap_syntax::{AstNode, SyntaxKind, TextRange};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Default)]
pub struct DependencyOutcome {
    pub wrappers_generated: usize,
    pub references_rewritten: usize,
    pub files_edited: BTreeSet<PathBuf>,
    pub warnings: Vec<String>,
    /// package name -> generated wrapper module name
    pub mapping: BTreeMap<String, String>,
}

pub struct DependencyRequest<'a> {
    pub input_root: &'a Path,
    pub copied: &'a BTreeSet<PathBuf>,
    pub graph: &'a CrateGraph,
    pub plan: &'a Plan,
}

#[derive(Debug, Clone)]
struct RootFile {
    path: PathBuf,
    text: String,
    src_dir: PathBuf,
}

/// Generate and stage dependency wrappers. The original [`EditPlan`] is
/// replaced only after every wrapper file and every reference has validated,
/// preserving transaction semantics across created files and text edits.
pub fn run(
    analysis: &RustAnalysis,
    req: &DependencyRequest<'_>,
    names: &mut NameDeriver,
    edits: &mut EditPlan,
) -> Result<DependencyOutcome> {
    let mut trial = edits.clone();
    let mut outcome = DependencyOutcome::default();
    let mut declarations: BTreeMap<PathBuf, (String, String, u32)> = BTreeMap::new();
    let mut created_wrappers = BTreeSet::new();

    let root_names: BTreeSet<String> = if !req.graph.workspace_members.is_empty() {
        req.graph.workspace_members.clone()
    } else if req.graph.root_crates.is_empty() {
        req.graph.workspace.keys().cloned().collect()
    } else {
        req.graph.root_crates.clone()
    };
    if root_names.is_empty() {
        return Ok(outcome);
    }

    let mut root_files: BTreeMap<String, Vec<RootFile>> = BTreeMap::new();
    let files = analysis.rust_files();
    for (file_id, path) in &files {
        let Some(krate) = crate_for_file(req.graph, path) else {
            continue;
        };
        if !root_names.contains(&krate.name) || !is_root_like(req.graph, &krate.name) {
            continue;
        }
        let Some(src_dir) = &krate.src_dir else {
            continue;
        };
        let is_root = is_target_root(path, src_dir);
        if !is_root {
            continue;
        }
        let Some((_, text)) = analysis.parse(*file_id) else {
            continue;
        };
        root_files
            .entry(krate.name.clone())
            .or_default()
            .push(RootFile {
                path: path.clone(),
                text,
                src_dir: src_dir.clone(),
            });
    }

    for (package, aliases) in &req.graph.dependency_aliases {
        if req.plan.dependencies.mode_for(package) != crate::config::DependencyMode::Wrapper {
            continue;
        }
        let Some(manifest_dir) = req.graph.dependency_manifest_dirs.get(package) else {
            outcome.warnings.push(format!(
                "wrapper requested for {package}, but cargo gave no manifest path"
            ));
            continue;
        };
        for (root_name, roots) in &root_files {
            if !req.graph.workspace.contains_key(root_name) {
                continue;
            }
            let references = find_resolved_references(
                analysis,
                req.graph,
                req.input_root,
                root_name,
                &files,
                aliases,
                manifest_dir,
            );
            if references.is_empty() {
                continue;
            }

            let identity = format!("{root_name}::{package}");
            let generated =
                names.derive(SeedDomain::DependencyWrapper, &identity, NameCase::Snake)?;
            let wrapper = format!("sv_{generated}");
            let mut referenced_roots = BTreeMap::new();
            for (path, _text, range, alias) in &references {
                for root in roots {
                    if root_covers_path(root, path) {
                        referenced_roots
                            .entry(root.path.clone())
                            .or_insert_with(|| (root.text.clone(), alias.clone(), *range));
                    }
                }
            }
            if referenced_roots.is_empty() {
                outcome.warnings.push(format!(
                    "wrapper requested for {package}, but no crate root owns its references"
                ));
                continue;
            }

            for (root_path, (root_text, alias, _)) in &referenced_roots {
                let wrapper_path = wrapper_module_path(root_path, &wrapper);
                let contents = format!(
                    "//! SourceVeil dependency boundary for `{package}`.\n#![allow(unused_imports)]\npub(crate) use ::{alias}::*;\n"
                );
                if created_wrappers.insert(wrapper_path.clone()) {
                    trial
                        .stage_create(FileCreate {
                            path: wrapper_path,
                            contents,
                        })
                        .map_err(|e| {
                            anyhow::anyhow!("staging dependency wrapper for {package}: {e}")
                        })?;
                }

                let insert_at = root_module_insert_offset(root_text);
                let declaration = wrapper_module_declaration(root_path, &wrapper);
                declarations
                    .entry(root_path.clone())
                    .and_modify(|(text, _, _)| text.push_str(&declaration))
                    .or_insert_with(|| (declaration, root_text.clone(), insert_at));
                outcome.files_edited.insert(root_path.clone());
            }

            // Stage each resolved reference once even when a shared source file
            // is compiled as both a library and a binary root.
            let mut unique_references: BTreeMap<(PathBuf, u32, u32), (String, String)> =
                BTreeMap::new();
            for (path, text, range, alias) in references {
                if roots.iter().any(|root| root_covers_path(root, &path)) {
                    unique_references
                        .entry((path, u32::from(range.start()), u32::from(range.end())))
                        .or_insert((text, alias));
                }
            }
            for ((path, start, end), (text, _)) in unique_references {
                let replacement = format!("crate::{wrapper}");
                trial
                    .stage(
                        SourceRef {
                            path: &path,
                            text: &text,
                        },
                        [replace(start, end, replacement)],
                    )
                    .map_err(|e| anyhow::anyhow!("staging dependency wrapper reference: {e}"))?;
                outcome.files_edited.insert(path);
                outcome.references_rewritten += 1;
            }
            outcome.wrappers_generated += 1;
            outcome.mapping.insert(package.clone(), wrapper);
        }
    }

    // Several wrapped dependencies can share one root file. Stage all module
    // declarations as one insertion so two wrappers never collide at the
    // same inner-attribute offset.
    for (path, (declaration, text, offset)) in declarations {
        trial
            .stage(
                SourceRef {
                    path: &path,
                    text: &text,
                },
                [replace(offset, offset, declaration)],
            )
            .map_err(|e| anyhow::anyhow!("staging dependency wrapper declaration: {e}"))?;
    }

    *edits = trial;
    Ok(outcome)
}

fn is_target_root(path: &Path, src_dir: &Path) -> bool {
    if path == src_dir.join("lib.rs") || path == src_dir.join("main.rs") {
        return true;
    }
    let Some(parent) = path.parent() else {
        return false;
    };
    if parent.parent() == Some(src_dir)
        && matches!(
            parent.file_name().and_then(|name| name.to_str()),
            Some("bin" | "examples")
        )
    {
        return true;
    }
    path.file_name().and_then(|name| name.to_str()) == Some("main.rs")
        && parent.parent().and_then(Path::parent) == Some(src_dir)
        && matches!(
            parent
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str()),
            Some("bin" | "examples")
        )
}

fn root_covers_path(root: &RootFile, path: &Path) -> bool {
    let primary =
        root.path == root.src_dir.join("lib.rs") || root.path == root.src_dir.join("main.rs");
    if primary {
        return path.starts_with(&root.src_dir)
            && !path.starts_with(root.src_dir.join("bin"))
            && !path.starts_with(root.src_dir.join("examples"));
    }
    // A shared `src/*.rs` module can be compiled into both a library and one
    // or more binary/example targets. Give each non-primary root its own
    // declaration so `crate::sv_*` remains valid in every target.
    if path.starts_with(&root.src_dir)
        && !path.starts_with(root.src_dir.join("bin"))
        && !path.starts_with(root.src_dir.join("examples"))
    {
        return true;
    }
    let Some(stem) = root.path.file_stem() else {
        return path == root.path;
    };
    let scope = root
        .path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(stem);
    path == root.path || path.starts_with(scope)
}

fn wrapper_module_path(root_path: &Path, wrapper: &str) -> PathBuf {
    let parent = root_path.parent().unwrap_or_else(|| Path::new("."));
    let target_directory = if matches!(
        parent.file_name().and_then(|name| name.to_str()),
        Some("bin" | "examples")
    ) {
        parent.join(root_path.file_stem().unwrap_or_default())
    } else {
        parent.to_path_buf()
    };
    target_directory.join(format!("{wrapper}.rs"))
}

fn wrapper_module_declaration(root_path: &Path, wrapper: &str) -> String {
    let parent = root_path.parent().unwrap_or_else(|| Path::new("."));
    if matches!(
        parent.file_name().and_then(|name| name.to_str()),
        Some("bin" | "examples")
    ) {
        let stem = root_path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("root");
        format!("#[path = \"{stem}/{wrapper}.rs\"]\nmod {wrapper};\n")
    } else {
        format!("mod {wrapper};\n")
    }
}

/// Find direct crate-root paths such as `helper_lib::public_api` whose first
/// segment resolves to the selected dependency. No regex replacement is used:
/// macro token trees, strings, comments and same-named local modules are left
/// alone when rust-analyzer cannot prove the target package.
fn find_resolved_references(
    analysis: &RustAnalysis,
    graph: &CrateGraph,
    input_root: &Path,
    root_name: &str,
    files: &[(FileId, PathBuf)],
    aliases: &BTreeSet<String>,
    manifest_dir: &Path,
) -> Vec<(PathBuf, String, TextRange, String)> {
    let config = GotoDefinitionConfig {
        ra_fixture: ra_ap_ide::RaFixtureConfig::default(),
    };
    let mut found = Vec::new();
    for (file_id, path) in files {
        let Some(relative) = strip_prefix_path(path, input_root) else {
            continue;
        };
        if relative.as_os_str().is_empty() {
            continue;
        }
        let Some(owner) = crate_for_file(graph, path) else {
            continue;
        };
        if owner.name != root_name {
            continue;
        }
        let Some((parsed, text)) = analysis.parse(*file_id) else {
            continue;
        };
        let tokens: Vec<_> = parsed
            .syntax()
            .descendants_with_tokens()
            .filter_map(|el| el.into_token())
            .filter(|token| token.kind() == SyntaxKind::IDENT)
            .collect();
        for token in tokens {
            let alias = token.text().to_string();
            if !aliases.contains(&alias) || is_inside_macro_token_tree(&token) {
                continue;
            }
            let range = token.text_range();
            let start = usize::from(range.start());
            let end = usize::from(range.end());
            let before = &text[..start];
            let after = &text[end..];
            if !after.trim_start().starts_with("::") || is_nested_path_segment(before.trim_end()) {
                continue;
            }
            let position = FilePosition {
                file_id: *file_id,
                offset: range.start(),
            };
            let Ok(Some(info)) = analysis.analysis().goto_definition(position, &config) else {
                continue;
            };
            if info.info.iter().any(|target| {
                analysis
                    .file_path(target.file_id)
                    .map(|target_path| target_path.starts_with(manifest_dir))
                    .unwrap_or(false)
            }) {
                found.push((path.clone(), text.clone(), range, alias));
            }
        }
    }
    found
}

fn is_nested_path_segment(before: &str) -> bool {
    let Some(prefix) = before.strip_suffix("::") else {
        return false;
    };
    prefix
        .trim_end()
        .chars()
        .last()
        .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '>' | ']' | ')'))
}

fn root_module_insert_offset(text: &str) -> u32 {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("#![") || trimmed.starts_with("//!") {
            offset += line.len();
        } else {
            break;
        }
    }
    offset as u32
}

#[cfg(test)]
mod tests {
    use super::{
        is_nested_path_segment, root_module_insert_offset, wrapper_module_declaration,
        wrapper_module_path,
    };
    use std::path::Path;

    #[test]
    fn wrapper_declaration_follows_inner_attributes() {
        let source = "#![allow(dead_code)]\n//! docs\n\nfn main() {}\n";
        assert_eq!(
            &source[..root_module_insert_offset(source) as usize],
            "#![allow(dead_code)]\n//! docs\n\n"
        );
    }

    #[test]
    fn binary_root_wrapper_uses_a_non_target_module_path() {
        let root = Path::new("src/bin/second.rs");
        assert_eq!(
            wrapper_module_path(root, "sv_boundary"),
            Path::new("src/bin/second/sv_boundary.rs")
        );
        assert_eq!(
            wrapper_module_declaration(root, "sv_boundary"),
            "#[path = \"second/sv_boundary.rs\"]\nmod sv_boundary;\n"
        );
    }

    #[test]
    fn absolute_dependency_paths_are_not_mistaken_for_nested_segments() {
        assert!(!is_nested_path_segment("::"));
        assert!(is_nested_path_segment("crate::module::"));
        assert!(is_nested_path_segment("types::<T>::"));
    }
}
