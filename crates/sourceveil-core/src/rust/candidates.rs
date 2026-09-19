//! Finding the items worth renaming, and deciding which of them are safe.
//!
//! Enumeration is a recursive walk rather than a flat `descendants()` scan,
//! because an item's *path* depends on the modules it sits inside, and a flat
//! scan has nowhere to keep that stack.
//!
//! Every decision here is deliberately conservative. A candidate that is
//! dropped costs a little obfuscation strength and shows up in the report; a
//! candidate that is wrongly renamed costs a broken build, or worse, a build
//! that compiles and links differently.

use super::ItemKind;
use ra_ap_syntax::ast::{self, AstNode, HasName};
use ra_ap_syntax::{SyntaxElement, SyntaxKind, SyntaxNode, TextRange};
use std::path::{Path, PathBuf};

/// Inline marker that pins an item. Deliberately a plain comment rather than a
/// procedural macro, so a project can adopt the tool without adding a
/// dependency to its own build.
pub const KEEP_MARKER: &str = "obfuscator:keep";
/// Pins every item in the file.
pub const KEEP_FILE_MARKER: &str = "obfuscator:keep-file";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Bare `pub`, with every enclosing module also bare `pub`.
    Public,
    /// `pub(crate)`, `pub(super)`, `pub(in ..)`, or a `pub` item inside a
    /// non-public module. Reachable only from within the crate.
    Restricted,
    /// No visibility modifier.
    Private,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub kind: ItemKind,
    /// The identifier as written.
    pub name: String,
    /// Byte range of that identifier *within its file*. This is the position
    /// handed to rust-analyzer.
    pub name_range: TextRange,
    /// The file the item is defined in.
    pub file: PathBuf,
    /// 1-based line of the identifier, for the report.
    pub line: u32,
    /// Best-effort fully-qualified path, used for the mapping file and the
    /// report. Never used for resolution.
    pub path: String,
    pub visibility: Visibility,
    /// Attribute paths seen on the item, normalized (see [`attribute_names`]).
    pub attributes: Vec<String>,
    /// A `// obfuscator:keep` comment is attached.
    pub inline_keep: bool,
    /// Declared with a non-Rust ABI, e.g. `extern "C" fn`.
    pub is_extern_abi: bool,
    /// The item is a member of a serde data model — a field of a type deriving
    /// `Serialize`/`Deserialize`, or a variant of such an enum.
    ///
    /// Its name is a wire-format key, not just a Rust identifier. Renaming it
    /// leaves the code compiling and changes every JSON document the program
    /// reads or writes, which is precisely the class of failure this tool
    /// exists to avoid.
    pub serde_model: bool,
    /// A function declared in an `impl` block. Method references are more
    /// difficult for rust-analyzer to resolve when a project uses generated
    /// receivers, so the rename pass can apply a token-safe fallback for
    /// these candidates.
    pub is_method: bool,
    /// A method implementing a trait contract. These names are kept when the
    /// contract is part of the language/framework (for example
    /// `Default::default`) because changing them changes the implementation,
    /// not just the local symbol.
    pub trait_method: bool,
    /// Enclosing function/closure range for a local or parameter binding.
    /// Used only by the token-safe fallback when semantic references are
    /// incomplete.
    pub scope_range: Option<TextRange>,
}

/// Everything the walker needs that is constant for one file.
pub struct FileContext<'a> {
    pub path: &'a Path,
    /// The file's text, used to turn byte offsets into line numbers.
    pub text: &'a str,
    /// Name of the crate this file belongs to.
    pub crate_name: &'a str,
    /// Path segments implied by the file's location in its crate: empty for
    /// `lib.rs` / `main.rs`, `["network"]` for `network.rs`.
    pub module_prefix: &'a [String],
}

/// Collect every renamable item in one file.
pub fn collect(file: &ast::SourceFile, ctx: &FileContext<'_>) -> Vec<Candidate> {
    if file_has_keep_marker(file) {
        return Vec::new();
    }

    let lines = LineIndex::new(ctx.text);
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::with_capacity(ctx.module_prefix.len() + 4);
    stack.push(ctx.crate_name.to_string());
    stack.extend(ctx.module_prefix.iter().cloned());

    walk(file.syntax(), &mut stack, ctx, &lines, false, &mut out);
    out
}

/// `serde_model` is true when the node being walked sits inside a type that
/// derives `Serialize`/`Deserialize`.
fn walk(
    node: &SyntaxNode,
    stack: &mut Vec<String>,
    ctx: &FileContext<'_>,
    lines: &LineIndex,
    serde_model: bool,
    out: &mut Vec<Candidate>,
) {
    for child in node.children() {
        if let Some(kind) = item_kind(&child) {
            // A declaration in an `extern` block has no Rust definition; its
            // name *is* the linker symbol, so renaming it changes what is
            // linked against rather than what the code is called.
            if !is_foreign_declaration(&child) {
                if let Some(name_node) = item_name(&child) {
                    let name = name_node.syntax().text().to_string();
                    if !name.is_empty() && name != "self" {
                        out.push(Candidate {
                            kind,
                            path: format!("{}::{}", stack.join("::"), name),
                            name,
                            name_range: name_node.syntax().text_range(),
                            file: ctx.path.to_path_buf(),
                            line: lines.line_of(usize::from(child.text_range().start())),
                            visibility: effective_visibility(&child),
                            attributes: attribute_names(&child),
                            inline_keep: has_inline_keep(&child, ctx.text),
                            is_extern_abi: has_extern_abi(&child),
                            serde_model,
                            is_method: kind == ItemKind::Function
                                && child.ancestors().any(|a| a.kind() == SyntaxKind::IMPL),
                            trait_method: kind == ItemKind::Function
                                && (child.ancestors().any(|a| a.kind() == SyntaxKind::TRAIT)
                                    || child
                                        .ancestors()
                                        .find(|a| a.kind() == SyntaxKind::IMPL)
                                        .and_then(ast::Impl::cast)
                                        .and_then(|i| i.trait_())
                                        .is_some()),
                            scope_range: None,
                        });
                    }
                }
            }
        }

        // `IdentPat` is the syntax node used for every ordinary binding in a
        // parameter or a local pattern (`let`, `match`, `for`, and closures).
        // It is deliberately collected separately from item declarations so
        // a name such as `value` can be renamed without treating a string,
        // field, or path segment with the same spelling as the binding.
        if let Some(kind) = binding_kind(&child) {
            if let Some(name_node) = ast::IdentPat::cast(child.clone()).and_then(|p| p.name()) {
                let name = name_node.syntax().text().to_string();
                if !name.is_empty() && name != "self" && name != "_" {
                    let offset = u32::from(name_node.syntax().text_range().start());
                    let scope = binding_scope_name(&child).unwrap_or_else(|| "scope".into());
                    out.push(Candidate {
                        kind,
                        path: format!("{}::{}::{}@{}", stack.join("::"), scope, name, offset),
                        name,
                        name_range: name_node.syntax().text_range(),
                        file: ctx.path.to_path_buf(),
                        line: lines.line_of(usize::from(child.text_range().start())),
                        visibility: Visibility::Private,
                        attributes: Vec::new(),
                        inline_keep: has_inline_keep(&child, ctx.text),
                        is_extern_abi: false,
                        serde_model,
                        is_method: false,
                        trait_method: false,
                        scope_range: binding_scope_range(&child),
                    });
                }
            }
        }

        // Descend. A type that derives a serde trait makes everything below it
        // part of its data model — its fields, and for an enum its variants and
        // their fields. Rust does not allow a type to be declared inside
        // another type's body, so this propagation cannot reach an unrelated
        // item.
        let child_serde = serde_model || is_serde_model_type(&child);

        // Extend the path for constructs that introduce a scope.
        match scope_name(&child) {
            Some(segment) => {
                stack.push(segment);
                walk(&child, stack, ctx, lines, child_serde, out);
                stack.pop();
            }
            None => walk(&child, stack, ctx, lines, child_serde, out),
        }
    }
}

/// Does this type derive serde's `Serialize` or `Deserialize`?
///
/// Both spellings are recognised — `Serialize` and `serde::Serialize` — and a
/// `#[derive(...)]` list may carry several derives at once. Matching on the
/// last path segment means a project that defines its own `Serialize` trait
/// gets its fields kept too. That is the intended direction to err in: keeping
/// a field costs a little obfuscation, and renaming one costs the wire format.
fn is_serde_model_type(node: &SyntaxNode) -> bool {
    if !matches!(
        node.kind(),
        SyntaxKind::STRUCT | SyntaxKind::ENUM | SyntaxKind::UNION
    ) {
        return false;
    }
    derived_traits(node)
        .iter()
        .any(|t| matches!(t.rsplit("::").next(), Some("Serialize" | "Deserialize")))
}

/// Trait paths named in `#[derive(...)]` on this item.
pub fn derived_traits(node: &SyntaxNode) -> Vec<String> {
    let mut out = Vec::new();
    for attr in node.children().filter_map(ast::Attr::cast) {
        let text = attr.syntax().text().to_string();
        let inner = strip_attr_wrapper(&text);
        let Some(rest) = inner.strip_prefix("derive") else {
            continue;
        };
        let rest = rest.trim_start();
        let Some(list) = rest.strip_prefix('(') else {
            continue;
        };
        for part in list.trim_end().trim_end_matches(')').split(',') {
            let path = part.trim();
            if !path.is_empty() {
                out.push(path.to_string());
            }
        }
    }
    out
}

/// `#[derive(Serialize)]` -> `derive(Serialize)`.
fn strip_attr_wrapper(text: &str) -> &str {
    text.trim_start_matches("#!")
        .trim_start_matches('#')
        .trim_start()
        .trim_start_matches('[')
        .trim_end()
        .trim_end_matches(']')
        .trim()
}

/// Byte offset -> 1-based line number, built once per file.
///
/// A naive `text[..offset].matches('\n').count()` per candidate is quadratic
/// in the number of candidates, which shows up on large generated files.
struct LineIndex {
    /// Byte offset of the start of each line.
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            text.bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i + 1),
        );
        Self { starts }
    }

    fn line_of(&self, offset: usize) -> u32 {
        match self.starts.binary_search(&offset) {
            Ok(i) => i as u32 + 1,
            Err(i) => i as u32,
        }
    }
}

/// Which item kind a syntax node is, if it is one we rename.
fn item_kind(node: &SyntaxNode) -> Option<ItemKind> {
    Some(match node.kind() {
        SyntaxKind::FN => ItemKind::Function,
        SyntaxKind::STRUCT => ItemKind::Struct,
        SyntaxKind::ENUM => ItemKind::Enum,
        SyntaxKind::UNION => ItemKind::Union,
        SyntaxKind::TRAIT => ItemKind::Trait,
        SyntaxKind::TYPE_ALIAS => ItemKind::TypeAlias,
        SyntaxKind::CONST => ItemKind::Const,
        SyntaxKind::STATIC => ItemKind::Static,
        SyntaxKind::MODULE => ItemKind::Module,
        SyntaxKind::MACRO_RULES => ItemKind::Macro,
        SyntaxKind::VARIANT => ItemKind::Variant,
        SyntaxKind::RECORD_FIELD => ItemKind::Field,
        _ => return None,
    })
}

/// Is this node declared inside an `extern` block?
fn is_foreign_declaration(node: &SyntaxNode) -> bool {
    node.ancestors()
        .any(|a| a.kind() == SyntaxKind::EXTERN_BLOCK)
}

/// Does the item declare a non-Rust ABI, as in `extern "C" fn`?
///
/// On its own this is harmless — Rust still mangles such a name. It only
/// matters combined with a linkage attribute, which is why the two are checked
/// together before reporting an ABI boundary.
fn has_extern_abi(node: &SyntaxNode) -> bool {
    node.kind() == SyntaxKind::FN
        && ast::Fn::cast(node.clone())
            .map(|f| f.abi().is_some())
            .unwrap_or(false)
}

/// The `Name` node of an item, if it has one.
fn item_name(node: &SyntaxNode) -> Option<ast::Name> {
    match node.kind() {
        SyntaxKind::FN => ast::Fn::cast(node.clone())?.name(),
        SyntaxKind::STRUCT => ast::Struct::cast(node.clone())?.name(),
        SyntaxKind::ENUM => ast::Enum::cast(node.clone())?.name(),
        SyntaxKind::UNION => ast::Union::cast(node.clone())?.name(),
        SyntaxKind::TRAIT => ast::Trait::cast(node.clone())?.name(),
        SyntaxKind::TYPE_ALIAS => ast::TypeAlias::cast(node.clone())?.name(),
        SyntaxKind::CONST => ast::Const::cast(node.clone())?.name(),
        SyntaxKind::STATIC => ast::Static::cast(node.clone())?.name(),
        SyntaxKind::MODULE => ast::Module::cast(node.clone())?.name(),
        SyntaxKind::MACRO_RULES => ast::MacroRules::cast(node.clone())?.name(),
        SyntaxKind::VARIANT => ast::Variant::cast(node.clone())?.name(),
        SyntaxKind::RECORD_FIELD => ast::RecordField::cast(node.clone())?.name(),
        _ => None,
    }
}

/// Classify an identifier pattern as a parameter or local binding.
///
/// `IdentPat` is only produced for bindings (paths such as `Foo::Bar` use a
/// different syntax node), so walking every such node is both more complete
/// and less error-prone than trying to enumerate each expression form.
fn binding_kind(node: &SyntaxNode) -> Option<ItemKind> {
    if node.kind() != SyntaxKind::IDENT_PAT {
        return None;
    }
    // Parameters in `extern "C" { fn foreign(x: T); }` are part of the ABI
    // declaration rather than local Rust bindings.
    if node
        .ancestors()
        .any(|ancestor| is_foreign_declaration(&ancestor))
    {
        return None;
    }
    if node.ancestors().any(|a| a.kind() == SyntaxKind::PARAM) {
        Some(ItemKind::Param)
    } else {
        Some(ItemKind::Local)
    }
}

/// Include the enclosing function/closure in a binding's mapping path. The
/// byte offset remains part of the path so shadowed bindings are distinct.
fn binding_scope_name(node: &SyntaxNode) -> Option<String> {
    for ancestor in node.ancestors() {
        if ancestor.kind() == SyntaxKind::FN {
            return ast::Fn::cast(ancestor)
                .and_then(|f| f.name())
                .map(|n| n.syntax().text().to_string());
        }
        if ancestor.kind() == SyntaxKind::CLOSURE_EXPR {
            return Some("closure".into());
        }
    }
    None
}

fn binding_scope_range(node: &SyntaxNode) -> Option<TextRange> {
    node.ancestors()
        .find(|ancestor| matches!(ancestor.kind(), SyntaxKind::FN | SyntaxKind::CLOSURE_EXPR))
        .map(|ancestor| ancestor.text_range())
}

/// Name segment introduced by a node, for path building.
///
/// Only constructs whose name is a stable part of a symbol path produce a
/// segment: modules, `impl` self types, traits, and the aggregate types whose
/// members are reached through them (`State::Idle`, `S::field`). Function
/// bodies are traversed without a segment, because an item nested in a
/// function is not nameable from outside it anyway.
fn scope_name(node: &SyntaxNode) -> Option<String> {
    match node.kind() {
        SyntaxKind::MODULE => {
            let m = ast::Module::cast(node.clone())?;
            Some(m.name()?.syntax().text().to_string())
        }
        SyntaxKind::IMPL => {
            let i = ast::Impl::cast(node.clone())?;
            let ty = i.self_ty()?;
            let text = ty.syntax().text().to_string();
            // `Vec<T>` contributes `Vec`; `foo::Bar` contributes `Bar`.
            let base = text.split('<').next().unwrap_or(&text).trim();
            let last = base.rsplit("::").next().unwrap_or(base).trim();
            (!last.is_empty()).then(|| last.to_string())
        }
        SyntaxKind::TRAIT => {
            let t = ast::Trait::cast(node.clone())?;
            Some(t.name()?.syntax().text().to_string())
        }
        SyntaxKind::ENUM | SyntaxKind::STRUCT | SyntaxKind::UNION => {
            Some(item_name(node)?.syntax().text().to_string())
        }
        _ => None,
    }
}

/// Effective visibility after accounting for everything that encloses it.
///
/// A `pub fn` inside a private `mod` is not reachable from another crate, and
/// renaming it cannot affect an external consumer. This is the difference
/// between a rename pass that is usable on a library and one that is not.
///
/// Two shapes need care, and both were wrong before:
///
/// - **An enum variant has no visibility token.** `pub enum State { Ready }`
///   makes `Ready` as public as the enum, but reading the variant's own
///   modifiers finds nothing and answers `Private`.
/// - **A `pub` field is only as public as its struct.** `pub` on a field of a
///   private struct reaches nothing at all.
fn effective_visibility(node: &SyntaxNode) -> Visibility {
    // A variant takes its visibility from the enum; everything else from its
    // own modifier. `pub enum State { Ready }` makes `Ready` as public as the
    // enum, but a variant carries no visibility token to read.
    let own = if node.kind() == SyntaxKind::VARIANT {
        match node.ancestors().find(|a| a.kind() == SyntaxKind::ENUM) {
            Some(enumeration) => direct_visibility(&enumeration),
            None => Visibility::Private,
        }
    } else {
        direct_visibility(node)
    };
    if own == Visibility::Private {
        return Visibility::Private;
    }

    // Everything the item sits inside has to be public too, or the modifier
    // reaches nothing. Modules are the common case; the aggregate types are
    // what make a `pub` field or a variant answerable at all.
    let mut ancestor = node.parent();
    while let Some(current) = ancestor {
        let encloses = matches!(
            current.kind(),
            SyntaxKind::MODULE
                | SyntaxKind::ENUM
                | SyntaxKind::STRUCT
                | SyntaxKind::UNION
                | SyntaxKind::TRAIT
        );
        if encloses && direct_visibility(&current) != Visibility::Public {
            return Visibility::Restricted;
        }
        ancestor = current.parent();
    }

    own
}

/// The item's own visibility modifier, ignoring enclosing modules.
fn direct_visibility(node: &SyntaxNode) -> Visibility {
    match node.children().find_map(ast::Visibility::cast) {
        None => Visibility::Private,
        Some(v) => {
            if v.syntax().text().to_string().trim() == "pub" {
                Visibility::Public
            } else {
                Visibility::Restricted
            }
        }
    }
}

/// Normalized attribute paths on an item.
///
/// `#[serde(rename_all = "camelCase")]` yields `serde`.
/// `#[unsafe(no_mangle)]` yields both `no_mangle` and `unsafe(no_mangle)`, so
/// a keep rule written either way matches.
pub fn attribute_names(node: &SyntaxNode) -> Vec<String> {
    let mut out = Vec::new();
    for attr in node.children().filter_map(ast::Attr::cast) {
        let text = attr.syntax().text().to_string();
        let inner = strip_attr_wrapper(&text);

        let name = if let Some(rest) = inner.strip_prefix("unsafe(") {
            // `unsafe(no_mangle)` / `unsafe(export_name = "...")`
            let inner_name = rest
                .split(['(', ')', '=', ','])
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if inner_name.is_empty() {
                continue;
            }
            out.push(format!("unsafe({inner_name})"));
            inner_name
        } else {
            inner
                .split(['(', '=', ' ', '\n', '\t'])
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        };

        if name.is_empty() {
            continue;
        }
        // Also expose the final segment so `#[tauri::command]` matches a keep
        // rule written as `command`.
        if let Some(last) = name.rsplit("::").next() {
            if last != name {
                out.push(last.to_string());
            }
        }
        out.push(name);
    }
    out
}

/// Is a `// obfuscator:keep` comment attached to this item?
///
/// rust-analyzer's tree is lossless, so leading trivia is attached to the item
/// as its own *children*:
///
/// ```text
/// FN@27..72
///   COMMENT@27..45 "// obfuscator:keep"
///   WHITESPACE@45..58 "\n            "
///   FN_KW@58..60 "fn"
/// ```
///
/// The scan runs over those children, from the item outwards. Two things have
/// to be distinguished, and both are checked here rather than left to chance:
///
/// - A blank line ends the run. Walking outwards means the whitespace *between*
///   a stray marker and this item is reached first, so one marker at the top of
///   a file cannot pin everything below it.
/// - A comment trailing the *previous* item's line belongs to that item. In
///   `fn a() {} // obfuscator:keep`, trivia attaches to the following token, so
///   the marker shows up as leading trivia of `b`. The whitespace that would
///   reveal this is a sibling of the item rather than a child of it, which is
///   why `text` is needed here: the test is whether only whitespace separates
///   the marker from the start of its line.
fn has_inline_keep(node: &SyntaxNode, text: &str) -> bool {
    let mut leading = Vec::new();
    for child in node.children_with_tokens() {
        match child {
            SyntaxElement::Token(token)
                if matches!(token.kind(), SyntaxKind::COMMENT | SyntaxKind::WHITESPACE) =>
            {
                leading.push(token);
            }
            // Attributes sit between the doc comments and the item; keep
            // scanning past them so `// obfuscator:keep` above an attribute
            // still counts.
            SyntaxElement::Node(n) if n.kind() == SyntaxKind::ATTR => continue,
            _ => break,
        }
    }

    for token in leading.iter().rev() {
        match token.kind() {
            // The nearest marker wins, and it only counts if it starts a line.
            SyntaxKind::COMMENT if token.text().contains(KEEP_MARKER) => {
                return starts_its_own_line(text, usize::from(token.text_range().start()));
            }
            // A blank line ends the attached-comment run.
            SyntaxKind::WHITESPACE if token.text().matches('\n').count() >= 2 => return false,
            _ => {}
        }
    }
    false
}

/// Does only whitespace separate `offset` from the start of its line?
fn starts_its_own_line(text: &str, offset: usize) -> bool {
    let before = &text[..offset.min(text.len())];
    match before.rfind('\n') {
        None => before.trim().is_empty(),
        Some(newline) => before[newline + 1..].trim().is_empty(),
    }
}

/// Does the file opt out of transformation entirely?
fn file_has_keep_marker(file: &ast::SourceFile) -> bool {
    file.syntax()
        .descendants_with_tokens()
        .filter_map(|el| el.into_token())
        .filter(|t| t.kind() == SyntaxKind::COMMENT)
        .any(|t| t.text().contains(KEEP_FILE_MARKER))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ra_ap_syntax::SourceFile;

    fn parse(src: &str) -> ast::SourceFile {
        SourceFile::parse(src, ra_ap_syntax::Edition::Edition2021).tree()
    }

    fn collect_src(src: &str) -> Vec<Candidate> {
        let file = parse(src);
        collect(
            &file,
            &FileContext {
                path: Path::new("src/lib.rs"),
                text: src,
                crate_name: "mycrate",
                module_prefix: &[],
            },
        )
    }

    fn paths(src: &str) -> Vec<String> {
        collect_src(src).into_iter().map(|c| c.path).collect()
    }

    fn attr_of(src: &str, name: &str) -> Vec<String> {
        collect_src(src)
            .into_iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .attributes
    }

    #[test]
    fn finds_items_and_builds_paths() {
        let found = paths(
            r#"
            fn top_level() {}

            mod network {
                pub fn connect() {}
                pub struct Client;
                pub enum State { Idle, Busy }
            }

            impl Client {
                fn helper(&self) {}
            }
            "#,
        );

        assert!(found.contains(&"mycrate::top_level".to_string()));
        assert!(found.contains(&"mycrate::network::connect".to_string()));
        assert!(found.contains(&"mycrate::network::Client".to_string()));
        assert!(found.contains(&"mycrate::network::State".to_string()));
        assert!(found.contains(&"mycrate::network::State::Idle".to_string()));
        assert!(found.contains(&"mycrate::Client::helper".to_string()));
    }

    #[test]
    fn module_prefix_from_file_location() {
        let file = parse("pub fn handler() {}");
        let prefix = vec!["api".to_string(), "routes".to_string()];
        let cands = collect(
            &file,
            &FileContext {
                path: Path::new("src/api/routes.rs"),
                text: "pub fn handler() {}",
                crate_name: "app",
                module_prefix: &prefix,
            },
        );
        assert_eq!(cands[0].path, "app::api::routes::handler");
    }

    #[test]
    fn visibility_accounts_for_enclosing_modules() {
        let cands = collect_src(
            r#"
            pub fn a() {}
            pub(crate) fn b() {}
            fn c() {}
            pub mod open { pub fn d() {} }
            mod closed { pub fn e() {} }
            "#,
        );
        let vis = |name: &str| {
            cands
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
                .visibility
        };

        assert_eq!(vis("a"), Visibility::Public);
        assert_eq!(vis("b"), Visibility::Restricted);
        assert_eq!(vis("c"), Visibility::Private);
        assert_eq!(vis("d"), Visibility::Public);
        assert_eq!(
            vis("e"),
            Visibility::Restricted,
            "a `pub` item in a private module is not externally reachable"
        );
    }

    #[test]
    fn attributes_are_normalized() {
        let src = r#"
            #[no_mangle]
            pub extern "C" fn exported() {}

            #[unsafe(no_mangle)]
            pub fn exported2() {}

            #[tauri::command]
            async fn cmd() {}

            #[serde(rename_all = "camelCase")]
            struct Config { field: u8 }
            "#;

        assert!(attr_of(src, "exported").contains(&"no_mangle".to_string()));
        assert!(
            attr_of(src, "exported2").contains(&"no_mangle".to_string()),
            "unsafe(no_mangle) must normalize to no_mangle"
        );
        assert!(attr_of(src, "cmd").contains(&"tauri::command".to_string()));
        assert!(attr_of(src, "cmd").contains(&"command".to_string()));
        assert!(attr_of(src, "Config").contains(&"serde".to_string()));
    }

    #[test]
    fn inline_keep_comment_pins_the_next_item() {
        let cands = collect_src(
            r#"
            // obfuscator:keep
            fn pinned() {}

            // an ordinary comment
            fn normal() {}

            // obfuscator:keep
            // a second comment line
            fn also_pinned() {}
            "#,
        );
        let keep = |name: &str| {
            cands
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
                .inline_keep
        };
        assert!(keep("pinned"));
        assert!(!keep("normal"));
        assert!(
            keep("also_pinned"),
            "consecutive comment lines stay attached"
        );
    }

    #[test]
    fn keep_comment_does_not_leak_past_a_blank_line() {
        let cands = collect_src(
            r#"
            // obfuscator:keep
            fn pinned() {}

            fn far_below() {}
            "#,
        );
        let far = cands.iter().find(|c| c.name == "far_below").unwrap();
        assert!(!far.inline_keep, "a blank line must detach the marker");
    }

    #[test]
    fn keep_file_marker_disables_the_whole_file() {
        let cands = collect_src(
            r#"
            // obfuscator:keep-file
            fn a() {}
            fn b() {}
            "#,
        );
        assert!(cands.is_empty());
    }

    #[test]
    fn extern_block_contents_are_not_candidates() {
        // The name in `extern "C" { fn foo(); }` is the linkage symbol, not a
        // Rust definition. Renaming it would change what gets linked against.
        let cands = collect_src(
            r#"
            extern "C" {
                fn foreign_thing(x: i32) -> i32;
                static FOREIGN_STATIC: i32;
            }
            "#,
        );
        assert!(
            cands.is_empty(),
            "foreign declarations must not be candidates, got {:?}",
            cands.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn local_bindings_and_strings_are_candidates_but_strings_are_not() {
        let cands = collect_src(
            r#"
            fn f() {
                let some_local = "some_local";
            }
            "#,
        );
        assert!(cands
            .iter()
            .any(|c| c.name == "f" && c.kind == ItemKind::Function));
        assert!(cands
            .iter()
            .any(|c| c.name == "some_local" && c.kind == ItemKind::Local));
        assert!(!cands
            .iter()
            .any(|c| c.name == "some_local" && c.kind == ItemKind::Function));
    }

    #[test]
    fn macro_rules_names_are_found() {
        let cands = collect_src("macro_rules! my_macro { () => {} }");
        assert_eq!(cands[0].name, "my_macro");
        assert_eq!(cands[0].kind, ItemKind::Macro);
    }

    #[test]
    fn record_fields_are_found() {
        let cands = collect_src("struct S { alpha: u8, beta: u8 }");
        let fields: Vec<_> = cands
            .iter()
            .filter(|c| c.kind == ItemKind::Field)
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(fields, vec!["alpha", "beta"]);
    }

    #[test]
    fn line_numbers_are_one_based() {
        let cands = collect_src("\n\nfn third_line() {}\n");
        assert_eq!(cands[0].line, 3);
    }

    #[test]
    fn line_index_handles_boundaries() {
        let idx = LineIndex::new("a\nbb\n\nccc");
        assert_eq!(idx.line_of(0), 1, "start of file");
        assert_eq!(idx.line_of(1), 1, "the newline itself is still line 1");
        assert_eq!(idx.line_of(2), 2);
        assert_eq!(idx.line_of(5), 3, "empty line");
        assert_eq!(idx.line_of(6), 4);
    }
    #[test]
    fn keep_comment_above_an_attribute_still_applies() {
        // Attributes sit between the comment and the item keyword, so the
        // scan has to step over them rather than stopping at the first
        // non-trivia child.
        let cands = collect_src(
            r#"
            // obfuscator:keep
            #[no_mangle]
            fn exported() {}
            "#,
        );
        let f = cands.iter().find(|c| c.name == "exported").unwrap();
        assert!(
            f.inline_keep,
            "the marker must survive an intervening attribute"
        );
        assert!(f.attributes.contains(&"no_mangle".to_string()));
    }

    #[test]
    fn trailing_comment_does_not_pin_the_next_item() {
        let cands = collect_src(
            r#"
            fn first() {} // obfuscator:keep
            fn second() {}
            "#,
        );
        let second = cands.iter().find(|c| c.name == "second").unwrap();
        assert!(!second.inline_keep);
    }

    // -- serde data model ---------------------------------------------------

    fn serde_flags(src: &str) -> Vec<(String, bool)> {
        collect_src(src)
            .into_iter()
            .map(|c| (c.name, c.serde_model))
            .collect()
    }

    fn flag_of(src: &str, name: &str) -> bool {
        serde_flags(src)
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .1
    }

    #[test]
    fn serde_fields_and_variants_are_flagged() {
        let src = r#"
            #[derive(Serialize, Deserialize)]
            struct User {
                user_name: String,
                device_id: u32,
            }

            #[derive(Serialize)]
            enum State {
                Connected,
                Disconnected { reason_code: u16 },
            }
            "#;

        for name in ["user_name", "device_id"] {
            assert!(flag_of(src, name), "field `{name}` is a wire-format key");
        }
        for name in ["Connected", "Disconnected", "reason_code"] {
            assert!(flag_of(src, name), "`{name}` is part of the wire format");
        }

        // The type's own name is not serialized by serde, so it stays a plain
        // Rust identifier and stays renameable.
        assert!(!flag_of(src, "User"));
        assert!(!flag_of(src, "State"));
    }

    #[test]
    fn every_spelling_of_the_derive_is_recognised() {
        let cases = [
            ("#[derive(Serialize)]", true),
            ("#[derive(Deserialize)]", true),
            ("#[derive(serde::Serialize)]", true),
            ("#[derive(serde::Deserialize)]", true),
            ("#[derive(Serialize, Deserialize)]", true),
            ("#[derive(Debug, Clone, Serialize)]", true),
            ("#[derive(Debug, Serialize)]\n#[derive(Clone)]", true),
            ("#[derive(Clone, Debug, PartialEq)]", false),
            ("#[derive(Default)]", false),
            ("", false),
        ];
        for (attr, expected) in cases {
            let src = format!("{attr}\nstruct Probe {{ network_timeout: u32 }}");
            assert_eq!(
                flag_of(&src, "network_timeout"),
                expected,
                "attribute {attr:?} should{} imply a serde model",
                if expected { "" } else { " not" }
            );
        }
    }

    #[test]
    fn types_outside_a_serde_model_stay_renameable() {
        let src = r#"
            #[derive(Clone)]
            struct Plain {
                scratch_buffer: Vec<u8>,
            }

            enum AlsoPlain {
                Idle,
                Busy { retry_count: u32 },
            }

            fn helper() {}
            "#;
        for name in ["scratch_buffer", "Idle", "Busy", "retry_count", "helper"] {
            assert!(
                !flag_of(src, name),
                "`{name}` is not part of any serde data model"
            );
        }
    }

    /// A serde model reached through a module boundary is still a serde model,
    /// and an unrelated `Serialize` trait in scope must not silently stop being
    /// detected.
    #[test]
    fn serde_detection_survives_nesting_and_paths() {
        let src = r#"
            mod inner {
                #[derive(serde::Serialize, serde::Deserialize)]
                pub struct Payload {
                    pub api_key: String,
                }
            }
            "#;
        assert!(flag_of(src, "api_key"));
    }

    #[test]
    fn a_variant_inherits_the_visibility_of_its_enum() {
        let cands = collect_src(
            r#"
            pub enum PublicState { Connected, Disconnected }
            pub struct PublicStruct { pub open: u8, closed: u8 }
            enum InternalState { Idle }
            "#,
        );
        let vis = |name: &str| {
            cands
                .iter()
                .find(|c| c.name == name)
                .unwrap_or_else(|| panic!("missing {name}"))
                .visibility
        };
        assert_eq!(vis("PublicState"), Visibility::Public);
        assert_eq!(
            vis("Connected"),
            Visibility::Public,
            "a variant has no visibility token of its own, but it is as reachable as its enum"
        );
        assert_eq!(vis("Disconnected"), Visibility::Public);
        assert_eq!(vis("open"), Visibility::Public);
        assert_eq!(vis("closed"), Visibility::Private);
        assert_eq!(vis("InternalState"), Visibility::Private);
        assert_eq!(vis("Idle"), Visibility::Private);
    }

    /// `pub` on a field is capped by the struct. `Restricted` rather than
    /// `Private` because that is the bucket the rename pass acts on — both mean
    /// "nothing outside this crate can reach it".
    #[test]
    fn a_public_field_needs_a_public_struct() {
        let cands = collect_src("struct Wrapper { pub field: u8 }");
        let f = cands.iter().find(|c| c.name == "field").unwrap();
        assert_ne!(
            f.visibility,
            Visibility::Public,
            "`pub` on a field of a private struct reaches nothing outside the crate"
        );

        let cands = collect_src("pub struct Wrapper { pub field: u8 }");
        let f = cands.iter().find(|c| c.name == "field").unwrap();
        assert_eq!(f.visibility, Visibility::Public);
    }

    /// The same rule one level further out: a public enum inside a private
    /// module is not public API either.
    #[test]
    fn a_variant_is_capped_by_the_module_holding_the_enum() {
        let cands = collect_src("mod inner { pub enum Public { Ready } }");
        let v = cands.iter().find(|c| c.name == "Ready").unwrap();
        assert_ne!(v.visibility, Visibility::Public);
    }
}
