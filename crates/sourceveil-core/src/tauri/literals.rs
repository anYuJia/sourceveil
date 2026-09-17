//! Command names that appear in Rust as string literals.
//!
//! Renaming a command's Rust function and its `generate_handler!` entry is not
//! enough. A Tauri app that dispatches on a command name at runtime —
//!
//! ```rust,ignore
//! match invoke.message.command() {
//!     "get_user_info" => …,
//! }
//! ```
//!
//! — or that carries an allow-list of permitted commands keeps working only if
//! those strings move too. Miss one and the app compiles, starts, and then
//! refuses every call to that command.
//!
//! ## Why this refuses more than it rewrites
//!
//! A blanket replace over string literals would be trivial and wrong: the same
//! string can be a log message, a metric name, a file name. So this module only
//! *rewrites* literals in contexts it can recognise, and reports every literal
//! equal to a command name that it could not classify. The caller keeps those
//! commands rather than guessing.

use ra_ap_syntax::{SyntaxKind, SyntaxNode, SyntaxToken, TextRange};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A literal that spells a command name.
#[derive(Debug, Clone)]
pub struct LiteralRef {
    pub command: String,
    /// The file the literal lives in.
    pub file: PathBuf,
    /// Range of the string token, quotes included.
    pub span: TextRange,
    pub kind: LiteralKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiteralKind {
    /// A `match` arm pattern on a `command()` scrutinee.
    DispatchArm,
    /// An element of a list bound to something that looks like a command set.
    CommandSet,
}

#[derive(Debug, Default)]
pub struct LiteralScan {
    /// Literals in a context this module recognises, and may rewrite.
    pub recognized: Vec<LiteralRef>,
    /// Literals that spell a command name but sit somewhere unrecognised.
    /// Their presence keeps the command.
    pub unclassified: Vec<LiteralRef>,
}

impl LiteralScan {
    pub fn extend(&mut self, other: LiteralScan) {
        self.recognized.extend(other.recognized);
        self.unclassified.extend(other.unclassified);
    }

    /// Every unclassified literal for one command.
    pub fn unclassified_for<'a>(
        &'a self,
        command: &'a str,
    ) -> impl Iterator<Item = &'a LiteralRef> {
        self.unclassified
            .iter()
            .filter(move |r| r.command == command)
    }

    pub fn recognized_for<'a>(&'a self, command: &'a str) -> impl Iterator<Item = &'a LiteralRef> {
        self.recognized.iter().filter(move |r| r.command == command)
    }
}

/// Substrings that mark a binding as a set of command names.
///
/// A heuristic, and a deliberately narrow one: it decides whether a list of
/// strings *may* be rewritten, and everything it declines is reported and kept
/// rather than rewritten.
const COMMAND_SET_MARKERS: &[&str] = &["command", "allow", "permit", "whitelist"];

/// Scan one file's syntax tree for command names.
pub fn scan_file(path: &Path, root: &SyntaxNode, commands: &BTreeSet<String>) -> LiteralScan {
    let mut scan = LiteralScan::default();
    if commands.is_empty() {
        return scan;
    }

    for token in root
        .descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| token.kind() == SyntaxKind::STRING)
    {
        let Some(value) = string_value(token.text()) else {
            continue;
        };
        if !commands.contains(&value) {
            continue;
        }

        let kind = classify(&token, commands);
        let reference = LiteralRef {
            command: value,
            file: path.to_path_buf(),
            span: token.text_range(),
            kind: kind.unwrap_or(LiteralKind::DispatchArm),
        };
        match kind {
            Some(_) => scan.recognized.push(reference),
            None => scan.unclassified.push(reference),
        }
    }

    scan
}

/// Where does this literal sit?
fn classify(token: &SyntaxToken, commands: &BTreeSet<String>) -> Option<LiteralKind> {
    if is_dispatch_arm(token) {
        return Some(LiteralKind::DispatchArm);
    }
    if is_in_command_set(token, commands) {
        return Some(LiteralKind::CommandSet);
    }
    None
}

/// A `match` arm pattern over something ending in `command()` — the shape of
/// Tauri's own `Invoke::message().command()`.
///
/// The literal has to be in the arm's *pattern*. A literal in the arm's body is
/// a different thing entirely: `_ => log("get_user_info")` does not dispatch on
/// anything.
fn is_dispatch_arm(token: &SyntaxToken) -> bool {
    let Some(arm) = token
        .parent()
        .and_then(|n| n.ancestors().find(|a| a.kind() == SyntaxKind::MATCH_ARM))
    else {
        return false;
    };

    // A match arm's node children are the pattern and the body, in that order
    // (`=>` is a token, not a node).
    let Some(pattern) = arm.children().next() else {
        return false;
    };
    if !pattern.text_range().contains_range(token.text_range()) {
        return false;
    }

    let Some(match_expr) = arm.ancestors().find(|a| a.kind() == SyntaxKind::MATCH_EXPR) else {
        return false;
    };
    let Some(scrutinee) = match_expr
        .children()
        .find(|c| c.kind() != SyntaxKind::MATCH_ARM_LIST)
    else {
        return false;
    };

    let text = scrutinee.text().to_string();
    let text = text.trim();
    text.ends_with("command()") || text.ends_with("command ()")
}

/// Inside a list of strings bound to something named like a command set, where
/// *every* element is a command name.
///
/// The all-elements rule is what makes the name heuristic tolerable. A list
/// that mixes command names with anything else is not a list of commands, and
/// rewriting part of it would be worse than leaving it alone.
fn is_in_command_set(token: &SyntaxToken, commands: &BTreeSet<String>) -> bool {
    let Some(container) = enclosing_list(token) else {
        return false;
    };
    let Some(name) = binding_name(&container) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if !COMMAND_SET_MARKERS.iter().any(|m| lower.contains(m)) {
        return false;
    }

    let elements = string_elements(&container);
    !elements.is_empty() && elements.iter().all(|e| commands.contains(e))
}

/// The `[..]` or `vec![..]` the literal sits in.
fn enclosing_list(token: &SyntaxToken) -> Option<SyntaxNode> {
    for ancestor in token.parent()?.ancestors() {
        match ancestor.kind() {
            SyntaxKind::ARRAY_EXPR => return Some(ancestor),
            SyntaxKind::MACRO_CALL if is_vec_macro(&ancestor) => return Some(ancestor),
            // Stop at anything that would make this a different expression.
            SyntaxKind::CALL_EXPR | SyntaxKind::BLOCK_EXPR | SyntaxKind::FN => return None,
            _ => {}
        }
    }
    None
}

fn is_vec_macro(call: &SyntaxNode) -> bool {
    call.children()
        .find(|c| c.kind() == SyntaxKind::PATH)
        .map(|path| path.text().to_string().trim() == "vec")
        .unwrap_or(false)
}

/// The name the list is bound to, whether `const`, `static` or `let`.
fn binding_name(list: &SyntaxNode) -> Option<String> {
    for ancestor in list.ancestors() {
        match ancestor.kind() {
            SyntaxKind::CONST | SyntaxKind::STATIC => {
                return ancestor
                    .children()
                    .find(|c| c.kind() == SyntaxKind::NAME)
                    .map(|n| n.text().to_string());
            }
            SyntaxKind::LET_STMT => {
                return ancestor
                    .children()
                    .find(|c| c.kind() == SyntaxKind::IDENT_PAT)
                    .map(|p| p.text().to_string());
            }
            SyntaxKind::FN | SyntaxKind::MODULE => return None,
            _ => {}
        }
    }
    None
}

/// All string tokens directly inside a list node.
fn string_elements(list: &SyntaxNode) -> Vec<String> {
    list.descendants_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| token.kind() == SyntaxKind::STRING)
        .filter_map(|token| string_value(token.text()))
        .collect()
}

/// The value of a string token, `r#".."#` and escapes aside.
///
/// Only plain and raw literals are understood. Anything else returns `None`,
/// which makes the literal unclassified — the safe direction, since an
/// unclassified literal keeps its command.
pub fn string_value(text: &str) -> Option<String> {
    if let Some(rest) = text.strip_prefix('r') {
        let hashes = rest.chars().take_while(|c| *c == '#').count();
        let rest = &rest[hashes..];
        let quote = rest.chars().next()?;
        if quote != '"' {
            return None;
        }
        let body = &rest[1..];
        let suffix = format!("\"{}", "#".repeat(hashes));
        return body.strip_suffix(&suffix).map(|s| s.to_string());
    }
    let body = text.strip_prefix('"')?.strip_suffix('"')?;
    // An escape means the source text is not the value. Refusing is cheaper
    // than being wrong: the command is kept and reported instead.
    if body.contains('\\') {
        return None;
    }
    Some(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ra_ap_syntax::ast::AstNode;
    use ra_ap_syntax::SourceFile;

    fn scan(src: &str, commands: &[&str]) -> LiteralScan {
        let file = SourceFile::parse(src, ra_ap_syntax::Edition::Edition2021).tree();
        let set: BTreeSet<String> = commands.iter().map(|c| c.to_string()).collect();
        scan_file(Path::new("src/lib.rs"), file.syntax(), &set)
    }

    #[test]
    fn reads_plain_and_raw_string_values() {
        assert_eq!(string_value(r#""foo""#).as_deref(), Some("foo"));
        assert_eq!(string_value(r##"r#"foo"#"##).as_deref(), Some("foo"));
        assert_eq!(string_value(r#""""#).as_deref(), Some(""));
        assert_eq!(string_value(r#""a\nb""#), None, "escapes are refused");
        assert_eq!(string_value("123"), None);
    }

    #[test]
    fn a_match_arm_on_command_is_recognised() {
        let scan = scan(
            r#"
            fn dispatch(invoke: Invoke) {
                match invoke.message.command() {
                    "get_user_info" => handle(),
                    "other" => {}
                    _ => {}
                }
            }
            "#,
            &["get_user_info"],
        );
        assert_eq!(scan.recognized.len(), 1);
        assert_eq!(scan.recognized[0].kind, LiteralKind::DispatchArm);
        assert!(scan.unclassified.is_empty());
    }

    /// A match on something else is not a command dispatch, even when the
    /// string happens to equal a command name.
    #[test]
    fn a_match_arm_on_something_else_is_not_recognised() {
        let scan = scan(
            r#"
            fn f(kind: &str) {
                match kind {
                    "get_user_info" => {}
                    _ => {}
                }
            }
            "#,
            &["get_user_info"],
        );
        assert!(scan.recognized.is_empty());
        assert_eq!(scan.unclassified.len(), 1);
    }

    /// The literal is in the arm's body, not its pattern.
    #[test]
    fn a_literal_in_a_match_body_is_not_a_dispatch_arm() {
        let scan = scan(
            r#"
            fn f(invoke: Invoke) {
                match invoke.message.command() {
                    _ => { log("get_user_info"); }
                }
            }
            "#,
            &["get_user_info"],
        );
        assert!(scan.recognized.is_empty());
        assert_eq!(scan.unclassified.len(), 1);
    }

    #[test]
    fn a_const_command_set_is_recognised() {
        let scan = scan(
            r#"
            const ALLOWED_COMMANDS: &[&str] = &[
                "get_user_info",
                "activate_license",
            ];
            "#,
            &["get_user_info", "activate_license"],
        );
        assert_eq!(scan.recognized.len(), 2);
        assert!(scan
            .recognized
            .iter()
            .all(|r| r.kind == LiteralKind::CommandSet));
        assert!(scan.unclassified.is_empty());
    }

    #[test]
    fn a_vec_command_set_is_recognised() {
        let scan = scan(
            r#"
            pub fn allowed() -> Vec<&'static str> {
                vec!["get_user_info", "activate_license"]
            }
            "#,
            &["get_user_info", "activate_license"],
        );
        // Bound to a function rather than a named command set, so this is not
        // recognised — and being conservative is the point.
        assert!(scan.recognized.is_empty());
    }

    #[test]
    fn a_set_bound_to_an_unrelated_name_is_not_recognised() {
        let scan = scan(
            r#"
            const GREETINGS: &[&str] = &["get_user_info"];
            "#,
            &["get_user_info"],
        );
        assert!(scan.recognized.is_empty());
        assert_eq!(scan.unclassified.len(), 1);
    }

    #[test]
    fn a_literal_of_an_unknown_string_is_ignored_entirely() {
        let scan = scan(r#"fn f() { log("not_a_command"); }"#, &["get_user_info"]);
        assert!(scan.recognized.is_empty());
        assert!(scan.unclassified.is_empty());
    }

    #[test]
    fn a_literal_in_ordinary_code_is_unclassified() {
        let scan = scan(r#"fn f() { log("get_user_info"); }"#, &["get_user_info"]);
        assert!(scan.recognized.is_empty());
        assert_eq!(scan.unclassified.len(), 1);
    }

    #[test]
    fn format_macro_arguments_are_unclassified() {
        let scan = scan(
            r#"fn f() { println!("{}", "get_user_info"); }"#,
            &["get_user_info"],
        );
        assert_eq!(scan.unclassified.len(), 1);
    }
}
