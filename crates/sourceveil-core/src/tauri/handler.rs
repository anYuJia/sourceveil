//! Reading and rewriting `tauri::generate_handler![...]`.
//!
//! This is the reference rust-analyzer cannot produce. A macro invocation's
//! arguments are a raw token tree, and the reference search does not descend
//! into one — measured, not assumed; see [`crate::rust`]. So the handler list is
//! parsed here, by hand, and only here: the rewriter is handed the exact spans
//! of the names it may change, and nothing else in the token tree is touched.
//!
//! That restriction is the point. A global pass over macro token trees would
//! rewrite identifiers inside `format!`, `include_str!` and every attribute the
//! project uses, which is how a source transform turns into a source corruption.

use ra_ap_syntax::{SyntaxElement, SyntaxKind, SyntaxNode, TextRange};

/// One entry of a `generate_handler![...]` list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerEntry {
    /// The path as written: `commands::get_user_info`.
    pub path: String,
    /// The command name — the final path segment.
    pub command: String,
    /// Span of that final segment. This is the only thing that gets replaced.
    pub name_range: TextRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerParseError {
    pub reason: String,
}

impl std::fmt::Display for HandlerParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

/// Parse the token tree of a `generate_handler![...]` invocation.
///
/// Anything this does not recognise is an error rather than a guess. A list
/// that cannot be read completely means no command downstream of it can be
/// shown to be rewritten, and the caller keeps them all.
pub fn parse_entries(tree: &SyntaxNode) -> Result<Vec<HandlerEntry>, HandlerParseError> {
    // Significant tokens only: trivia carries no meaning here, and the list's
    // own brackets are the delimiters rather than content. A nested bracket
    // would sit inside a child node, which is rejected below.
    let mut tokens = Vec::new();
    for element in tree.children_with_tokens() {
        match element {
            SyntaxElement::Node(node) => {
                return Err(HandlerParseError {
                    reason: format!(
                        "a nested {:?} inside generate_handler! cannot be resolved statically",
                        node.kind()
                    ),
                })
            }
            SyntaxElement::Token(token) => match token.kind() {
                SyntaxKind::WHITESPACE | SyntaxKind::COMMENT => {}
                SyntaxKind::L_BRACK | SyntaxKind::R_BRACK => {}
                _ => tokens.push(token),
            },
        }
    }

    let mut out = Vec::new();
    let mut current: Vec<(String, TextRange)> = Vec::new();
    let mut index = 0;

    while index < tokens.len() {
        let token = &tokens[index];
        match token.kind() {
            SyntaxKind::IDENT => {
                current.push((token.text().to_string(), token.text_range()));
                index += 1;
            }
            // Inside a token tree the separator is not lexed as one token:
            // `commands::foo` arrives as IDENT, COLON, COLON, IDENT. Both
            // spellings are accepted so this does not depend on which way a
            // given rust-analyzer version lexes it.
            SyntaxKind::COLON2 => index += 1,
            SyntaxKind::COLON
                if tokens.get(index + 1).map(|t| t.kind()) == Some(SyntaxKind::COLON) =>
            {
                index += 2;
            }
            SyntaxKind::COMMA => {
                finish_group(&mut current, &mut out);
                index += 1;
            }
            // A lone colon is not a path separator, so it is not something this
            // reader understands. Refusing beats guessing.
            other => {
                return Err(HandlerParseError {
                    reason: format!("unexpected {other:?} in generate_handler!"),
                })
            }
        }
    }
    finish_group(&mut current, &mut out);

    Ok(out)
}

fn finish_group(current: &mut Vec<(String, TextRange)>, out: &mut Vec<HandlerEntry>) {
    // A trailing comma produces an empty group, which is not an error.
    if current.is_empty() {
        return;
    }
    let path = current
        .iter()
        .map(|(segment, _)| segment.as_str())
        .collect::<Vec<_>>()
        .join("::");
    let (command, name_range) = current
        .last()
        .cloned()
        .expect("group is non-empty, checked above");
    out.push(HandlerEntry {
        path,
        command,
        name_range,
    });
    current.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ra_ap_syntax::ast::AstNode;
    use ra_ap_syntax::SourceFile;

    /// Parse a whole file and hand back the token tree of the first macro call.
    fn tree_of(src: &str) -> SyntaxNode {
        let file = SourceFile::parse(src, ra_ap_syntax::Edition::Edition2021).tree();
        file.syntax()
            .descendants()
            .find(|n| n.kind() == SyntaxKind::TOKEN_TREE)
            .expect("a macro token tree")
    }

    fn entries(src: &str) -> Vec<HandlerEntry> {
        parse_entries(&tree_of(src)).expect("parse")
    }

    fn commands(src: &str) -> Vec<String> {
        entries(src).into_iter().map(|e| e.command).collect()
    }

    #[test]
    fn reads_bare_names() {
        assert_eq!(commands("x![a, b]"), vec!["a", "b"]);
    }

    #[test]
    fn reads_qualified_paths() {
        let e = entries("x![commands::get_user_info, license::activate]");
        assert_eq!(e[0].path, "commands::get_user_info");
        assert_eq!(e[0].command, "get_user_info");
        assert_eq!(e[1].path, "license::activate");
        assert_eq!(e[1].command, "activate");
    }

    #[test]
    fn tolerates_whitespace_newlines_and_a_trailing_comma() {
        let src = "x![\n    commands::foo,\n    bar,\n]";
        assert_eq!(commands(src), vec!["foo", "bar"]);
    }

    #[test]
    fn handles_a_deeply_qualified_path() {
        let e = entries("x![a::b::c::foo]");
        assert_eq!(e[0].path, "a::b::c::foo");
        assert_eq!(e[0].command, "foo");
    }

    #[test]
    fn an_empty_list_is_not_an_error() {
        assert!(entries("x![]").is_empty());
    }

    #[test]
    fn the_recorded_span_covers_only_the_final_segment() {
        let src = "x![commands::get_user_info]";
        let entry = &entries(src)[0];
        assert_eq!(&src[entry.name_range], "get_user_info");
    }

    /// The span is used as an edit target, so it has to be exact even when the
    /// path is the whole entry.
    #[test]
    fn the_span_of_a_bare_name_covers_that_name() {
        let src = "x![get_user_info]";
        let entry = &entries(src)[0];
        assert_eq!(&src[entry.name_range], "get_user_info");
    }

    #[test]
    fn a_nested_token_tree_is_refused_rather_than_guessed() {
        let src = "x![foo(1)]";
        let err = parse_entries(&tree_of(src)).unwrap_err();
        assert!(err.reason.contains("nested"), "{err}");
    }

    #[test]
    fn an_attribute_inside_the_list_is_refused() {
        let src = "x![#[cfg(test)] foo]";
        assert!(parse_entries(&tree_of(src)).is_err());
    }

    /// End to end on the shape the fixture uses.
    #[test]
    fn reads_a_realistic_handler_list() {
        let src = r#"
            fn main() {
                tauri::generate_handler![
                    commands::get_user_info,
                    commands::activate_license,
                    commands::sync_state,
                    standalone,
                ];
            }
        "#;
        assert_eq!(
            commands(src),
            vec![
                "get_user_info",
                "activate_license",
                "sync_state",
                "standalone"
            ]
        );
    }
}
