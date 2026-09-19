//! Final, syntax-aware comment removal. Never operates on the input tree.

use anyhow::{bail, Context, Result};
use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use ra_ap_syntax::{ast::AstNode, Edition, SourceFile, SyntaxKind};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ops::Range;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommentStats {
    pub enabled: bool,
    pub files_scanned: usize,
    pub files_edited: usize,
    pub comments_removed: usize,
    pub notices_extracted: usize,
}

pub struct CommentOutcome {
    pub stats: CommentStats,
    pub warnings: Vec<String>,
}

/// Format support is explicit. Unknown formats are not guessed at using regex.
pub fn strip_workspace(root: &Path) -> Result<CommentOutcome> {
    let mut stats = CommentStats {
        enabled: true,
        ..Default::default()
    };
    let mut pending = Vec::new();
    let mut notices = Vec::new();
    let mut warnings = Vec::new();
    let walker = walkdir::WalkDir::new(root)
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
        });
    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let extension = syntax_extension(path);
        if !matches!(
            extension.as_str(),
            "rs" | "js"
                | "jsx"
                | "ts"
                | "tsx"
                | "mjs"
                | "cjs"
                | "mts"
                | "cts"
                | "css"
                | "html"
                | "htm"
                | "toml"
                | "jsonc"
        ) {
            if matches!(
                extension.as_str(),
                "vue" | "svelte" | "scss" | "less" | "yaml" | "yml" | "sh" | "py"
            ) {
                warnings.push(format!(
                    "comment removal does not parse {}: left unchanged",
                    path.strip_prefix(root)?.display()
                ));
            }
            continue;
        }
        let source =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        stats.files_scanned += 1;
        let (output, removed) = strip_source(path, &source)
            .with_context(|| format!("stripping comments in {}", path.display()))?;
        if removed.is_empty() {
            continue;
        }
        for comment in &removed {
            let lower = comment.to_ascii_lowercase();
            if [
                "copyright",
                "@license",
                "@preserve",
                "spdx-license",
                "licensed under",
                "license (",
            ]
            .iter()
            .any(|word| lower.contains(word))
            {
                notices.push(format!(
                    "Source: {}\n{}\n",
                    path.strip_prefix(root)?.display(),
                    comment
                ));
            }
        }
        stats.comments_removed += removed.len();
        stats.files_edited += 1;
        pending.push((path.to_owned(), output));
    }
    // Parse every supported file before writing any. A malformed file must not
    // yield a success report for a partially cleaned tree.
    for (path, output) in pending {
        std::fs::write(&path, output).with_context(|| format!("writing {}", path.display()))?;
    }
    stats.notices_extracted = notices.len();
    if !notices.is_empty() {
        let path = root.join("SOURCEVEIL_NOTICES.txt");
        let mut text = if path.exists() {
            std::fs::read_to_string(&path)?
        } else {
            "License/attribution notices extracted from source comments. Keep with distributions.\n\n".into()
        };
        text.push_str(&notices.join("\n"));
        std::fs::write(path, text)?;
    }
    Ok(CommentOutcome { stats, warnings })
}

pub fn strip_source(path: &Path, source: &str) -> Result<(String, Vec<String>)> {
    let extension = syntax_extension(path);
    let mut separators = HashSet::new();
    let ranges = match extension.as_str() {
        "rs" => {
            let parsed = SourceFile::parse(source, Edition::Edition2024);
            if !parsed.errors().is_empty() {
                bail!("Rust syntax errors; comments were not stripped");
            }
            parsed
                .tree()
                .syntax()
                .descendants_with_tokens()
                .filter_map(|el| el.into_token())
                .filter(|token| {
                    matches!(
                        token.kind(),
                        SyntaxKind::COMMENT
                            | SyntaxKind::INNER_DOC_COMMENT
                            | SyntaxKind::OUTER_DOC_COMMENT
                    )
                })
                .map(|token| {
                    u32::from(token.text_range().start()) as usize
                        ..u32::from(token.text_range().end()) as usize
                })
                .collect()
        }
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "mts" | "cts" => {
            js_comments(source, SourceType::from_path(path)?)?
        }
        "css" => css_comments(source, &mut separators)?,
        "html" | "htm" => return strip_html(source),
        "toml" => hash_comments(source)?,
        "jsonc" => json_comments(source)?,
        _ => bail!("unsupported comment syntax"),
    };
    let css = extension == "css";
    apply_ranges(source, ranges, css.then_some(&separators))
}

fn syntax_extension(path: &Path) -> String {
    if path.file_name().is_some_and(|name| name == "Cargo.lock") {
        "toml".into()
    } else {
        path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase()
    }
}

fn js_comments(source: &str, ty: SourceType) -> Result<Vec<Range<usize>>> {
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, source, ty).parse();
    if !parsed.diagnostics.is_empty() {
        bail!("JavaScript/TypeScript syntax errors; comments were not stripped");
    }
    Ok(parsed
        .program
        .comments
        .iter()
        .filter_map(|comment| {
            let range = comment.span.start as usize..comment.span.end as usize;
            let text = source.get(range.clone())?;
            (!is_typescript_triple_slash_directive(text)).then_some(range)
        })
        .collect())
}

/// Triple-slash references are parsed as comments, but TypeScript consumes
/// them as compiler directives. Removing Vite's common
/// `/// <reference types="vite/client" />`, for example, deletes all static
/// asset module declarations and breaks an otherwise valid production build.
fn is_typescript_triple_slash_directive(comment: &str) -> bool {
    let Some(body) = comment.strip_prefix("///") else {
        return false;
    };
    let body = body.trim_start();
    body.starts_with("<reference")
        || body.starts_with("<amd-module")
        || body.starts_with("<amd-dependency")
}

fn css_comments(source: &str, separators: &mut HashSet<usize>) -> Result<Vec<Range<usize>>> {
    fn scan(
        parser: &mut cssparser::Parser<'_, '_>,
        ranges: &mut Vec<Range<usize>>,
        separators: &mut HashSet<usize>,
    ) -> Result<()> {
        let mut previous = cssparser::TokenSerializationType::Nothing;
        let mut pending = None;
        loop {
            let start = parser.position().byte_index();
            let Ok(token) = parser.next_including_whitespace_and_comments() else {
                break;
            };
            let token = token.clone();
            let end = parser.position().byte_index();
            if matches!(token, cssparser::Token::Comment(_)) {
                ranges.push(start..end);
                pending.get_or_insert(start);
                continue;
            }
            if let Some(at) = pending.take() {
                if previous.needs_separator_when_before(token.serialization_type()) {
                    separators.insert(at);
                }
            }
            previous = token.serialization_type();
            match token {
                cssparser::Token::Function(_)
                | cssparser::Token::ParenthesisBlock
                | cssparser::Token::SquareBracketBlock
                | cssparser::Token::CurlyBracketBlock => {
                    let mut inner_error = None;
                    let result: std::result::Result<(), cssparser::ParseError<'_, ()>> = parser
                        .parse_nested_block(|p| {
                            if let Err(error) = scan(p, ranges, separators) {
                                inner_error = Some(error);
                            }
                            Ok(())
                        });
                    if let Some(error) = inner_error {
                        return Err(error);
                    }
                    if result.is_err() {
                        bail!("invalid CSS block");
                    }
                    previous = cssparser::TokenSerializationType::Other;
                }
                token if token.is_parse_error() => bail!("invalid CSS token"),
                _ => {}
            }
        }
        Ok(())
    }
    let mut input = cssparser::ParserInput::new(source);
    let mut ranges = Vec::new();
    scan(
        &mut cssparser::Parser::new(&mut input),
        &mut ranges,
        separators,
    )?;
    Ok(ranges)
}

fn apply_ranges(
    source: &str,
    mut ranges: Vec<Range<usize>>,
    css: Option<&HashSet<usize>>,
) -> Result<(String, Vec<String>)> {
    ranges.sort_by_key(|r| r.start);
    let mut output = String::with_capacity(source.len());
    let mut removed = Vec::new();
    let mut cursor = 0;
    for range in ranges {
        if range.start < cursor || range.end > source.len() {
            bail!("overlapping or invalid comment spans");
        }
        output.push_str(&source[cursor..range.start]);
        let comment = &source[range.clone()];
        removed.push(comment.to_owned());
        // Preserve JS ASI and Rust token separation. CSS comments themselves
        // are not descendant combinators, so do not turn .a/**/.b into .a .b.
        if let Some(separators) = css {
            if separators.contains(&range.start) {
                output.push(' ');
            }
        } else {
            let lines: String = comment
                .chars()
                .filter(|c| matches!(c, '\r' | '\n' | '\u{2028}' | '\u{2029}'))
                .collect();
            if lines.is_empty() {
                output.push(' ');
            } else {
                output.push_str(&lines);
            }
        }
        cursor = range.end;
    }
    output.push_str(&source[cursor..]);
    Ok((output, removed))
}

fn quoted_end(source: &str, start: usize, triple: bool) -> Result<usize> {
    let bytes = source.as_bytes();
    let quote = bytes[start];
    let width = if triple && bytes.get(start..start + 3).is_some_and(|s| s == [quote; 3]) {
        3
    } else {
        1
    };
    let mut i = start + width;
    while i < bytes.len() {
        if quote == b'"' && bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes
            .get(i..i + width)
            .is_some_and(|s| s.iter().all(|b| *b == quote))
        {
            i += width;
            if width == 3 {
                while bytes.get(i) == Some(&quote) {
                    i += 1;
                }
            }
            return Ok(i);
        }
        i += 1;
    }
    bail!("unterminated quoted string")
}

fn hash_comments(source: &str) -> Result<Vec<Range<usize>>> {
    let _: toml::Value = toml::from_str(source).context("invalid TOML")?;
    let b = source.as_bytes();
    let mut i = 0;
    let mut ranges = Vec::new();
    while i < b.len() {
        match b[i] {
            b'\'' | b'"' => i = quoted_end(source, i, true)?,
            b'#' => {
                let start = i;
                while i < b.len() && !matches!(b[i], b'\r' | b'\n') {
                    i += 1;
                }
                ranges.push(start..i);
            }
            _ => i += 1,
        }
    }
    Ok(ranges)
}

fn json_comments(source: &str) -> Result<Vec<Range<usize>>> {
    let b = source.as_bytes();
    let mut i = 0;
    let mut ranges = Vec::new();
    while i < b.len() {
        if b[i] == b'"' {
            i = quoted_end(source, i, false)?;
        } else if b.get(i..i + 2) == Some(b"//") {
            let start = i;
            while i < b.len() && !matches!(b[i], b'\n' | b'\r') {
                i += 1;
            }
            ranges.push(start..i);
        } else if b.get(i..i + 2) == Some(b"/*") {
            let end = source[i + 2..]
                .find("*/")
                .context("unterminated JSONC comment")?
                + i
                + 4;
            ranges.push(i..end);
            i = end;
        } else {
            i += 1;
        }
    }
    Ok(ranges)
}

fn strip_html(source: &str) -> Result<(String, Vec<String>)> {
    let lower = source.to_ascii_lowercase();
    let bytes = source.as_bytes();
    let mut output = String::new();
    let mut removed = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if source[cursor..].starts_with("<!--") {
            let end = source[cursor + 4..]
                .find("-->")
                .context("unterminated HTML comment")?
                + cursor
                + 7;
            removed.push(source[cursor..end].to_owned());
            cursor = end;
            continue;
        }
        if bytes[cursor] != b'<' {
            let end = source[cursor..]
                .find('<')
                .map_or(bytes.len(), |n| cursor + n);
            output.push_str(&source[cursor..end]);
            cursor = end;
            continue;
        }
        let mut end = cursor + 1;
        let mut quote = None;
        while end < bytes.len() {
            match (quote, bytes[end]) {
                (None, b'\'' | b'"') => quote = Some(bytes[end]),
                (Some(q), c) if q == c => quote = None,
                (None, b'>') => {
                    end += 1;
                    break;
                }
                _ => {}
            }
            end += 1;
        }
        let tag = lower[cursor + 1..end].trim_start();
        let name_end = tag
            .find(|c: char| !c.is_ascii_alphanumeric())
            .unwrap_or(tag.len());
        let name = &tag[..name_end];
        output.push_str(&source[cursor..end]);
        cursor = end;
        if name == "plaintext" {
            output.push_str(&source[cursor..]);
            break;
        }
        if !matches!(
            name,
            "script" | "style" | "textarea" | "title" | "xmp" | "iframe" | "noembed" | "noframes"
        ) {
            continue;
        }
        let close = format!("</{name}");
        let close_start = lower[cursor..]
            .match_indices(&close)
            .find_map(|(i, _)| {
                let at = cursor + i + close.len();
                bytes
                    .get(at)
                    .is_some_and(|b| b.is_ascii_whitespace() || matches!(b, b'>' | b'/'))
                    .then_some(cursor + i)
            })
            .unwrap_or(bytes.len());
        let body = &source[cursor..close_start];
        // Data-block scripts (JSON, import maps, templates) are not JavaScript.
        let ordinary_script = html_attribute(&tag[name_end..], "type").is_none_or(|value| {
            matches!(
                value.trim(),
                "" | "module"
                    | "text/javascript"
                    | "application/javascript"
                    | "text/ecmascript"
                    | "application/ecmascript"
            )
        });
        if name == "style" || (name == "script" && ordinary_script) {
            let path = Path::new(if name == "style" {
                "inline.css"
            } else {
                "inline.js"
            });
            let (stripped, comments) = strip_source(path, body)?;
            output.push_str(&stripped);
            removed.extend(comments);
        } else {
            output.push_str(body);
        }
        cursor = close_start;
    }
    Ok((output, removed))
}

fn html_attribute<'a>(mut attrs: &'a str, wanted: &str) -> Option<&'a str> {
    while !attrs.is_empty() {
        attrs = attrs.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '/');
        if attrs.starts_with('>') || attrs.is_empty() {
            break;
        }
        let end = attrs
            .find(|c: char| c.is_ascii_whitespace() || matches!(c, '=' | '>'))
            .unwrap_or(attrs.len());
        if end == 0 {
            return None;
        }
        let name = &attrs[..end];
        attrs = attrs[end..].trim_start();
        let mut value = "";
        if let Some(rest) = attrs.strip_prefix('=') {
            attrs = rest.trim_start();
            if let Some(quote @ ('\'' | '"')) = attrs.chars().next() {
                attrs = &attrs[1..];
                let end = attrs.find(quote).unwrap_or(attrs.len());
                value = &attrs[..end];
                attrs = attrs.get(end + 1..).unwrap_or("");
            } else {
                let end = attrs
                    .find(|c: char| c.is_ascii_whitespace() || c == '>')
                    .unwrap_or(attrs.len());
                value = &attrs[..end];
                attrs = &attrs[end..];
            }
        }
        if name == wanted {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(extension: &str, source: &str) -> String {
        strip_source(Path::new(&format!("sample.{extension}")), source)
            .unwrap()
            .0
    }

    #[test]
    fn rust_nested_and_doc_comments_leave_literal_bytes_alone() {
        let source = "//! documentation\n/// public docs\nfn main() { /* outer /* inner */ tail */ let _url = r#\"https://x/*keep*/\"#; // trailing\n }";
        let (out, comments) = strip_source(Path::new("x.rs"), source).unwrap();
        assert_eq!(comments.len(), 4);
        assert!(out.contains("r#\"https://x/*keep*/\"#"));
        assert!(!out.contains("documentation"));
        assert!(strip_source(Path::new("x.rs"), &out).unwrap().1.is_empty());
    }

    #[test]
    fn javascript_preserves_regex_templates_and_asi() {
        let source = "#!/usr/bin/env node\n// comment\nconst url='https://x';const r=/https?:\\/\\//;const t=`// text ${1 /* remove */ + 2}`;function f(){return /*\n split\n*/ 2;}";
        let out = strip("js", source);
        assert!(out.starts_with("#!/usr/bin/env node"));
        assert!(out.contains("/https?:\\/\\//"));
        assert!(out.contains("`// text ${1"));
        assert!(out.contains("return \n\n 2"));
        assert!(!out.contains("remove"));
    }

    #[test]
    fn html_script_type_uses_attributes_not_substring_matches() {
        let out = strip(
            "html",
            r#"<script data-type="json">/*gone*/let cookie=1;</script><script type="application/json" data-note="javascript">{"x":"/*keep*/"}</script>"#,
        );
        assert!(!out.contains("gone"));
        assert!(out.contains("/*keep*/"));
    }

    #[test]
    fn css_removal_preserves_token_boundaries() {
        assert_eq!(
            strip(
                "css",
                "#/**/id @/**/media a/**/(b) .x/**//**/.y {x:1/**/px}"
            ),
            "# id @ media a (b) .x.y {x:1 px}"
        );
    }

    #[test]
    fn typescript_and_jsx_comments_are_not_string_contents() {
        let out = strip("tsx", "// note\nconst a: string='//kept';const el=<div>{/* remove */}<span title='/* kept */'/></div>;");
        assert!(out.contains("'//kept'"));
        assert!(out.contains("'/* kept */'"));
        assert!(!out.contains("remove"));
    }

    #[test]
    fn typescript_compiler_directives_survive_comment_removal() {
        let source = "/// <reference types=\"vite/client\" />\n/// <amd-module name=\"client\" />\n// remove me\nconst asset = 'icon.png';";
        let out = strip("ts", source);
        assert!(out.contains("/// <reference types=\"vite/client\" />"));
        assert!(out.contains("/// <amd-module name=\"client\" />"));
        assert!(!out.contains("remove me"));
    }

    #[test]
    fn css_does_not_invent_descendant_selectors_or_touch_urls() {
        let out = strip("css", ".a/**/.b { content:'/*keep*/'; background:url(https://x/a/*keep*/b); /*remove*/ } @media/**/screen { .x { color:red; } }");
        assert!(out.contains(".a.b"));
        assert!(out.contains("url(https://x/a/*keep*/b)"));
        assert!(out.contains("@media screen"));
        assert!(!out.contains("remove"));
    }

    #[test]
    fn html_handles_raw_text_attributes_and_embedded_languages() {
        let out = strip("html", "<p title='<!--keep-->'>a<!--remove-->b</p><textarea><!--keep--></textarea><script>let x='<!--keep-->'; //gone\n</script><style>.a/**/.b{color:red}</style><script type='application/json'>{\"x\":\"//keep\"}</script>");
        assert!(out.contains(">ab</p>"));
        assert!(out.contains("title='<!--keep-->'"));
        assert!(out.contains("<textarea><!--keep--></textarea>"));
        assert!(out.contains("let x='<!--keep-->'"));
        assert!(out.contains("\"//keep\""));
        assert!(out.contains(".a.b"));
        assert!(!out.contains("gone"));
    }

    #[test]
    fn toml_and_jsonc_keep_strings() {
        let input = "#gone\nurl='https://x/#keep' #gone\ntext=\"\"\"\n#keep\n\"\"\"\n";
        let out = strip("toml", input);
        assert_eq!(
            toml::from_str::<toml::Value>(input).unwrap(),
            toml::from_str::<toml::Value>(&out).unwrap()
        );
        assert!(!out.contains("gone"));
        let out = strip(
            "jsonc",
            "{ /*gone*/ \"url\":\"https://x/*keep*/\" //gone\n}",
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&out).unwrap()["url"],
            "https://x/*keep*/"
        );
    }

    #[test]
    fn workspace_is_fail_closed_and_preserves_legal_notices_separately() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.js");
        std::fs::write(
            &path,
            "/*! Copyright Example; licensed under MIT */\nconst a=1;",
        )
        .unwrap();
        std::fs::write(tmp.path().join("z.js"), "const x = /* unterminated").unwrap();
        assert!(strip_workspace(tmp.path()).is_err());
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("Copyright"));
        std::fs::write(tmp.path().join("z.js"), "// remove\nconst x=1;").unwrap();
        let result = strip_workspace(tmp.path()).unwrap();
        assert_eq!(result.stats.comments_removed, 2);
        assert_eq!(result.stats.notices_extracted, 1);
        assert!(!std::fs::read_to_string(&path)
            .unwrap()
            .contains("Copyright"));
        assert!(
            std::fs::read_to_string(tmp.path().join("SOURCEVEIL_NOTICES.txt"))
                .unwrap()
                .contains("Copyright")
        );
        assert_eq!(
            strip_workspace(tmp.path()).unwrap().stats.comments_removed,
            0
        );
    }
}
