//! Run report.
//!
//! Both a machine-readable `report.json` and the human summary printed to
//! stdout. The summary is what a CI log shows when a transform goes wrong, so
//! it leads with the things that explain a failure: what was skipped and why,
//! then the verification stage results.

use crate::seed::SeedInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
// `writeln!` into a `String` resolves through `fmt::Write`, which has to be in
// scope for the macro to find it.
use std::fmt::Write as _;
use std::path::Path;

pub const REPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileCounts {
    pub rust_scanned: usize,
    #[serde(default)]
    pub frontend_scanned: usize,
}

/// Why a candidate symbol was left alone. Kept as a closed enum so the report
/// can be grouped and so the reasons stay honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    /// Named in `keep.symbols` or matched `keep.patterns`.
    KeepRule,
    /// Carried `// obfuscator:keep`.
    InlineKeepComment,
    /// Carried an attribute that pins the symbol name.
    IntrinsicAttribute,
    /// The name occurs as an identifier inside a macro token tree, where
    /// rust-analyzer cannot resolve or rewrite references. See
    /// [`crate::rust`] for the measurement behind this rule.
    MacroCallReference,
    /// The item is part of a serde data model, so its name is a wire-format
    /// key rather than a Rust identifier. Renaming it would change the JSON
    /// without changing anything the compiler can see.
    SerdeModel,
    /// `pub` item in a crate that something outside the workspace depends on.
    ExternallyReachable,
    /// Lives inside a `macro_rules!` body or a macro invocation we cannot
    /// rewrite.
    MacroGenerated,
    /// rust-analyzer could not resolve it, or refused the rename.
    Unresolvable,
    /// The rename would have had to edit a file outside the generated tree.
    EditOutsideOutput,
    /// The rename would have moved or renamed a file, which is a V2 pass.
    RequiresFileRename,
    /// Would have collided with an edit already scheduled at the same span.
    EditConflict,
    /// The item kind is not enabled in the active profile.
    KindDisabled,
    /// The symbol is FFI-visible or otherwise ABI-relevant.
    AbiBoundary,
}

impl SkipReason {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipReason::KeepRule => "keep-rule",
            SkipReason::InlineKeepComment => "inline-keep-comment",
            SkipReason::IntrinsicAttribute => "intrinsic-attribute",
            SkipReason::MacroCallReference => "macro-call-reference",
            SkipReason::SerdeModel => "serde-model",
            SkipReason::ExternallyReachable => "externally-reachable",
            SkipReason::MacroGenerated => "macro-generated",
            SkipReason::Unresolvable => "unresolvable",
            SkipReason::EditOutsideOutput => "edit-outside-output",
            SkipReason::RequiresFileRename => "requires-file-rename",
            SkipReason::EditConflict => "edit-conflict",
            SkipReason::KindDisabled => "kind-disabled",
            SkipReason::AbiBoundary => "abi-boundary",
        }
    }
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedSymbol {
    pub name: String,
    pub symbol_path: String,
    pub file: String,
    pub line: u32,
    pub reason: SkipReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RenameStats {
    pub functions: usize,
    pub types: usize,
    pub traits: usize,
    pub enums: usize,
    pub consts: usize,
    pub statics: usize,
    pub modules: usize,
    pub macros: usize,
    pub fields: usize,
    pub other: usize,
    /// Files actually rewritten.
    pub files_edited: usize,
    /// Individual text edits applied.
    pub edits_applied: usize,
}

impl RenameStats {
    pub fn total(&self) -> usize {
        self.functions
            + self.types
            + self.traits
            + self.enums
            + self.consts
            + self.statics
            + self.modules
            + self.macros
            + self.fields
            + self.other
    }

    pub fn bump(&mut self, kind: crate::rust::ItemKind) {
        use crate::rust::ItemKind as K;
        match kind {
            K::Function => self.functions += 1,
            K::Struct | K::Enum | K::Union | K::TypeAlias => self.types += 1,
            K::Trait => self.traits += 1,
            K::Variant => self.enums += 1,
            K::Const => self.consts += 1,
            K::Static => self.statics += 1,
            K::Module => self.modules += 1,
            K::Macro => self.macros += 1,
            K::Field => self.fields += 1,
            K::Other => self.other += 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageResult {
    pub stage: String,
    pub passed: bool,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub report_version: u32,
    pub profile: String,
    pub seed: SeedInfo,
    pub files: FileCounts,
    pub rename: RenameStats,
    /// Count of skipped symbols grouped by reason.
    pub skipped_by_reason: BTreeMap<String, usize>,
    pub skipped: Vec<SkippedSymbol>,
    pub verification: Vec<StageResult>,
    pub warnings: Vec<String>,
}

impl Report {
    pub fn new(profile: impl Into<String>, seed: SeedInfo) -> Self {
        Self {
            report_version: REPORT_VERSION,
            profile: profile.into(),
            seed,
            files: FileCounts::default(),
            rename: RenameStats::default(),
            skipped_by_reason: BTreeMap::new(),
            skipped: Vec::new(),
            verification: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn skip(&mut self, skipped: SkippedSymbol) {
        *self
            .skipped_by_reason
            .entry(skipped.reason.as_str().to_string())
            .or_insert(0) += 1;
        // A per-symbol list is useful for the first few hundred entries and
        // becomes noise after that; the grouped counts always tell the story.
        const MAX_LISTED: usize = 500;
        if self.skipped.len() < MAX_LISTED {
            self.skipped.push(skipped);
        }
    }

    pub fn verification_passed(&self) -> bool {
        self.verification.iter().all(|s| s.passed)
    }

    pub fn write(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        let w = &mut out;

        let _ = writeln!(w, "sourceveil report");
        let _ = writeln!(w, "================");
        let _ = writeln!(w, "profile:        {}", self.profile);
        let _ = writeln!(w, "seed:           {} ({})", self.seed.seed, self.seed.mode);
        if let Some(src) = &self.seed.derived_from {
            let _ = writeln!(w, "seed derived:   HMAC(secret, {src})");
        }
        let _ = writeln!(w);

        let _ = writeln!(w, "Rust files scanned:      {}", self.files.rust_scanned);
        let _ = writeln!(
            w,
            "Frontend files scanned:  {}",
            self.files.frontend_scanned
        );
        let _ = writeln!(w);

        let r = &self.rename;
        let _ = writeln!(w, "Functions renamed:  {}", r.functions);
        let _ = writeln!(w, "Types renamed:      {}", r.types);
        let _ = writeln!(w, "Traits renamed:     {}", r.traits);
        let _ = writeln!(w, "Variants renamed:   {}", r.enums);
        let _ = writeln!(w, "Consts renamed:     {}", r.consts);
        let _ = writeln!(w, "Statics renamed:    {}", r.statics);
        let _ = writeln!(w, "Modules renamed:    {}", r.modules);
        let _ = writeln!(w, "Macros renamed:     {}", r.macros);
        let _ = writeln!(w, "Fields renamed:     {}", r.fields);
        let _ = writeln!(w, "  total symbols:    {}", r.total());
        let _ = writeln!(w, "Files edited:       {}", r.files_edited);
        let _ = writeln!(w, "Text edits applied: {}", r.edits_applied);
        let _ = writeln!(w);

        let _ = writeln!(
            w,
            "Symbols kept:       {}",
            self.skipped_by_reason.values().sum::<usize>()
        );
        for (reason, count) in &self.skipped_by_reason {
            let _ = writeln!(w, "  {reason:<24} {count}");
        }

        if !self.verification.is_empty() {
            let _ = writeln!(w);
            let _ = writeln!(w, "Verification:");
            for stage in &self.verification {
                let status = if stage.passed { "PASS" } else { "FAIL" };
                let _ = writeln!(
                    w,
                    "  {:<16} {status}  ({:.1}s){}",
                    stage.stage,
                    stage.duration_ms as f64 / 1000.0,
                    stage
                        .detail
                        .as_deref()
                        .map(|d| format!("\n      {d}"))
                        .unwrap_or_default()
                );
            }
        }

        if !self.warnings.is_empty() {
            let _ = writeln!(w);
            let _ = writeln!(w, "Warnings:");
            for warning in &self.warnings {
                let _ = writeln!(w, "  - {warning}");
            }
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rust::ItemKind;

    #[test]
    fn stats_accumulate_by_kind() {
        let mut s = RenameStats::default();
        s.bump(ItemKind::Function);
        s.bump(ItemKind::Struct);
        s.bump(ItemKind::Enum);
        s.bump(ItemKind::Variant);
        assert_eq!(s.functions, 1);
        assert_eq!(s.types, 2, "struct and enum both count as types");
        assert_eq!(s.enums, 1, "variants are tracked separately");
        assert_eq!(s.total(), 4);
    }

    #[test]
    fn skip_list_is_capped_but_counts_are_not() {
        let mut r = Report::new(
            "safe",
            SeedInfo {
                seed: 1,
                mode: "explicit".into(),
                derived_from: None,
                key_present: false,
                warning: None,
            },
        );
        for i in 0..600 {
            r.skip(SkippedSymbol {
                name: format!("sym{i}"),
                symbol_path: format!("crate::sym{i}"),
                file: "src/lib.rs".into(),
                line: i as u32,
                reason: SkipReason::KeepRule,
                detail: None,
            });
        }
        assert_eq!(r.skipped.len(), 500);
        assert_eq!(r.skipped_by_reason["keep-rule"], 600);
    }

    #[test]
    fn render_mentions_the_essentials() {
        let mut r = Report::new(
            "safe",
            SeedInfo {
                seed: 7,
                mode: "explicit".into(),
                derived_from: None,
                key_present: false,
                warning: None,
            },
        );
        r.rename.bump(ItemKind::Function);
        r.verification.push(StageResult {
            stage: "cargo-check".into(),
            passed: true,
            duration_ms: 1500,
            detail: None,
        });

        let text = r.render();
        assert!(text.contains("seed:           7 (explicit)"));
        assert!(text.contains("Functions renamed:  1"));
        assert!(text.contains("cargo-check"));
        assert!(text.contains("PASS"));
    }
}
