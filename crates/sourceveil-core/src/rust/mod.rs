//! Rust semantic analysis and the rename pass.
//!
//! ## Why rust-analyzer
//!
//! The forbidden implementation — and the one that is tempting because it is
//! twenty lines long — is regex or token substitution over identifiers. It
//! fails on exactly the cases that make up a real codebase:
//!
//! ```rust,ignore
//! foo                     // a binding
//! obj.foo                 // a field, possibly on an external type
//! module::foo             // a path segment
//! "foo"                   // a string that must not change
//! #[serde(rename = "foo")]  // a wire-format contract
//! macro_rules! foo        // a compile-time name in its own namespace
//! include_str!("foo")     // a file path
//! ```
//!
//! Every one of those is the same seven characters to a regex and a different
//! thing to a compiler. So the pass resolves each candidate through
//! rust-analyzer's name resolution and asks it for the *edit set* of a rename,
//! rather than deciding for itself which occurrences matter.
//!
//! ## The correctness gate
//!
//! `Analysis::rename` is authoritative about *which* occurrences to rewrite,
//! but it is not authoritative about *whether we may*. Three rules are applied
//! on top of every proposed rename, and a rename that violates any of them is
//! dropped rather than partially applied:
//!
//! 1. Every file the edit touches must be one we copied into the output. An
//!    edit into the sysroot, into the registry, or into `target/` means the
//!    rename reaches outside the generated tree; dropping it keeps the output
//!    self-consistent.
//! 2. The rename must not want to move or create a file. Physical module-file
//!    renaming is a separate pass, and silently doing half of it produces a
//!    tree where `mod foo;` points at a file called `foo.rs` that has been
//!    renamed.
//! 3. Two renames must not want to write the same span. Resolution makes this
//!    impossible in principle — an identifier occurrence resolves to exactly
//!    one definition — so a collision means an assumption is wrong, and the
//!    later rename is dropped and reported.
//!
//! ## Where rust-analyzer cannot see
//!
//! rust-analyzer's reference search does not reach identifiers inside a macro
//! token tree. Measured against `ra_ap_*` 0.0.352, for a function `target_fn`:
//!
//! | call site in the source | rewritten by a rename? |
//! | --- | --- |
//! | `target_fn()` | yes |
//! | `apply_ident!(target_fn)` — ident argument to a `macro_rules!` macro | yes |
//! | `format!("{}", target_fn())` | **no** |
//! | `vec![target_fn(), target_fn()]` | **no** |
//! | `target_fn()` inside a `macro_rules!` body | **no** |
//! | `target_fn()` inside `#[cfg(test)]` | **no**, unless the test cfg is on |
//!
//! `Analysis::find_all_refs` reports the same set as `Analysis::rename`, so
//! there is no second API to fall back on — the information is not available,
//! not merely unused.
//!
//! Renaming `target_fn` while one of those references stays put would be a
//! broken build, so SourceVeil closes the gap without falling back to global
//! text replacement:
//!
//! - Supported macro grammars and nested token trees are traversed by the
//!   syntax/scope pass. Module-path positions are classified separately from
//!   same-spelled values and fields.
//! - A candidate defined below a direct `#[cfg(...)]` can use a constrained,
//!   kind-shaped fallback whose edits remain inside cfg syntax.
//! - With `cargo-check` verification selected, rustc's primary missing
//!   field/method/path spans drive a bounded exact-reference completion loop.
//!   An old leaf name is eligible only when it has one unambiguous generated
//!   spelling in the mapping, and every edit batch is compiled again.
//! - Without compiler verification, unresolved macro-token references are
//!   kept and reported under
//!   [`crate::report::SkipReason::MacroCallReference`].
//!
//! The ordinary verification pipeline remains the final gate. An ambiguous or
//! unsupported reference is never guessed at: it is either kept before edits
//! or causes the generated build to fail.

pub mod analysis;
pub mod bindings;
pub mod candidates;
pub mod contracts;
pub mod rename;

/// What kind of item a candidate is. Drives both which config toggle applies
/// to it and which casing its replacement name must use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ItemKind {
    Function,
    Struct,
    Enum,
    Union,
    Trait,
    TypeAlias,
    Const,
    Static,
    Module,
    Macro,
    /// An enum variant.
    Variant,
    /// A named struct or union field.
    Field,
    /// A local pattern binding (`let`, `match`, `for`, or closure binding).
    Local,
    /// A function parameter binding.
    Param,
    Other,
}

impl ItemKind {
    /// Casing the replacement must use so the rename does not introduce lint
    /// warnings that a `-D warnings` build would turn into errors.
    pub fn name_case(self) -> crate::names::NameCase {
        use crate::names::NameCase;
        match self {
            // Value namespace, snake_case.
            ItemKind::Function
            | ItemKind::Module
            | ItemKind::Field
            | ItemKind::Local
            | ItemKind::Param => NameCase::Snake,
            // Type namespace, CamelCase.
            ItemKind::Struct
            | ItemKind::Enum
            | ItemKind::Union
            | ItemKind::Trait
            | ItemKind::TypeAlias
            | ItemKind::Variant
            | ItemKind::Other => NameCase::Camel,
            // `non_upper_case_globals` is warn-by-default for both of these.
            ItemKind::Const | ItemKind::Static => NameCase::Screaming,
            // A `macro_rules!` name lives in the macro namespace and is
            // conventionally snake_case.
            ItemKind::Macro => NameCase::Snake,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Function => "fn",
            ItemKind::Struct => "struct",
            ItemKind::Enum => "enum",
            ItemKind::Union => "union",
            ItemKind::Trait => "trait",
            ItemKind::TypeAlias => "type",
            ItemKind::Const => "const",
            ItemKind::Static => "static",
            ItemKind::Module => "mod",
            ItemKind::Macro => "macro_rules",
            ItemKind::Variant => "variant",
            ItemKind::Field => "field",
            ItemKind::Local => "local",
            ItemKind::Param => "param",
            ItemKind::Other => "item",
        }
    }

    /// Whether the active plan enables renaming this kind.
    pub fn enabled_in(self, plan: &crate::plan::RenamePlan) -> bool {
        match self {
            ItemKind::Function => plan.functions,
            ItemKind::Struct | ItemKind::Enum | ItemKind::Union | ItemKind::TypeAlias => plan.types,
            ItemKind::Trait => plan.traits,
            ItemKind::Variant => plan.enums,
            ItemKind::Const => plan.consts,
            ItemKind::Static => plan.statics,
            ItemKind::Module => plan.modules,
            ItemKind::Macro => plan.macros,
            ItemKind::Field => plan.fields,
            ItemKind::Local => plan.locals,
            ItemKind::Param => plan.params,
            ItemKind::Other => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::NameCase;

    #[test]
    fn casing_is_chosen_per_namespace() {
        assert_eq!(ItemKind::Function.name_case(), NameCase::Snake);
        assert_eq!(ItemKind::Struct.name_case(), NameCase::Camel);
        assert_eq!(ItemKind::Variant.name_case(), NameCase::Camel);
        assert_eq!(ItemKind::Const.name_case(), NameCase::Screaming);
        assert_eq!(ItemKind::Static.name_case(), NameCase::Screaming);
        assert_eq!(ItemKind::Macro.name_case(), NameCase::Snake);
    }
}
