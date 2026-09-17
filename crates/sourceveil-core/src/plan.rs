//! Resolution of [`Config`] + [`Profile`] into a concrete [`Plan`].
//!
//! Passes never read [`Config`] directly — they read `Plan`, so that the
//! "profile vs explicit vs default" question is answered in exactly one place.

use crate::config::{AnalyzeSource, Config, DependencyMode, Profile, VerifyStage};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Plan {
    pub profile: Profile,
    pub project: ProjectPlan,
    pub rename: RenamePlan,
    pub strings: StringsPlan,
    pub tauri: TauriPlan,
    pub frontend: FrontendPlan,
    pub dependencies: DependenciesPlan,
    pub build: BuildPlan,
    pub keep: KeepPlan,
    /// Things the user asked for that this build cannot do.
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ProjectPlan {
    pub rust_root: Option<PathBuf>,
    pub frontend_root: Option<PathBuf>,
    pub frontend_source: Option<PathBuf>,
    pub ignore: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RenamePlan {
    pub functions: bool,
    pub types: bool,
    pub traits: bool,
    pub enums: bool,
    pub consts: bool,
    pub statics: bool,
    pub modules: bool,
    pub module_files: bool,
    pub macros: bool,
    pub fields: bool,
    pub locals: bool,
    pub params: bool,
    pub name_len: (usize, usize),
}

impl RenamePlan {
    /// True when no rename work at all is requested.
    pub fn is_noop(&self) -> bool {
        !(self.functions
            || self.types
            || self.traits
            || self.enums
            || self.consts
            || self.statics
            || self.modules
            || self.macros
            || self.fields
            || self.locals
            || self.params)
    }
}

#[derive(Debug, Clone, Default)]
pub struct StringsPlan {
    pub enabled: bool,
    pub logs: bool,
    pub errors: bool,
    pub internal: bool,
    pub ui: bool,
    pub endpoints: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TauriPlan {
    pub commands: bool,
    pub events: bool,
    pub window_labels: bool,
    pub scan_command_literals: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FrontendPlan {
    pub enabled: bool,
    pub rename_private_identifiers: bool,
    /// Permanently off in V1; kept in the schema so configs fail loudly rather
    /// than silently ignoring it.
    pub property_mangling: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DependenciesPlan {
    pub default: DependencyMode,
    pub crates: BTreeMap<String, DependencyMode>,
}

impl DependenciesPlan {
    pub fn mode_for(&self, name: &str) -> DependencyMode {
        self.crates.get(name).copied().unwrap_or(self.default)
    }
}

#[derive(Debug, Clone)]
pub struct BuildPlan {
    pub seed: String,
    pub verify: bool,
    pub verify_stages: Vec<VerifyStage>,
    pub write_mapping: bool,
    pub mapping_dir: PathBuf,
    pub analyze: AnalyzeSource,
    pub load_out_dirs: bool,
    pub strict: bool,
}

#[derive(Debug, Clone, Default)]
pub struct KeepPlan {
    pub symbols: Vec<String>,
    pub patterns: Vec<String>,
    pub files: Vec<String>,
    pub attributes: Vec<String>,
}

/// Attributes that always pin a symbol regardless of config. These name a
/// linkage-level symbol or a compile-time protocol; renaming either produces a
/// silently broken artifact rather than a build error.
pub const INTRINSIC_KEEP_ATTRIBUTES: &[&str] = &[
    "no_mangle",
    "unsafe(no_mangle)",
    "export_name",
    "unsafe(export_name)",
    "link_name",
    "unsafe(link_name)",
    "no_link",
    "macro_export",
    "proc_macro",
    "proc_macro_derive",
    "proc_macro_attribute",
    "global_allocator",
    "panic_handler",
    "alloc_error_handler",
    "used",
];

/// Item names that are never renamed, whatever the configuration says.
///
/// `main` is the process entry point. Renaming it obfuscates nothing — the
/// name is fixed by the language — and produces a crate with no `main` and a
/// link error. It is kept unconditionally rather than only when it is
/// recognised as an entry point, because the check costs more than the
/// obfuscation it would buy: `main` is four characters and carries no business
/// meaning.
pub const INTRINSIC_KEEP_NAMES: &[&str] = &["main"];

impl Plan {
    pub fn resolve(cfg: &Config) -> Result<Self> {
        let profile = cfg.profile();
        let mut unsupported = Vec::new();

        if profile == Profile::Aggressive {
            unsupported.push(
                "profile `aggressive`: function splitting and indirect dispatch are not \
                 implemented in this build; falling back to `balanced` behaviour"
                    .to_string(),
            );
        }

        let p = cfg.profile();
        let balanced = matches!(p, Profile::Balanced | Profile::Aggressive);

        // -- rename ---------------------------------------------------------
        let r = &cfg.rename;
        let name_len_min = r.name_len_min.unwrap_or(5);
        let name_len_max = r.name_len_max.unwrap_or(9);
        if name_len_min == 0 || name_len_min > name_len_max || name_len_max > 64 {
            bail!(
                "rename.name_len_min/name_len_max must satisfy 1 <= min <= max <= 64, \
                 got {name_len_min}..={name_len_max}"
            );
        }

        let rename = RenamePlan {
            functions: r.functions.unwrap_or(true),
            types: r.types.unwrap_or(true),
            traits: r.traits.unwrap_or(true),
            enums: r.enums.unwrap_or(true),
            consts: r.consts.unwrap_or(true),
            statics: r.statics.unwrap_or(true),
            modules: r.modules.unwrap_or(true),
            module_files: r.module_files.unwrap_or(false),
            // `macro_rules!` bodies are a token-level protocol. Renaming works
            // when the macro is crate-local and declarative, but the failure
            // mode is a broken build in a dependent crate, so it stays opt-in.
            macros: r.macros.unwrap_or(false),
            fields: r.fields.unwrap_or(balanced),
            locals: r.locals.unwrap_or(false),
            params: r.params.unwrap_or(false),
            name_len: (name_len_min, name_len_max),
        };

        if rename.module_files {
            unsupported.push(
                "rename.module_files: physical module-file renaming is a V2 pass; \
                 module identifiers will be renamed but files stay in place"
                    .to_string(),
            );
        }
        if rename.locals || rename.params {
            unsupported.push(
                "rename.locals/params: local-binding rename is not implemented in this build"
                    .to_string(),
            );
        }

        // -- strings --------------------------------------------------------
        let s = &cfg.strings;
        let strings_enabled = s.enabled.unwrap_or(balanced);
        let strings = StringsPlan {
            enabled: strings_enabled,
            logs: s.logs.unwrap_or(false),
            errors: s.errors.unwrap_or(false),
            internal: s.internal.unwrap_or(balanced),
            ui: s.ui.unwrap_or(false),
            endpoints: s.endpoints.unwrap_or(false),
        };
        if strings.enabled
            && (strings.logs
                || strings.errors
                || strings.internal
                || strings.ui
                || strings.endpoints)
        {
            unsupported.push(
                "strings.*: string protection pass is not implemented in this build".to_string(),
            );
        }

        // -- tauri ----------------------------------------------------------
        let t = &cfg.tauri;
        let tauri = TauriPlan {
            commands: t.commands.unwrap_or(true),
            events: t.events.unwrap_or(true),
            window_labels: t.window_labels.unwrap_or(false),
            scan_command_literals: t.scan_command_literals.unwrap_or(true),
        };
        if tauri.commands || tauri.events {
            unsupported.push(
                "tauri.commands/events: cross-language IPC pass is not implemented in this build; \
                 `#[tauri::command]` handlers are pinned by an automatic keep rule"
                    .to_string(),
            );
        }
        if tauri.window_labels {
            unsupported.push(
                "tauri.window_labels: window labels are a framework-level identifier and are \
                 kept regardless; this build ignores the setting"
                    .to_string(),
            );
        }

        // -- frontend -------------------------------------------------------
        let f = &cfg.frontend;
        let frontend = FrontendPlan {
            enabled: f.enabled.unwrap_or(false),
            rename_private_identifiers: f.rename_private_identifiers.unwrap_or(balanced),
            property_mangling: f.property_mangling.unwrap_or(false),
        };
        if frontend.property_mangling {
            unsupported.push(
                "frontend.property_mangling: unsupported by design — property names cross the \
                 JSON / React-prop / store boundary and cannot be proven safe from the frontend \
                 alone; this build ignores the setting"
                    .to_string(),
            );
        }
        if frontend.enabled || frontend.rename_private_identifiers {
            unsupported.push(
                "frontend.*: TypeScript analyzer pass is not implemented in this build".to_string(),
            );
        }

        // -- dependencies ---------------------------------------------------
        let dependencies = DependenciesPlan {
            default: cfg.dependencies.default,
            crates: cfg
                .dependencies
                .crates
                .iter()
                .map(|(k, v)| (k.clone(), v.mode()))
                .collect(),
        };

        // -- build ----------------------------------------------------------
        let b = &cfg.build;
        let verify = b.verify.unwrap_or(true);
        let mut verify_stages = b.verify_stages.clone().unwrap_or_else(default_stages);
        dedup_stages(&mut verify_stages);

        let build = BuildPlan {
            seed: b.seed.clone(),
            verify,
            verify_stages,
            write_mapping: b.write_mapping.unwrap_or(true),
            mapping_dir: b
                .mapping_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from(".obfuscator")),
            analyze: b.analyze.unwrap_or(AnalyzeSource::Input),
            load_out_dirs: b.load_out_dirs.unwrap_or(true),
            strict: b.strict.unwrap_or(false),
        };

        Ok(Plan {
            profile,
            project: ProjectPlan {
                rust_root: cfg.project.rust_root.clone(),
                frontend_root: cfg.project.frontend_root.clone(),
                frontend_source: cfg.project.frontend_source.clone(),
                ignore: cfg.project.ignore.clone(),
            },
            rename,
            strings,
            tauri,
            frontend,
            dependencies,
            build,
            keep: KeepPlan {
                symbols: cfg.keep.symbols.clone(),
                patterns: cfg.keep.patterns.clone(),
                files: cfg.keep.files.clone(),
                attributes: cfg.keep.attributes.clone(),
            },
            unsupported,
        })
    }
}

fn default_stages() -> Vec<VerifyStage> {
    vec![
        VerifyStage::CargoMetadata,
        VerifyStage::CargoCheck,
        VerifyStage::NpmTypecheck,
        VerifyStage::NpmBuild,
        VerifyStage::LeakScan,
    ]
}

fn dedup_stages(stages: &mut Vec<VerifyStage>) {
    let mut seen = Vec::new();
    stages.retain(|s| {
        if seen.contains(s) {
            false
        } else {
            seen.push(*s);
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(toml_src: &str) -> Plan {
        Plan::resolve(&Config::parse(toml_src).unwrap()).unwrap()
    }

    #[test]
    fn safe_profile_renames_symbols_but_not_fields() {
        let p = plan("");
        assert!(p.rename.functions);
        assert!(p.rename.types);
        assert!(!p.rename.fields);
        assert!(!p.rename.locals);
        assert!(!p.strings.internal);
    }

    #[test]
    fn balanced_profile_turns_on_field_rename() {
        let p = plan("profile = \"balanced\"");
        assert!(p.rename.fields);
        assert!(p.strings.internal);
    }

    #[test]
    fn explicit_value_beats_profile() {
        let p = plan("profile = \"balanced\"\n[rename]\nfields = false\n");
        assert!(!p.rename.fields);
    }

    #[test]
    fn aggressive_reports_unsupported_features() {
        let p = plan("profile = \"aggressive\"");
        assert!(p.unsupported.iter().any(|u| u.contains("aggressive")));
    }

    #[test]
    fn name_length_bounds_are_validated() {
        let err = Plan::resolve(
            &Config::parse("[rename]\nname_len_min = 20\nname_len_max = 5\n").unwrap(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("name_len"));
    }

    #[test]
    fn intrinsic_keep_attributes_cover_unsafe_wrapped_forms() {
        // `#[unsafe(no_mangle)]` is the Rust 2024 spelling; both must be pinned.
        assert!(INTRINSIC_KEEP_ATTRIBUTES.contains(&"no_mangle"));
        assert!(INTRINSIC_KEEP_ATTRIBUTES.contains(&"unsafe(no_mangle)"));
    }
}
