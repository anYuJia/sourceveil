//! The rename mapping artifact.
//!
//! `mapping.json` is the only record of what became what, and it is the thing
//! that makes a stack trace from a shipped build attributable to a source line.
//! It is also, for exactly that reason, the single most sensitive file the tool
//! produces: shipping it inside an installer would hand an analyst the whole
//! answer key. [`Mapping::assert_not_in_output`] is the guard for that.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const MAPPING_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub mapping_version: u32,
    /// The resolved build seed. Not the seed *key*.
    pub seed: u64,
    /// Fully-qualified original symbol path -> replacement identifier.
    #[serde(default)]
    pub symbols: BTreeMap<String, String>,
    /// Tauri command name -> replacement, applied to both `invoke()` and the
    /// Rust handler.
    #[serde(default)]
    pub commands: BTreeMap<String, String>,
    /// Tauri event channel -> replacement.
    #[serde(default)]
    pub events: BTreeMap<String, String>,
    /// Original string literal -> replacement, for the string pass.
    #[serde(default)]
    pub strings: BTreeMap<String, String>,
}

impl Default for Mapping {
    /// An empty mapping, for accumulation before the seed is known.
    fn default() -> Self {
        Self::new(0)
    }
}

impl Mapping {
    pub fn new(seed: u64) -> Self {
        Self {
            mapping_version: MAPPING_VERSION,
            seed,
            symbols: BTreeMap::new(),
            commands: BTreeMap::new(),
            events: BTreeMap::new(),
            strings: BTreeMap::new(),
        }
    }

    pub fn record_symbol(&mut self, path: impl Into<String>, new: impl Into<String>) {
        self.symbols.insert(path.into(), new.into());
    }

    /// Reverse view: replacement identifier -> original symbol path. This is
    /// what turns a name in a crash log back into something greppable.
    pub fn reverse_symbols(&self) -> BTreeMap<&str, &str> {
        self.symbols
            .iter()
            .map(|(orig, new)| (new.as_str(), orig.as_str()))
            .collect()
    }

    /// Original values from the cross-language protocols: command names,
    /// event channels, and protected strings.
    ///
    /// These are unambiguous. A command name is a *value* the frontend sends;
    /// its presence anywhere in the output means a call site was missed, and
    /// there is no innocent explanation. The leak scan fails the build on one.
    pub fn protocol_originals(&self) -> Vec<&str> {
        self.commands
            .keys()
            .map(String::as_str)
            .chain(self.events.keys().map(String::as_str))
            .chain(self.strings.keys().map(String::as_str))
            .collect()
    }

    /// Original names of renamed Rust symbols.
    ///
    /// Weaker evidence, and reported rather than enforced. A symbol name is an
    /// ordinary identifier, and the same text legitimately survives in a doc
    /// comment, in the other language (`UserInfo` the TypeScript interface
    /// beside `UserInfo` the Rust struct), and as an unrelated method on some
    /// external type (`.build()` beside a renamed `build`). Enforcing a text
    /// match over those produces noise proportional to how common the word is,
    /// which teaches people to ignore the check.
    pub fn symbol_originals(&self) -> Vec<&str> {
        self.symbols
            .keys()
            .map(|k| k.rsplit("::").next().unwrap_or(k))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
            && self.commands.is_empty()
            && self.events.is_empty()
            && self.strings.is_empty()
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self).context("serializing mapping")?;
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let m: Mapping =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if m.mapping_version != MAPPING_VERSION {
            anyhow::bail!(
                "mapping at {} has version {}, expected {}",
                path.display(),
                m.mapping_version,
                MAPPING_VERSION
            );
        }
        Ok(m)
    }

    /// Refuse to let the mapping be written somewhere that ships.
    ///
    /// The check is deliberately blunt: anything under a `dist`, `build`,
    /// `target`, `resources` or `bundle` directory, or anything inside the
    /// frontend tree, is treated as shippable and rejected.
    pub fn assert_not_in_output(&self, path: &Path) -> Result<()> {
        const SHIPPING_DIRS: &[&str] = &[
            "dist",
            "build",
            "target",
            "bundle",
            "resources",
            "public",
            "assets",
            "node_modules",
        ];
        for component in path.components() {
            let name = component.as_os_str().to_string_lossy();
            if SHIPPING_DIRS.contains(&name.as_ref()) {
                anyhow::bail!(
                    "refusing to write mapping.json to {}: the path contains {:?}, which is \
                     packaged into the release artifact. Write the mapping outside the build \
                     output (see [build] mapping_dir).",
                    path.display(),
                    name
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mapping.json");

        let mut m = Mapping::new(42);
        m.record_symbol("crate::network::connect", "q7k9a");
        m.commands.insert("get_profile".into(), "m8q2x".into());
        m.write(&path).unwrap();

        let back = Mapping::read(&path).unwrap();
        assert_eq!(back.seed, 42);
        assert_eq!(back.symbols["crate::network::connect"], "q7k9a");
        assert_eq!(back.commands["get_profile"], "m8q2x");
    }

    #[test]
    fn reverse_lookup_maps_back_to_the_original() {
        let mut m = Mapping::new(1);
        m.record_symbol("crate::auth::verify", "P81xy");
        assert_eq!(m.reverse_symbols()["P81xy"], "crate::auth::verify");
    }

    #[test]
    fn originals_are_split_by_kind() {
        let mut m = Mapping::new(1);
        m.record_symbol("crate::auth::verify", "P81xy");
        m.commands
            .insert("get_secret_status".into(), "K81qm".into());

        let symbols = m.symbol_originals();
        assert!(symbols.contains(&"verify"));
        assert!(!symbols.contains(&"crate::auth::verify"));

        let protocol = m.protocol_originals();
        assert!(protocol.contains(&"get_secret_status"));
        assert!(
            !protocol.contains(&"verify"),
            "a symbol is not a protocol value"
        );
    }

    #[test]
    fn refuses_shipping_directories() {
        let m = Mapping::new(1);
        assert!(m
            .assert_not_in_output(Path::new("out/frontend/dist/.obfuscator/mapping.json"))
            .is_err());
        assert!(m
            .assert_not_in_output(Path::new("out/src-tauri/target/mapping.json"))
            .is_err());
        assert!(m
            .assert_not_in_output(Path::new(".obfuscated/.obfuscator/mapping.json"))
            .is_ok());
    }
}
