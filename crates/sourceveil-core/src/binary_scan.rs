//! Scan a built artifact for semantic names that should have disappeared.
//!
//! This module never mutates the binary. It is deliberately format-agnostic:
//! Rust/Tauri strings live as bytes in PE, ELF and Mach-O alike, and a raw
//! byte search also catches sidecar blobs an object parser would ignore.
//!
//! Protocol values are strong evidence: if an original Tauri command/event or
//! protected string survives in the shipped artifact, a rewrite was missed.
//! Rust symbol names are weaker evidence and are reported but not fatal.

use crate::mapping::Mapping;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryLeak {
    pub value: String,
    pub encoding: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryScanReport {
    pub path: PathBuf,
    pub bytes_scanned: u64,
    pub protocol_leaks: Vec<BinaryLeak>,
    pub symbol_hits: Vec<BinaryLeak>,
}

impl BinaryScanReport {
    pub fn passed(&self) -> bool {
        self.protocol_leaks.is_empty()
    }
}

pub fn scan_file(path: &Path, mapping: &Mapping) -> Result<BinaryScanReport> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut report = BinaryScanReport {
        path: path.to_path_buf(),
        bytes_scanned: bytes.len() as u64,
        ..Default::default()
    };

    for value in mapping
        .protocol_originals()
        .into_iter()
        .filter(|value| value.len() >= 3)
    {
        collect_hits(&bytes, value, &mut report.protocol_leaks);
    }

    for value in mapping
        .symbol_originals()
        .into_iter()
        .filter(|value| value.len() >= 3)
    {
        collect_hits(&bytes, value, &mut report.symbol_hits);
    }

    report.protocol_leaks.sort_by_key(|hit| (hit.offset, hit.value.clone()));
    report.protocol_leaks.dedup_by(|a, b| {
        a.offset == b.offset && a.value == b.value && a.encoding == b.encoding
    });
    report.symbol_hits.sort_by_key(|hit| (hit.offset, hit.value.clone()));
    report
        .symbol_hits
        .dedup_by(|a, b| a.offset == b.offset && a.value == b.value && a.encoding == b.encoding);

    Ok(report)
}

fn collect_hits(bytes: &[u8], value: &str, out: &mut Vec<BinaryLeak>) {
    let utf8 = value.as_bytes();
    for offset in find_all(bytes, utf8) {
        out.push(BinaryLeak {
            value: value.to_string(),
            encoding: "utf-8".into(),
            offset: offset as u64,
        });
    }

    // Windows-facing strings are often widened before crossing Win32/COM
    // boundaries. Looking for UTF-16LE costs little and catches those too.
    let utf16le: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    if utf16le.len() >= 6 {
        for offset in find_all(bytes, &utf16le) {
            out.push(BinaryLeak {
                value: value.to_string(),
                encoding: "utf-16le".into(),
                offset: offset as u64,
            });
        }
    }
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    while start + needle.len() <= haystack.len() {
        let Some(rel) = haystack[start..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            break;
        };
        let at = start + rel;
        out.push(at);
        start = at.saturating_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> Mapping {
        let mut mapping = Mapping::new(1);
        mapping.commands.insert("get_private_status".into(), "Q7Kp2".into());
        mapping.events.insert("session-updated".into(), "X9mA1".into());
        mapping.record_symbol("crate::auth::verify_license", "m7q2x");
        mapping
    }

    #[test]
    fn finds_utf8_protocol_values() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app.bin");
        std::fs::write(&path, b"xxget_private_statusyy").unwrap();

        let report = scan_file(&path, &mapping()).unwrap();
        assert!(!report.passed());
        assert_eq!(report.protocol_leaks.len(), 1);
        assert_eq!(report.protocol_leaks[0].offset, 2);
        assert_eq!(report.protocol_leaks[0].encoding, "utf-8");
    }

    #[test]
    fn finds_utf16le_protocol_values() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app.exe");
        let mut bytes = vec![0x90, 0x90];
        bytes.extend("session-updated".encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(&path, bytes).unwrap();

        let report = scan_file(&path, &mapping()).unwrap();
        assert!(report
            .protocol_leaks
            .iter()
            .any(|hit| hit.value == "session-updated" && hit.encoding == "utf-16le"));
    }

    #[test]
    fn symbol_hits_are_informational() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app");
        std::fs::write(&path, b"verify_license").unwrap();

        let report = scan_file(&path, &mapping()).unwrap();
        assert!(report.passed());
        assert_eq!(report.symbol_hits.len(), 1);
    }

    #[test]
    fn renamed_values_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app");
        std::fs::write(&path, b"Q7Kp2 X9mA1 m7q2x").unwrap();

        let report = scan_file(&path, &mapping()).unwrap();
        assert!(report.passed());
        assert!(report.protocol_leaks.is_empty());
    }
}
