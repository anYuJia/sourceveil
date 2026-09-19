//! Scan a built artifact for semantic names that should have disappeared.
//!
//! This module never mutates the binary. It is deliberately format-agnostic:
//! Rust/Tauri strings live as bytes in PE, ELF and Mach-O alike, and a raw
//! byte search also catches sidecar blobs an object parser would ignore.
//!
//! Protocol matches fail the strict gate, but raw bytes cannot establish
//! provenance: dependencies or unrelated substrings can contain the same value.
//! Preserve those hits for review rather than silently filtering them out.
//! Rust symbol names are weaker evidence and are reported but not fatal.

use crate::mapping::Mapping;
use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

#[derive(Debug, Clone)]
struct ScanTarget {
    value: String,
    encoding: &'static str,
    protocol: bool,
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

    let mut patterns = Vec::new();
    let mut targets = Vec::new();
    let mut pattern_indices = BTreeMap::new();

    // Even a one- or two-byte protocol original fails the strict gate.
    // This is a conservative match, not proof of its origin. The noise policy below
    // applies only to ordinary Rust symbols.
    for value in mapping.protocol_originals() {
        add_value_patterns(
            value,
            true,
            &mut patterns,
            &mut targets,
            &mut pattern_indices,
        );
    }

    for value in mapping
        .symbol_originals()
        .into_iter()
        .filter(|value| value.len() >= 3)
    {
        add_value_patterns(
            value,
            false,
            &mut patterns,
            &mut targets,
            &mut pattern_indices,
        );
    }

    if !patterns.is_empty() {
        let matcher = AhoCorasick::new(&patterns).context("building binary scan matcher")?;
        for found in matcher.find_overlapping_iter(&bytes) {
            let offset = found.start() as u64;
            for target in &targets[found.pattern().as_usize()] {
                let leak = BinaryLeak {
                    value: target.value.clone(),
                    encoding: target.encoding.into(),
                    offset,
                };
                if target.protocol {
                    report.protocol_leaks.push(leak);
                } else {
                    report.symbol_hits.push(leak);
                }
            }
        }
    }

    report
        .protocol_leaks
        .sort_by_key(|hit| (hit.offset, hit.value.clone()));
    report
        .protocol_leaks
        .dedup_by(|a, b| a.offset == b.offset && a.value == b.value && a.encoding == b.encoding);
    report
        .symbol_hits
        .sort_by_key(|hit| (hit.offset, hit.value.clone()));
    report
        .symbol_hits
        .dedup_by(|a, b| a.offset == b.offset && a.value == b.value && a.encoding == b.encoding);

    Ok(report)
}

fn add_value_patterns(
    value: &str,
    protocol: bool,
    patterns: &mut Vec<Vec<u8>>,
    targets: &mut Vec<Vec<ScanTarget>>,
    pattern_indices: &mut BTreeMap<Vec<u8>, usize>,
) {
    add_pattern(
        value.as_bytes().to_vec(),
        ScanTarget {
            value: value.to_string(),
            encoding: "utf-8",
            protocol,
        },
        patterns,
        targets,
        pattern_indices,
    );

    // Windows-facing strings are often widened before crossing Win32/COM
    // boundaries. Looking for UTF-16LE catches those too.
    let utf16le: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    add_pattern(
        utf16le,
        ScanTarget {
            value: value.to_string(),
            encoding: "utf-16le",
            protocol,
        },
        patterns,
        targets,
        pattern_indices,
    );
}

fn add_pattern(
    pattern: Vec<u8>,
    target: ScanTarget,
    patterns: &mut Vec<Vec<u8>>,
    targets: &mut Vec<Vec<ScanTarget>>,
    pattern_indices: &mut BTreeMap<Vec<u8>, usize>,
) {
    if pattern.is_empty() {
        return;
    }
    if let Some(index) = pattern_indices.get(&pattern).copied() {
        targets[index].push(target);
        return;
    }

    let index = patterns.len();
    pattern_indices.insert(pattern.clone(), index);
    patterns.push(pattern);
    targets.push(vec![target]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping() -> Mapping {
        let mut mapping = Mapping::new(1);
        mapping
            .commands
            .insert("get_private_status".into(), "Q7Kp2".into());
        mapping
            .events
            .insert("session-updated".into(), "X9mA1".into());
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
    fn short_protocol_values_are_not_silently_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app.bin");
        let mut bytes = b"go".to_vec();
        bytes.push(0xff);
        bytes.extend("go".encode_utf16().flat_map(u16::to_le_bytes));
        std::fs::write(&path, bytes).unwrap();

        let mut mapping = mapping();
        mapping.commands.insert("go".into(), "R7x2p".into());
        let report = scan_file(&path, &mapping).unwrap();

        assert!(!report.passed());
        assert!(report
            .protocol_leaks
            .iter()
            .any(|hit| hit.value == "go" && hit.encoding == "utf-8"));
        assert!(report
            .protocol_leaks
            .iter()
            .any(|hit| hit.value == "go" && hit.encoding == "utf-16le"));
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

    #[test]
    fn finds_overlapping_protocol_values() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("app.bin");
        std::fs::write(&path, b"session-updated").unwrap();

        let mut mapping = mapping();
        mapping.strings.insert("session".into(), "Q7m2x".into());
        let report = scan_file(&path, &mapping).unwrap();

        assert!(report
            .protocol_leaks
            .iter()
            .any(|hit| hit.value == "session" && hit.offset == 0));
        assert!(report
            .protocol_leaks
            .iter()
            .any(|hit| hit.value == "session-updated" && hit.offset == 0));
    }
}
