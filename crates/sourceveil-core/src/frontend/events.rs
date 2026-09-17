//! Event channel analysis. Filled in by the event pass.

use super::SourceFile;
use anyhow::Result;
use std::path::Path;

#[derive(Debug, Default)]
pub struct EventAnalysis {
    pub files_scanned: usize,
    pub warnings: Vec<String>,
}

pub fn analyze(_sources: &[SourceFile], _root: &Path) -> Result<EventAnalysis> {
    Ok(EventAnalysis::default())
}
