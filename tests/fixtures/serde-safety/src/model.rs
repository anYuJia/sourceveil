//! Every serde representation this tool has to leave alone.
//!
//! The names here are deliberately distinctive: the end-to-end test greps the
//! generated tree for them, so anything that leaks into a rename shows up.

use serde::{Deserialize, Serialize};

/// Plain model. Every field name is a JSON key.
#[derive(Serialize, Deserialize)]
pub struct UserAccount {
    pub user_name: String,
    pub device_id: u32,
    pub internal_scratch: Vec<u8>,
}

/// Container attribute that rewrites every key. The rename pass does not
/// evaluate `rename_all`, so it must not touch these either.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub session_token: String,
    pub expires_at: u64,
}

/// Externally tagged: the variant name *is* the JSON key.
#[derive(Serialize, Deserialize)]
pub enum ConnectionState {
    Connected,
    Disconnected { reason_code: u16 },
}

/// Internally tagged: the variant name is the value of `kind`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AppEvent {
    Started { started_at: u64 },
    Stopped,
}

/// A field that already carries its own rename.
#[derive(Serialize)]
pub struct LegacyRecord {
    #[serde(rename = "legacy_name")]
    pub modern_name: String,
}

/// Not a serde model. Its fields are ordinary Rust identifiers and must still
/// be renamed, or this fixture would prove nothing.
#[derive(Default)]
pub struct RuntimeState {
    pub scratch_buffer: Vec<u8>,
    pub retry_count: u32,
}

impl RuntimeState {
    /// Deliberately not a `format!`. Anything mentioned inside a macro token
    /// tree is pinned by the macro-reference rule, so a field that only ever
    /// appears in one could never be renamed, and this fixture exists to prove
    /// that non-serde fields still are.
    pub fn summary(&self) -> String {
        let mut out = String::from("bytes=");
        out.push_str(&self.scratch_buffer.len().to_string());
        out.push_str(" retries=");
        out.push_str(&self.retry_count.to_string());
        out
    }
}
