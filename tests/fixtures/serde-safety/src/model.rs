//! Serde protocol fixture.
//!
//! Supported members should be renamed under the balanced profile while their
//! wire names remain byte-for-byte stable. Unsupported representations stay
//! pinned and are reported.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UserAccount {
    pub user_name: String,
    pub device_id: u32,
    pub internal_scratch: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub session_token: String,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize)]
pub enum ConnectionState {
    Connected,
    Disconnected { reason_code: u16 },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AppEvent {
    Started { started_at: u64 },
    Stopped,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AdjacentEvent {
    Login { user_name: String },
    Logout,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all_fields = "camelCase")]
pub enum FieldRuleEvent {
    Payload { user_name: String, retry_count: u32 },
}

#[derive(Serialize, Deserialize)]
pub struct DirectionalRecord {
    #[serde(rename(serialize = "outValue", deserialize = "in_value"))]
    pub value_field: String,
}

#[derive(Serialize, Deserialize)]
pub struct LegacyRecord {
    #[serde(rename = "current_name", alias = "old_name")]
    pub modern_name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransparentRecord {
    pub raw_value: String,
}

/// Not a serde model. Its fields are ordinary Rust identifiers and must still
/// be renamed, or this fixture would prove nothing.
#[derive(Default)]
pub struct RuntimeState {
    pub scratch_buffer: Vec<u8>,
    pub retry_count: u32,
}

impl RuntimeState {
    pub fn summary(&self) -> String {
        let mut out = String::from("bytes=");
        out.push_str(&self.scratch_buffer.len().to_string());
        out.push_str(" retries=");
        out.push_str(&self.retry_count.to_string());
        out
    }
}
