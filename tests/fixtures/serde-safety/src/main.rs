//! Real serde corpus.
//!
//! Every model reference is evaluated outside the final println! macro. This is
//! deliberate: rust-analyzer cannot rewrite arbitrary identifiers nested in a
//! macro token tree, and this fixture is testing serde rather than that known
//! macro boundary.

mod model;

use model::{
    AdjacentEvent, AppEvent, ConnectionState, DirectionalRecord, FieldRuleEvent, LegacyRecord,
    RawIdentifierRecord, RuntimeState, SessionRecord, TransparentRecord, UserAccount,
};

fn main() {
    let mut lines = Vec::<String>::new();

    let user = UserAccount {
        user_name: "alice".to_string(),
        device_id: 7,
        internal_scratch: vec![1, 2, 3],
    };
    lines.push(serde_json::to_string(&user).unwrap());

    let session = SessionRecord {
        session_token: "tok-abc".to_string(),
        expires_at: 1_730_000_000,
    };
    lines.push(serde_json::to_string(&session).unwrap());

    let disconnected = ConnectionState::Disconnected { reason_code: 42 };
    let connected = ConnectionState::Connected;
    lines.push(serde_json::to_string(&disconnected).unwrap());
    lines.push(serde_json::to_string(&connected).unwrap());

    let started = AppEvent::Started { started_at: 99 };
    let stopped = AppEvent::Stopped;
    lines.push(serde_json::to_string(&started).unwrap());
    lines.push(serde_json::to_string(&stopped).unwrap());

    let login = AdjacentEvent::Login {
        user_name: "bob".to_string(),
    };
    let logout = AdjacentEvent::Logout;
    lines.push(serde_json::to_string(&login).unwrap());
    lines.push(serde_json::to_string(&logout).unwrap());

    let field_rule = FieldRuleEvent::Payload {
        user_name: "carol".to_string(),
        retry_count: 4,
    };
    lines.push(serde_json::to_string(&field_rule).unwrap());

    let directional = DirectionalRecord {
        value_field: "directional".to_string(),
    };
    lines.push(serde_json::to_string(&directional).unwrap());

    let legacy = LegacyRecord {
        modern_name: "x".to_string(),
    };
    lines.push(serde_json::to_string(&legacy).unwrap());

    // Deserialize payloads written against the original wire contract.
    let incoming = r#"{"user_name":"bob","device_id":1,"internal_scratch":[]}"#;
    let parsed: UserAccount = serde_json::from_str(incoming).unwrap();
    lines.push(serde_json::to_string(&parsed).unwrap());

    let tagged = r#"{"kind":"Stopped"}"#;
    let event: AppEvent = serde_json::from_str(tagged).unwrap();
    lines.push(serde_json::to_string(&event).unwrap());

    let adjacent = r#"{"type":"Login","data":{"user_name":"dave"}}"#;
    let event: AdjacentEvent = serde_json::from_str(adjacent).unwrap();
    lines.push(serde_json::to_string(&event).unwrap());

    let directional_in = r#"{"in_value":"from-old-peer"}"#;
    let directional: DirectionalRecord = serde_json::from_str(directional_in).unwrap();
    lines.push(serde_json::to_string(&directional).unwrap());

    let alias_in = r#"{"old_name":"legacy"}"#;
    let alias: LegacyRecord = serde_json::from_str(alias_in).unwrap();
    lines.push(serde_json::to_string(&alias).unwrap());

    // `r#` escapes a Rust keyword but is not part of serde's wire name.
    let raw_in = r#"{"type":"protocol-kind"}"#;
    let raw: RawIdentifierRecord = serde_json::from_str(raw_in).unwrap();
    let raw_value = raw.r#type.clone();
    lines.push(serde_json::to_string(&raw).unwrap());
    lines.push(raw_value);

    // Unsupported representation: this field must be claimed and kept.
    let transparent = TransparentRecord {
        raw_value: "raw".to_string(),
    };
    lines.push(serde_json::to_string(&transparent).unwrap());

    let runtime = RuntimeState {
        scratch_buffer: vec![9, 9],
        retry_count: 3,
    };
    lines.push(format!("runtime: {}", runtime.summary()));

    for line in lines {
        println!("{line}");
    }
}
