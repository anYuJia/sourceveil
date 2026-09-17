//! Prints the wire format. The end-to-end test compares this output before and
//! after the transform, byte for byte.

mod model;

use model::{
    AppEvent, ConnectionState, LegacyRecord, RuntimeState, SessionRecord, UserAccount,
};

fn main() {
    let user = UserAccount {
        user_name: "alice".to_string(),
        device_id: 7,
        internal_scratch: vec![1, 2, 3],
    };
    println!("{}", serde_json::to_string(&user).unwrap());

    let session = SessionRecord {
        session_token: "tok-abc".to_string(),
        expires_at: 1_730_000_000,
    };
    println!("{}", serde_json::to_string(&session).unwrap());

    println!(
        "{}",
        serde_json::to_string(&ConnectionState::Disconnected { reason_code: 42 }).unwrap()
    );
    println!("{}", serde_json::to_string(&ConnectionState::Connected).unwrap());

    println!(
        "{}",
        serde_json::to_string(&AppEvent::Started { started_at: 99 }).unwrap()
    );
    println!("{}", serde_json::to_string(&AppEvent::Stopped).unwrap());

    println!(
        "{}",
        serde_json::to_string(&LegacyRecord {
            modern_name: "x".to_string()
        })
        .unwrap()
    );

    // Deserialisation must still accept documents written with the *original*
    // keys, which is the half of the contract that a compile check cannot see.
    let incoming = r#"{"user_name":"bob","device_id":1,"internal_scratch":[]}"#;
    let parsed: UserAccount = serde_json::from_str(incoming).unwrap();
    println!("{}", serde_json::to_string(&parsed).unwrap());

    let tagged = r#"{"kind":"Stopped"}"#;
    let event: AppEvent = serde_json::from_str(tagged).unwrap();
    println!("{}", serde_json::to_string(&event).unwrap());

    let runtime = RuntimeState {
        scratch_buffer: vec![9, 9],
        retry_count: 3,
    };
    println!("runtime: {}", runtime.summary());
}
