//! The commands themselves. Every name here is a protocol value on the
//! frontend side as well, so renaming one has to move both.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UserInfo {
    pub user_name: String,
    pub device_id: u32,
}

#[tauri::command]
pub fn get_user_info(user_id: u32) -> UserInfo {
    UserInfo {
        user_name: "alice".to_string(),
        device_id: user_id,
    }
}

#[tauri::command]
pub async fn activate_license(key: String) -> Result<bool, String> {
    if key.is_empty() {
        return Err("empty key".to_string());
    }
    Ok(true)
}

#[tauri::command]
pub fn sync_state() -> u32 {
    7
}

// The short form, reached through an import rather than a full path. Whether
// this is Tauri or clap cannot be told from the syntax, so the pass resolves
// it through the compiler.
use tauri::command;

#[command]
pub fn probe_vault_health() -> &'static str {
    "pong"
}
