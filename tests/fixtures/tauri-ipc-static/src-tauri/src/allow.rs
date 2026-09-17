//! Rust-side uses of command names that are not the definition and not the
//! handler list: an allow-list and a dispatch arm.

/// A command set. Every element is a command name, which is what makes it
/// recognisable as one.
pub const ALLOWED_COMMANDS: &[&str] = &[
    "get_user_info",
    "activate_license",
    "sync_state",
];

pub fn is_allowed(command: &str) -> bool {
    ALLOWED_COMMANDS.contains(&command)
}

/// The dispatch shape Tauri itself uses: a match on the invoked command name.
pub fn dispatch(invoke: &tauri::ipc::Invoke<tauri::test::MockRuntime>) -> bool {
    match invoke.message.command() {
        "get_user_info" => true,
        "sync_state" => true,
        _ => false,
    }
}
