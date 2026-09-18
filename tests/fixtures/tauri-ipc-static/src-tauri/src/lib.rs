//! A minimal but real Tauri 2 app: real macros, real handler list, real invoke
//! protocol. Nothing here is a mock of Tauri's surface.

pub mod allow;
pub mod commands;

pub fn build() -> tauri::App<tauri::test::MockRuntime> {
    tauri::test::mock_builder()
        .invoke_handler(tauri::generate_handler![
            commands::get_user_info,
            commands::activate_license,
            commands::sync_state,
            commands::probe_vault_health,
        ])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .expect("failed to build a mock app")
}
