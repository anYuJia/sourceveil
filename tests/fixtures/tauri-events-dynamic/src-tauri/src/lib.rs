//! A minimal but real Tauri 2 app exercising the event API on both sides.

pub mod events;

pub fn build() -> tauri::App<tauri::test::MockRuntime> {
    tauri::test::mock_builder()
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .expect("failed to build a mock app")
}
