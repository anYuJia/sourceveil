//! Every Rust-side event shape Tauri 2 offers.
//!
//! Each event name below is also a string on the frontend side, except for the
//! two that are internal to one language — those are marked.

use tauri::{AppHandle, Emitter, Listener};

/// A type with an `emit` and a `listen` of its own.
///
/// Nothing says these names belong to Tauri, and a pass that matched on the
/// method name alone would rewrite this call. It must not.
pub struct LocalBus;

impl LocalBus {
    pub fn emit(&self, _name: &str, _payload: u32) {}
    pub fn listen(&self, _name: &str) {}
}

pub fn not_tauri(bus: &LocalBus) {
    // If either of these were taken for a Tauri call, the event it names would
    // gain a producer or a consumer it does not have, and would stop being
    // classified as reaching outside the workspace.
    bus.emit("plugin-status", 1);
    bus.listen("telemetry-ping");
}

pub fn produce<R: tauri::Runtime>(app: &AppHandle<R>) {
    // Cross-language: the frontend listens for both of these.
    app.emit("download-progress", 1u32).unwrap();
    app.emit_to("main", "session-updated", 2u32).unwrap();
    app.emit_filter("open-file", 3u32, |_target| true).unwrap();

    // Listened for by the frontend only.
    app.emit("startup-complete", 4u32).unwrap();

    // Rust to Rust.
    app.emit("rust-internal-tick", 5u32).unwrap();

    // Nothing in the workspace listens for this, so something outside it may.
    app.emit("telemetry-ping", 6u32).unwrap();
}

pub fn consume<R: tauri::Runtime>(app: &AppHandle<R>) {
    app.listen("frontend-ready", |_event| {});
    app.listen_any("sync-state", |_event| {});
    app.once("rust-internal-tick", |_event| {});
}
