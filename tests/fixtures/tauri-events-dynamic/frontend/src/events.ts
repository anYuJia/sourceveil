// The frontend half of the event protocol.
//
// Every string here that names an event is also a string on the Rust side,
// except the two that are internal to one language — those are marked.

import { emit, emitTo, listen, once } from "@tauri-apps/api/event";
import { getCurrentWebviewWindow } from "@tauri-apps/api/webviewWindow";

/// A receiver that is not a Tauri window, and a bus that is not Tauri's.
///
/// These exist to be ignored. `emit` and `listen` are ordinary names, and a
/// pass that matched on the callee alone would take these for Tauri calls.
interface Bus {
  emit(name: string): void;
  once(name: string): void;
}
declare const socket: Bus;
declare const emitter: Bus;

export function notTauri(): void {
  // If either of these were mistaken for a Tauri call, the event they name
  // would gain a producer or a consumer it does not have, and stop being
  // classified as external.
  socket.emit("plugin-status");
  emitter.once("telemetry-ping");
}

/// Emitted here, listened for in Rust.
export async function announceReady(): Promise<void> {
  await emit("frontend-ready", { at: Date.now() });
}

/// `emitTo` takes a window label first. The label is not this pass's business.
export async function pushState(): Promise<void> {
  await emitTo("main", "sync-state", { ready: true });
}

export function watch(): void {
  void listen("download-progress", () => {});
  void listen<{ user: string }>("session-updated", () => {});
  void once("startup-complete", () => {});
}

/// The name held in a module constant.
const EVENT = "open-file";

export function watchOpenFile(): void {
  void listen(EVENT, () => {});
}

/// Emitted and listened for entirely inside the frontend.
export async function refresh(): Promise<void> {
  await emit("fe-internal-refresh", {});
}

export function onRefresh(): void {
  void listen("fe-internal-refresh", () => {});
}

/// Through a window receiver, rather than the module functions.
export async function resized(): Promise<void> {
  const win = getCurrentWebviewWindow();
  await win.emit("window-resized", { w: 1, h: 1 });
}

export function onResized(): void {
  const win = getCurrentWebviewWindow();
  void win.listen("window-resized", () => {});
}

/// A runtime-computed event name on the frontend side.
export function wildcard(eventName: string): void {
  void listen(eventName, () => {});
}

/// Only ever listened for. Something outside this workspace produces it — a
/// plugin, or another page — so the name stays.
export function watchPlugin(): void {
  void listen("plugin-status", () => {});
}
