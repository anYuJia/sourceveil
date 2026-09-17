// The one construct that decides the whole namespace.
//
// `invoke(name)` computes a command name at runtime, so `name` could be any
// command the backend registered. There is no way to rename "the statically
// referenced commands" and leave the rest, because this call is potentially a
// call to every one of them. So the frontend says so, and the pass keeps the
// entire namespace and reports exactly where this is.

import { invoke } from "@tauri-apps/api/core";

export function dispatchByName(name: string): Promise<unknown> {
  return invoke(name);
}

export function dispatchByPrefix(prefix: string, action: string): Promise<unknown> {
  return invoke(`${prefix}_${action}`);
}
