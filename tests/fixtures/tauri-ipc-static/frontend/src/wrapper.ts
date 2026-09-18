// A project-local wrapper. Its callers are static, so the commands they name
// are still renameable even though the wrapper's own body takes a variable.

import { invoke } from "@tauri-apps/api/core";

export function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args);
}

export function probeVaultHealth(): Promise<string> {
  return call<string>("probe_vault_health");
}
