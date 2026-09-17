// The frontend half of the IPC contract. Every command name below is also a
// `#[tauri::command]` function name on the Rust side, and renaming one without
// the other produces an app that starts and then refuses every call.

import { invoke } from "@tauri-apps/api/core";

export interface UserInfo {
  userName: string;
  deviceId: number;
}

/// A plain literal argument.
export async function getUserInfo(userId: number): Promise<UserInfo> {
  return invoke<UserInfo>("get_user_info", { userId });
}

/// A typed invocation.
export async function activateLicense(key: string): Promise<boolean> {
  return invoke<boolean>("activate_license", { key });
}

/// The command name held in a module constant that is only ever passed to
/// `invoke`, which is what makes rewriting the constant safe.
const SYNC_COMMAND = "sync_state";

export async function sync(): Promise<number> {
  return invoke<number>(SYNC_COMMAND);
}
