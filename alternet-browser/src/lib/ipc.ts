/**
 * AlterNet Browser — Tauri IPC wrappers
 *
 * Manifesto VI: Her IPC çağrısı kullanıcıyı daha egemen kılar.
 */

import { invoke } from "@tauri-apps/api/core";

export interface IdentityInfo {
  alter_uri: string;
  peer_id: string;
  pubkey_hex: string;
  keyfile: string;
}

export interface PublishResult {
  alter_uri: string;
  pubkey_hex: string;
  block_count: number;
  title: string | null;
}

export interface FetchResult {
  status: string;
  alter_uri: string;
  path: string | null;
  error: string | null;
}

export type FetchStatus =
  | "Idle"
  | { Fetching: { progress: number } }
  | { Ready: { path: string } }
  | { Error: { message: string } };

export interface PinInfo {
  root_cid: string;
  author_pubkey_hex: string;
  label: string | null;
  pinned_at: number;
  block_count: number;
}

export interface FolderValidation {
  exists: boolean;
  has_index_html: boolean;
  file_count: number;
  total_bytes: number;
}

export const ipc = {
  getIdentity: () => invoke<IdentityInfo>("get_identity"),

  generateIdentity: (output?: string) =>
    invoke<IdentityInfo>("generate_identity", { output }),

  fetchSite: (uri: string) => invoke<FetchResult>("fetch_site", { uri }),

  getSiteStatus: (uri: string) => invoke<FetchStatus>("get_site_status", { uri }),

  publishSite: (
    path: string,
    title?: string,
    description?: string
  ) => invoke<PublishResult>("publish_site", { path, title, description }),

  validatePublishFolder: (path: string) =>
    invoke<FolderValidation>("validate_publish_folder", { path }),

  resolveName: (name: string) => invoke<string>("resolve_name", { name }),

  pinSite: (uri: string, label?: string) =>
    invoke<string>("pin_site", { uri, label }),

  listPins: () => invoke<PinInfo[]>("list_pins"),

  unpinSite: (uri: string) => invoke<void>("unpin_site", { uri }),
};
