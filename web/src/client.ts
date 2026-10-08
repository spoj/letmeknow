// The browser's session: lmk-node in WebAssembly (crates/web), its records and files kept in IndexedDB. Its relay and
// membership service are letmeknow.dev's unless localStorage names others ("lmk relay", "lmk membership"), as tests do.
import init, { type Lmk, invite_kind, start } from "../pkg/lmk_web.js";
import wasm from "../pkg/lmk_web_bg.wasm";
import * as store from "./store";

export type Identity = {
  id: string;
  name: string;
  how: "self" | "verified" | "introduced" | "unknown";
  by?: string;
  warning?: string;
  error?: string;
  new_device?: string;
  introduced?: { by: string; name: string };
};
export type Person = { key: string; fp: string; name: string; device: string; you?: boolean; identity?: Identity; added_by?: { name?: string; how: string } };
export type Named = { id: string; name: string };
export type Settings = { kind: "chat" | "doc"; name: string; open?: Named[]; keep?: number; devices_of?: string };
export type Group = { group: string; settings: Settings; members: Person[]; joined: boolean };
export type Attachment = { link: string; name: string; size: number; type: string };
export type Item =
  | {
      type: "message";
      id: string;
      at: number;
      from: Person;
      content: string;
      to?: string[];
      reply_to?: string;
      urgent?: boolean;
      attachment?: Attachment;
      pending?: boolean;
      refused?: { name: string; reason: string }[];
    }
  | { type: "leave"; id: string; at: number; from: Person }
  | { type: "joined"; at: number; member: Person; by: Person; how: string }
  | { type: "left"; at: number; member: Person; by: Person }
  | { type: "settings"; at: number; by: Person; before?: Settings; settings: Settings }
  | { type: "introduced"; at: number; by: Person; identity: Named; how: string };
export type Event = { type: string; group?: string; id?: string; hash?: string; text?: string; by?: string };
export type Me = { key: string; fp: string; name: string; device: { key: string; name: string }; identities: Named[] };
export type Contacts = { contacts: (Named & { how: string; by?: string })[]; introductions: (Named & { by: string })[] };

export const kindOf = (link: string): string | undefined => {
  try {
    return invite_kind(link);
  } catch {
    return undefined;
  }
};

/** Files whose ciphertext this browser holds, by hash. */
export const held = new Set<string>();
const listeners = new Set<(event: Event) => void>();
export const listen = (listener: (event: Event) => void) => listeners.add(listener);
export const unlisten = (listener: (event: Event) => void) => listeners.delete(listener);

let records: [Uint8Array, Uint8Array][];
let files: Map<string, Uint8Array>;

/** Loads what this browser keeps; true if it has a session. */
export async function prepare(): Promise<boolean> {
  await init({ module_or_path: wasm });
  ({ records, files } = await store.load());
  return records.length > 0;
}

export async function open(name = "", device = ""): Promise<Lmk> {
  for (const hash of files.keys()) held.add(hash);
  const config = { name, device, relay: localStorage.getItem("lmk relay") ?? undefined, membership: localStorage.getItem("lmk membership") ?? undefined };
  const saveFile = (hash: string, ciphertext: Uint8Array) => {
    held.add(hash);
    store.saveFile(hash, ciphertext);
  };
  const lmk = await start(records, [...files.values()], JSON.stringify(config), store.save, saveFile, (json: string) => {
    const event = JSON.parse(json) as Event;
    for (const listener of listeners) listener(event);
  });
  addEventListener("pagehide", () => lmk.flush());
  return lmk;
}

/** The hash a file link names. */
export const hashOf = (link: string) => /^lmk:([0-9a-f]{64})\./.exec(link)?.[1] ?? "";

/** A file's plaintext, fetched from the members online if this browser does not hold it yet. */
export async function file(lmk: Lmk, gid: string, link: string): Promise<Uint8Array> {
  const hash = hashOf(link);
  if (!held.has(hash)) {
    const arrived = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => (listeners.delete(wait), reject(new Error("no member online holds the file"))), 90_000);
      const wait = (event: Event) => {
        if (event.type !== "file" || event.hash !== hash) return;
        clearTimeout(timer);
        listeners.delete(wait);
        resolve();
      };
      listeners.add(wait);
    });
    lmk.fetch(gid, link);
    await arrived;
  }
  return (await lmk.file(link))!;
}

export type { Lmk };
