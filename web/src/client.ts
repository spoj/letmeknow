// The browser's session: lmk-node in WebAssembly (crates/web), its records and files kept in IndexedDB. One tab at a
// time runs it, holding the Web Lock "lmk8"; the other tabs call it over the BroadcastChannel "lmk8", and hear
// its events there. When that tab closes, a waiting tab takes the lock and runs the session from IndexedDB. Its
// default membership is compiled into the trusted frontend (backend.json): its directory is fetched, and must name the
// compiled key. Explicit localStorage choices override the domain; the backend never supplies code.
import init, { type Lmk, invite_kind, start } from "../pkg/lmk_web.js";
import wasm from "../pkg/lmk_web_bg.wasm";
import * as store from "./store";

/** A member as the client core describes it; an endpoint that is not one has only its `iroh` key. */
export type Identity = { id: string; name: string; how: "self" | "observed" | "unknown"; error?: string; observed?: { names: string[]; other_ids: string[] } };
/** A member; `name` is how it shows: "Matthew · phone", or its fingerprint where it speaks for no identity this browser could check. */
export type Person = { fp: string; name: string; handle?: string; device: string; you?: boolean; identity?: Identity; added_by?: { fp: string; how: string }; away?: boolean };
export type Named = { id: string; name: string };
export type Settings = { kind: "chat" | "doc" | "table"; name: string };
export type Group = { group: string; settings: Settings; members: Person[] };
export type Attachment = { link: string; name: string; size: number; type: string; kept: boolean };

export type Item =
  | {
      type: "message";
      id: string;
      /** When it arrived; the timeline is in this order. */
      at: number;
      /** When the sender sent it, by its clock. */
      sent_at?: number;
      from: Person;
      content: string;
      to?: string[];
      reply_to?: string;
      urgent?: boolean;
      attachment?: Attachment;
      /** Delivered without messages it needed, which were given up on. */
      late?: boolean;
      /** A send that failed, kept with its text until sent again or dropped. */
      failed?: { error: string; retry: () => void; drop: () => void };
      /** Of this browser's own: no cut keeps it yet. */
      only_here?: boolean;
      /** Of this browser's own: the other members that hold it, and those that read it. */
      held_by?: Person[];
      read_by?: Person[];
      /** Members that lost this message of this browser's. */
      lost_by?: Person[];
    }
  | { type: "missing"; at: number; missing: { from: Person; seqs: number[] }[] }
  | { type: "lost"; at: number; member: Person; messages: { from: Person; seqs: number[]; ids: string[] }[] }
  | { type: "leave"; id: string; at: number; from: Person; only_here: boolean }
  | { type: "joined"; at: number; member: Person; by: Person }
  | { type: "left"; at: number; member: Person; by: Person }
  | { type: "revoked"; at: number; removed: Person[]; added: Person[] }
  | { type: "settings"; at: number; by: Person; before?: Settings; settings: Settings };
export type Event = { type: string; group?: string; identity?: string; hash?: string; text?: string; by?: string; not_kept?: string[] };
export type Me = { fp: string; device: { name: string }; identity: Named | null };


/** The session's methods, as every tab calls them: asynchronously, wherever it runs. */
type Methods = Exclude<keyof Lmk, "free" | symbol>;
export type Session = { [K in Methods]: Lmk[K] extends (...args: infer A) => infer R ? (...args: A) => Promise<Awaited<R>> : never };
type Call = { id: string; method: string; args: unknown[] };
type Message = Partial<Call> & { ready?: boolean; ask?: boolean; event?: Event; result?: unknown; error?: string };

export const kindOf = (link: string): string | undefined => {
  try {
    return invite_kind(link);
  } catch {
    return undefined;
  }
};

const listeners = new Set<(event: Event) => void>();
export const listen = (listener: (event: Event) => void) => listeners.add(listener);
export const unlisten = (listener: (event: Event) => void) => listeners.delete(listener);
const dispatch = (event: Event) => listeners.forEach(listener => listener(event));

const channel = new BroadcastChannel("lmk8");
const tab = crypto.randomUUID();
let calls = 0;
/** This tab's calls not answered yet: sent again whenever a tab starts running the session. */
const pending = new Map<string, Call & { resolve: (result: unknown) => void; reject: (error: Error) => void }>();
/** Calls this tab took while running the session, so a call sent again runs once. */
const taken = new Set<string>();
let local: Lmk | undefined;
let storageFailure: Event | undefined;
let leading = false;
let readied: () => void;
let failed: (error: unknown) => void;
let ran: () => void;
/** Resolves once the session runs, in this tab or another. */
export const ready = new Promise<void>((resolve, reject) => { readied = resolve; failed = reject; });
const runsHere = new Promise<void>(resolve => (ran = resolve));
/** Whether this tab runs the session. */
export const runs = () => leading;

function call(method: string, args: unknown[]): Promise<unknown> {
  if (leading) return method === "open" ? run(...(args as string[])) : (running ?? runsHere).then(() => (local![method as Methods] as (...a: unknown[]) => unknown)(...args));
  const id = `${tab} ${calls++}`;
  return new Promise((resolve, reject) => {
    pending.set(id, { id, method, args, resolve, reject });
    channel.postMessage({ id, method, args });
  });
}

export const lmk = new Proxy({} as Session, { get: (_, method: string) => (...args: unknown[]) => call(method, args) });

/** A request of the client core, as `letmeknow`'s command channel takes it: `{cmd, ...}`. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const request = async (request: { cmd: string } & Record<string, unknown>): Promise<any> => JSON.parse(await lmk.request(JSON.stringify(request)));

/** Starts the session in another tab, or in this one if it holds the lock, as `name` on device `device` if new. */
export const open = (device: string) => call("open", [device]) as Promise<void>;

async function answer({ id, method, args }: Call) {
  try {
    channel.postMessage({ id, result: await call(method, args) });
  } catch (error) {
    channel.postMessage({ id, error: error instanceof Error ? error.message : String(error) });
  }
}

channel.onmessage = ({ data }: MessageEvent<Message>) => {
  if (data.method && leading && (local || data.method === "open") && !taken.has(data.id!)) {
    taken.add(data.id!);
    answer(data as Call);
  }
  if (data.ask && local) channel.postMessage({ ready: true, event: storageFailure });
  if (data.ready) {
    readied();
    for (const { id, method, args } of pending.values()) channel.postMessage({ id, method, args });
  }
  if (data.event) dispatch(data.event);
  const waiting = data.id !== undefined && !data.method && pending.get(data.id);
  if (!waiting) return;
  pending.delete(waiting.id);
  if (data.error !== undefined) waiting.reject(new Error(data.error));
  else waiting.resolve(data.result);
};

let running: Promise<void> | undefined;
/** Runs the session in this tab, from what IndexedDB keeps, creating it as `name` on `device` if there is none. */
function run(device = ""): Promise<void> {
  running ??= (async () => {
    const { records, kept } = await store.load();
    let membership = localStorage.getItem("lmk membership") ?? BACKEND.domain;
    if (membership.includes("@") || membership === "letmeknow.dev") {
      localStorage.removeItem("lmk membership");
      localStorage.removeItem("lmk relay");
      dispatch({ type: "warning", text: `lmk membership ${membership} is letmeknow 0.17's: a membership is a domain now, as --membership <domain> is. This browser uses ${BACKEND.domain}.` });
      membership = BACKEND.domain;
    }
    const relays = localStorage.getItem("lmk relay")?.split(",") ?? [];
    const config = { device, membership, relays, backend: BACKEND };
    local = await start(records, kept, JSON.stringify(config), store, (json: string) => {
      const event = JSON.parse(json) as Event;
      if (event.type === "storage_failed") storageFailure = event;
      dispatch(event);
      channel.postMessage({ event });
    });
    addEventListener("pagehide", () => local!.flush(false).catch(error => dispatch({ type: "warning", text: String(error) })));
    ran();
    readied();
    for (const waiting of pending.values()) {
      pending.delete(waiting.id);
      call(waiting.method, waiting.args).then(waiting.resolve, waiting.reject);
    }
    channel.postMessage({ ready: true });
  })();
  return running;
}

/** Loads the WebAssembly and waits for the lock; resolves whether this browser has a session. */
export async function prepare(): Promise<boolean> {
  const had = await store.has();
  await init({ module_or_path: wasm });
  navigator.locks.request("lmk8", async () => {
    leading = true;
    if (await store.has()) await run();
    await new Promise(() => {});
  }).catch(error => {
    failed(error);
    dispatch({ type: "warning", text: String(error) });
  });
  channel.postMessage({ ask: true });
  return had;
}

/** A file's plaintext, fetched from the members online if this browser does not hold it yet. */
export async function file(gid: string, link: string): Promise<Uint8Array> {
  const held = await lmk.file(link);
  if (held) return held;
  const hash = /^lmk:([0-9a-f]{64})\./.exec(link)?.[1];
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
  await lmk.fetch(gid, link);
  await arrived;
  return (await lmk.file(link))!;
}

/** Bytes as the session's commands take them: unpadded base64url. */
export function b64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function unb64(text: string): Uint8Array {
  return Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), char => char.charCodeAt(0));
}
