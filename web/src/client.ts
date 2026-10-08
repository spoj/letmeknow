// The browser member: the session process's protocol, with keys and MLS in WebAssembly (client/src/web.rs) and the
// relay reached from this page's own origin. Unlike an agent session it keeps message text, and nothing is held back.
import init, { Member, Pake, blob_open, blob_seal, entity_list, invite_words, locate, open, random, seal } from "../pkg/letmeknow.js";
import wasm from "../pkg/letmeknow_bg.wasm";
import * as Y from "yjs";
import * as store from "./store";

export type Entity = { id: string; name?: string; error?: string; new?: boolean; yours?: boolean };
export type Person = { name: string; fp: string; device?: string; as?: string[]; you?: boolean; entity?: Entity };
/** The person a member is, by its verified entity, or else the member itself. */
export const whose = (p: Person) => (!p.entity?.error && p.entity?.name) || p.name;
/** `kind` says what the group shares, fixed when it is made: a chat or a doc. */
export type Settings = { kind: string; name?: string; open?: { id: string; name: string }[]; requests?: string };
/** A file sent with a message: the link to its blob, its name, size in bytes and media type. */
export type Attachment = { link: string; name: string; size: number; type?: string };
/** What a chat shows. Other kinds of group show no items: a warning in one goes to `onerror`. */
export type Item =
  | { type: "message"; id: string; from: Person; content: string; to?: string[]; reply_to?: string; urgent?: boolean; attachment?: Attachment; after: string[]; at: number }
  | { type: "joined" | "left"; member: Person; by: Person; at: number }
  | { type: "settings"; settings: Settings; before: Settings; by: Person; at: number }
  | { type: "warning"; text: string; at: number };
/** An entity this browser is in. Its secret locates and seals the entity's inbox. */
export type Membership = { id: string; name: string; secret: string };
export type Opening = { group: string; relay: string; kind: string; name: string; requests: string; closed?: boolean };
export type Invite = { code: string; link: string };
export type List = { id: string; name: string; members: { id: string; key?: string; name: string }[] };
/**
 * `read` counts the items a person has seen. `pending` is the id of a commit this browser posted without hearing the
 * relay's answer: catching up tells whether the relay took it.
 */
export type Group = { gid: string; cursor: number; settings: Settings; posted: string[]; requests: number; read: number; pending?: string };
/** What a socket announces: a page row, without `data` when the entry is large. */
type Notice = { seq: number; at: number; data?: string };
type Payload =
  | ({ type: "settings" } & Settings)
  | { type: "message"; content?: string; after: string[]; to?: string[]; reply_to?: string; urgent?: boolean; attachment?: Attachment }
  | { type: "edit"; update: string };
/** The kind of group each type of message belongs to; settings belong to every kind. */
const BELONGS: Record<string, string> = { message: "chat", edit: "doc" };
/** The most a blob holds. */
export const MAX_BLOB_BYTES = 10 * 1024 * 1024;

const INVITE_TTL_MS = 600_000;
const origin = location.origin;
const hex = (bytes: Uint8Array) => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
const unhex = (s: string) => Uint8Array.from(s.match(/../g) ?? [], h => parseInt(h, 16));
const b64 = (bytes: Uint8Array) => btoa(Array.from(bytes, b => String.fromCharCode(b)).join(""));
const unb64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const utf8 = (s: string) => new TextEncoder().encode(s);
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const same = (a: Settings, b: Settings) =>
  a.name === b.name && a.requests === b.requests && JSON.stringify(a.open ?? []) === JSON.stringify(b.open ?? []);
/** A link to a blob: `lmk:<hash>#<key>`. */
const LINK = /lmk:([0-9a-f]{64})#([0-9a-f]{64})/g;
const sha256 = async (bytes: Uint8Array) => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)));

/** The relay's answer to a request it refused. */
class Refused extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

async function http(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(origin + path, init);
  if (!response.ok && response.status !== 409) throw new Refused(response.status, `relay answered ${response.status}: ${(await response.text()).trim()}`);
  return response;
}

/**
 * Long-polls with `poll` until it yields something, for as long as an invite or join request lives. A poll that failed
 * on the way (no answer, or a relay failure) is tried again a few seconds later: a dropped connection says nothing about
 * the invite.
 */
async function wait<T>(poll: () => Promise<T | undefined>, expired: string): Promise<T> {
  for (const deadline = Date.now() + INVITE_TTL_MS; Date.now() < deadline; ) {
    try {
      const found = await poll();
      if (found !== undefined) return found;
    } catch (error) {
      if (error instanceof Refused && error.status < 500) throw error;
      await new Promise(resolve => setTimeout(resolve, 3_000));
    }
  }
  throw new Error(expired);
}

/** The data a long-poll on an invite brought, if any. */
async function inviteData(path: string): Promise<string | undefined> {
  const response = await http(path);
  return response.status === 204 ? undefined : (await response.json()).data;
}

// Boxes: append-only logs on the relay holding sealed text (entity lists, inboxes, join requests and replies).
async function boxRead(address: string, after = 0, wait = 0): Promise<{ seq: number; at: number; data: string }[]> {
  const entries: { seq: number; at: number; data: string }[] = await (await http(`/b/${address}?after=${after}&wait=${wait}`)).json();
  return entries.map(e => ({ ...e, data: atob(e.data) }));
}

/**
 * Whether a page whose entries are `sizes` bytes holds everything after its cursor. The relay ends a page early only
 * before an entry that would take it past 2 MiB, and entries are at most 1 MiB, so a page of at most 1 MiB is whole:
 * there is no need to ask for the next, empty one.
 */
const whole = (sizes: number[]) => sizes.reduce((a, b) => a + b, 0) <= 1024 * 1024;

async function boxAll(address: string): Promise<string[]> {
  const all: string[] = [];
  for (let after = 0; ; ) {
    const page = await boxRead(address, after);
    all.push(...page.map(e => e.data));
    if (whole(page.map(e => e.data.length))) return all;
    after = page[page.length - 1].seq;
  }
}

// Bodies are read even when unused: one left unread holds its connection open until the browser drops it.
const boxAppend = async (address: string, data: string): Promise<number> => (await (await http(`/b/${address}`, { method: "POST", body: data })).json()).seq;
const place = (label: string, secret: Uint8Array): { address: string; key: Uint8Array } => {
  const { address, key } = JSON.parse(locate(label, secret));
  return { address, key: unhex(key) };
};

/** What an invite slot holds: a group invite, a device link, or nothing (used or expired). */
export async function inviteKind(slot: string): Promise<"group" | "entity" | null> {
  const response = await fetch(`${origin}/i/${slot}/pake?wait=0`);
  if (!response.ok) return null;
  return (await response.json()).data.startsWith("entity ") ? "entity" : "group";
}

export class Client {
  member?: Member;
  /** `left`: groups this browser left, which it no longer lists as open to it. */
  me = { name: "", entities: [] as Membership[], left: [] as string[] };
  groups = new Map<string, Group>();
  items = new Map<string, Item[]>();
  /** Each group's members as `members` last checked them. */
  people = new Map<string, Person[]>();
  /** Each doc group's text, as a Yjs document. */
  docs = new Map<string, Y.Doc>();
  onchange = () => {};
  onerror = (_error: unknown) => {};
  private seen = new Set<string>();
  private lists = new Map<string, { at: number; list: List }>();
  private outbox = new Map<string, { updates: Uint8Array[]; timer?: ReturnType<typeof setTimeout> }>();
  private sockets = new Map<string, { socket: WebSocket; check: () => void }>();
  /** Welcomes for admitted join requests not yet written to their reply box, by its address. */
  private replies = new Map<string, string>();
  /** Inbox entries by entity, kept while the inbox's socket announces nothing new; `inboxNotices` counts announcements. */
  private inboxes = new Map<string, string[]>();
  private inboxNotices = 0;
  /** Groups loaded with the page whose keys are to be replaced once caught up. */
  private loaded = new Set<string>();
  private writes = new Map<string, [string, string, unknown]>();
  private saved = new Map<string, string>();
  private dirtyDocs = new Set<string>();
  private queue: Promise<unknown> = Promise.resolve();
  /** Blobs kept in IndexedDB, and those fetched or being fetched since the page loaded, as "<gid> <hash>". */
  private blobs = new Set<string>();
  private fetched = new Set<string>();
  private images = new Map<string, Promise<string>>();

  static async start(): Promise<Client> {
    await init({ module_or_path: wasm });
    const client = new Client();
    const state = async (key: string) => JSON.parse((await store.get<string>("state", key))!);
    const saved = await store.get<string>("state", "member");
    if (saved) {
      client.member = Member.load(saved);
      client.blobs = new Set(await store.keys("blobs", ""));
      client.me = { left: [], ...(await state("me")) };
      client.seen = new Set(await state("seen"));
      for (const group of (await state("groups")) as Group[]) {
        client.groups.set(group.gid, group);
        client.items.set(group.gid, await store.all<Item>("items", `${group.gid} `));
        // Made before groups had kinds, and unreadable now: left here, though not in the group.
        if (!group.settings.kind) {
          client.member.leave(group.gid);
          await client.forget(group.gid);
        }
      }
      for (const { gid, state, unsent } of await store.all<{ gid: string; state: Uint8Array; unsent?: Uint8Array }>("docs", "")) {
        client.track(gid, state);
        if (unsent) client.queueUpdate(gid, unsent);
      }
    }
    return client;
  }

  /**
   * Runs `job` after every job before it: the member's state changes one step at a time, and is saved after each.
   * Failures go to `onerror` too, as most jobs start from timers and sockets.
   */
  run<T>(job: () => Promise<T>): Promise<T> {
    const result = this.queue.then(job).finally(() => this.save());
    this.queue = result.catch(error => this.onerror(error)).finally(() => this.onchange());
    return result;
  }

  private async save() {
    if (!this.member) return;
    for (const gid of this.dirtyDocs) {
      const doc = this.docs.get(gid);
      const unsent = this.outbox.get(gid)?.updates ?? [];
      if (doc) this.write("docs", gid, { gid, state: Y.encodeStateAsUpdate(doc), unsent: unsent.length ? Y.mergeUpdates(unsent) : undefined });
    }
    this.dirtyDocs.clear();
    const state = { member: this.member.save(), me: JSON.stringify(this.me), groups: JSON.stringify([...this.groups.values()]), seen: JSON.stringify([...this.seen]) };
    const changed = Object.entries(state).filter(([key, value]) => this.saved.get(key) !== value);
    for (const [key, value] of changed) this.write("state", key, value);
    const writes = [...this.writes.values()];
    this.writes.clear();
    if (writes.length) await store.put(writes);
    for (const [key, value] of changed) this.saved.set(key, value);
  }

  private write(store: string, key: string, value: unknown) {
    this.writes.set(`${store} ${key}`, [store, key, value]);
  }

  /** First use: this browser becomes a member named `label`, and starts the entity `entity`, unless a device link will add it to one. */
  async create(label: string, entity?: string) {
    this.member = new Member(label);
    this.me = { name: label, entities: [], left: [] };
    await this.run(async () => {
      if (entity) await this.createEntity(entity);
    });
    this.connect();
  }

  startEntity(name: string) {
    return this.run(() => this.createEntity(name));
  }

  markRead(gid: string) {
    return this.run(async () => {
      this.groups.get(gid)!.read = this.items.get(gid)!.length;
    });
  }

  private async createEntity(name: string) {
    const { id, address, entry } = JSON.parse(this.member!.entity_create(name));
    await boxAppend(address, entry);
    this.me.entities.push({ id, name, secret: hex(random(32)) });
  }

  /** The entities this browser speaks as: its first entity, if it has one. */
  private path(): string {
    return JSON.stringify(this.me.entities.slice(0, 1).map(e => e.id));
  }

  /**
   * Follows every group, and the requests box of every open group, on sockets. A group's socket brings each new
   * message; while a socket is down, it is reopened every 15 seconds (a box's every minute), and each failed try polls.
   */
  connect() {
    for (const gid of this.groups.keys()) {
      this.loaded.add(gid);
      this.followGroup(gid);
      this.followRequests(gid);
      this.run(() => this.members(gid));
    }
    setInterval(() => this.groups.forEach((_, gid) => this.followGroup(gid)), 15_000);
    setInterval(() => this.groups.forEach((_, gid) => this.followRequests(gid)), 60_000);
    setInterval(() => this.groups.forEach((_, gid) => this.run(() => this.updateKey(gid))), 3_600_000);
    // A device that slept may hold sockets that look open but are dead, and lost others.
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) return;
      this.sockets.forEach(s => s.check());
      this.groups.forEach((_, gid) => this.followGroup(gid));
    });
  }

  /**
   * Opens the socket `key` on `path` unless it is open: `update` gets each notice, and is called without one when the
   * socket opens (to fetch what came before) or fails to (a poll). A ping unanswered for 10 seconds closes it.
   */
  private follow(key: string, path: string, update: (notice?: Notice) => void) {
    const existing = this.sockets.get(key)?.socket;
    if (existing && existing.readyState <= WebSocket.OPEN) return;
    const socket = new WebSocket(`${origin.replace(/^http/, "ws")}${path}/ws`);
    let opened = false;
    let unanswered: ReturnType<typeof setTimeout> | undefined;
    const check = () => {
      if (socket.readyState !== WebSocket.OPEN || unanswered) return;
      socket.send("ping");
      unanswered = setTimeout(() => socket.close(), 10_000);
    };
    const ping = setInterval(check, 30_000);
    socket.onopen = () => {
      opened = true;
      update();
    };
    socket.onmessage = event => {
      if (event.data === "pong") {
        clearTimeout(unanswered);
        unanswered = undefined;
        return;
      }
      const notice = JSON.parse(event.data);
      update(typeof notice === "object" ? notice : undefined);
    };
    socket.onclose = () => {
      clearInterval(ping);
      clearTimeout(unanswered);
      if (!opened && this.sockets.get(key)?.socket === socket) update();
    };
    this.sockets.set(key, { socket, check });
  }

  private followGroup(gid: string) {
    this.follow(gid, `/g/${gid}`, notice => this.run(() => this.noticed(gid, notice)));
  }

  /** Follows the requests box of a group open to an entity, or stops once it is closed. */
  private followRequests(gid: string) {
    const { open: opened, requests } = this.groups.get(gid)?.settings ?? {};
    const key = `requests ${gid}`;
    if (opened?.length && requests) return this.follow(key, `/b/${place("requests", unhex(requests)).address}`, () => this.run(() => this.admitRequests(gid)));
    const socket = this.sockets.get(key)?.socket;
    this.sockets.delete(key);
    socket?.close();
  }

  /** Takes a message from its notice when it is the next one; otherwise fetches what this browser lacks. */
  private async noticed(gid: string, notice?: Notice) {
    const group = this.groups.get(gid);
    if (!group || (notice && notice.seq <= group.cursor)) return;
    if (notice?.data !== undefined && notice.seq === group.cursor + 1) return this.take(gid, notice.seq, notice.data);
    try {
      await this.catchUp(gid);
    } catch (error) {
      // Reopened, and so tried again, within 15 seconds: an open socket would announce only what comes next.
      this.sockets.get(gid)?.socket.close();
      throw error;
    }
    // Caught up after loading: replace this member's keys, for post-compromise security.
    if (this.loaded.delete(gid)) await this.updateKey(gid);
  }

  private async catchUp(gid: string) {
    for (;;) {
      const group = this.groups.get(gid);
      if (!group) return;
      const page: { seq: number; data: string }[] = await (await http(`/g/${gid}/messages?after=${group.cursor}`)).json();
      for (const { seq, data } of page) await this.take(gid, seq, data);
      // Base64 is a third larger than what it encodes.
      if (whole(page.map(m => (m.data.length * 3) / 4))) return;
    }
  }

  private async take(gid: string, seq: number, data: string) {
    const group = this.groups.get(gid);
    if (!group || seq <= group.cursor) return;
    group.cursor = seq;
    const bytes = unb64(data);
    const id = await sha256(bytes);
    // This browser's commit, which the relay took though its answer never came.
    if (id === group.pending) return this.merge(gid);
    if (group.posted.includes(id)) return;
    try {
      await this.receive(gid, id, bytes);
    } catch (error) {
      this.show(gid, { type: "warning", text: `A message could not be read: ${error}`, at: Date.now() });
    }
  }

  private async receive(gid: string, id: string, bytes: Uint8Array) {
    const result = JSON.parse(this.member!.process(gid, bytes));
    if (result.proposal) {
      await this.post(gid, () => this.member!.commit_proposals(gid));
      return;
    }
    if (result.changes) {
      // Merging another member's commit drops this browser's own for the same epoch: the relay took that one instead.
      this.groups.get(gid)!.pending = undefined;
      for (const change of result.changes) this.show(gid, { type: change.type, member: await this.describe(change.member), by: await this.describe(change.by), at: Date.now() });
      if (result.removed) {
        const { name, kind } = this.groups.get(gid)!.settings;
        const by = whose(await this.describe(result.sender));
        await this.forget(gid);
        this.onerror(`${by} removed you from ${name ? `“${name}”` : ({ chat: "a chat", doc: "a document" }[kind] ?? "a group")}`);
        return;
      }
      await this.members(gid);
      return;
    }
    const payload: Payload = result.payload;
    const kind = this.groups.get(gid)!.settings.kind;
    if (payload.type !== "settings" && BELONGS[payload.type] !== kind) {
      // A type that belongs to no kind this browser knows (a folder's "joined", or a newer version's) says nothing here.
      if (BELONGS[payload.type]) this.show(gid, { type: "warning", text: `Ignored a ${BELONGS[payload.type]} message in this ${kind}`, at: Date.now() });
      return;
    }
    // An edit is never shown, so it does not meet the sender's entity.
    if (payload.type === "edit") return this.applyEdit(gid, payload.update);
    const from = await this.describe(result.sender);
    if (payload.type === "message") {
      const { content = "", to, reply_to, urgent, attachment, after } = payload;
      return this.show(gid, { type: "message", id, from, content, to, reply_to, urgent, attachment, after, at: Date.now() });
    }
    const { type, ...settings } = payload;
    if (settings.kind !== kind) return this.show(gid, { type: "warning", text: `Ignored settings that would make this ${kind} a ${settings.kind}`, at: Date.now() });
    await this.settle(gid, settings, from);
  }

  /**
   * Posts what `build` makes at the group's current epoch; if the relay has moved on, catches up and builds again. A
   * commit whose answer never comes stays pending until catching up shows whether the relay took it.
   */
  private async post(gid: string, build: () => Uint8Array): Promise<{ seq: number; id: string }> {
    const group = this.groups.get(gid)!;
    if (group.pending) {
      await this.catchUp(gid);
      if (group.pending) {
        this.member!.settle(gid, false);
        group.pending = undefined;
      }
    }
    for (let attempt = 0; attempt < 3; attempt++) {
      const bytes = build();
      const id = await sha256(bytes);
      group.posted = [...group.posted.slice(-50), id];
      if (this.member!.pending(gid)) group.pending = id;
      // Saved first, so that after a reload this browser still knows the message as its own, and never reuses its keys.
      await this.save();
      const response = await http(`/g/${gid}/messages`, { method: "POST", body: bytes as BodyInit });
      if (response.status === 409) {
        await response.text();
        this.member!.settle(gid, false);
        group.pending = undefined;
        await this.catchUp(gid);
        continue;
      }
      await this.merge(gid);
      return { seq: (await response.json()).seq, id };
    }
    throw new Error("the group kept changing; try again");
  }

  /** Merges this browser's commit once the relay took it, and shows the membership changes it makes. */
  private async merge(gid: string) {
    const group = this.groups.get(gid)!;
    const committed = group.pending !== undefined;
    group.pending = undefined;
    for (const change of JSON.parse(this.member!.settle(gid, true))) {
      this.show(gid, { type: change.type, member: await this.describe(change.member), by: await this.describe(change.by), at: Date.now() });
    }
    if (committed) await this.members(gid);
  }

  private show(gid: string, item: Item) {
    const items = this.items.get(gid);
    if (!items) return;
    if (this.groups.get(gid)!.settings.kind !== "chat") return item.type === "warning" && this.onerror(item.text);
    this.write("items", `${gid} ${String(items.length).padStart(10, "0")}`, item);
    items.push(item);
  }

  /** Read-frontier tips: messages no message lists in `after`. A person sees every message, so all count as read. */
  private tips(gid: string): string[] {
    const messages = (this.items.get(gid) ?? []).filter(i => i.type === "message") as Extract<Item, { type: "message" }>[];
    const covered = new Set(messages.flatMap(m => m.after));
    return messages.map(m => m.id).filter(id => !covered.has(id));
  }

  /** Sends a message, with `file` uploaded first, outside the queue, as it may take a while. */
  async send(gid: string, content: string, options: { to?: string[]; reply_to?: string; urgent?: boolean }, file?: File) {
    const attachment = file && { link: await this.attach(gid, new Uint8Array(await file.arrayBuffer())), name: file.name, size: file.size, type: file.type || undefined };
    return this.run(async () => {
      const message = { type: "message" as const, content, after: this.tips(gid), ...options, attachment };
      const { id } = await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify(message))));
      this.show(gid, { ...message, id, from: await this.self(gid), at: Date.now() });
    });
  }

  /** The group's members, each checked against its entity's list; kept in `people` too. */
  async members(gid: string): Promise<Person[]> {
    const members: Person[] = [];
    for (const member of JSON.parse(this.member!.members(gid))) members.push(await this.describe(member, false));
    this.people.set(gid, members);
    return members;
  }

  private async self(gid: string): Promise<Person> {
    return (await this.members(gid)).find(m => m.you)!;
  }

  /**
   * Checks the entities a member says it speaks as against their lists: the first must list its device (or the member
   * itself), each later one the one before. An entity is `new` until this browser meets it: until it shows the person an
   * item (message, membership change, settings) from or about it. Listing members, which is redrawn, is no meeting.
   */
  private async describe(person: Person, meet = true): Promise<Person> {
    const { as: path, ...described } = person;
    if (!path) return described;
    let holder = person.device ?? person.fp;
    let name = "";
    for (const id of path) {
      try {
        const list = await this.list(id, holder);
        if (!list.members.some(m => m.id === holder)) return { ...described, entity: { id, error: `not on ${list.name}'s list` } };
        name = list.name;
      } catch (error) {
        return { ...described, entity: { id, error: String(error) } };
      }
      holder = id;
    }
    const fresh = !this.seen.has(holder);
    if (meet) this.seen.add(holder);
    const yours = this.me.entities.some(e => e.id === holder);
    return { ...described, entity: { id: holder, name, new: fresh && !yours, yours } };
  }

  /**
   * An entity's list as the relay has it. A list fetched in the last minute answers for `member` if it is on it; anyone
   * else is checked with the relay, so a device added a moment ago counts at once. Without `member`, always fetched.
   */
  async list(id: string, member?: string): Promise<List> {
    const cached = this.lists.get(id);
    if (cached && Date.now() - cached.at < 60_000 && cached.list.members.some(m => m.id === member)) return cached.list;
    const list: List = JSON.parse(entity_list(id, JSON.stringify(await boxAll(place("list", utf8(id)).address))));
    this.lists.set(id, { at: Date.now(), list });
    return list;
  }

  /** Appends the entry `build` makes from the list's entries, and checks with `done` that it took effect. */
  private async appendEntity(id: string, build: (entries: string) => string, done: (list: List) => boolean) {
    const { address } = place("list", utf8(id));
    for (let attempt = 0; attempt < 3; attempt++) {
      await boxAppend(address, build(JSON.stringify(await boxAll(address))));
      if (done(await this.list(id))) return;
    }
    throw new Error("the entity's list kept changing; try again");
  }

  /** Renames this browser: in each group by a key update that carries the name, and on its entities' lists. */
  renameDevice(name: string) {
    return this.run(async () => {
      this.member!.rename(name);
      this.me.name = name;
      for (const gid of this.groups.keys()) await this.post(gid, () => this.member!.update_key(gid));
      const me = this.member!.entry();
      for (const { id } of this.me.entities) {
        await this.appendEntity(id, entries => this.member!.entity_add(id, entries, me), list => list.members.some(m => m.id === this.member!.fp() && m.name === name));
      }
    });
  }

  removeFromEntity(entity: Membership, member: string) {
    return this.run(async () => {
      await this.appendEntity(entity.id, entries => this.member!.entity_remove(entity.id, entries, member), list => !list.members.some(m => m.id === member));
      if (member === this.member!.fp()) this.me.entities = this.me.entities.filter(e => e.id !== entity.id);
    });
  }

  /** A new group of `kind` named `name`, which this browser's other devices may join. */
  newGroup(kind: string, name: string): Promise<string> {
    return this.run(async () => {
      const gid = this.member!.create_group(this.path());
      this.groups.set(gid, { gid, cursor: 0, settings: { kind }, posted: [], requests: 0, read: 0 });
      this.items.set(gid, []);
      this.followGroup(gid);
      const settings = { kind, ...(name ? { name } : {}) };
      const entity = this.me.entities[0];
      if (entity) await this.openTo(gid, entity, settings);
      else await this.setSettings(gid, settings);
      return gid;
    });
  }

  removeMember(gid: string, fp: string) {
    return this.run(async () => {
      await this.post(gid, () => this.member!.remove(gid, fp));
    });
  }

  /** Leaves a group: asks the others to commit this member's removal, as no member can commit its own, and forgets it. */
  leave(gid: string) {
    return this.run(async () => {
      if (JSON.parse(this.member!.members(gid)).length > 1) await this.post(gid, () => this.member!.leave_proposal(gid));
      this.member!.leave(gid);
      this.me.left.push(gid);
      await this.forget(gid);
    });
  }

  /** An invite into group `gid`, or with `entity`, for another device to join that entity. Resolves once it admitted whoever redeemed it. */
  async invite(target: { gid: string } | { entity: Membership }, update: (invite: Invite) => void) {
    const words = invite_words();
    const pake = new Pake(words);
    const owner = hex(random(32));
    let slot = "";
    for (let attempt = 0; attempt < 10 && !slot; attempt++) {
      const id = String(1 + (new DataView(random(4).buffer).getUint32(0) % 999));
      const body = JSON.stringify({ ttl: INVITE_TTL_MS / 1000, owner, pake: ("entity" in target ? "entity " : "") + b64(pake.message()) });
      const response = await http(`/i/${id}`, { method: "PUT", body });
      await response.text();
      if (response.status === 201) slot = id;
    }
    if (!slot) throw new Error("no free invite slot on the relay; try again");
    update({ code: `${slot}-${words}`, link: `${origin}/i/${slot}#${words}` });
    const join = JSON.parse(await wait(() => inviteData(`/i/${slot}/join?wait=25`), "nobody used the invite within 10 minutes"));
    const key = pake.finish(unb64(join.pake), slot);
    const welcome = (data: Uint8Array) =>
      http(`/i/${slot}/welcome`, { method: "POST", headers: { Authorization: `Bearer ${owner}` }, body: JSON.stringify({ data: seal(key, "welcome", data) }) });
    let envelope: object;
    try {
      envelope = await this.run(() => this.admit(target, key, join));
    } catch (error) {
      // Sealed under our key: a joiner with a wrong code cannot open it either, and stops waiting.
      await welcome(utf8(JSON.stringify({ error: String(error) })));
      throw error;
    }
    await welcome(utf8(JSON.stringify(envelope)));
    if ("gid" in target) await this.run(() => this.postState(target.gid));
  }

  private async admit(target: { gid: string } | { entity: Membership }, key: Uint8Array, join: { device?: string; key_package?: string }): Promise<object> {
    if ("entity" in target) {
      const member = text(open(key, "join", join.device!));
      const id = JSON.parse(member).id;
      await this.appendEntity(target.entity.id, entries => this.member!.entity_add(target.entity.id, entries, member), list => list.members.some(m => m.id === id));
      return { entity: { ...target.entity, relay: origin } };
    }
    return this.add(target.gid, open(key, "join", join.key_package!));
  }

  /** Adds the member with this key package; returns the envelope that lets it join. */
  private async add(gid: string, keyPackage: Uint8Array): Promise<object> {
    let welcome = "";
    const { seq } = await this.post(gid, () => {
      const added = JSON.parse(this.member!.add(gid, keyPackage));
      welcome = added.welcome;
      return unb64(added.commit);
    });
    return { group: gid, seq, welcome, settings: this.groups.get(gid)!.settings };
  }

  /**
   * Redeems an invite link: joins its group, which this browser's other devices may then join too, or for a device
   * link, adds this browser to the entity.
   */
  async redeem(slot: string, words: string): Promise<string> {
    const theirs: string = (await (await http(`/i/${slot}/pake?wait=0`)).json()).data;
    const pake = new Pake(words);
    const key = pake.finish(unb64(theirs.replace(/^entity /, "")), slot);
    const join: Record<string, string> = { pake: b64(pake.message()) };
    if (theirs.startsWith("entity ")) join.device = seal(key, "join", utf8(this.member!.entry()));
    else join.key_package = seal(key, "join", this.member!.key_package(this.path()));
    await http(`/i/${slot}/join`, { method: "POST", body: JSON.stringify({ data: JSON.stringify(join) }) });
    const data = await wait(() => inviteData(`/i/${slot}/welcome?wait=25`), "the inviter did not answer within 10 minutes");
    const envelope = JSON.parse(text(open(key, "welcome", data)));
    return this.run(async () => {
      const gid = await this.welcome(envelope);
      const entity = this.me.entities[0];
      if (gid && entity && this.groups.has(gid)) await this.openTo(gid, entity);
      return gid;
    });
  }

  private async welcome(envelope: { error?: string; entity?: Membership; group: string; seq: number; welcome: string; settings: Settings }): Promise<string> {
    if (envelope.error) throw new Error(`the inviter could not add this browser: ${envelope.error}`);
    if (envelope.entity) {
      const { id, name, secret } = envelope.entity;
      // First, so that this browser speaks as it from now on.
      this.me.entities = [{ id, name, secret }, ...this.me.entities.filter(e => e.id !== id)];
      return "";
    }
    const gid = envelope.group;
    this.member!.join(gid, unb64(envelope.welcome));
    this.groups.set(gid, { gid, cursor: envelope.seq, settings: envelope.settings, posted: [], requests: 0, read: 0 });
    this.items.set(gid, []);
    this.followGroup(gid);
    await this.catchUp(gid);
    await this.members(gid);
    return gid;
  }

  rename(gid: string, name: string) {
    return this.run(() => this.setSettings(gid, { ...this.groups.get(gid)!.settings, name }));
  }

  /** Lets sessions of `entity` join the group without an invite, and tells the entity's devices through its inbox. */
  open(gid: string, entity: Membership) {
    return this.run(() => this.openTo(gid, entity));
  }

  private async openTo(gid: string, entity: Membership, current = this.groups.get(gid)!.settings) {
    if (current.open?.some(o => o.id === entity.id)) return;
    const settings = { ...current, open: [...(current.open ?? []), { id: entity.id, name: entity.name }], requests: current.requests || hex(random(32)) };
    const inbox = place("inbox", unhex(entity.secret));
    const opening: Opening = { group: gid, relay: origin, kind: settings.kind, name: settings.name ?? "", requests: settings.requests };
    await boxAppend(inbox.address, seal(inbox.key, "inbox", utf8(JSON.stringify(opening))));
    await this.setSettings(gid, settings);
  }

  private async setSettings(gid: string, settings: Settings) {
    await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify({ type: "settings", ...settings }))));
    await this.settle(gid, settings, await this.self(gid));
  }

  private async settle(gid: string, settings: Settings, by: Person) {
    const group = this.groups.get(gid)!;
    const before = group.settings;
    if (same(before, settings)) return;
    group.settings = settings;
    this.followRequests(gid);
    this.show(gid, { type: "settings", settings, before, by, at: Date.now() });
  }

  close(gid: string, entity: Membership) {
    return this.run(async () => {
      const current = this.groups.get(gid)!.settings;
      const inbox = place("inbox", unhex(entity.secret));
      const closing: Opening = { group: gid, relay: origin, kind: current.kind, name: current.name ?? "", requests: current.requests!, closed: true };
      await boxAppend(inbox.address, seal(inbox.key, "inbox", utf8(JSON.stringify(closing))));
      await this.setSettings(gid, { ...current, open: (current.open ?? []).filter(o => o.id !== entity.id) });
    });
  }

  /**
   * Groups open to this browser's entities, from their inboxes: the latest entry for each group, unless it closed it.
   * An inbox is followed on a socket, and fetched again only once that announces something or is down.
   */
  async openings(): Promise<{ opening: Opening; entity: Membership }[]> {
    const found: { opening: Opening; entity: Membership }[] = [];
    for (const entity of this.me.entities) {
      const inbox = place("inbox", unhex(entity.secret));
      const key = `inbox ${entity.id}`;
      this.follow(key, `/b/${inbox.address}`, () => {
        this.inboxNotices++;
        this.inboxes.delete(entity.id);
      });
      const live = this.sockets.get(key)!.socket.readyState === WebSocket.OPEN;
      let entries = live ? this.inboxes.get(entity.id) : undefined;
      if (!entries) {
        const notices = this.inboxNotices;
        entries = await boxAll(inbox.address);
        if (live && notices === this.inboxNotices) this.inboxes.set(entity.id, entries);
      }
      for (const entry of entries) {
        let opening: Opening;
        try {
          opening = JSON.parse(text(open(inbox.key, "inbox", entry)));
        } catch {
          continue;
        }
        const others = found.filter(f => f.opening.group !== opening.group || f.entity.id !== entity.id);
        found.splice(0, found.length, ...others, ...(opening.closed ? [] : [{ opening, entity }]));
      }
    }
    // An opening without a kind is for a group made before groups had kinds, which this browser cannot read.
    return found.filter(f => f.opening.kind && !this.groups.has(f.opening.group) && !this.me.left.includes(f.opening.group));
  }

  /** Asks to join an open group; whichever member is online checks the request and adds this browser. */
  async joinOpen(opening: Opening, entity: Membership): Promise<string> {
    const keyPackage = this.member!.key_package(JSON.stringify([entity.id]));
    const reply = random(32);
    const requests = place("requests", unhex(opening.requests));
    await boxAppend(requests.address, seal(requests.key, "request", utf8(JSON.stringify({ key_package: b64(keyPackage), reply: hex(reply) }))));
    const back = place("reply", reply);
    const data = await wait(async () => (await boxRead(back.address, 0, 25))[0]?.data, "no member admitted the request; one must be online");
    return this.run(() => this.welcome(JSON.parse(text(open(back.key, "welcome", data)))));
  }

  /**
   * Admits the join requests in an open group's requests box from sessions that speak as an entity the group is open
   * to. The cursor moves past a request once it is handled, so one that failed is tried again shortly.
   */
  private async admitRequests(gid: string) {
    const group = this.groups.get(gid);
    const { open: opened, requests } = group?.settings ?? {};
    if (!group || !opened?.length || !requests) return;
    const box = place("requests", unhex(requests));
    try {
      for (const entry of await boxRead(box.address, group.requests)) {
        // Expired requests are skipped, so an old one posted again cannot bring back a session that left.
        if (entry.at + INVITE_TTL_MS >= Date.now()) await this.admitRequest(gid, opened, box.key, entry.data);
        group.requests = entry.seq;
      }
    } catch (error) {
      setTimeout(() => this.run(() => this.admitRequests(gid)), 15_000);
      throw error;
    }
  }

  /** Admits one join request. A request that cannot be admitted is refused with a warning; a throw means it may be on a later try. */
  private async admitRequest(gid: string, opened: { id: string }[], key: Uint8Array, data: string) {
    let read: { keyPackage: Uint8Array; applicant: Person; back: { address: string; key: Uint8Array } };
    try {
      const request = JSON.parse(text(open(key, "request", data)));
      const keyPackage = unb64(request.key_package);
      read = { keyPackage, applicant: JSON.parse(this.member!.applicant(keyPackage)), back: place("reply", unhex(request.reply)) };
    } catch (error) {
      this.show(gid, { type: "warning", text: `A request to join could not be read: ${error}`, at: Date.now() });
      return;
    }
    const { keyPackage, applicant, back } = read;
    if (!this.replies.has(back.address)) {
      const present = () => JSON.parse(this.member!.members(gid)).some((m: Person) => m.fp === applicant.fp);
      if (present()) return;
      // Fetched first, so a list the relay failed to give fails this try instead of refusing the request.
      for (const id of applicant.as ?? []) await this.list(id);
      const described = await this.describe(applicant, false);
      if (!described.entity || described.entity.error || !opened.some(o => o.id === described.entity!.id)) {
        this.show(gid, { type: "warning", text: `Turned away ${applicant.name}, who asked to join: not a device of anyone this group lets join without an invite`, at: Date.now() });
        return;
      }
      let envelope: object;
      try {
        envelope = await this.add(gid, keyPackage);
      } catch (error) {
        if (present()) return; // another member was first
        throw error;
      }
      this.replies.set(back.address, seal(back.key, "welcome", utf8(JSON.stringify(envelope))));
    }
    await boxAppend(back.address, this.replies.get(back.address)!);
    this.replies.delete(back.address);
    await this.postState(gid);
  }

  /**
   * What a member just added needs from the others, who keep it: in a doc group, the text, as one edit, and the blobs
   * it links, kept on the relay. It cannot read what was sent before it joined; its welcome brought the settings.
   */
  private async postState(gid: string) {
    if (this.groups.get(gid)!.settings.kind !== "doc") return;
    await this.refreshBlobs(gid);
    await this.postEdit(gid, Y.encodeStateAsUpdate(this.doc(gid)));
  }

  private async updateKey(gid: string) {
    if (this.groups.has(gid)) await this.post(gid, () => this.member!.update_key(gid));
  }

  private async forget(gid: string) {
    this.groups.delete(gid);
    for (const key of [gid, `requests ${gid}`]) {
      const socket = this.sockets.get(key)?.socket;
      this.sockets.delete(key);
      socket?.close();
    }
    this.items.delete(gid);
    this.docs.delete(gid);
    for (const key of this.writes.keys()) if (key.startsWith(`items ${gid} `) || key === `docs ${gid}`) this.writes.delete(key);
    await store.remove("items", `${gid} `);
    await store.remove("docs", gid);
    await store.remove("blobs", `${gid} `);
    for (const key of this.blobs) if (key.startsWith(`${gid} `)) this.blobs.delete(key);
  }

  // A doc group's text: a Yjs document, bound to the editor. Local edits go out at most about once a second.

  doc(gid: string): Y.Doc {
    return this.docs.get(gid) ?? this.track(gid);
  }

  private track(gid: string, state?: Uint8Array): Y.Doc {
    const doc = new Y.Doc();
    if (state) Y.applyUpdate(doc, state, "remote");
    doc.on("update", (update: Uint8Array, source: unknown) => source !== "remote" && this.queueUpdate(gid, update));
    this.docs.set(gid, doc);
    this.dirtyDocs.add(gid);
    return doc;
  }

  private applyEdit(gid: string, update: string) {
    Y.applyUpdate(this.doc(gid), unb64(update), "remote");
    this.dirtyDocs.add(gid);
    this.keepBlobs(gid);
  }

  private queueUpdate(gid: string, update: Uint8Array) {
    const out = this.outbox.get(gid) ?? { updates: [] };
    out.updates.push(update);
    this.outbox.set(gid, out);
    this.dirtyDocs.add(gid);
    this.flush(gid, 1_000);
  }

  /** Sends the text's local edits as one update; if that fails, tries again later. */
  private flush(gid: string, delay: number) {
    const out = this.outbox.get(gid)!;
    out.timer ??= setTimeout(() => {
      out.timer = undefined;
      this.run(async () => {
        if (!out.updates.length || !this.groups.has(gid)) return;
        const sending = out.updates.length;
        await this.postEdit(gid, Y.mergeUpdates(out.updates.slice(0, sending)));
        out.updates.splice(0, sending);
        this.dirtyDocs.add(gid);
      }).catch(() => this.flush(gid, 5_000));
    }, delay);
  }

  private async postEdit(gid: string, update: Uint8Array) {
    await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify({ type: "edit", update: b64(update) }))));
  }

  // Blobs: files that messages and docs link, each sealed under its own key, which the link carries. The relay keeps a
  // blob for 7 days after it was last put or kept, so members keep every blob their doc links, and keep them on the
  // relay for each member they add.

  /** Uploads `bytes` to the group sealed under a fresh key; returns the link to it. */
  async attach(gid: string, bytes: Uint8Array): Promise<string> {
    if (bytes.length > MAX_BLOB_BYTES) throw new Error(`files go up to ${MAX_BLOB_BYTES / 1024 / 1024} MB`);
    const key = random(32);
    const sealed = blob_seal(key, bytes);
    const hash = await sha256(sealed);
    await (await http(`/g/${gid}/blobs/${hash}`, { method: "PUT", body: sealed as BodyInit })).text();
    await this.keep(gid, hash, sealed);
    return `lmk:${hash}#${hex(key)}`;
  }

  /** A linked image as a data: URL, the one kind of image source besides this origin that the page's policy allows. */
  image(gid: string, link: string): Promise<string> {
    if (!this.images.has(link)) this.images.set(link, this.file(gid, link).then(dataUrl));
    return this.images.get(link)!;
  }

  /** The bytes of the file a link points to. */
  async file(gid: string, link: string): Promise<Uint8Array> {
    const [, hash, key] = new RegExp(LINK.source).exec(link)!;
    return blob_open(unhex(key), await this.blob(gid, hash));
  }

  /** Every blob a doc group's text links. */
  private linked(gid: string): Set<string> {
    if (this.groups.get(gid)?.settings.kind !== "doc") return new Set();
    return new Set([...this.doc(gid).getText("text").toString().matchAll(LINK)].map(m => m[1]));
  }

  /** A blob's sealed bytes, as kept here, or else from the relay, and then kept. */
  private async blob(gid: string, hash: string): Promise<Uint8Array> {
    const kept = await store.get<Uint8Array>("blobs", `${gid} ${hash}`);
    if (kept) return kept;
    const sealed = new Uint8Array(await (await http(`/g/${gid}/blobs/${hash}`)).arrayBuffer());
    if ((await sha256(sealed)) !== hash) throw new Error(`the relay altered blob ${hash}`);
    await this.keep(gid, hash, sealed);
    return sealed;
  }

  private async keep(gid: string, hash: string, sealed: Uint8Array) {
    await store.put([["blobs", `${gid} ${hash}`, sealed]]);
    this.blobs.add(`${gid} ${hash}`);
  }

  /** Fetches the blobs the doc links that this browser lacks, once per page load. */
  private keepBlobs(gid: string) {
    for (const hash of this.linked(gid)) {
      const key = `${gid} ${hash}`;
      if (this.blobs.has(key) || this.fetched.has(key)) continue;
      this.fetched.add(key);
      this.blob(gid, hash).catch(error => this.onerror(`A file the document links could not be fetched: ${error}`));
    }
  }

  /**
   * Keeps every blob the doc links on the relay, for the member just added: for another 7 days where the relay has it,
   * put again from this browser's copy where it no longer does.
   */
  private async refreshBlobs(gid: string) {
    for (const hash of this.linked(gid)) {
      try {
        await (await http(`/g/${gid}/blobs/${hash}`, { method: "POST" })).text();
      } catch (error) {
        if (!(error instanceof Refused && error.status === 404)) throw error;
        const sealed = await store.get<Uint8Array>("blobs", `${gid} ${hash}`);
        if (sealed) await (await http(`/g/${gid}/blobs/${hash}`, { method: "PUT", body: sealed as BodyInit })).text();
      }
    }
  }
}

function dataUrl(bytes: Uint8Array): string {
  const head = String.fromCharCode(...bytes.subarray(0, 12));
  const type = head.startsWith("\x89PNG") ? "png" : head.startsWith("\xff\xd8\xff") ? "jpeg" : head.startsWith("GIF8") ? "gif" : head.startsWith("RIFF") && head.endsWith("WEBP") ? "webp" : "";
  if (!type) throw new Error("not an image");
  return `data:image/${type};base64,${b64(bytes)}`;
}
