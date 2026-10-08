// The browser member: the session process's protocol, with keys and MLS in WebAssembly (client/src/web.rs) and the
// relay reached from this page's own origin. Unlike an agent session it keeps message text, and nothing is held back.
import init, { Member, Pake, entity_list, invite_words, locate, open, random, seal } from "../pkg/letmeknow.js";
import wasm from "../pkg/letmeknow_bg.wasm";
import * as Y from "yjs";
import * as store from "./store";

export type Entity = { id: string; name?: string; error?: string; new?: boolean; yours?: boolean };
export type Person = { name: string; fp: string; device?: string; as?: string[]; you?: boolean; entity?: Entity };
export type Settings = { name?: string; open?: { id: string; name: string }[]; requests?: string };
export type Item =
  | { type: "message"; id: string; from: Person; content: string; to?: string[]; reply_to?: string; urgent?: boolean; attachment?: string; after: string[]; at: number }
  | { type: "joined" | "left"; member: Person; by: Person; at: number }
  | { type: "settings"; settings: Settings; by: Person; at: number }
  | { type: "warning"; text: string; at: number };
/** An entity this browser is in. Its secret locates and seals the entity's inbox. */
export type Membership = { id: string; name: string; secret: string };
export type Opening = { group: string; relay: string; name: string; requests: string; closed?: boolean };
export type Invite = { code: string; link: string };
export type List = { id: string; name: string; members: { id: string; key?: string; name: string }[] };
export type FileDoc = { gid: string; id: string; name: string; doc: Y.Doc };
/**
 * `read` counts the items a person has seen. `pending` is the id of a commit this browser posted without hearing the
 * relay's answer: catching up tells whether the relay took it.
 */
export type Group = { gid: string; cursor: number; settings: Settings; posted: string[]; requests: number; read: number; pending?: string };
/** What a socket announces: a page row, without `data` when the entry is large. */
type Notice = { seq: number; at: number; data?: string };
type FileUpdate = { id: string; name?: string; update: string };
type Payload = { content?: string; after: string[]; to?: string[]; reply_to?: string; urgent?: boolean; attachment?: string; settings?: Settings; file?: FileUpdate };

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

const boxAppend = (address: string, data: string) => http(`/b/${address}`, { method: "POST", body: data });
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
  me = { name: "", entities: [] as Membership[] };
  groups = new Map<string, Group>();
  items = new Map<string, Item[]>();
  files = new Map<string, FileDoc>();
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
  private dirtyFiles = new Set<string>();
  private queue: Promise<unknown> = Promise.resolve();

  static async start(): Promise<Client> {
    await init({ module_or_path: wasm });
    const client = new Client();
    const state = async (key: string) => JSON.parse((await store.get<string>("state", key))!);
    const saved = await store.get<string>("state", "member");
    if (saved) {
      client.member = Member.load(saved);
      client.me = await state("me");
      client.seen = new Set(await state("seen"));
      for (const group of (await state("groups")) as Group[]) {
        client.groups.set(group.gid, group);
        client.items.set(group.gid, await store.all<Item>("items", `${group.gid} `));
      }
      for (const file of await store.all<{ gid: string; id: string; name: string; state: Uint8Array; unsent?: Uint8Array }>("files", "")) {
        client.track(file.gid, file.id, file.name, file.state);
        if (file.unsent) client.queueUpdate(file.gid, file.id, file.unsent);
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
    for (const key of this.dirtyFiles) {
      const file = this.files.get(key);
      const unsent = this.outbox.get(key)?.updates ?? [];
      if (file) this.write("files", key, { gid: file.gid, id: file.id, name: file.name, state: Y.encodeStateAsUpdate(file.doc), unsent: unsent.length ? Y.mergeUpdates(unsent) : undefined });
    }
    this.dirtyFiles.clear();
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
    this.me = { name: label, entities: [] };
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
    const socket = new WebSocket(`${origin.replace(/^http/, "ws")}${path}/ws?messages`);
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
      this.show(gid, { type: "warning", text: `message ${id.slice(0, 8)}: ${error}`, at: Date.now() });
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
        const name = this.groups.get(gid)!.settings.name || `group ${gid.slice(0, 6)}`;
        await this.forget(gid);
        this.onerror(`${result.sender.name} removed you from ${name}`);
      }
      return;
    }
    const payload: Payload = result.payload;
    if (payload.file) return this.applyFile(gid, payload.file);
    const from = await this.describe(result.sender);
    if (payload.settings) return this.settle(gid, payload.settings, from);
    const { content = "", to, reply_to, urgent, attachment, after } = payload;
    this.show(gid, { type: "message", id, from, content, to, reply_to, urgent, attachment, after, at: Date.now() });
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
    this.groups.get(gid)!.pending = undefined;
    for (const change of JSON.parse(this.member!.settle(gid, true))) {
      this.show(gid, { type: change.type, member: await this.describe(change.member), by: await this.describe(change.by), at: Date.now() });
    }
  }

  private show(gid: string, item: Item) {
    const items = this.items.get(gid);
    if (!items) return;
    this.write("items", `${gid} ${String(items.length).padStart(10, "0")}`, item);
    items.push(item);
  }

  /** Read-frontier tips: messages no message lists in `after`. A person sees every message, so all count as read. */
  private tips(gid: string): string[] {
    const messages = (this.items.get(gid) ?? []).filter(i => i.type === "message") as Extract<Item, { type: "message" }>[];
    const covered = new Set(messages.flatMap(m => m.after));
    return messages.map(m => m.id).filter(id => !covered.has(id));
  }

  send(gid: string, content: string, options: { to?: string[]; reply_to?: string; urgent?: boolean }) {
    return this.run(async () => {
      const payload: Payload = { content, after: this.tips(gid), ...options };
      const { id } = await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify(payload))));
      this.show(gid, { type: "message", id, from: await this.self(gid), content, ...options, after: payload.after, at: Date.now() });
    });
  }

  async members(gid: string): Promise<Person[]> {
    const members: Person[] = [];
    for (const member of JSON.parse(this.member!.members(gid))) members.push(await this.describe(member, false));
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

  removeFromEntity(entity: Membership, member: string) {
    return this.run(async () => {
      await this.appendEntity(entity.id, entries => this.member!.entity_remove(entity.id, entries, member), list => !list.members.some(m => m.id === member));
      if (member === this.member!.fp()) this.me.entities = this.me.entities.filter(e => e.id !== entity.id);
    });
  }

  newGroup(): Promise<string> {
    return this.run(async () => {
      const gid = this.member!.create_group(this.path());
      this.groups.set(gid, { gid, cursor: 0, settings: {}, posted: [], requests: 0, read: 0 });
      this.items.set(gid, []);
      this.followGroup(gid);
      return gid;
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
      if ((await http(`/i/${id}`, { method: "PUT", body })).status === 201) slot = id;
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
    return { group: gid, seq, welcome };
  }

  /** Redeems an invite link: joins its group, or for a device link, adds this browser to the entity. */
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
    return this.run(() => this.welcome(envelope));
  }

  private async welcome(envelope: { error?: string; entity?: Membership; group: string; seq: number; welcome: string }): Promise<string> {
    if (envelope.error) throw new Error(`the inviter could not add this browser: ${envelope.error}`);
    if (envelope.entity) {
      const { id, name, secret } = envelope.entity;
      // First, so that this browser speaks as it from now on.
      this.me.entities = [{ id, name, secret }, ...this.me.entities.filter(e => e.id !== id)];
      return "";
    }
    const gid = envelope.group;
    this.member!.join(gid, unb64(envelope.welcome));
    this.groups.set(gid, { gid, cursor: envelope.seq, settings: {}, posted: [], requests: 0, read: 0 });
    this.items.set(gid, []);
    this.followGroup(gid);
    await this.catchUp(gid);
    return gid;
  }

  rename(gid: string, name: string) {
    return this.run(() => this.setSettings(gid, { ...this.groups.get(gid)!.settings, name }));
  }

  /** Lets sessions of `entity` join the group without an invite, and tells the entity's devices through its inbox. */
  open(gid: string, entity: Membership) {
    return this.run(async () => {
      const current = this.groups.get(gid)!.settings;
      const settings = { ...current, open: [...(current.open ?? []).filter(o => o.id !== entity.id), { id: entity.id, name: entity.name }], requests: current.requests || hex(random(32)) };
      const inbox = place("inbox", unhex(entity.secret));
      const opening: Opening = { group: gid, relay: origin, name: settings.name ?? "", requests: settings.requests };
      await boxAppend(inbox.address, seal(inbox.key, "inbox", utf8(JSON.stringify(opening))));
      await this.setSettings(gid, settings);
    });
  }

  private async setSettings(gid: string, settings: Settings) {
    await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify({ after: [], settings }))));
    await this.settle(gid, settings, await this.self(gid));
  }

  private async settle(gid: string, settings: Settings, by: Person) {
    const group = this.groups.get(gid)!;
    if (same(group.settings, settings)) return;
    group.settings = settings;
    this.followRequests(gid);
    this.show(gid, { type: "settings", settings, by, at: Date.now() });
  }

  close(gid: string, entity: Membership) {
    return this.run(async () => {
      const current = this.groups.get(gid)!.settings;
      const inbox = place("inbox", unhex(entity.secret));
      const closing: Opening = { group: gid, relay: origin, name: current.name ?? "", requests: current.requests!, closed: true };
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
    return found.filter(f => !this.groups.has(f.opening.group));
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
      this.show(gid, { type: "warning", text: `ignored a join request that does not read: ${error}`, at: Date.now() });
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
        this.show(gid, { type: "warning", text: `refused a join request from ${applicant.name}: it speaks as no entity the group is open to`, at: Date.now() });
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

  /** What a member who was just added needs from the others, who keep it: the settings, and a snapshot of every file. */
  private async postState(gid: string) {
    const settings = this.groups.get(gid)!.settings;
    if (Object.keys(settings).length) await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify({ after: [], settings }))));
    for (const file of this.files.values()) {
      if (file.gid === gid) await this.postFile(gid, file.id, file.name, Y.encodeStateAsUpdate(file.doc));
    }
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
    for (const [key, file] of this.files) if (file.gid === gid) this.files.delete(key);
    for (const key of this.writes.keys()) if (key.startsWith(`items ${gid} `) || key.startsWith(`files ${gid} `)) this.writes.delete(key);
    await store.remove("items", `${gid} `);
    await store.remove("files", `${gid} `);
  }

  // Files: one Yjs document each, bound to the editor. Local edits go out at most about once a second.

  filesOf(gid: string): FileDoc[] {
    return [...this.files.values()].filter(f => f.gid === gid);
  }

  createFile(gid: string, name: string) {
    return this.run(async () => {
      const id = hex(random(8));
      const doc = this.track(gid, id, name);
      await this.postFile(gid, id, name, Y.encodeStateAsUpdate(doc));
      return id;
    });
  }

  private track(gid: string, id: string, name: string, state?: Uint8Array): Y.Doc {
    const doc = new Y.Doc();
    if (state) Y.applyUpdate(doc, state, "remote");
    doc.on("update", (update: Uint8Array, source: unknown) => source !== "remote" && this.queueUpdate(gid, id, update));
    this.files.set(`${gid} ${id}`, { gid, id, name, doc });
    this.dirtyFiles.add(`${gid} ${id}`);
    return doc;
  }

  private applyFile(gid: string, update: FileUpdate) {
    const key = `${gid} ${update.id}`;
    if (!this.files.has(key)) this.track(gid, update.id, "");
    const file = this.files.get(key)!;
    if (update.name) file.name = update.name;
    Y.applyUpdate(file.doc, unb64(update.update), "remote");
    this.dirtyFiles.add(key);
  }

  private queueUpdate(gid: string, id: string, update: Uint8Array) {
    const key = `${gid} ${id}`;
    const out = this.outbox.get(key) ?? { updates: [] };
    out.updates.push(update);
    this.outbox.set(key, out);
    this.dirtyFiles.add(key);
    this.flush(gid, id, 1_000);
  }

  /** Sends a file's local edits as one update; if that fails, tries again later. */
  private flush(gid: string, id: string, delay: number) {
    const key = `${gid} ${id}`;
    const out = this.outbox.get(key)!;
    out.timer ??= setTimeout(() => {
      out.timer = undefined;
      this.run(async () => {
        if (!out.updates.length || !this.groups.has(gid)) return;
        const sending = out.updates.length;
        await this.postFile(gid, id, "", Y.mergeUpdates(out.updates.slice(0, sending)));
        out.updates.splice(0, sending);
        this.dirtyFiles.add(key);
      }).catch(() => this.flush(gid, id, 5_000));
    }, delay);
  }

  private async postFile(gid: string, id: string, name: string, update: Uint8Array) {
    const file: FileUpdate = { id, update: b64(update), ...(name ? { name } : {}) };
    await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify({ after: [], file }))));
  }
}
