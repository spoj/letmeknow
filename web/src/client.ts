// The browser member: the session process's protocol, with keys and MLS in WebAssembly (client/src/web.rs) and the
// relay reached from this page's own origin. Unlike an agent session it keeps message text, and nothing is held back.
import init, { Member, Pake, blob_open, blob_seal, entity_list, invite_words, locate, open, random, seal } from "../pkg/letmeknow.js";
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
/** `read` counts the items a person has seen. */
export type Group = { gid: string; cursor: number; settings: Settings; posted: string[]; requests: number; read: number };
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
/** A link to a blob in a file: `lmk:<hash>#<key>`. */
const LINK = /lmk:([0-9a-f]{64})#([0-9a-f]{64})/g;
const sha256 = async (bytes: Uint8Array) => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource)));

async function http(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(origin + path, init);
  if (!response.ok && response.status !== 409) throw new Error(`relay answered ${response.status}: ${(await response.text()).trim()}`);
  return response;
}

// Boxes: append-only logs on the relay holding sealed text (entity lists, inboxes, join requests and replies).
async function boxRead(address: string, after = 0, wait = 0): Promise<{ seq: number; at: number; data: string }[]> {
  const entries: { seq: number; at: number; data: string }[] = await (await http(`/b/${address}?after=${after}&wait=${wait}`)).json();
  return entries.map(e => ({ ...e, data: atob(e.data) }));
}

async function boxAll(address: string): Promise<string[]> {
  const all: string[] = [];
  for (let page = await boxRead(address); page.length; page = await boxRead(address, page[page.length - 1].seq)) all.push(...page.map(e => e.data));
  return all;
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
  /** `left`: groups this browser left, which it no longer lists as open to it. */
  me = { name: "", entities: [] as Membership[], left: [] as string[] };
  groups = new Map<string, Group>();
  items = new Map<string, Item[]>();
  files = new Map<string, FileDoc>();
  onchange = () => {};
  onerror = (_error: unknown) => {};
  private seen = new Set<string>();
  private lists = new Map<string, { at: number; list: List }>();
  private outbox = new Map<string, { updates: Uint8Array[]; timer?: ReturnType<typeof setTimeout> }>();
  private sockets = new Map<string, WebSocket>();
  private writes = new Map<string, [string, string, unknown]>();
  private saved = new Map<string, string>();
  private dirtyFiles = new Set<string>();
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

  /** Follows every group: a socket announces new messages; a poll every 15 seconds covers a lost socket and reopens it. */
  connect() {
    for (const gid of this.groups.keys()) {
      this.follow(gid);
      this.run(async () => {
        await this.catchUp(gid);
        await this.updateKey(gid);
      });
    }
    setInterval(() => {
      for (const gid of this.groups.keys()) {
        this.follow(gid);
        this.run(() => this.catchUp(gid));
      }
    }, 15_000);
    setInterval(() => this.run(() => this.admitRequests()), 5_000);
    setInterval(() => this.groups.forEach((_, gid) => this.run(() => this.updateKey(gid))), 3_600_000);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) return;
      for (const gid of this.groups.keys()) {
        this.follow(gid);
        this.run(() => this.catchUp(gid));
      }
    });
  }

  private follow(gid: string) {
    const existing = this.sockets.get(gid);
    if (existing && existing.readyState <= WebSocket.OPEN) return;
    const socket = new WebSocket(`${origin.replace(/^http/, "ws")}/g/${gid}/ws`);
    const ping = setInterval(() => socket.readyState === WebSocket.OPEN && socket.send("ping"), 30_000);
    socket.onmessage = event => event.data !== "pong" && this.run(() => this.catchUp(gid));
    socket.onclose = () => clearInterval(ping);
    this.sockets.set(gid, socket);
  }

  private async catchUp(gid: string) {
    for (;;) {
      const group = this.groups.get(gid);
      if (!group) return;
      const page: { seq: number; data: string }[] = await (await http(`/g/${gid}/messages?after=${group.cursor}`)).json();
      if (!page.length) return;
      for (const { seq, data } of page) {
        if (!this.groups.has(gid)) return;
        group.cursor = seq;
        const bytes = unb64(data);
        const id = await sha256(bytes);
        if (group.posted.includes(id)) continue;
        try {
          await this.receive(gid, id, bytes);
        } catch (error) {
          this.show(gid, { type: "warning", text: `A message could not be read: ${error}`, at: Date.now() });
        }
      }
    }
  }

  private async receive(gid: string, id: string, bytes: Uint8Array) {
    const result = JSON.parse(this.member!.process(gid, bytes));
    if (result.proposal) {
      await this.post(gid, () => this.member!.commit_proposals(gid));
      return;
    }
    if (result.changes) {
      for (const change of result.changes) this.show(gid, { type: change.type, member: await this.describe(change.member), by: await this.describe(change.by), at: Date.now() });
      if (result.removed) {
        const name = this.groups.get(gid)!.settings.name;
        await this.forget(gid);
        this.onerror(`${result.sender.name} removed you from ${name ? `“${name}”` : "a group"}`);
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

  /** Posts what `build` makes at the group's current epoch; if the relay has moved on, catches up and builds again. */
  private async post(gid: string, build: () => Uint8Array): Promise<{ seq: number; id: string }> {
    for (let attempt = 0; attempt < 3; attempt++) {
      const bytes = build();
      const id = await sha256(bytes);
      const group = this.groups.get(gid)!;
      group.posted = [...group.posted.slice(-50), id];
      let response: Response;
      try {
        response = await http(`/g/${gid}/messages`, { method: "POST", body: bytes as BodyInit });
      } catch (error) {
        this.member!.settle(gid, false);
        throw error;
      }
      if (response.status === 409) {
        this.member!.settle(gid, false);
        await this.catchUp(gid);
        continue;
      }
      for (const change of JSON.parse(this.member!.settle(gid, true))) {
        this.show(gid, { type: change.type, member: await this.describe(change.member), by: await this.describe(change.by), at: Date.now() });
      }
      return { seq: (await response.json()).seq, id };
    }
    throw new Error("the group kept changing; try again");
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

  send(gid: string, content: string, options: { to?: string[]; reply_to?: string; urgent?: boolean; attachment?: string }) {
    return this.run(async () => {
      const payload: Payload = { content, after: this.tips(gid), ...options };
      const { id } = await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify(payload))));
      this.show(gid, { type: "message", id, from: await this.self(gid), content, ...options, after: payload.after, at: Date.now() });
    });
  }

  async members(gid: string): Promise<Person[]> {
    const members: Person[] = [];
    for (const member of JSON.parse(this.member!.members(gid))) members.push(await this.describe(member));
    return members;
  }

  private async self(gid: string): Promise<Person> {
    return (await this.members(gid)).find(m => m.you)!;
  }

  /**
   * Checks the entities a member says it speaks as against their lists: the first must list its device (or the member
   * itself), each later one the one before. Notes entities this browser meets for the first time.
   */
  private async describe(person: Person): Promise<Person> {
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
    this.seen.add(holder);
    return { ...described, entity: { id: holder, name, new: fresh, yours: this.me.entities.some(e => e.id === holder) } };
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

  /** A new group named `name`, which this browser's other devices may join. */
  newGroup(name: string): Promise<string> {
    return this.run(async () => {
      const gid = this.member!.create_group(this.path());
      this.groups.set(gid, { gid, cursor: 0, settings: {}, posted: [], requests: 0, read: 0 });
      this.items.set(gid, []);
      this.follow(gid);
      const entity = this.me.entities[0];
      if (entity) await this.openTo(gid, entity, name ? { name } : {});
      else if (name) await this.setSettings(gid, { name });
      return gid;
    });
  }

  /**
   * After joining `gid` by invite, lets this browser's other devices join it too. Waits a moment for the settings the
   * inviter posts after adding a member, as settings are posted whole and older ones would undo the inviter's.
   */
  async openToOwn(gid: string) {
    const entity = this.me.entities[0];
    for (let i = 0; i < 10 && this.groups.has(gid) && !Object.keys(this.groups.get(gid)!.settings).length; i++) await new Promise(r => setTimeout(r, 500));
    if (!entity || !this.groups.has(gid)) return;
    await this.run(async () => {
      await this.catchUp(gid);
      if (this.groups.has(gid)) await this.openTo(gid, entity);
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
      if ((await http(`/i/${id}`, { method: "PUT", body })).status === 201) slot = id;
    }
    if (!slot) throw new Error("no free invite slot on the relay; try again");
    update({ code: `${slot}-${words}`, link: `${origin}/i/${slot}#${words}` });
    for (;;) {
      const response = await http(`/i/${slot}/join?wait=25`);
      if (response.status === 204) continue;
      const join = JSON.parse((await response.json()).data);
      const key = pake.finish(unb64(join.pake), slot);
      const welcome = (data: Uint8Array) =>
        http(`/i/${slot}/welcome`, { method: "POST", headers: { Authorization: `Bearer ${owner}` }, body: JSON.stringify({ data: seal(key, "welcome", data) }) });
      try {
        const envelope = await this.run(() => this.admit(target, key, join));
        await welcome(utf8(JSON.stringify(envelope)));
      } catch (error) {
        // Sealed under our key, so a joiner with a wrong code cannot open it and stops waiting.
        await welcome(new Uint8Array());
        throw error;
      }
      if ("gid" in target) await this.run(() => this.postState(target.gid));
      return;
    }
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
    for (;;) {
      const response = await http(`/i/${slot}/welcome?wait=25`);
      if (response.status === 204) continue;
      const envelope = JSON.parse(text(open(key, "welcome", (await response.json()).data)));
      return this.run(() => this.welcome(envelope));
    }
  }

  private async welcome(envelope: { entity?: Membership; group: string; seq: number; welcome: string }): Promise<string> {
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
    this.follow(gid);
    await this.catchUp(gid);
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
    const opening: Opening = { group: gid, relay: origin, name: settings.name ?? "", requests: settings.requests };
    await boxAppend(inbox.address, seal(inbox.key, "inbox", utf8(JSON.stringify(opening))));
    await this.setSettings(gid, settings);
  }

  private async setSettings(gid: string, settings: Settings) {
    await this.post(gid, () => this.member!.encrypt(gid, utf8(JSON.stringify({ after: [], settings }))));
    await this.settle(gid, settings, await this.self(gid));
  }

  private async settle(gid: string, settings: Settings, by: Person) {
    const group = this.groups.get(gid)!;
    if (same(group.settings, settings)) return;
    group.settings = settings;
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

  /** Groups open to this browser's entities, from their inboxes: the latest entry for each group, unless it closed it. */
  async openings(): Promise<{ opening: Opening; entity: Membership }[]> {
    const found: { opening: Opening; entity: Membership }[] = [];
    for (const entity of this.me.entities) {
      const inbox = place("inbox", unhex(entity.secret));
      for (const entry of await boxAll(inbox.address)) {
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
    return found.filter(f => !this.groups.has(f.opening.group) && !this.me.left.includes(f.opening.group));
  }

  /** Asks to join an open group; whichever member is online checks the request and adds this browser. */
  async joinOpen(opening: Opening, entity: Membership): Promise<string> {
    const keyPackage = this.member!.key_package(JSON.stringify([entity.id]));
    const reply = random(32);
    const requests = place("requests", unhex(opening.requests));
    await boxAppend(requests.address, seal(requests.key, "request", utf8(JSON.stringify({ key_package: b64(keyPackage), reply: hex(reply) }))));
    const back = place("reply", reply);
    for (const deadline = Date.now() + INVITE_TTL_MS; Date.now() < deadline; ) {
      const entries = await boxRead(back.address, 0, 25);
      if (entries.length) return this.run(() => this.welcome(JSON.parse(text(open(back.key, "welcome", entries[0].data)))));
    }
    throw new Error("no member admitted the request; one must be online");
  }

  /** Admits join requests to open groups from sessions that speak as an entity the group is open to. */
  private async admitRequests() {
    for (const group of [...this.groups.values()]) {
      const { open: opened, requests } = group.settings;
      if (!opened?.length || !requests) continue;
      const box = place("requests", unhex(requests));
      for (const entry of await boxRead(box.address, group.requests)) {
        group.requests = entry.seq;
        // Expired requests are skipped, so an old one posted again cannot bring back a session that left.
        if (entry.at + INVITE_TTL_MS < Date.now()) continue;
        const request = JSON.parse(text(open(box.key, "request", entry.data)));
        const keyPackage = unb64(request.key_package);
        const applicant = await this.describe(JSON.parse(this.member!.applicant(keyPackage)));
        const present = () => JSON.parse(this.member!.members(group.gid)).some((m: Person) => m.fp === applicant.fp);
        if (present()) continue;
        if (!applicant.entity || applicant.entity.error || !opened.some(o => o.id === applicant.entity!.id)) {
          this.show(group.gid, { type: "warning", text: `Turned away ${applicant.name}, who asked to join: not a device of anyone this group lets join without an invite`, at: Date.now() });
          continue;
        }
        let envelope: object;
        try {
          envelope = await this.add(group.gid, keyPackage);
        } catch (error) {
          if (present()) continue; // another member was first
          throw error;
        }
        const back = place("reply", unhex(request.reply));
        await boxAppend(back.address, seal(back.key, "welcome", utf8(JSON.stringify(envelope))));
        await this.postState(group.gid);
      }
    }
  }

  /** What a member who was just added needs from the others, who keep it: the settings, and a snapshot of every file. */
  private async postState(gid: string) {
    await this.refreshBlobs(gid);
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
    this.sockets.get(gid)?.close();
    this.groups.delete(gid);
    this.items.delete(gid);
    for (const [key, file] of this.files) if (file.gid === gid) this.files.delete(key);
    for (const key of this.writes.keys()) if (key.startsWith(`items ${gid} `) || key.startsWith(`files ${gid} `)) this.writes.delete(key);
    await store.remove("items", `${gid} `);
    await store.remove("files", `${gid} `);
    await store.remove("blobs", `${gid} `);
    for (const key of this.blobs) if (key.startsWith(`${gid} `)) this.blobs.delete(key);
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
    this.keepBlobs(gid);
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

  // Blobs: images that files link, each sealed under its own key, which the link carries. The relay keeps them only as
  // long as messages, so members keep every blob their files link, and put them again for each member they add.

  /** Uploads `bytes` to the group sealed under a fresh key; returns the link to it. */
  async attach(gid: string, bytes: Uint8Array): Promise<string> {
    const key = random(32);
    const sealed = blob_seal(key, bytes);
    const hash = await sha256(sealed);
    await http(`/g/${gid}/blobs/${hash}`, { method: "PUT", body: sealed as BodyInit });
    await this.keep(gid, hash, sealed);
    return `lmk:${hash}#${hex(key)}`;
  }

  /** A linked image as a data: URL, the one kind of image source besides this origin that the page's policy allows. */
  image(gid: string, link: string): Promise<string> {
    if (!this.images.has(link)) {
      const [, hash, key] = new RegExp(LINK.source).exec(link)!;
      this.images.set(link, this.blob(gid, hash).then(sealed => dataUrl(blob_open(unhex(key), sealed))));
    }
    return this.images.get(link)!;
  }

  /** Every blob the group's files link. */
  private linked(gid: string): Set<string> {
    return new Set(this.filesOf(gid).flatMap(f => [...f.doc.getText("text").toString().matchAll(LINK)].map(m => m[1])));
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

  /** Fetches the blobs the group's files link that this browser lacks, once per page load. */
  private keepBlobs(gid: string) {
    for (const hash of this.linked(gid)) {
      const key = `${gid} ${hash}`;
      if (this.blobs.has(key) || this.fetched.has(key)) continue;
      this.fetched.add(key);
      this.blob(gid, hash).catch(error => this.onerror(`a file links image ${hash.slice(0, 8)}, which cannot be fetched: ${error}`));
    }
  }

  /** Puts every blob the group's files link, that this browser keeps, on the relay again, for the member just added. */
  private async refreshBlobs(gid: string) {
    for (const hash of this.linked(gid)) {
      const sealed = await store.get<Uint8Array>("blobs", `${gid} ${hash}`);
      if (sealed) await http(`/g/${gid}/blobs/${hash}`, { method: "PUT", body: sealed as BodyInit });
    }
  }
}

function dataUrl(bytes: Uint8Array): string {
  const head = String.fromCharCode(...bytes.subarray(0, 12));
  const type = head.startsWith("\x89PNG") ? "png" : head.startsWith("\xff\xd8\xff") ? "jpeg" : head.startsWith("GIF8") ? "gif" : head.startsWith("RIFF") && head.endsWith("WEBP") ? "webp" : "";
  if (!type) throw new Error("not an image");
  return `data:image/${type};base64,${b64(bytes)}`;
}
