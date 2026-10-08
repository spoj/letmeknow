// The page: one browser member, its groups, their chat and files. Joining from a link waits for a click, so link
// scanners that open it join nothing.
import "./app.css";
import type { EditorView } from "@codemirror/view";
import { Client, type Invite, type Item, type Membership, type Opening, type Person, inviteKind } from "./client";
import { editor } from "./editor";

type Child = Node | string | false | undefined | null | 0;
function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const element = Object.assign(document.createElement(tag), props);
  element.append(...(children.filter(c => c != null && c !== false && c !== 0) as (Node | string)[]));
  return element;
}

/** Rebuilds `element` only when `key` changed, so that what a person is selecting or clicking stays put. */
const shown = new WeakMap<HTMLElement, string>();
function update(element: HTMLElement, key: string, build: () => Child[]) {
  if (shown.get(element) === key) return;
  shown.set(element, key);
  element.replaceChildren(...(build().filter(c => c != null && c !== false && c !== 0) as (Node | string)[]));
}

const root = document.getElementById("app")!;
const agents = h("details", { className: "agents" }, h("summary", {}, "For agents"), document.getElementById("agents")!);
const status = h("p", { className: "status", onclick: () => (status.textContent = "") });
const fail = (error: unknown) => {
  status.textContent = error instanceof Error ? error.message : String(error);
};
const slot = /^\/i\/([1-9][0-9]{0,2})$/.exec(location.pathname)?.[1];
const invite = slot && location.hash.length > 1 ? { slot, words: decodeURIComponent(location.hash.slice(1)) } : undefined;

let client: Client;
let selected: string | undefined;
let tab: "chat" | "files" = "chat";
let file: string | undefined;
let view: EditorView | undefined;
let replyTo: string | undefined;
let members: Person[] = [];
const to = new Set<string>();
let openings: { opening: Opening; entity: Membership }[] = [];

const nav = h("nav");
const header = h("header");
const panel = h("div", { className: "panel" });
const tabs = h("div", { className: "tabs" });
const messages = h("ol", { className: "messages" });
const files = h("div", { className: "files" });
const editorHost = h("div", { className: "editor" });
const input = h("textarea", { placeholder: "Message (Enter sends, Shift+Enter for a new line)", rows: 2 });
const urgent = h("input", { type: "checkbox" });
const chips = h("div", { className: "chips" });
const composer = h("div", { className: "composer" }, chips, input, h("label", {}, urgent, " urgent"), h("button", { onclick: submit }, "Send"));
const chat = h("div", { className: "chat" }, messages, composer);
const group = h("section", { className: "group" }, header, tabs, chat);
const home = h("section", { className: "home" });

navigator.locks.request("letmeknow", { ifAvailable: true }, async lock => {
  if (!lock) return root.prepend(h("p", { className: "notice" }, "letmeknow is open in another tab of this browser; use that one."));
  await boot().catch(fail);
  await new Promise(() => {});
});

async function boot() {
  root.prepend(status);
  client = await Client.start();
  client.onerror = fail;
  client.onchange = render;
  const kind = invite ? await inviteKind(invite.slot) : null;
  if (!client.member) return welcome(kind);
  client.connect();
  layout();
  if (kind) {
    const what = kind === "group" ? "You're invited to a group." : "This link adds this browser to an entity: it will speak as it.";
    panel.replaceChildren(h("p", {}, what, " ", h("button", { onclick: () => redeem().catch(fail) }, kind === "group" ? "Join" : "Add this browser")));
  }
}

function welcome(kind: "group" | "entity" | null) {
  const heading = !invite
    ? "End-to-end encrypted group chat for people and their agents."
    : kind === "group"
      ? "You're invited to an end-to-end encrypted group chat."
      : kind === "entity"
        ? "This link adds this browser to someone's devices."
        : "This invite was used or has expired; ask for a new one.";
  const name = h("input", { placeholder: "Your name", autofocus: true });
  const button = h("button", {}, kind === "group" ? "Join" : kind === "entity" ? "Add this browser" : "Start");
  button.onclick = async () => {
    const label = name.value.trim();
    if (!label) return name.focus();
    button.disabled = true;
    try {
      await client.create(label, kind === "entity" ? undefined : label);
      layout();
      if (kind) await redeem();
    } catch (error) {
      button.disabled = false;
      fail(error);
    }
  };
  root.replaceChildren(status, h("div", { className: "welcome" }, h("h1", {}, "letmeknow"), h("p", {}, heading), name, button), agents);
}

async function redeem() {
  panel.replaceChildren(h("p", {}, "Joining…"));
  const gid = await client.redeem(invite!.slot, invite!.words);
  history.replaceState(null, "", "/");
  panel.replaceChildren();
  if (gid) select(gid);
  else devices();
}

function layout() {
  root.replaceChildren(status, h("div", { className: "layout" }, nav, h("div", { className: "main" }, panel, group, home)), agents);
  refreshOpenings();
  setInterval(refreshOpenings, 60_000);
  const first = [...client.groups.keys()][0];
  if (first) select(first);
  else devices();
}

async function refreshOpenings() {
  openings = await client.openings().catch(error => (fail(error), openings));
  render();
}

function select(gid: string | undefined) {
  selected = gid;
  tab = "chat";
  closeFile();
  to.clear();
  replyTo = undefined;
  panel.replaceChildren();
  render();
}

function closeFile() {
  view?.destroy();
  view = undefined;
  file = undefined;
}

let rendering = Promise.resolve();
function render() {
  rendering = rendering.then(draw).catch(fail);
}

async function draw() {
  const groups = [...client.groups.values()].sort((a, b) => last(b.gid) - last(a.gid));
  const unread = (gid: string) => (gid === selected ? 0 : client.items.get(gid)!.length - client.groups.get(gid)!.read);
  const total = groups.reduce((n, g) => n + unread(g.gid), 0);
  document.title = total ? `(${total}) letmeknow` : "letmeknow";
  const key = JSON.stringify([selected, groups.map(g => [g.gid, g.settings.name, unread(g.gid)]), openings.map(o => o.opening.group)]);
  update(nav, key, () => [
    h("button", { className: "new", onclick: () => newGroup().catch(fail) }, "+ New group"),
    ...groups.map(g =>
      h("button", { className: g.gid === selected ? "on" : "", onclick: () => select(g.gid) }, title(g.gid), unread(g.gid) > 0 && h("b", {}, String(unread(g.gid))))
    ),
    openings.length > 0 && h("h3", {}, "Open to you"),
    ...openings.map(o => h("div", { className: "opening" }, o.opening.name || `group ${o.opening.group.slice(0, 6)}`, h("button", { onclick: () => joinOpen(o) }, "Join"))),
    h("button", { className: "devices", onclick: devices }, `${client.me.name} · devices`)
  ]);
  if (selected && !client.groups.has(selected)) selected = undefined;
  group.hidden = !selected;
  home.hidden = !!selected;
  if (!selected) return;
  const gid = selected!;
  const items = client.items.get(gid)!;
  if (client.groups.get(gid)!.read !== items.length) client.markRead(gid);
  members = await client.members(gid);
  const me = members.find(m => m.you)!;
  const settings = client.groups.get(gid)!.settings;
  update(header, JSON.stringify([gid, settings, members.map(label)]), () => [
    h("h2", {}, title(gid)),
    h("p", { className: "members" }, members.map(m => (m.you ? `${label(m)} (you)` : label(m))).join(", ")),
    h("button", { onclick: () => rename(gid) }, "Rename"),
    h("button", { onclick: () => inviteInto(gid) }, "Invite"),
    ...client.me.entities.map(e =>
      settings.open?.some(o => o.id === e.id)
        ? h("button", { onclick: () => client.close(gid, e), title: `Stop letting sessions speaking as ${e.name} join` }, `Close to ${e.name}`)
        : h("button", { onclick: () => client.open(gid, e), title: `Let any session speaking as ${e.name} join without an invite` }, `Open to ${e.name}`)
    )
  ]);
  const fileList = client.filesOf(gid);
  update(tabs, JSON.stringify([gid, tab, fileList.length]), () => [
    h("button", { className: tab === "chat" ? "on" : "", onclick: () => ((tab = "chat"), closeFile(), render()) }, "Chat"),
    h("button", { className: tab === "files" ? "on" : "", onclick: () => ((tab = "files"), render()) }, `Files (${fileList.length})`)
  ]);
  group.replaceChildren(header, tabs, tab === "chat" ? chat : files);
  if (tab === "files") {
    update(files, JSON.stringify([gid, file, fileList.map(f => [f.id, f.name])]), () => [
      h("div", { className: "list" }, ...fileList.map(f => h("button", { className: f.id === file ? "on" : "", onclick: () => openFile(gid, f.id) }, f.name || f.id)), h("button", { onclick: () => newFile(gid) }, "+ New file")),
      editorHost
    ]);
    return;
  }
  const atBottom = messages.scrollHeight - messages.scrollTop - messages.clientHeight < 40;
  update(messages, JSON.stringify([gid, items.length]), () => items.map(item => line(item, items, me)));
  if (atBottom) messages.scrollTop = messages.scrollHeight;
  update(chips, JSON.stringify([gid, members.map(m => m.fp), [...to], replyTo]), () => [
    "To: ",
    ...members.filter(m => !m.you).map(m => h("button", { className: to.has(m.fp) ? "on" : "", onclick: () => (to.has(m.fp) ? to.delete(m.fp) : to.add(m.fp), render()) }, label(m))),
    to.size === 0 && h("small", {}, "everyone"),
    replyTo && h("span", { className: "replying" }, " · replying ", h("button", { onclick: () => ((replyTo = undefined), render()) }, "×"))
  ]);
}

function line(item: Item, items: Item[], me: Person): HTMLElement {
  const time = h("time", {}, new Date(item.at).toLocaleString([], { hour: "2-digit", minute: "2-digit", day: "numeric", month: "short" }));
  switch (item.type) {
    case "message": {
      const parent = item.reply_to && (items.find(i => i.type === "message" && i.id === item.reply_to) as Extract<Item, { type: "message" }> | undefined);
      const names = item.to?.map(fp => label(members.find(m => m.fp === fp) ?? { name: fp.slice(0, 8), fp }));
      const classes = [item.from.fp === me.fp && "mine", item.to?.includes(me.fp) && "direct", item.urgent && "urgent"].filter(Boolean).join(" ");
      return h(
        "li",
        { className: classes },
        h("div", { className: "meta" }, who(item.from), names && ` → ${names.join(", ")}`, item.urgent && h("b", {}, " urgent"), " ", time, h("button", { onclick: () => ((replyTo = item.id), render(), input.focus()) }, "Reply")),
        parent && h("blockquote", {}, `${label(parent.from)}: ${parent.content.slice(0, 200)}`),
        h("div", { className: "text" }, item.content),
        item.attachment && h("button", { onclick: () => download(item.attachment!) }, "Save attachment")
      );
    }
    case "joined":
    case "left":
      return h("li", { className: "event" }, who(item.member), ` ${item.type}`, item.by.fp !== item.member.fp && h("span", {}, " · by ", who(item.by)), " ", time);
    case "settings": {
      const { name, open } = item.settings;
      const said = [name && `named the group “${name}”`, open?.length ? `opened it to ${open.map(o => o.name).join(", ")}` : "closed it to entities"].filter(Boolean).join(" and ");
      return h("li", { className: "event" }, who(item.by), ` ${said} `, time);
    }
    case "warning":
      return h("li", { className: "event warn" }, item.text, " ", time);
  }
}

function label(p: Person): string {
  const entity = p.entity && !p.entity.error ? p.entity.name : undefined;
  return entity && entity !== p.name ? `${entity} · ${p.name}` : p.name;
}

function who(p: Person): HTMLElement {
  const title = p.entity?.error ? `${p.entity.error} (key ${p.fp})` : `key ${p.fp}`;
  return h("span", { className: p.entity?.error ? "who warn" : "who", title }, label(p), p.entity?.new && h("small", {}, " new"));
}

function title(gid: string): string {
  return client.groups.get(gid)!.settings.name || `group ${gid.slice(0, 6)}`;
}

function last(gid: string): number {
  return client.items.get(gid)!.at(-1)?.at ?? 0;
}

async function submit() {
  const content = input.value.trim();
  if (!content || !selected) return;
  input.value = "";
  const options = { to: to.size ? [...to] : undefined, reply_to: replyTo, urgent: urgent.checked || undefined };
  to.clear();
  replyTo = undefined;
  urgent.checked = false;
  await client.send(selected, content, options).catch(() => (input.value = content));
}

input.onkeydown = event => {
  if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
  event.preventDefault();
  submit();
};

async function newGroup() {
  select(await client.newGroup());
  inviteInto(selected!);
}

function rename(gid: string) {
  const name = prompt("Group name", client.groups.get(gid)!.settings.name ?? "");
  if (name !== null) client.rename(gid, name.trim());
}

function inviteInto(gid: string) {
  showInvite("Anyone with this code or link joins the group, once, within 10 minutes. Agents run: letmeknow join CODE", { gid });
}

/** The home view: what this browser speaks as, and the devices that speak as it too. */
function devices() {
  select(undefined);
  const list = h("div");
  const drawDevices = async () => {
    const entities = await Promise.all(client.me.entities.map(async entity => ({ entity, list: await client.list(entity.id) })));
    list.replaceChildren(
      ...entities.map(({ entity, list: { members } }) => {
        const box = h("div", { className: "entity" });
        const link = () => showInvite(`Open the link on the other device, or run letmeknow join CODE there; its sessions then speak as ${entity.name}.`, { entity }, box).then(drawDevices);
        box.append(
          h("h3", {}, entity.name),
          h("p", {}, `These devices speak as ${entity.name}:`),
          h("ul", {}, ...members.map(m => h("li", {}, m.name, m.id === client.member!.fp() && " (this browser) ", h("button", { onclick: () => remove(entity, m) }, "Remove")))),
          h("button", { onclick: link }, "Link a device")
        );
        return box;
      })
    );
    if (!entities.length) {
      const name = h("input", { placeholder: "Your name", value: client.me.name });
      list.append(h("p", {}, "This browser speaks as no entity. ", name, h("button", { onclick: () => client.startEntity(name.value.trim()).then(drawDevices) }, "Start one")));
    }
  };
  const remove = async (entity: Membership, m: { id: string; name: string }) => {
    if (!confirm(`Remove ${m.name} from ${entity.name}? Its sessions will no longer count as ${entity.name}.`)) return;
    await client.removeFromEntity(entity, m.id);
    await drawDevices();
  };
  home.replaceChildren(
    h("h2", {}, "letmeknow"),
    h("p", {}, "End-to-end encrypted group chat for people and their agents. Start a group with + New group, then invite people and agents into it with a code."),
    list
  );
  drawDevices().catch(fail);
}

/** Shows an invite until it is used, then resolves; one that fails stays, with why. */
function showInvite(help: string, target: { gid: string } | { entity: Membership }, into: HTMLElement = panel) {
  const box = h("div", { className: "invite" }, h("p", {}, "Creating an invite…"));
  into.append(box);
  return client
    .invite(target, (invite: Invite) =>
      box.replaceChildren(
        h("p", {}, help),
        h("p", {}, h("code", {}, invite.code), " ", h("button", { onclick: () => navigator.clipboard.writeText(invite.link) }, "Copy link")),
        h("p", {}, h("code", {}, invite.link)),
        h("p", { className: "state" }, "Waiting for someone to use it.")
      )
    )
    .then(() => box.remove())
    .catch(error => box.replaceChildren(h("p", { className: "warn" }, `The invite failed: ${error instanceof Error ? error.message : error}`)));
}

async function joinOpen(o: { opening: Opening; entity: Membership }) {
  panel.replaceChildren(h("p", {}, `Asking to join as ${o.entity.name}; a member who is online lets you in…`));
  try {
    const gid = await client.joinOpen(o.opening, o.entity);
    openings = openings.filter(x => x !== o);
    select(gid);
  } catch (error) {
    panel.replaceChildren();
    fail(error);
  }
}

function openFile(gid: string, id: string) {
  closeFile();
  file = id;
  render();
  view = editor(editorHost, client.files.get(`${gid} ${id}`)!.doc.getText("text"));
}

async function newFile(gid: string) {
  const name = prompt("File name", "notes.md");
  if (name?.trim()) openFile(gid, await client.createFile(gid, name.trim()));
}

function download(data: string) {
  const url = URL.createObjectURL(new Blob([Uint8Array.from(atob(data), c => c.charCodeAt(0))]));
  h("a", { href: url, download: "attachment" }).click();
  URL.revokeObjectURL(url);
}
