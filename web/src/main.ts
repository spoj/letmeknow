// The page: one browser member and its groups, each a chat or a doc. Background jobs end in render(), which appends new
// items and patches only what changed, so what a person is typing in, selecting or scrolling stays put. Joining from a
// link waits for a click, so link scanners that open it join nothing.
import "./app.css";
import type { EditorView } from "@codemirror/view";
import { type Attachment, Client, type Invite, type Item, MAX_BLOB_BYTES, type Membership, type Opening, type Person, type Settings, inviteKind, whose } from "./client";

type Child = Node | string | false | undefined | null | 0;
type Message = Extract<Item, { type: "message" }>;
const kids = (children: Child[]) => children.filter(c => c != null && c !== false && c !== 0) as (Node | string)[];
function h<K extends keyof HTMLElementTagNameMap>(tag: K, props: Record<string, unknown> = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const element = Object.assign(document.createElement(tag), props);
  element.append(...kids(children));
  return element;
}

/** Rebuilds `element` only when `key` changed. */
const shown = new WeakMap<HTMLElement, string>();
function update(element: HTMLElement, key: string, build: () => Child[]) {
  if (shown.get(element) === key) return;
  shown.set(element, key);
  element.replaceChildren(...kids(build()));
}

const set = (element: HTMLElement, text: string) => element.textContent !== text && (element.textContent = text);
const form = (submit: () => unknown, ...children: Child[]) =>
  h("form", { onsubmit: (event: Event) => (event.preventDefault(), submit()) }, ...children);
const field = (label: string, input: HTMLElement, hint?: string) => h("label", { className: "field" }, h("span", {}, label), input, hint && h("small", {}, hint));
const megabytes = (bytes: number) => (bytes < 1e6 ? `${Math.ceil(bytes / 1000)} KB` : `${(bytes / 1e6).toFixed(1)} MB`);
/** What each kind of group is called, and the mark beside its name in the list. */
const KINDS: Record<string, { name: string; mark: string }> = { chat: { name: "chat", mark: "💬" }, doc: { name: "document", mark: "📄" } };
const kindOf = (gid: string) => KINDS[client.groups.get(gid)!.settings.kind];

const root = document.getElementById("app")!;
const agentsHelp = document.getElementById("agents")!;
const toasts = h("div", { className: "toasts" });
const narrow = matchMedia("(max-width: 699px)");
const wide = matchMedia("(min-width: 1000px)");
const touch = matchMedia("(pointer: coarse)");
const slot = /^\/i\/([1-9][0-9]{0,2})$/.exec(location.pathname)?.[1];
const invite = slot && location.hash.length > 1 ? { slot, words: decodeURIComponent(location.hash.slice(1)) } : undefined;

function toast(error: unknown) {
  const text = error instanceof Error ? error.message : String(error);
  if ([...toasts.children].some(t => t.textContent === text)) return;
  const note = h("div", { className: "toast", role: "status", onclick: () => note.remove() }, text);
  toasts.append(note);
  setTimeout(() => note.remove(), 8_000);
}

/** Disables `button` and shows `label` on it while `job` runs. */
async function busy(button: HTMLButtonElement, label: string, job: () => Promise<unknown>) {
  const was = button.textContent;
  button.disabled = true;
  button.textContent = label;
  try {
    await job();
  } catch (error) {
    toast(error);
  } finally {
    button.disabled = false;
    button.textContent = was;
  }
}

/** A button that asks once more before it runs `job`. */
function confirmed(text: string, again: string, job: () => Promise<unknown>) {
  const button = h("button", { type: "button", className: "danger" }, text);
  button.onclick = () => {
    if (!button.dataset.armed) return ((button.dataset.armed = "1"), (button.textContent = again));
    busy(button, "…", job);
  };
  return button;
}

function modal(title: string, ...content: Child[]): HTMLDialogElement {
  const dialog = h(
    "dialog",
    {},
    h("header", {}, h("h2", {}, title), h("button", { type: "button", className: "icon quiet", title: "Close", ariaLabel: "Close", onclick: () => dialog.close() }, "×")),
    h("div", { className: "dialog-body" }, ...content)
  );
  dialog.onclose = () => dialog.remove();
  document.body.append(dialog);
  dialog.showModal();
  return dialog;
}

let client: Client;
let page: "group" | "devices" | "start" = "start";
let selected: string | undefined;
let openings: { opening: Opening; entity: Membership }[] = [];
/** Open groups this browser asked to join and waits on, by group id: their names. */
const joining = new Map<string, string>();

navigator.locks.request("letmeknow", { ifAvailable: true }, async lock => {
  if (!lock) return root.replaceChildren(h("div", { className: "card notice" }, h("h1", {}, "letmeknow is open in another tab"), h("p", {}, "Use that one: one tab at a time holds this browser's keys.")));
  await boot().catch(toast);
  await new Promise(() => {});
});

async function boot() {
  client = await Client.start();
  client.onerror = toast;
  client.onchange = render;
  const kind = invite ? await inviteKind(invite.slot) : null;
  if (!client.member) return welcome(kind);
  client.connect();
  enter();
  if (invite) offer(kind);
}

// Names: whose a member is comes first, from its verified entity ("Matthew · phone").

function label(p: Person): string {
  const entity = p.entity && !p.entity.error ? p.entity.name : undefined;
  return entity && entity !== p.name ? `${entity} · ${p.name}` : p.name;
}

function unverified(p: Person): string | undefined {
  const error = p.entity?.error;
  if (!error) return;
  const name = /^not on (.*)'s list$/.exec(error)?.[1];
  return name ? `Says it is ${name}'s, but is not on ${name}'s list of devices.` : `Could not check whose this is: ${error}`;
}

function who(p: Person): HTMLElement {
  const warning = unverified(p);
  const first = p.entity?.new && `The first time you see anyone of ${p.entity.name}'s`;
  return h("span", { className: warning ? "who warn" : "who", title: [warning, first, `key ${p.fp}`].filter(Boolean).join("\n") }, warning && "⚠ ", label(p), first && h("small", {}, " new"));
}

/** The group's name, or else who else is in it, leaving out this person's other devices. */
function title(gid: string): string {
  const mine = client.me.entities.map(e => e.id);
  const members: Person[] = client.people.get(gid) ?? JSON.parse(client.member!.members(gid));
  const others = members.filter(m => !m.you && !mine.includes(m.entity?.id ?? m.as?.[0] ?? "")).map(whose);
  return client.groups.get(gid)!.settings.name || [...new Set(others)].join(", ") || `New ${kindOf(gid)?.name ?? "group"}`;
}

/** The chat shown beside a doc on wide screens: the one picked for it there, while this browser is in it. */
function beside(gid?: string): string | undefined {
  const chat = gid && localStorage.getItem(`beside ${gid}`);
  return chat && client.groups.get(chat)?.settings.kind === "chat" ? chat : undefined;
}

function unread(gid: string): number {
  const visible = page === "group" && document.visibilityState === "visible";
  const seen = visible && (gid === selected || (wide.matches && gid === beside(selected)));
  return seen ? 0 : client.items.get(gid)!.length - client.groups.get(gid)!.read;
}

// First visit, and invites.

function welcome(kind: "group" | "entity" | null) {
  const guess = touch.matches ? "phone" : "laptop";
  const name = h("input", { required: true, autocomplete: "name", autofocus: true, value: kind === "entity" ? guess : "" });
  const device = h("input", { required: true, value: guess });
  const deviceField = field("This device", device, "As in “Matthew · phone”, so you can tell your devices apart.");
  const ready = () => name.reportValidity() && device.reportValidity() && name.value.trim();
  let body: Child[];
  if (kind === "group") {
    const join = h("button", { className: "primary" }, "Join");
    body = [
      h("h1", {}, "You're invited"),
      h("p", {}, "Someone sent you this link to share a chat or a document with you, and perhaps with their agents. It is end-to-end encrypted: only those in it can read it."),
      form(
        () => ready() && busy(join, "Joining…", async () => {
          await client.create(device.value.trim(), name.value.trim());
          enter();
          await redeem(invite!.slot, invite!.words);
        }),
        field("Your name", name, "Everyone you share with sees it."),
        deviceField,
        join
      )
    ];
  } else if (kind === "entity") {
    const add = h("button", { className: "primary" }, "Add this browser");
    body = [
      h("h1", {}, "Add this browser to your devices"),
      h("p", {}, "This link comes from one of your other devices. Once added, this browser joins your groups and speaks for you there."),
      form(
        () => ready() && busy(add, "Adding…", async () => {
          await client.create(name.value.trim());
          enter();
          await redeem(invite!.slot, invite!.words);
        }),
        field("Name this device", name, "Shown next to your name, as in “Matthew · phone”."),
        add
      )
    ];
  } else {
    body = [
      invite
        ? [h("h1", {}, "This invite has expired"), h("p", {}, "An invite works once, within 10 minutes. Ask whoever sent it for a new one, or start your own chat or document.")]
        : [h("h1", {}, "letmeknow"), h("p", { className: "lede" }, "End-to-end encrypted chats and documents, for you and your agents on any computer.")],
      field("Your name", name, "Shown to everyone you share with."),
      deviceField,
      ...starters(async kind => {
        if (!ready()) return false;
        await client.create(device.value.trim(), kind === "entity" ? undefined : name.value.trim());
        enter();
        return true;
      }),
      h("details", { className: "agents" }, h("summary", {}, "For agents"), agentsHelp)
    ].flat();
  }
  root.replaceChildren(h("div", { className: "card welcome" }, ...body), toasts);
}

/**
 * The ways in: start a chat or a document, or join with a code. `before` runs first (on a first visit, it creates the
 * member, which a device link adds to an entity) and says whether to go on.
 */
function starters(before: (kind: "group" | "entity") => Promise<boolean> = async () => true): HTMLElement[] {
  const name = h("input", { placeholder: "e.g. Q3 plan" });
  const chat = h("button", { className: "primary" }, "New chat");
  const doc = h("button", { type: "button" }, "New document");
  const start = (kind: string, button: HTMLButtonElement) =>
    busy(button, "Starting…", async () => (await before("group")) && select(await client.newGroup(kind, name.value.trim())));
  doc.onclick = () => start("doc", doc);
  const code = h("input", { placeholder: "417-acid-zebra", autocomplete: "off", autocapitalize: "none", spellcheck: false });
  const joinButton = h("button", {}, "Join");
  const join = form(
    () => busy(joinButton, "Joining…", async () => {
      const parsed = parseCode(code.value);
      if (!parsed) return code.setCustomValidity("A code looks like 417-acid-zebra."), code.reportValidity(), code.setCustomValidity("");
      const kind = await inviteKind(parsed.slot);
      if (!kind) return toast("That code was used or has expired. Ask for a new one.");
      if (!(await before(kind))) return;
      await redeem(parsed.slot, parsed.words);
    }),
    h("h2", {}, "Join with a code"),
    field("Invite code or link", code, "A code works once, within 10 minutes of being made."),
    joinButton
  );
  return [
    h(
      "section",
      { className: "starter" },
      form(
        () => start("chat", chat),
        h("h2", {}, "Start"),
        h("p", { className: "muted" }, "A chat, to talk back and forth with people and agents; or a document, one page that all of them edit at once, like a task list."),
        field("Name", name, "Optional. You can rename it later."),
        h("div", { className: "row" }, chat, doc)
      )
    ),
    h("div", { className: "or" }, "or"),
    h("section", { className: "starter" }, join)
  ];
}

function parseCode(text: string): { slot: string; words: string } | undefined {
  const match = /(?:^|\/i\/)([1-9][0-9]{0,2})(?:#|[\s-]+)([a-z]+)[\s-]+([a-z]+)\s*$/i.exec(text.trim());
  return match ? { slot: match[1], words: `${match[2]}-${match[3]}`.toLowerCase() } : undefined;
}

/** For a browser that already has groups: asks before it uses the invite it was opened with. */
function offer(kind: "group" | "entity" | null) {
  history.replaceState(null, "", "/");
  if (!kind) return toast("That invite was used or has expired. Ask for a new one.");
  const go = h("button", { className: "primary", autofocus: true }, kind === "group" ? "Join" : "Add this browser");
  const dialog = modal(
    kind === "group" ? "You're invited" : "Add this browser to your devices",
    h("p", {}, kind === "group" ? "Join to share a chat or a document with whoever sent you the link, and perhaps their agents." : "This browser becomes one of the devices of whoever made this link: it joins their chats and documents and speaks for them."),
    h("div", { className: "buttons" }, go)
  );
  go.onclick = () => busy(go, "Joining…", async () => {
    await redeem(invite!.slot, invite!.words);
    dialog.close();
  });
}

/** Uses an invite: lands in the group it joined, or, for a device link, joins every group open to this browser's person. */
async function redeem(slot: string, words: string) {
  const gid = await client.redeem(slot, words);
  history.replaceState(null, "", "/");
  if (gid) return select(gid);
  showDevices();
  openings = await client.openings();
  openings.forEach(o => joinOpen(o, false));
}

async function joinOpen(o: { opening: Opening; entity: Membership }, open = true) {
  joining.set(o.opening.group, o.opening.name);
  render();
  try {
    const gid = await client.joinOpen(o.opening, o.entity);
    openings = openings.filter(x => x.opening.group !== gid);
    if (open) select(gid);
  } catch (error) {
    toast(`Could not join ${o.opening.name || `a ${KINDS[o.opening.kind]?.name ?? "group"}`}: ${error instanceof Error ? error.message : error}`);
  } finally {
    joining.delete(o.opening.group);
    render();
  }
}

// The layout: groups on the side, the selected group or a page in the main area. Narrow screens show one at a time.
// On wide screens a doc may have a chat beside it.

const groupList = h("nav", { className: "group-list" });
const navButtons = new Map<string, { button: HTMLButtonElement; name: HTMLElement; badge: HTMLElement }>();
const openList = h("div", { className: "open-list" });
const meName = h("b");
const meButton = h("button", { className: "me quiet", onclick: () => showDevices() }, meName, h("small", {}, "Your devices"));
const sidebar = h(
  "aside",
  { className: "sidebar" },
  h("div", { className: "brand" }, "letmeknow"),
  h(
    "div",
    { className: "side-actions" },
    h("button", { onclick: () => newGroupDialog("chat") }, "New chat"),
    h("button", { onclick: () => newGroupDialog("doc") }, "New doc"),
    h("button", { onclick: joinDialog }, "Join")
  ),
  groupList,
  openList,
  meButton
);
const main = h("main", { className: "main" });
const layout = h("div", { className: "layout" }, sidebar, main);
const devicesPage = h("section", { className: "page" });
const startPage = h("section", { className: "page" });
const views = new Map<string, View>();

function enter() {
  root.replaceChildren(layout, toasts);
  refreshOpenings();
  setInterval(refreshOpenings, 60_000);
  const last = localStorage.getItem("group");
  const shown = last && client.groups.has(last) ? last : [...client.groups.keys()].at(-1);
  if (!shown) return showStart();
  select(shown);
  if (narrow.matches) layout.classList.remove("in-main");
}

// Free while the inboxes' sockets are up; redrawing only on a change keeps an idle page from fetching anything.
async function refreshOpenings() {
  const found = await client.openings().catch(error => (toast(error), openings));
  if (JSON.stringify(found) === JSON.stringify(openings)) return;
  openings = found;
  render();
}

function show(element: HTMLElement) {
  if (page === "group" && selected) views.get(selected)?.hide();
  if (element.parentElement !== main) main.append(element);
  for (const child of main.children) (child as HTMLElement).hidden = child !== element;
  layout.classList.add("in-main");
}

function viewOf(gid: string): View {
  let view = views.get(gid);
  if (!view) {
    const kind = client.groups.get(gid)!.settings.kind;
    view = kind === "chat" ? new ChatView(gid) : kind === "doc" ? new DocView(gid) : new View(gid);
    views.set(gid, view);
  }
  return view;
}

function select(gid: string) {
  const view = viewOf(gid);
  if (page !== "group" || selected !== gid) show(view.el);
  layout.classList.add("in-main");
  page = "group";
  selected = gid;
  localStorage.setItem("group", gid);
  view.show();
  render();
}

function showStart() {
  show(startPage);
  page = "start";
  selected = undefined;
  startPage.replaceChildren(
    h("header", { className: "page-head" }, back(), h("h1", {}, "Start")),
    h("div", { className: "card" }, h("p", {}, "Start a chat or a document and invite people and agents into it, or join one with a code someone gave you."), ...starters())
  );
  render();
}

function back() {
  return h("button", { className: "back quiet icon", title: "All groups", onclick: () => layout.classList.remove("in-main") }, "‹");
}

let rendering = Promise.resolve();
function render() {
  rendering = rendering.then(draw).catch(toast);
}

async function draw() {
  for (const [gid, view] of views) {
    if (client.groups.has(gid)) continue;
    view.el.remove();
    view.destroy();
    views.delete(gid);
    if (gid === selected) selected = undefined;
  }
  if (page === "group" && !selected) {
    const newest = [...client.groups.keys()].at(-1);
    if (newest) select(newest);
    else showStart();
  }
  drawNav();
  const total = [...client.groups.keys()].reduce((n, gid) => n + unread(gid), 0);
  document.title = total ? `(${total}) letmeknow` : "letmeknow";
  if (page !== "group" || !selected) return;
  await views.get(selected)!.update();
  for (const gid of [selected, beside(selected)]) {
    const group = gid && client.groups.get(gid);
    if (group && unread(gid!) === 0 && group.read !== client.items.get(gid!)!.length) client.markRead(gid!);
  }
}
document.addEventListener("visibilitychange", render);
wide.addEventListener("change", render);

function drawNav() {
  for (const [gid, entry] of navButtons) {
    if (client.groups.has(gid)) continue;
    entry.button.remove();
    navButtons.delete(gid);
  }
  for (const gid of client.groups.keys()) {
    let entry = navButtons.get(gid);
    if (!entry) {
      const kind = kindOf(gid);
      const name = h("span"), badge = h("b");
      const mark = h("i", { className: "mark", title: kind ? `A ${kind.name}` : "A kind of group this version cannot show", ariaHidden: "true" }, kind?.mark ?? "?");
      entry = { button: h("button", { onclick: () => select(gid) }, mark, name, badge), name, badge };
      navButtons.set(gid, entry);
      groupList.prepend(entry.button);
    }
    set(entry.name, title(gid));
    const count = unread(gid);
    set(entry.badge, count ? String(count) : "");
    entry.button.classList.toggle("on", page === "group" && gid === selected);
  }
  const waiting = [...joining].filter(([gid]) => !client.groups.has(gid));
  const offered = openings.filter(o => !joining.has(o.opening.group));
  update(openList, JSON.stringify([waiting, offered.map(o => [o.opening.group, o.opening.name])]), () => [
    (waiting.length > 0 || offered.length > 0) && h("h3", {}, "You can join"),
    ...waiting.map(([, name]) => h("div", { className: "opening" }, h("span", {}, name || "Unnamed"), h("small", {}, "joining…"))),
    ...offered.map(o =>
      h("div", { className: "opening" }, h("span", {}, `${KINDS[o.opening.kind]?.mark ?? "?"} ${o.opening.name || `Unnamed ${KINDS[o.opening.kind]?.name ?? "group"}`}`), h("button", { onclick: () => joinOpen(o) }, "Join"))
    )
  ]);
  set(meName, client.me.entities[0]?.name ?? client.me.name);
  meButton.classList.toggle("on", page === "devices");
}

function newGroupDialog(kind: "chat" | "doc") {
  const name = h("input", { placeholder: kind === "chat" ? "e.g. Q3 plan" : "e.g. Tasks", autofocus: true });
  const create = h("button", { className: "primary" }, "Start");
  const dialog = modal(
    `New ${KINDS[kind].name}`,
    kind === "doc" && h("p", { className: "muted" }, "One page that everyone in it, people and agents, edits at once."),
    form(() => busy(create, "Starting…", async () => {
      select(await client.newGroup(kind, name.value.trim()));
      dialog.close();
    }), field("Name", name, "Optional. You can rename it later."), h("div", { className: "buttons" }, create))
  );
}

function joinDialog() {
  const code = h("input", { placeholder: "417-acid-zebra", autofocus: true, autocomplete: "off", autocapitalize: "none", spellcheck: false });
  const join = h("button", { className: "primary" }, "Join");
  const dialog = modal(
    "Join with a code",
    form(() => busy(join, "Joining…", async () => {
      const parsed = parseCode(code.value);
      if (!parsed) return code.setCustomValidity("A code looks like 417-acid-zebra."), code.reportValidity(), code.setCustomValidity("");
      if (!(await inviteKind(parsed.slot))) return toast("That code was used or has expired. Ask for a new one.");
      await redeem(parsed.slot, parsed.words);
      dialog.close();
    }), field("Invite code or link", code, "Codes work once, within 10 minutes of being made."), h("div", { className: "buttons" }, join))
  );
}

// Your devices.

async function showDevices() {
  show(devicesPage);
  page = "devices";
  selected = undefined;
  render();
  const body = h("div", { className: "card" });
  devicesPage.replaceChildren(h("header", { className: "page-head" }, back(), h("h1", {}, "Your devices")), body);
  const draw = async (): Promise<void> => {
    const entity = client.me.entities[0];
    if (!entity) {
      const name = h("input", { value: client.me.name, required: true });
      const start = h("button", { className: "primary" }, "Start");
      return body.replaceChildren(
        h("p", {}, "This browser is not one of anyone's devices. Give your name to make it your first one; you can then add your other devices."),
        form(() => name.reportValidity() && busy(start, "Starting…", () => client.startEntity(name.value.trim()).then(draw)), field("Your name", name), start)
      );
    }
    const { members } = await client.list(entity.id);
    const me = client.member!.fp();
    body.replaceChildren(
      h("p", {}, `The browsers and computers that are you, ${entity.name}. They join the chats and documents that let your other devices join, and others see them as yours.`),
      h(
        "ul",
        { className: "devices" },
        ...members.map(m =>
          h(
            "li",
            {},
            h("span", { title: `key ${m.id}` }, m.name, m.id === me && h("small", {}, " this browser")),
            m.id === me && h("button", { className: "quiet", onclick: () => renameDialog().then(draw) }, "Rename"),
            confirmed("Remove", m.id === me ? "Remove this browser?" : `Remove ${m.name}?`, async () => {
              await client.removeFromEntity(entity, m.id);
              await draw();
            })
          )
        )
      ),
      h("button", { className: "primary", onclick: () => inviteDialog({ entity }).then(draw) }, "Add a device"),
      h("p", { className: "muted" }, "A removed device stays in the chats and documents it is in until someone removes it there.")
    );
  };
  await draw().catch(toast);
}

function renameDialog(): Promise<void> {
  const name = h("input", { required: true, value: client.me.name });
  const rename = h("button", { className: "primary" }, "Rename");
  const dialog = modal("Rename this device", form(
    () => name.reportValidity() && busy(rename, "Renaming…", async () => {
      await client.renameDevice(name.value.trim());
      dialog.close();
    }),
    field("Name this device", name, "Everyone you share with sees the new name from now on."),
    h("div", { className: "buttons" }, rename)
  ));
  return new Promise(resolve => dialog.addEventListener("close", () => resolve()));
}

// Invites: a link, the code it holds, and a QR code of the link. Both work once, within 10 minutes.

async function inviteDialog(target: { gid: string } | { entity: Membership }) {
  const device = "entity" in target;
  const kind = device ? "" : (kindOf(target.gid)?.name ?? "group");
  const { encode } = await import("uqr");
  const body = h("div", { className: "invite" }, h("p", { className: "muted" }, "Making an invite…"));
  const dialog = modal(device ? "Add a device" : "Invite someone", body);
  const draw = (invite: Invite) => {
    const { data, size } = encode(invite.link, { border: 0 });
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
    svg.setAttribute("aria-label", "QR code of the link");
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", data.flatMap((row, y) => row.map((dark, x) => (dark ? `M${x} ${y}h1v1h-1z` : ""))).join(""));
    svg.append(path);
    body.replaceChildren(
      h("p", {}, device ? "Open this link on your other device, or scan the QR code with its camera. Your chats and documents then appear there." : `Send this link to a person or an agent. Whoever opens it first joins the ${kind}.`),
      h("div", { className: "qr" }, svg),
      copyable(invite.link),
      h("p", {}, "Or type the code ", h("code", { className: "code" }, invite.code), device ? " on the other device." : ` on ${location.host}.`),
      h("p", {}, device ? "On a computer, an agent adds it with:" : "An agent joins with:"),
      copyable(`letmeknow join '${invite.link}'`),
      h("p", { className: "expiry" }, "It works once, within 10 minutes. Waiting for it to be used…")
    );
  };
  await client
    .invite(target, draw)
    .then(() => {
      body.replaceChildren(h("p", { className: "done" }, device ? "Added. The device now joins your chats and documents." : `They joined the ${kind}.`));
      setTimeout(() => dialog.close(), 1_500);
    })
    .catch(error =>
      body.replaceChildren(
        h("p", { className: "warn" }, `This invite stopped working: ${error instanceof Error ? error.message : error}`),
        h("div", { className: "buttons" }, h("button", { className: "primary", onclick: () => (dialog.close(), inviteDialog(target)) }, "Make a new one"))
      )
    );
}

function copyable(text: string) {
  const button = h("button", { type: "button" }, "Copy");
  button.onclick = async () => {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = "Copy"), 1_500);
  };
  return h("div", { className: "copy" }, h("code", {}, text), button);
}

// A group: its name and people on top, and below them what it shares, a chat or a doc. A kind of group this version
// does not know shows only that.

class View {
  readonly el: HTMLElement;
  protected members: Person[] = [];
  private heading = h("h2");
  private people = h("button", { className: "people quiet" });
  private raw = "";
  private described = 0;

  constructor(readonly gid: string, ...actions: Child[]) {
    this.el = h(
      "section",
      { className: "group" },
      h(
        "header",
        { className: "group-head" },
        back(),
        h("div", { className: "title" }, this.heading, this.people),
        h(
          "div",
          { className: "head-actions" },
          ...actions,
          h("button", { onclick: () => inviteDialog({ gid }) }, "Invite"),
          h("button", { className: "icon quiet", title: "Settings", ariaLabel: "Settings", onclick: () => this.settingsDialog() }, "⋯")
        )
      )
    );
    this.people.onclick = () => this.settingsDialog();
    if (!kindOf(gid)) this.el.append(h("div", { className: "empty" }, h("p", {}, "This is a kind of group this version of letmeknow cannot show. Reload the page to update it.")));
  }

  async update() {
    set(this.heading, title(this.gid));
    // Checked again on an update a minute later too, as a member's device may have been taken off its person's list.
    const raw = client.member!.members(this.gid);
    if (raw !== this.raw || Date.now() - this.described > 60_000) {
      this.raw = raw;
      this.described = Date.now();
      this.members = await client.members(this.gid);
      this.drawPeople();
    }
  }

  protected drawPeople() {
    const others = this.members.filter(m => !m.you);
    const warned = others.some(m => m.entity?.error);
    const names = new Set(others.map(m => (m.entity?.yours && !m.entity.error ? `your ${m.name}` : label(m))));
    this.people.replaceChildren(...(others.length ? [warned ? "⚠ " : "", [...names].join(", "), " and you"] : ["Only you so far"]));
    this.people.classList.toggle("warn", warned);
  }

  show(_focus = true) {}

  hide() {}

  destroy() {}

  private settingsDialog() {
    const gid = this.gid;
    const settings = client.groups.get(gid)!.settings;
    const kind = kindOf(gid)?.name ?? "group";
    const name = h("input", { value: settings.name ?? "", placeholder: title(gid), ariaLabel: "Name" });
    const save = h("button", {}, "Rename");
    const entity = client.me.entities[0];
    const open = h("input", { type: "checkbox", checked: !!entity && !!settings.open?.some(o => o.id === entity.id) });
    open.onchange = async () => {
      open.disabled = true;
      await (open.checked ? client.open(gid, entity) : client.close(gid, entity)).catch(error => ((open.checked = !open.checked), toast(error)));
      open.disabled = false;
    };
    const dialog = modal(
      kind[0].toUpperCase() + kind.slice(1),
      form(() => busy(save, "Renaming…", () => client.rename(gid, name.value.trim())), field("Name", h("div", { className: "row" }, name, save))),
      h("h3", {}, "People"),
      h(
        "ul",
        { className: "people-list" },
        ...this.members.map(m => {
          const warning = unverified(m);
          const item: HTMLLIElement = h(
            "li",
            {},
            h("div", {}, who(m), m.you && h("small", { className: "muted" }, " you"), warning && h("p", { className: "warn" }, warning)),
            !m.you && confirmed("Remove", `Remove ${label(m)}?`, async () => {
              await client.removeMember(gid, m.fp);
              item.remove();
            })
          );
          return item;
        })
      ),
      entity && h("label", { className: "switch" }, open, h("span", {}, h("b", {}, "Your other devices can join"), h("small", {}, `Devices you add join this ${kind} on their own, without an invite.`))),
      h("div", { className: "buttons leave" }, confirmed(`Leave ${kind}`, "Leave for good?", async () => {
        await client.leave(gid);
        dialog.close();
      }))
    );
  }
}

/** A chat: messages in order, and a composer that sends text and a file, to everyone or to some. */
class ChatView extends View {
  private list = h("ol", { className: "messages" });
  private newer = h("button", { className: "newer", hidden: true }, "New messages ↓");
  private empty = h("div", { className: "empty", hidden: true });
  private input = h("textarea", { rows: 1, placeholder: "Message" });
  private context = h("div", { className: "context" });
  private chips = h("span", { className: "chips" });
  private chipButtons = new Map<string, HTMLButtonElement>();
  private urgent = h("input", { type: "checkbox" });
  private picker = h("input", { type: "file", hidden: true });
  private shown = 0;
  private stuck = true;
  private top = 0;
  private to = new Set<string>();
  private replyTo?: Message;
  private attachment?: File;
  /** The sender and time of the last message, and its day. */
  private last?: { fp: string; at: number };
  private day = "";

  constructor(gid: string) {
    super(gid);
    const send = h("button", { className: "primary send", onclick: () => this.submit() }, "Send");
    const attach = h("button", { className: "attach quiet icon", title: "Send a file, up to 10 MB", ariaLabel: "Attach a file", onclick: () => this.picker.click() }, "+");
    this.el.append(
      h("div", { className: "log" }, this.list, this.empty, this.newer),
      h(
        "div",
        { className: "composer" },
        this.context,
        h("div", { className: "row" }, attach, this.picker, this.input, send),
        h("div", { className: "options" }, h("span", { className: "muted" }, "To"), this.chips, h("label", { className: "urgent-toggle" }, this.urgent, "Urgent"))
      )
    );
    this.newer.onclick = () => this.bottom();
    this.list.onscroll = () => {
      if (!this.list.clientHeight) return;
      this.stuck = this.list.scrollHeight - this.list.scrollTop - this.list.clientHeight < 40;
      if (this.stuck) this.newer.hidden = true;
    };
    new ResizeObserver(() => this.list.clientHeight && this.stuck && this.bottom()).observe(this.list);
    this.input.oninput = () => this.grow();
    this.input.onkeydown = event => {
      if (event.key === "Escape" && this.replyTo) return ((this.replyTo = undefined), this.drawContext());
      if (event.key !== "Enter" || event.shiftKey || event.isComposing || touch.matches) return;
      event.preventDefault();
      this.submit();
    };
    this.input.onpaste = event => {
      const file = event.clipboardData?.files[0];
      if (file) (event.preventDefault(), this.attach(file));
    };
    this.el.ondragover = event => event.preventDefault();
    this.el.ondrop = event => {
      const file = event.dataTransfer?.files[0];
      if (!file) return;
      event.preventDefault();
      this.attach(file);
    };
    this.picker.onchange = () => {
      const file = this.picker.files?.[0];
      this.picker.value = "";
      if (file) this.attach(file);
    };
  }

  hide() {
    this.top = this.list.scrollTop;
  }

  show(focus = true) {
    this.restore();
    if (focus && !touch.matches && !this.el.contains(document.activeElement)) this.input.focus();
  }

  /** Back where the list was when it was hidden: the bottom if it was there. Its scroll position is lost while hidden. */
  private restore() {
    if (this.stuck) this.bottom();
    else this.list.scrollTop = this.top;
  }

  private bottom() {
    this.list.scrollTop = this.list.scrollHeight;
    this.stuck = true;
    this.newer.hidden = true;
  }

  async update() {
    await super.update();
    const items = client.items.get(this.gid);
    if (!items) return;
    const added = items.length > this.shown;
    for (; this.shown < items.length; this.shown++) {
      const item = items[this.shown];
      const day = new Date(item.at).toDateString();
      const line = this.line(item, items);
      if (!line) continue;
      if (day !== this.day) this.list.append(h("li", { className: "day" }, dayName(item.at)));
      this.day = day;
      this.list.append(line);
    }
    if (added && this.stuck) this.bottom();
    else if (added) this.newer.hidden = false;
  }

  private line(item: Item, items: Item[]): HTMLElement | null {
    const at = timeOf(item.at);
    if (item.type !== "message") this.last = undefined;
    switch (item.type) {
      case "message": {
        const mine = item.from.fp === client.member!.fp();
        const plain = !item.reply_to && !item.to && !item.urgent;
        const follows = plain && this.last?.fp === item.from.fp && item.at - this.last.at < 300_000;
        this.last = { fp: item.from.fp, at: item.at };
        const parent = item.reply_to ? (items.find(i => i.type === "message" && i.id === item.reply_to) as Message | undefined) : undefined;
        const to = item.to?.map(fp => this.members.find(m => m.fp === fp)).filter(m => m != null);
        const classes = ["message", mine && "mine", follows && "follows", item.to?.includes(client.member!.fp()) && "direct", item.urgent && "urgent"];
        return h(
          "li",
          { className: classes.filter(Boolean).join(" "), tabIndex: -1 },
          !follows && h("div", { className: "meta" }, who(item.from), to?.length && h("span", { className: "muted" }, "to ", to.map(label).join(", ")), item.urgent && h("span", { className: "tag" }, "Urgent"), at),
          parent && h("blockquote", {}, h("b", {}, label(parent.from)), " ", (parent.content || parent.attachment?.name || "").slice(0, 160)),
          item.content && h("div", { className: "text" }, item.content),
          item.attachment && this.attachmentView(item.attachment),
          h("div", { className: "actions" }, h("button", { className: "quiet", onclick: () => this.reply(item) }, "Reply"))
        );
      }
      case "joined":
      case "left": {
        const self = item.by.fp === item.member.fp;
        const said = item.type === "joined" ? (self ? [who(item.member), " joined"] : [who(item.by), " added ", who(item.member)]) : self ? [who(item.member), " left"] : [who(item.by), " removed ", who(item.member)];
        return h("li", { className: "event" }, ...said, at);
      }
      case "settings": {
        const { before, settings: after } = item;
        const ids = (s: Settings) => (s.open ?? []).map(o => o.id);
        const theirs = (id: string) => id === item.by.entity?.id;
        const said = [
          (after.name ?? "") !== (before.name ?? "") && (after.name ? `named the chat “${after.name}”` : "removed the chat's name"),
          ...(after.open ?? []).filter(o => !ids(before).includes(o.id)).map(o => (theirs(o.id) ? "let their other devices join" : `let ${o.name}'s devices join`)),
          ...(before.open ?? []).filter(o => !ids(after).includes(o.id)).map(o => (theirs(o.id) ? "stopped letting their other devices join" : `stopped letting ${o.name}'s devices join`))
        ].filter(Boolean);
        return said.length ? h("li", { className: "event" }, who(item.by), ` ${said.join(" and ")}`, at) : null;
      }
      case "warning":
        return h("li", { className: "event warn" }, item.text, at);
    }
  }

  /** An image shows in the chat; any other file downloads on a click. */
  private attachmentView(file: Attachment): HTMLElement {
    if (/^image\/(png|jpeg|gif|webp)$/.test(file.type ?? "")) {
      const image = h("img", { className: "image", alt: file.name });
      image.onload = () => this.stuck && this.bottom();
      client.image(this.gid, file.link).then(
        src => (image.src = src),
        error => image.replaceWith(h("p", { className: "muted" }, `${file.name} could not be shown: ${error instanceof Error ? error.message : error}`))
      );
      return image;
    }
    const button = h("button", { className: "download" }, `Download ${file.name} (${megabytes(file.size)})`);
    button.onclick = () => busy(button, "Downloading…", async () => download(await client.file(this.gid, file.link), file.name));
    return button;
  }

  protected drawPeople() {
    super.drawPeople();
    const others = this.members.filter(m => !m.you);
    this.empty.hidden = others.length > 0;
    this.empty.replaceChildren(
      h("p", {}, "Only you so far. Invite a person or an agent: they get a link and a code that work once, within 10 minutes."),
      h("button", { className: "primary", onclick: () => inviteDialog({ gid: this.gid }) }, "Invite someone")
    );
    for (const fp of this.to) if (!others.some(m => m.fp === fp)) this.to.delete(fp);
    const everyone = h("button", { type: "button", onclick: () => (this.to.clear(), this.drawChips()) }, "Everyone");
    this.chipButtons = new Map([["", everyone]]);
    for (const m of others) {
      const chip = h("button", { type: "button", title: `key ${m.fp}`, onclick: () => (this.to.has(m.fp) ? this.to.delete(m.fp) : this.to.add(m.fp), this.drawChips()) }, label(m));
      this.chipButtons.set(m.fp, chip);
    }
    this.chips.replaceChildren(...this.chipButtons.values());
    this.drawChips();
  }

  private drawChips() {
    for (const [fp, chip] of this.chipButtons) {
      const on = fp ? this.to.has(fp) : this.to.size === 0;
      chip.classList.toggle("on", on);
      chip.setAttribute("aria-pressed", String(on));
    }
  }

  private drawContext() {
    const close = (job: () => void) => h("button", { className: "icon quiet", title: "Cancel", onclick: () => (job(), this.drawContext()) }, "×");
    const { replyTo, attachment } = this;
    this.context.replaceChildren(
      ...kids([
        replyTo && h("div", {}, h("span", {}, "Replying to ", h("b", {}, label(replyTo.from)), ": ", (replyTo.content || replyTo.attachment?.name || "").slice(0, 80)), close(() => (this.replyTo = undefined))),
        attachment && h("div", {}, h("span", {}, "Attached ", h("b", {}, attachment.name), ` · ${megabytes(attachment.size)}`), close(() => (this.attachment = undefined)))
      ])
    );
  }

  private reply(item: Message) {
    this.replyTo = item;
    this.drawContext();
    this.input.focus();
  }

  private grow() {
    this.input.style.height = "auto";
    this.input.style.height = `${Math.min(this.input.scrollHeight + 2, 200)}px`;
  }

  private attach(file: File) {
    if (file.size > MAX_BLOB_BYTES) return toast(`${file.name} is too large: files go up to 10 MB.`);
    this.attachment = file;
    this.drawContext();
    this.input.focus();
  }

  private async submit() {
    const content = this.input.value.trim();
    const { attachment } = this;
    if (!content && !attachment) return;
    const options = { to: this.to.size ? [...this.to] : undefined, reply_to: this.replyTo?.id, urgent: this.urgent.checked || undefined };
    this.input.value = "";
    this.grow();
    this.to.clear();
    this.replyTo = undefined;
    this.attachment = undefined;
    this.urgent.checked = false;
    this.drawChips();
    this.drawContext();
    this.stuck = true;
    try {
      await client.send(this.gid, content, options, attachment);
    } catch (error) {
      toast(error);
      if (!this.input.value) this.input.value = content;
      this.attachment ??= attachment;
      this.grow();
      this.drawContext();
    }
  }
}

/** A doc: one text that everyone in it edits at once, and on wide screens, a chat picked to show beside it. */
class DocView extends View {
  private host = h("div", { className: "editor" });
  private side = h("div", { className: "beside" });
  private picker: HTMLSelectElement;
  private editor?: EditorView;

  constructor(gid: string) {
    const picker = h("select", { className: "beside-picker", title: "A chat to show beside the document", ariaLabel: "Chat beside" });
    super(gid, picker);
    this.picker = picker;
    picker.onchange = () => {
      localStorage.setItem(`beside ${gid}`, picker.value);
      this.place();
      render();
    };
    this.el.append(h("div", { className: "body" }, this.host, this.side));
    import("./editor").then(({ editor }) => {
      if (!client.groups.has(gid)) return;
      const blobs = {
        show: (link: string) => client.image(gid, link),
        attach: (bytes: Uint8Array) => client.attach(gid, bytes),
        open: (link: string, name: string) => client.file(gid, link).then(bytes => download(bytes, name), toast),
        fail: toast
      };
      this.editor = editor(this.host, client.doc(gid).getText("text"), blobs);
    });
  }

  async update() {
    await super.update();
    const chats = [...client.groups.keys()].filter(gid => client.groups.get(gid)!.settings.kind === "chat");
    const chosen = beside(this.gid) ?? "";
    update(this.picker, JSON.stringify([chats.map(title), chosen]), () => [
      h("option", { value: "" }, "No chat beside"),
      ...chats.map(gid => h("option", { value: gid }, `💬 ${title(gid)}`))
    ]);
    this.picker.value = chosen;
    this.place();
    const chat = this.side.firstElementChild && beside(this.gid);
    if (chat) await views.get(chat)!.update();
  }

  /** Shows the chat picked for this doc beside it, on wide screens. */
  private place() {
    const chat = wide.matches ? beside(this.gid) : undefined;
    const view = chat && viewOf(chat);
    if (view && view.el.parentElement !== this.side) {
      this.side.replaceChildren(view.el);
      view.el.hidden = false;
      view.show(false);
    }
    if (!view) this.side.replaceChildren();
  }

  show() {
    this.place();
    this.editor?.requestMeasure();
  }

  destroy() {
    this.editor?.destroy();
  }
}

function timeOf(at: number): HTMLElement {
  return h("time", { dateTime: new Date(at).toISOString(), title: new Date(at).toLocaleString() }, new Date(at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
}

function dayName(at: number): string {
  const day = new Date(at).toDateString();
  if (day === new Date().toDateString()) return "Today";
  if (day === new Date(Date.now() - 86_400_000).toDateString()) return "Yesterday";
  return new Date(at).toLocaleDateString([], { weekday: "long", day: "numeric", month: "long" });
}

function download(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
  h("a", { href: url, download: name }).click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
