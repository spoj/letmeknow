// The page: this browser's session and its groups, each a chat, a doc, or a repository, shown as its pushes and chat. Background work ends in render(), which patches
// only what changed, so what a person is typing, selecting or scrolling stays put. Joining from a link waits for a
// click, so link scanners that open it join nothing.
import "./app.css";
import * as client from "./client";
import type { Attachment, Group, Item, Me, Person } from "./client";

const { lmk } = client;

type Child = Node | string | false | undefined | null | 0 | Child[];
type Message = Extract<Item, { type: "message" }>;
const kids = (children: Child[]) => (children as unknown[]).flat(Infinity).filter(c => c != null && c !== false && c !== 0) as (Node | string)[];
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
const form = (submit: () => unknown, ...children: Child[]) => h("form", { onsubmit: (event: Event) => (event.preventDefault(), submit()) }, ...children);
const field = (label: string, input: HTMLElement, hint?: string) => h("label", { className: "field" }, h("span", {}, label), input, hint && h("small", {}, hint));
const megabytes = (bytes: number) => (bytes < 1e6 ? `${Math.ceil(bytes / 1000)} KB` : `${(bytes / 1e6).toFixed(1)} MB`);
const KINDS = { chat: { name: "chat", mark: "💬" }, doc: { name: "document", mark: "📄" }, git: { name: "repository", mark: "🌿" } };
/** Files up to this size every member fetches; larger ones only on request. */
const FILE_LIMIT = 25 << 20;
const INVITE_PREFIX = "https://letmeknow.dev/i";

const root = document.getElementById("app")!;
const agentsHelp = document.getElementById("agents")!;
const toasts = h("div", { className: "toasts" });
const narrow = matchMedia("(max-width: 699px)");
const touch = matchMedia("(pointer: coarse)");
const invite = location.pathname === "/i" && location.hash.length > 1 ? INVITE_PREFIX + location.hash : undefined;

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

let me: Me;
let groups: Group[] = [];
let page: "group" | "devices" | "start" = "start";
let selected: string | undefined;
let entered: Promise<void> | undefined;
const group = (gid: string) => groups.find(g => g.group === gid && g.joined);
const unread = (gid: string) => Number(localStorage.getItem(`unread ${gid}`) ?? 0);

// The page is its own root of trust: a service worker serves this version until the person takes a new one.
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/sw.js").then(registration => {
    const offer = () => registration.waiting && navigator.serviceWorker.controller && offerUpdate(registration.waiting);
    offer();
    registration.onupdatefound = () => registration.installing?.addEventListener("statechange", offer);
    setInterval(() => registration.update(), 3_600_000);
  }, toast);
  // A tab the old version served reloads once the new one takes over; the first one to install changes nothing.
  let reload = !!navigator.serviceWorker.controller;
  navigator.serviceWorker.addEventListener("controllerchange", () => reload && ((reload = false), location.reload()));
}

function offerUpdate(waiting: ServiceWorker) {
  if (document.querySelector(".banner")) return;
  const take = h("button", { className: "primary", onclick: () => waiting.postMessage("skip") }, "Reload");
  document.body.append(h("div", { className: "banner", role: "status" }, h("span", {}, "A new version of letmeknow is ready."), take));
}

// Every tab shows the app; one of them runs the session for all (see client.ts).
boot().catch(toast);

async function boot() {
  const had = await client.prepare();
  const kind = invite && client.kindOf(invite);
  if (!had) welcome(kind);
  await client.ready;
  await (entered ??= enter());
  if (invite && had) offer(kind);
}

async function start(name: string, device: string) {
  await client.open(name, device);
  navigator.storage?.persist?.();
  await (entered ??= enter());
}

client.listen(event => {
  // The tab that runs the session counts what is unread; a tab showing the group clears it.
  if (event.type === "message" && client.runs() && event.group && !(page === "group" && event.group === selected && document.visibilityState === "visible")) {
    localStorage.setItem(`unread ${event.group}`, String(unread(event.group) + 1));
  }
  if (event.type === "warning") toast(event.text);
  if (event.type === "removed") toast(`You were removed from ${title(event.group!)}${event.by ? ` by ${event.by}` : ""}.`);
  if (event.type === "edited") docs.get(event.group!)?.edited();
  if (entered) render();
});

// Names: a member's identity first, as this browser knows it ("Matthew · phone"), else its own name.

function label(p: Person): string {
  return p.identity && !p.identity.error ? `${p.identity.name} · ${p.device}` : p.name;
}

/** What a member's name rests on: this browser's own identity, a contact, an introduction, or only its own word. */
function standing(p: Person): string | undefined {
  const i = p.identity;
  if (!i) return "speaks as no identity";
  if (i.error) return `unverified: ${i.error}`;
  if (i.how === "self") return "you";
  if (i.how === "verified") return "verified contact";
  if (i.how === "introduced") return `introduced by ${i.by}`;
  return i.introduced ? `their own name; ${i.introduced.by} says they are ${i.introduced.name}` : "their own name, not a contact";
}

function who(p: Person): HTMLElement {
  const i = p.identity;
  const warning = i?.error ?? i?.warning ?? i?.new_device;
  const level = p.you ? "self" : i && !i.error ? i.how : "unknown";
  return h(
    "span",
    { className: warning ? "who warn" : "who", title: [standing(p), warning, `key ${p.fp}`].filter(Boolean).join("\n") },
    warning && "⚠ ",
    label(p),
    level !== "self" && h("small", { className: `level ${level}` }, level === "verified" ? " ✓" : level === "introduced" ? " (introduced)" : level === "unknown" ? " (unverified)" : "")
  );
}

/** The group's name, or else who else is in it. */
function title(gid: string): string {
  const g = group(gid) ?? groups.find(g => g.group === gid);
  if (!g) return "a group";
  if (g.settings.devices_of) return `${g.settings.name}'s devices`;
  const others = (g.members ?? []).filter(m => !m.you).map(label);
  return g.settings.name || [...new Set(others)].join(", ") || `New ${KINDS[g.settings.kind].name}`;
}

// First visit, and invites.

function ios() {
  const apple = /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  return apple && !(navigator as { standalone?: boolean }).standalone && !matchMedia("(display-mode: standalone)").matches;
}

function welcome(kind: string | undefined) {
  if (ios() && !sessionStorage.getItem("in safari")) {
    const anyway = h("button", { onclick: () => (sessionStorage.setItem("in safari", "1"), welcome(kind)) }, "Use it in Safari instead");
    return root.replaceChildren(
      h(
        "div",
        { className: "card welcome" },
        h("h1", {}, "Add letmeknow to your Home Screen first"),
        h(
          "p",
          {},
          "Tap Share, then Add to Home Screen, and open letmeknow from there. The Home Screen app keeps its own storage, apart from Safari's, so it is a device of its own; and Safari forgets a site's storage after a week without a visit."
        ),
        invite && h("p", { className: "muted" }, "To use this invite there, copy the link now and paste it into the app's Join."),
        invite && copyable(invite),
        anyway
      ),
      toasts
    );
  }
  const guess = touch.matches ? "phone" : "laptop";
  const name = h("input", { required: true, autocomplete: "name", autofocus: true });
  const device = h("input", { required: true, value: guess });
  const deviceField = field("This device", device, "As in “Matthew · phone”, so you can tell your devices apart.");
  const ready = () => name.reportValidity() && device.reportValidity();
  let body: Child[];
  if (kind === "group") {
    const join = h("button", { className: "primary" }, "Join");
    body = [
      h("h1", {}, "You're invited"),
      h("p", {}, "Someone sent you this link to share a chat or a document with you, and perhaps with their agents. It is end-to-end encrypted: only those in it can read it."),
      form(
        () =>
          ready() &&
          busy(join, "Joining…", async () => {
            await start(name.value.trim(), device.value.trim());
            await redeem(invite!);
          }),
        field("Your name", name, "Everyone you share with sees it."),
        deviceField,
        join
      )
    ];
  } else if (kind === "device") {
    const add = h("button", { className: "primary" }, "Add this browser");
    device.autofocus = true;
    body = [
      h("h1", {}, "Add this browser to your devices"),
      h("p", {}, "This link comes from one of your other devices. Once added, this browser joins your groups and speaks for you there."),
      form(
        () =>
          device.reportValidity() &&
          busy(add, "Adding…", async () => {
            await start(device.value.trim(), device.value.trim());
            await redeem(invite!);
          }),
        field("Name this device", device, "Shown next to your name, as in “Matthew · phone”."),
        add
      )
    ];
  } else {
    body = [
      invite
        ? [h("h1", {}, "This is not a letmeknow invite"), h("p", {}, "Ask whoever sent it for a new link, or start your own chat or document.")]
        : [h("h1", {}, "letmeknow"), h("p", { className: "lede" }, "End-to-end encrypted chats and documents, for you and your agents on any computer.")],
      field("Your name", name, "Shown to everyone you share with."),
      deviceField,
      ...starters(async () => {
        if (!ready()) return false;
        await start(name.value.trim(), device.value.trim());
        return true;
      }),
      h("details", { className: "agents" }, h("summary", {}, "For agents"), agentsHelp)
    ].flat();
  }
  root.replaceChildren(h("div", { className: "card welcome" }, ...body), toasts);
}

/** The ways in: start a chat or a document, or join with a link. `before` runs first and says whether to go on. */
function starters(before: () => Promise<boolean> = async () => true): HTMLElement[] {
  const name = h("input", { placeholder: "e.g. Q3 plan" });
  const chat = h("button", { className: "primary" }, "New chat");
  const doc = h("button", { type: "button" }, "New document");
  const create = (kind: string, button: HTMLButtonElement) => busy(button, "Starting…", async () => (await before()) && select(await lmk.create(kind, name.value.trim())));
  doc.onclick = () => create("doc", doc);
  const link = h("input", { placeholder: "https://letmeknow.dev/i#…", autocomplete: "off", autocapitalize: "none", spellcheck: false });
  const joinButton = h("button", {}, "Join");
  const join = form(
    () =>
      busy(joinButton, "Joining…", async () => {
        if (!client.kindOf(link.value.trim())) return toast("That is not a letmeknow invite link.");
        if (await before()) await redeem(link.value.trim());
      }),
    h("h2", {}, "Join with a link"),
    field("Invite link", link, "A link works once, within 10 minutes of being made."),
    joinButton
  );
  return [
    h(
      "section",
      { className: "starter" },
      form(
        () => create("chat", chat),
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

/** For a browser that has a session already: asks before it uses the invite it was opened with. */
function offer(kind: string | undefined) {
  history.replaceState(null, "", "/");
  if (!kind) return toast("That is not a letmeknow invite link.");
  const go = h("button", { className: "primary", autofocus: true }, kind === "group" ? "Join" : "Add this browser");
  const dialog = modal(
    kind === "group" ? "You're invited" : "Add this browser to your devices",
    h(
      "p",
      {},
      kind === "group"
        ? "Join to share a chat or a document with whoever sent you the link, and perhaps their agents."
        : "This browser becomes one of the devices of whoever made this link: it joins their chats and documents and speaks for them."
    ),
    h("div", { className: "buttons" }, go)
  );
  go.onclick = () =>
    busy(go, "Joining…", async () => {
      await redeem(invite!);
      dialog.close();
    });
}

/** Uses an invite link: lands in the group it joined, or, for a device link, on this browser's devices. */
async function redeem(link: string) {
  const joined = JSON.parse(await lmk.join(link));
  history.replaceState(null, "", "/");
  if (joined.group) await select(joined.group);
  else showDevices();
}

// The layout: groups on the side, the selected group or a page in the main area. Narrow screens show one at a time.

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
const docs = new Map<string, DocView>();

async function enter() {
  me = JSON.parse(await lmk.me());
  groups = JSON.parse(await lmk.groups());
  root.replaceChildren(layout, toasts);
  const last = localStorage.getItem("group");
  const shown = last && group(last) ? last : groups.filter(g => g.joined).at(-1)?.group;
  if (!shown) return showStart();
  await select(shown);
  if (narrow.matches) layout.classList.remove("in-main");
}

function show(element: HTMLElement) {
  if (element.parentElement !== main) main.append(element);
  for (const child of main.children) (child as HTMLElement).hidden = child !== element;
  layout.classList.add("in-main");
}

async function select(gid: string) {
  groups = JSON.parse(await lmk.groups());
  let view = views.get(gid);
  if (!view) {
    view = group(gid)!.settings.kind === "doc" ? new DocView(gid) : new ChatView(gid);
    views.set(gid, view);
  }
  show(view.el);
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
    h("div", { className: "card" }, h("p", {}, "Start a chat or a document and invite people and agents into it, or join one with a link someone gave you."), ...starters())
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
  me = JSON.parse(await lmk.me());
  groups = JSON.parse(await lmk.groups());
  for (const [gid, view] of views) {
    if (group(gid)) continue;
    view.el.remove();
    view.destroy();
    views.delete(gid);
    docs.delete(gid);
    if (gid === selected) selected = undefined;
  }
  if (page === "group" && !selected) {
    const newest = groups.filter(g => g.joined).at(-1);
    if (newest) await select(newest.group);
    else showStart();
  }
  drawNav();
  const total = groups.reduce((n, g) => n + unread(g.group), 0);
  document.title = total ? `(${total}) letmeknow` : "letmeknow";
  if (page === "group" && selected && document.visibilityState === "visible") localStorage.removeItem(`unread ${selected}`);
  if (page === "group" && selected) await views.get(selected)!.update();
  if (page === "devices") await drawDevices();
}
document.addEventListener("visibilitychange", render);

function drawNav() {
  for (const [gid, entry] of navButtons) {
    if (group(gid)) continue;
    entry.button.remove();
    navButtons.delete(gid);
  }
  for (const g of groups.filter(g => g.joined)) {
    let entry = navButtons.get(g.group);
    if (!entry) {
      const name = h("span"),
        badge = h("b");
      const mark = h("i", { className: "mark", ariaHidden: "true" }, g.settings.devices_of ? "🔒" : KINDS[g.settings.kind].mark);
      entry = { button: h("button", { onclick: () => select(g.group) }, mark, name, badge), name, badge };
      navButtons.set(g.group, entry);
      groupList.prepend(entry.button);
    }
    set(entry.name, title(g.group));
    set(entry.badge, unread(g.group) ? String(unread(g.group)) : "");
    entry.button.classList.toggle("on", page === "group" && g.group === selected);
  }
  const open = groups.filter(g => !g.joined);
  update(openList, JSON.stringify(open.map(o => [o.group, o.settings.name, o.failed])), () => [
    open.length > 0 && h("h3", {}, "Open to you"),
    ...open.map(o => {
      const name = `${KINDS[o.settings.kind].mark} ${o.settings.name || `Unnamed ${KINDS[o.settings.kind].name}`}`;
      if (!o.failed) return h("div", { className: "opening" }, h("span", {}, name), h("small", {}, "joining…"));
      const join = h("button", {}, "Join");
      join.onclick = () => busy(join, "…", async () => select(JSON.parse(await lmk.join_open(o.group)).group));
      return h("div", { className: "opening" }, h("span", {}, name), join);
    })
  ]);
  set(meName, me.identities[0]?.name ?? me.name);
  meButton.classList.toggle("on", page === "devices");
}

function newGroupDialog(kind: "chat" | "doc") {
  const name = h("input", { placeholder: kind === "chat" ? "e.g. Q3 plan" : "e.g. Tasks", autofocus: true });
  const create = h("button", { className: "primary" }, "Start");
  const dialog = modal(
    `New ${KINDS[kind].name}`,
    kind === "doc" && h("p", { className: "muted" }, "One page that everyone in it, people and agents, edits at once."),
    form(
      () =>
        busy(create, "Starting…", async () => {
          await select(await lmk.create(kind, name.value.trim()));
          dialog.close();
        }),
      field("Name", name, "Optional. You can rename it later."),
      h("div", { className: "buttons" }, create)
    )
  );
}

function joinDialog() {
  const link = h("input", { placeholder: "https://letmeknow.dev/i#…", autofocus: true, autocomplete: "off", autocapitalize: "none", spellcheck: false });
  const join = h("button", { className: "primary" }, "Join");
  const dialog = modal(
    "Join with a link",
    form(
      () =>
        busy(join, "Joining…", async () => {
          if (!client.kindOf(link.value.trim())) return toast("That is not a letmeknow invite link.");
          await redeem(link.value.trim());
          dialog.close();
        }),
      field("Invite link", link, "An invite into a group, or a device link from one of your devices. It works once, within 10 minutes."),
      h("div", { className: "buttons" }, join)
    )
  );
}

// Your devices: the identities this browser is a device of, their device lists, and their contacts.

function showDevices() {
  show(devicesPage);
  page = "devices";
  selected = undefined;
  devicesPage.replaceChildren(h("header", { className: "page-head" }, back(), h("h1", {}, "Your devices")), devicesBody);
  shown.delete(devicesBody);
  render();
}

const devicesBody = h("div", { className: "card" });
async function drawDevices() {
  const identity = me.identities[0];
  const contacts: client.Contacts = JSON.parse(await lmk.contacts());
  if (!identity) {
    return update(devicesBody, "none", () => {
      const name = h("input", { value: me.name, required: true });
      const create = h("button", { className: "primary" }, "Start");
      return [
        h("p", {}, "This browser is no one's device yet. Give your name to make it your first device; you can then add your other devices, and others can tell it is you."),
        form(() => name.reportValidity() && busy(create, "Starting…", async () => (await lmk.identity_create(name.value.trim()), render())), field("Your name", name), create),
        h("p", { className: "muted" }, "To add this browser to an identity you have on another device, make a device link there and open it here, or paste it into Join.")
      ];
    });
  }
  const list: { devices: { key: string; name: string; you: boolean }[] } = await lmk.devices(identity.id).then(JSON.parse, () => ({ devices: [] }));
  update(devicesBody, JSON.stringify([identity, list, contacts]), () => [
    h("p", {}, `The browsers and computers that are you, ${identity.name}. They join the chats and documents open to you, and others see them as yours.`),
    h(
      "ul",
      { className: "devices" },
      ...list.devices.map(d =>
        h(
          "li",
          {},
          h("span", { title: `key ${d.key}` }, d.name, d.you && h("small", {}, " this browser")),
          confirmed("Remove", d.you ? "Remove this browser?" : `Remove ${d.name}?`, async () => {
            await lmk.remove_device(identity.id, d.key);
            shown.delete(devicesBody);
            render();
          })
        )
      )
    ),
    h("button", { className: "primary", onclick: () => inviteDialog({ identity: identity.id }) }, "Add a device"),
    h("h2", {}, "Contacts"),
    contacts.contacts.length === 0 && h("p", { className: "muted" }, "Whoever joins through an invite you made for them becomes your contact."),
    contacts.contacts.length > 0 &&
      h("ul", { className: "devices" }, ...contacts.contacts.map(c => h("li", {}, h("span", {}, c.name), h("small", {}, c.how === "verified" ? "verified" : `introduced by ${c.by}`)))),
    contacts.introductions.length > 0 && h("h3", {}, "Introduced to you"),
    contacts.introductions.length > 0 &&
      h(
        "ul",
        { className: "devices" },
        ...contacts.introductions.map(i => {
          const accept = h("button", {}, "Accept");
          accept.onclick = () => busy(accept, "…", async () => (await lmk.accept(i.id, undefined), render()));
          return h("li", {}, h("span", {}, i.name, h("small", {}, ` by ${i.by}`)), accept);
        })
      )
  ]);
}

// Invites: a link and its QR code, single use, within 10 minutes. A device link adds a device to an identity.

async function inviteDialog(target: { gid: string } | { identity: string }) {
  const device = "identity" in target;
  const g = device ? undefined : group(target.gid);
  const kind = g ? KINDS[g.settings.kind].name : "";
  const body = h("div", { className: "invite" });
  const dialog = modal(device ? "Add a device" : "Invite someone", body);
  const make = async (label?: string) => {
    // The link opens this server's app, which is letmeknow.dev's unless the person runs their own.
    const made = new URL(device ? await lmk.invite_device(target.identity) : await lmk.invite(target.gid, label));
    const link = location.origin + made.pathname + made.hash;
    const { encode } = await import("uqr");
    const { data, size } = encode(link, { border: 0 });
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
    svg.setAttribute("aria-label", "QR code of the link");
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", data.flatMap((row, y) => row.map((dark, x) => (dark ? `M${x} ${y}h1v1h-1z` : ""))).join(""));
    svg.append(path);
    body.replaceChildren(
      h(
        "p",
        {},
        device
          ? "Open this link on your other device, or scan the QR code with its camera. Your chats and documents then reach it."
          : `Send this link to a person or an agent. Whoever opens it first joins the ${kind}${label ? ` as your contact “${label}”` : ""}.`
      ),
      h("div", { className: "qr" }, svg),
      copyable(link),
      h("p", {}, device ? "On a computer, an agent's session adds it with:" : "An agent joins with:"),
      copyable(`letmeknow join '${link}'`),
      h("p", { className: "expiry" }, "It works once, within 10 minutes, while this browser is open.")
    );
    const gid = device ? groups.find(g => g.settings.devices_of === target.identity)?.group : target.gid;
    const joined = (event: client.Event) => {
      if (event.type !== "joined" || event.group !== gid || !dialog.open) return;
      body.replaceChildren(h("p", { className: "done" }, device ? "Added. The device now joins your chats and documents." : `They joined the ${kind}.`));
      setTimeout(() => dialog.close(), 1_500);
    };
    client.listen(joined);
    dialog.addEventListener("close", () => client.unlisten(joined));
  };
  // Contacts belong to an identity, so only a browser that is a device of one labels its invites.
  if (device || !me.identities.length) return make().catch(toast);
  const label = h("input", { placeholder: "e.g. Bob (Acme)" });
  const go = h("button", { className: "primary" }, "Make a link");
  body.append(
    form(
      () => busy(go, "…", () => make(label.value.trim() || undefined)),
      field("For", label, "Optional: who it is for. Whoever uses it becomes your contact by this name."),
      h("div", { className: "buttons" }, go)
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

// A group: its name and people on top, and below them what it shares, a chat or a doc.

class View {
  readonly el: HTMLElement;
  protected members: Person[] = [];
  private heading = h("h2");
  private people = h("button", { className: "people quiet" });

  constructor(readonly gid: string) {
    const devicesOf = group(gid)?.settings.devices_of;
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
          devicesOf
            ? h("button", { onclick: () => inviteDialog({ identity: devicesOf }) }, "Add a device")
            : h("button", { onclick: () => inviteDialog({ gid }) }, "Invite"),
          h("button", { className: "icon quiet", title: "Settings", ariaLabel: "Settings", onclick: () => this.settingsDialog() }, "⋯")
        )
      )
    );
    this.people.onclick = () => this.settingsDialog();
  }

  async update() {
    set(this.heading, title(this.gid));
    const members = group(this.gid)?.members ?? [];
    if (JSON.stringify(members) === JSON.stringify(this.members)) return;
    this.members = members;
    this.drawPeople();
  }

  protected drawPeople() {
    const others = this.members.filter(m => !m.you);
    const warned = others.some(m => m.identity?.error || m.identity?.warning);
    this.people.replaceChildren(...(others.length ? [warned ? "⚠ " : "", [...new Set(others.map(label))].join(", "), " and you"] : ["Only you so far"]));
    this.people.classList.toggle("warn", warned);
  }

  show() {}

  destroy() {}

  private async settingsDialog() {
    const gid = this.gid;
    const settings = group(gid)!.settings;
    const kind = KINDS[settings.kind].name;
    const name = h("input", { value: settings.name, placeholder: title(gid), ariaLabel: "Name" });
    const save = h("button", {}, "Rename");
    const contacts: client.Contacts = JSON.parse(await lmk.contacts());
    const openable = [...me.identities.map(i => ({ ...i, own: true })), ...contacts.contacts.map(c => ({ id: c.id, name: c.name, own: false }))];
    const toggle = (identity: { id: string; name: string; own: boolean }) => {
      const box = h("input", { type: "checkbox", checked: !!settings.open?.some(o => o.id === identity.id) });
      box.onchange = async () => {
        box.disabled = true;
        await lmk.set_open(gid, identity.id, identity.name, box.checked).catch(error => ((box.checked = !box.checked), toast(error)));
        box.disabled = false;
      };
      const text = identity.own ? "Your other devices can join" : `${identity.name}'s devices can join`;
      return h("label", { className: "switch" }, box, h("span", {}, h("b", {}, text), h("small", {}, `Their devices join this ${kind} on their own, without an invite.`)));
    };
    const dialog = modal(
      settings.devices_of ? title(gid) : kind[0].toUpperCase() + kind.slice(1),
      !settings.devices_of && form(() => busy(save, "Renaming…", () => lmk.rename(gid, name.value.trim())), field("Name", h("div", { className: "row" }, name, save))),
      h("h3", {}, "People"),
      h(
        "ul",
        { className: "people-list" },
        ...this.members.map(m => {
          const introduced = m.identity?.how === "unknown" && m.identity.introduced;
          const accept = introduced && h("button", {}, `Accept as ${introduced.name}`);
          if (accept) accept.onclick = () => busy(accept, "…", async () => (await lmk.accept(m.identity!.id, undefined), render(), dialog.close()));
          return h(
            "li",
            {},
            h(
              "div",
              {},
              who(m),
              m.you && h("small", { className: "muted" }, " you"),
              h("p", { className: m.identity?.error ? "warn" : "muted" }, standing(m)),
              m.added_by && h("p", { className: "muted" }, `added by ${m.added_by.name ?? "a former member"} (${m.added_by.how})`)
            ),
            accept,
            !m.you && !settings.devices_of && confirmed("Remove", `Remove ${label(m)}?`, () => lmk.remove(gid, m.key))
          );
        })
      ),
      !settings.devices_of && openable.map(toggle),
      !settings.devices_of &&
        h(
          "div",
          { className: "buttons leave" },
          confirmed(`Leave ${kind}`, "Leave for good?", async () => {
            if (!(await lmk.leave(gid))) toast("Asked the others to remove you; you leave once one of them is online.");
            render();
            dialog.close();
          })
        )
    );
  }
}

/** A chat: its timeline, and a composer that sends text and a file, to everyone or to some. */
class ChatView extends View {
  private list = h("ol", { className: "messages" });
  private newer = h("button", { className: "newer", hidden: true }, "New messages ↓");
  private empty = h("div", { className: "empty", hidden: true });
  private input = h("textarea", { rows: 1, placeholder: "Message", ariaLabel: "Message" });
  private context = h("div", { className: "context" });
  private chips = h("span", { className: "chips" });
  private chipButtons = new Map<string, HTMLButtonElement>();
  private urgent = h("input", { type: "checkbox" });
  private picker = h("input", { type: "file", hidden: true });
  /** Each item's element, by its key, with the JSON it was drawn from. */
  private lines = new Map<string, { json: string; el: HTMLElement }>();
  private stuck = true;
  private to = new Set<string>();
  private replyTo?: Message;
  private attachment?: File;

  constructor(gid: string) {
    super(gid);
    const send = h("button", { className: "primary send", onclick: () => this.submit() }, "Send");
    const attach = h("button", { className: "attach quiet icon", title: "Send a file", ariaLabel: "Attach a file", onclick: () => this.picker.click() }, "+");
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

  show() {
    if (this.stuck) this.bottom();
    if (!touch.matches && !this.el.contains(document.activeElement)) this.input.focus();
  }

  private bottom() {
    this.list.scrollTop = this.list.scrollHeight;
    this.stuck = true;
    this.newer.hidden = true;
  }

  async update() {
    await super.update();
    const items: Item[] = JSON.parse(await lmk.items(this.gid));
    const keep = new Set<string>();
    let added = false;
    let previous: Item | undefined;
    let at: Element | null = this.list.firstElementChild;
    for (const item of items) {
      const key = "id" in item ? item.id : `${item.type} ${item.at}`;
      const follows = item.type === "message" && previous?.type === "message" && previous.from.key === item.from.key && item.at - previous.at < 300_000 && !item.reply_to;
      const json = JSON.stringify([item, follows]);
      previous = item;
      keep.add(key);
      let line = this.lines.get(key);
      if (line?.json !== json) {
        if (line && at === line.el) at = at.nextElementSibling;
        line?.el.remove();
        added ||= !line;
        line = { json, el: this.line(item, items, follows) };
        this.lines.set(key, line);
      }
      if (line.el !== at) this.list.insertBefore(line.el, at);
      at = line.el.nextElementSibling;
    }
    for (const [key, line] of this.lines) if (!keep.has(key)) (line.el.remove(), this.lines.delete(key));
    if (added && this.stuck) this.bottom();
    else if (added) this.newer.hidden = false;
  }

  private line(item: Item, items: Item[], follows: boolean): HTMLElement {
    const at = timeOf(item.at);
    switch (item.type) {
      case "message": {
        const parent = item.reply_to ? (items.find(i => i.type === "message" && i.id === item.reply_to) as Message | undefined) : undefined;
        const to = item.to?.map(fp => this.members.find(m => m.fp === fp)).filter(m => m != null);
        const classes = ["message", item.from.you && "mine", follows && "follows", item.to?.includes(me.fp) && "direct", item.urgent && "urgent"];
        const status = item.refused
          ? h("p", { className: "status warn" }, `Refused by ${item.refused.map(r => `${r.name} (${r.reason})`).join(", ")}`)
          : item.pending && h("p", { className: "status warn" }, "Pending: no other member holds it yet. It goes out when one is online while this browser is open.");
        return h(
          "li",
          { className: classes.filter(Boolean).join(" "), tabIndex: -1 },
          !follows &&
            h(
              "div",
              { className: "meta" },
              who(item.from),
              to?.length && h("span", { className: "muted" }, "to ", to.map(label).join(", ")),
              item.urgent && h("span", { className: "tag" }, "Urgent"),
              at
            ),
          item.reply_to &&
            h("blockquote", {}, parent ? [h("b", {}, label(parent.from)), " ", (parent.content || parent.attachment?.name || "").slice(0, 160)] : "a message this browser does not hold"),
          item.content && h("div", { className: "text" }, item.content),
          item.attachment && this.attachmentView(item.attachment),
          status,
          item.unread && this.unreadView(item, item.unread),
          h("div", { className: "actions" }, h("button", { className: "quiet", onclick: () => this.reply(item) }, "Reply"))
        );
      }
      case "leave":
        return h("li", { className: "event" }, who(item.from), " asked to leave", at);
      case "joined":
      case "left": {
        const self = item.by.key === item.member.key;
        const said =
          item.type === "joined" ? [who(item.by), item.how === "open" ? " let in " : " added ", who(item.member)] : self ? [who(item.member), " left"] : [who(item.by), " removed ", who(item.member)];
        return h("li", { className: "event" }, ...said, at);
      }
      case "settings": {
        const { before, settings: after } = item;
        const ids = (s?: { open?: { id: string }[] }) => (s?.open ?? []).map(o => o.id);
        const said = [
          before && after.name !== before.name && (after.name ? `named it “${after.name}”` : "removed its name"),
          ...(after.open ?? []).filter(o => !ids(before).includes(o.id)).map(o => `let ${o.name}'s devices join`),
          ...(before?.open ?? []).filter(o => !ids(after).includes(o.id)).map(o => `stopped letting ${o.name}'s devices join`)
        ].filter(Boolean);
        return h("li", { className: "event" }, who(item.by), ` ${said.join(" and ") || "changed the settings"}`, at);
      }
      case "introduced":
        return h("li", { className: "event" }, who(item.by), ` introduced ${item.identity.name}`, at);
      case "pushed":
        return h(
          "li",
          { className: "event pushed" },
          who(item.by),
          ` pushed to ${item.ref.replace(/^refs\/heads\//, "")}`,
          at,
          h("ul", {}, ...item.subjects.map(subject => h("li", {}, subject)))
        );
    }
  }

  /** An image shows in the chat; any other file downloads on a click. */
  private attachmentView(file: Attachment): HTMLElement {
    if (/^image\/(png|jpeg|gif|webp)$/.test(file.type) && (file.kept || file.size <= FILE_LIMIT)) {
      const image = h("img", { className: "image", alt: file.name });
      image.onload = () => this.stuck && this.bottom();
      client.file(this.gid, file.link).then(
        bytes => (image.src = URL.createObjectURL(new Blob([bytes as BlobPart], { type: file.type }))),
        error => image.replaceWith(h("p", { className: "muted" }, `${file.name} could not be shown: ${error instanceof Error ? error.message : error}`))
      );
      return image;
    }
    const button = h("button", { className: "download" }, `${file.kept ? "Download" : "Fetch"} ${file.name} (${megabytes(file.size)})`);
    button.onclick = () => busy(button, "Fetching…", async () => download(await client.file(this.gid, file.link), file.name));
    return button;
  }

  protected drawPeople() {
    super.drawPeople();
    const others = this.members.filter(m => !m.you);
    this.empty.hidden = others.length > 0;
    this.empty.replaceChildren(
      h("p", {}, "Only you so far. Invite a person or an agent: they get a link that works once, within 10 minutes."),
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
        replyTo &&
          h(
            "div",
            {},
            h("span", {}, "Replying to ", h("b", {}, label(replyTo.from)), ": ", (replyTo.content || replyTo.attachment?.name || "").slice(0, 80)),
            close(() => (this.replyTo = undefined))
          ),
        attachment &&
          h(
            "div",
            {},
            h("span", {}, "Attached ", h("b", {}, attachment.name), ` · ${megabytes(attachment.size)}`),
            close(() => (this.attachment = undefined))
          )
      ])
    );
  }

  /** Who could not read a message of this browser's, and a button that sends it again as a new message replying to it. */
  private unreadView(item: Message, names: string[]): HTMLElement {
    const resend = h("button", { className: "quiet" }, "Resend");
    resend.onclick = () =>
      busy(resend, "Sending…", async () => {
        const { attachment } = item;
        const bytes = attachment && (await client.file(this.gid, attachment.link));
        await lmk.send(this.gid, item.content, item.id, item.to ?? [], !!item.urgent, attachment?.name, attachment?.type, bytes);
        render();
      });
    return h("p", { className: "status warn" }, `${names.join(", ")} could not read this `, resend);
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
    this.attachment = file;
    this.drawContext();
    this.input.focus();
  }

  private async submit() {
    const content = this.input.value.trim();
    const { attachment, replyTo } = this;
    if (!content && !attachment) return;
    const to = [...this.to];
    const urgent = this.urgent.checked;
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
      const bytes = attachment && new Uint8Array(await attachment.arrayBuffer());
      const sent = lmk.send(this.gid, content, replyTo?.id, to, urgent, attachment?.name, attachment?.type, bytes);
      setTimeout(render, 50);
      const answer = JSON.parse(await sent);
      if (answer.attachment && answer.attachment.held_by.length === 0) toast(`No other member holds ${attachment!.name} yet: it is available only while this browser is open.`);
    } catch (error) {
      toast(error);
      if (!this.input.value) this.input.value = content;
      this.attachment ??= attachment;
      this.grow();
      this.drawContext();
    }
    render();
  }
}

/** A doc: one text that everyone in it edits at once, in CodeMirror bound to the doc's Yjs text. */
class DocView extends View {
  private host = h("div", { className: "editor" });
  private bound?: { edited: () => void; measure: () => void; destroy: () => void };

  constructor(gid: string) {
    super(gid);
    docs.set(gid, this);
    this.el.append(h("div", { className: "body" }, this.host));
    import("./editor").then(async ({ bind }) => {
      if (!group(gid)) return;
      const files = {
        show: (link: string) => client.file(gid, link).then(bytes => URL.createObjectURL(new Blob([bytes as BlobPart]))),
        attach: (bytes: Uint8Array) => lmk.add_file(gid, bytes),
        open: (link: string, name: string) => client.file(gid, link).then(bytes => download(bytes, name), toast),
        fail: toast
      };
      this.bound = await bind(this.host, lmk, gid, files);
    });
  }

  edited() {
    this.bound?.edited();
  }

  show() {
    this.bound?.measure();
  }

  destroy() {
    this.bound?.destroy();
  }
}

function timeOf(at: number): HTMLElement {
  return h("time", { dateTime: new Date(at).toISOString(), title: new Date(at).toLocaleString() }, new Date(at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
}

function download(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
  h("a", { href: url, download: name }).click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
