// The page: this browser's session and its groups, each a chat or a doc. Background work ends in render(), which patches
// only what changed, so what a person is typing, selecting or scrolling stays put. Joining from a link waits for a
// click, so link scanners that open it join nothing.
import "@fontsource-variable/ibm-plex-sans/wght.css";
import "@fontsource-variable/ibm-plex-sans/wght-italic.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "./app.css";
import * as client from "./client";
import type { Attachment, Group, Item, Me, Person } from "./client";
import type * as Yjs from "yjs";
import { icon } from "./icons";
import * as store from "./store";

const { lmk, request } = client;

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
const KINDS = { chat: "chat", doc: "document", table: "table" };
/** Files up to this size every member fetches; larger ones only on request. */
const FILE_LIMIT = 25 << 20;
const INVITE_PREFIX = "https://letmeknow.dev/i";
/** letmeknow 0.17's invite links, which this version cannot read. */
const madeByOlder = (link: string) => /#6\./.test(link);
const OLDER_INVITE = "This invite was made by letmeknow 0.17. Its maker must restart with `npx -y @letmeknow/cli@0.18`, then make a new link.";

const root = document.getElementById("app")!;
const agentsHelp = document.getElementById("agents")!;
const toasts = h("div", { className: "toasts" });
const narrow = matchMedia("(max-width: 699px)");
const touch = matchMedia("(pointer: coarse)");
const invite = /^\/i\/?$/.test(location.pathname) && location.hash.length > 1 ? INVITE_PREFIX + location.hash : undefined;

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
    h("header", {}, h("h2", {}, title), h("button", { type: "button", className: "icon quiet", title: "Close", ariaLabel: "Close", onclick: () => dialog.close() }, icon("close"))),
    h("div", { className: "dialog-body" }, ...content)
  );
  dialog.onclose = () => dialog.remove();
  document.body.append(dialog);
  dialog.showModal();
  return dialog;
}

let me: Me;
let groups: Group[] = [];
let page: "group" | "devices" = "group";
let selected: string | undefined;
let entered: Promise<void> | undefined;
/** How many of this browser's messages and files no cut keeps yet: closing the page while any is loses them. */
let onlyHere = 0;
let storageFailed = false;
addEventListener("beforeunload", event => (onlyHere || storageFailed) && event.preventDefault());
const group = (gid: string) => groups.find(g => g.group === gid);
const unread = (gid: string) => Number(localStorage.getItem(`unread ${gid}`) ?? 0);

// Cache this release offline; the hosting origin still controls installed code.
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
boot().catch(error => root.replaceChildren(
  h("div", { className: "card welcome", role: "alert" }, h("h1", {}, "Could not open this session"), h("p", {}, String(error))),
  toasts
));

async function boot() {
  await keptByOlder();
  const had = await client.prepare();
  const kind = invite && client.kindOf(invite);
  if (!had) welcome(kind);
  await client.ready;
  await (entered ??= enter());
  if (invite && had) offer(kind);
}

/** letmeknow 0.17's chats stay in its own database, which this version leaves as it is: said once. */
async function keptByOlder() {
  if (localStorage.getItem("lmk 0.17 kept") || !(await store.older())) return;
  localStorage.setItem("lmk 0.17 kept", "1");
  const ok = h("button", { className: "primary" }, "OK");
  const notice = h("div", { className: "banner", role: "status" }, h("span", {}, "Chats from letmeknow 0.17 stay with 0.17 in this browser. This version keeps its own and does not open them."), ok);
  ok.onclick = () => notice.remove();
  document.body.append(notice);
}

/** Starts this browser's session, and given `name`, makes it the first device of an identity of that name; without, it is to join one by a device link. */
async function start(device: string, name?: string) {
  await client.open(device);
  navigator.storage?.persist?.();
  if (name) await request({ cmd: "identity", op: { create: { name } } });
  await (entered ??= enter());
}

client.listen(event => {
  if (event.type === "storage_failed") {
    if (storageFailed) return;
    storageFailed = true;
    const retry = h("button", { className: "primary" }, "Retry saving and reload");
    retry.onclick = () => busy(retry, "Saving…", () => lmk.flush(true));
    document.body.append(h("div", { className: "banner", role: "alert" }, h("span", {}, event.text), retry));
    return;
  }
  if (event.type === "storage_saved") {
    storageFailed = false;
    location.reload();
    return;
  }
  // The tab that runs the session counts what is unread; a tab showing the group clears it.
  if (event.type === "message" && client.runs() && event.group && !(page === "group" && event.group === selected && document.visibilityState === "visible")) {
    localStorage.setItem(`unread ${event.group}`, String(unread(event.group) + 1));
  }
  if (event.type === "warning") toast(event.text);
  if (event.type === "removed") toast(`You were removed from ${title(event.group!)}${event.by ? ` by ${event.by}` : ""}.${event.not_kept?.length ? ` ${event.not_kept.length} of your messages were not kept by any cut, so the others may lack them.` : ""}`);
  if (event.type === "added") toast(`Your ${event.by} added this browser to ${title(event.group!)}.`);
  if (event.type === "edited") editors.get(event.group!)?.edited();
  if (entered) render();
});

function standing(p: Person): string {
  const i = p.identity;
  if (!i) return "Speaks as no identity";
  if (i.error) return `Authorization failed: ${i.error}`;
  return `${i.how === "self" ? "Your identity. " : ""}${i.observed ? "Locally observed here" : "Authorized claim; not recorded as a local observation"}; not independently verified`;
}

function bindingWarning(p: Person): string | undefined {
  const o = p.identity?.observed;
  if (!o || p.identity?.error) return;
  const warnings = [];
  if (o.names.length > 1) warnings.push(`Changed identity-name claim; first observed here as ${JSON.stringify(o.names[0])}.`);
  if (o.other_ids.length) warnings.push("This name is also claimed by other identities. Names are not unique.");
  return warnings.join(" ") || undefined;
}

function who(p: Person): HTMLElement {
  const warning = p.identity?.error || bindingWarning(p);
  return h(
    "span",
    { className: warning ? "who warn" : "who", title: [standing(p), warning, p.identity?.id, `key ${p.fp}`].filter(Boolean).join("\n") },
    warning && "⚠ ",
    p.name
  );
}

/** The group's name, or else who else is in it. */
function title(gid: string): string {
  const g = group(gid);
  if (!g) return "a group";
  const others = g.members.filter(m => !m.you).map(p => p.name);
  return g.settings.name || [...new Set(others)].join(", ") || `New ${KINDS[g.settings.kind]}`;
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
  const name = h("input", { required: true, autocomplete: "name", autofocus: true });
  const device = h("input", { required: true, value: touch.matches ? "phone" : "laptop" });
  const ready = () => name.reportValidity() && device.reportValidity();
  let body: Child[];
  if (kind === "group") {
    const join = h("button", { className: "primary" }, "Join");
    const go = () => ready() && busy(join, "Joining…", async () => (await start(device.value.trim(), name.value.trim()), await redeem(invite!)));
    body = [h("h1", {}, "You're invited"), form(go, field("Your name", name), field("Device name", device), join)];
  } else if (kind === "device") {
    const add = h("button", { className: "primary" }, "Add this browser");
    device.autofocus = true;
    const go = () => device.reportValidity() && busy(add, "Adding…", async () => (await start(device.value.trim()), await redeem(invite!)));
    body = [h("h1", {}, "Add this browser to your devices"), form(go, field("Device name", device), add)];
  } else {
    const begin = h("button", { className: "primary" }, "Continue");
    const go = () => ready() && busy(begin, "Starting…", () => start(device.value.trim(), name.value.trim()));
    body = [
      h("h1", {}, invite ? "This is not a letmeknow invite" : "letmeknow"),
      invite && madeByOlder(invite) && h("p", {}, OLDER_INVITE),
      form(go, field("Your name", name), field("Device name", device), begin),
      h("details", { className: "agents" }, h("summary", {}, "For agents"), agentsHelp)
    ];
  }
  root.replaceChildren(h("div", { className: "card welcome" }, ...body), toasts);
}

/** For a browser that has a session already: asks before it uses the invite it was opened with. */
function offer(kind: string | undefined) {
  history.replaceState(null, "", "/");
  if (!kind) return toast(madeByOlder(invite!) ? OLDER_INVITE : "That is not a letmeknow invite link.");
  if (kind === "device" && me.identity) return leaveDialog(invite);
  const go = h("button", { className: "primary", autofocus: true }, kind === "group" ? "Join" : "Add this browser");
  const dialog = modal(
    kind === "group" ? "You're invited" : "Add this browser to your devices",
    h(
      "p",
      {},
      kind === "group"
        ? "Join to share a chat or a document with whoever sent you the link, and perhaps their agents."
        : "This browser becomes one of the devices of whoever made this link: it can join their chats and documents and speaks for them."
    ),
    h("div", { className: "buttons" }, go)
  );
  go.onclick = () =>
    busy(go, "Joining…", async () => {
      await redeem(invite!);
      dialog.close();
    });
}

/** Uses an invite link: lands in the group it joined, or, for a device link, on this browser's devices. A browser on an
 * identity asks first to move to the one a device link is of. */
async function redeem(link: string) {
  if (client.kindOf(link) === "device" && me?.identity) return leaveDialog(link);
  const joined = await request({ cmd: "join", target: link });
  history.replaceState(null, "", "/");
  if (joined.group) await select(joined.group);
  else showDevices();
}

// The layout: groups on the side, the selected group or a page in the main area. Narrow screens show one at a time.

const groupList = h("nav", { className: "group-list" });
const navButtons = new Map<string, { button: HTMLButtonElement; name: HTMLElement; badge: HTMLElement }>();
const meName = h("b");
const meButton = h("button", { className: "me quiet", onclick: () => showDevices() }, meName, h("small", {}, "Your devices"));
const sidebar = h(
  "aside",
  { className: "sidebar" },
  h("div", { className: "brand" }, h("img", { src: "/icon.svg", alt: "" }), "letmeknow"),
  h(
    "div",
    { className: "side-actions" },
    h("button", { onclick: () => createGroup("chat").catch(toast) }, icon("chat"), "New chat"),
    h("button", { onclick: () => createGroup("doc").catch(toast) }, icon("doc"), "New doc"),
    h("button", { onclick: () => createGroup("table").catch(toast) }, icon("table"), "New table"),
    h("button", { onclick: joinDialog }, icon("join"), "Join")
  ),
  groupList,
  meButton
);
const main = h("main", { className: "main" });
const layout = h("div", { className: "layout" }, sidebar, main);
const devicesPage = h("section", { className: "page" });
const views = new Map<string, View>();
/** The views of documents and tables, which others' edits reach. */
const editors = new Map<string, DocView | TableView>();

async function enter() {
  me = JSON.parse(await lmk.me());
  groups = JSON.parse(await lmk.groups());
  root.replaceChildren(layout, toasts);
  const last = localStorage.getItem("group");
  const shown = last && group(last) ? last : groups.at(-1)?.group;
  if (shown) await select(shown);
  else render();
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
    const kind = group(gid)!.settings.kind;
    view = kind === "doc" ? new DocView(gid) : kind === "table" ? new TableView(gid) : new ChatView(gid);
    views.set(gid, view);
  }
  show(view.el);
  page = "group";
  selected = gid;
  localStorage.setItem("group", gid);
  view.show();
  render();
}

function back() {
  return h("button", { className: "back quiet icon", title: "All groups", onclick: () => layout.classList.remove("in-main") }, icon("back"));
}

let rendering = Promise.resolve();
function render() {
  rendering = rendering.then(draw).catch(toast);
}

async function draw() {
  me = JSON.parse(await lmk.me());
  groups = JSON.parse(await lmk.groups());
  onlyHere = await lmk.only_here();
  for (const [gid, view] of views) {
    if (group(gid)) continue;
    view.el.remove();
    view.destroy();
    views.delete(gid);
    editors.delete(gid);
    if (gid === selected) selected = undefined;
  }
  if (page === "group" && !selected) {
    // With no group, the main area stays empty, and a narrow screen shows the list.
    const newest = groups.at(-1);
    if (newest) await select(newest.group);
    else layout.classList.remove("in-main");
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
  for (const g of groups) {
    let entry = navButtons.get(g.group);
    if (!entry) {
      const name = h("span"),
        badge = h("b");
      entry = { button: h("button", { onclick: () => select(g.group) }, icon(g.settings.kind), name, badge), name, badge };
      navButtons.set(g.group, entry);
      groupList.prepend(entry.button);
    }
    set(entry.name, title(g.group));
    set(entry.badge, unread(g.group) ? String(unread(g.group)) : "");
    entry.button.classList.toggle("on", page === "group" && g.group === selected);
  }
  set(meName, me.identity?.name ?? me.device.name);
  meButton.classList.toggle("on", page === "devices");
}

/** Starts a group of `kind`, unnamed, and opens its settings, where it gets a name and its people. */
async function createGroup(kind: keyof typeof KINDS) {
  const gid = await lmk.create(kind, "");
  await select(gid);
  views.get(gid)!.settingsDialog();
}

function joinDialog() {
  const link = h("input", { placeholder: "https://letmeknow.dev/i#…", autofocus: true, autocomplete: "off", autocapitalize: "none", spellcheck: false });
  const join = h("button", { className: "primary" }, "Join");
  const dialog = modal(
    "Join with a link",
    form(
      () =>
        busy(join, "Joining…", async () => {
          if (!client.kindOf(link.value.trim())) return toast(madeByOlder(link.value) ? OLDER_INVITE : "That is not a letmeknow invite link.");
          await redeem(link.value.trim());
          dialog.close();
        }),
      field("Invite link", link, "An invite into a group, or a device link from one of your devices. It works once, within 10 minutes."),
      h("div", { className: "buttons" }, join)
    )
  );
}

// Your devices: the identity this browser is a device of, and its devices, with the sessions each runs and their groups.

/** A group a device's session is in, with its other members as they show to it; a browser's own have no session. */
type SessionGroup = { session?: string; name: string; kind: string; members: string[] };
type Listed = { devices: { key: string; name: string; you: boolean; sessions: string[]; groups: SessionGroup[] }[] };

/** A group of another session, in a line: "tine: Plans, a chat with Matthew · phone". */
function sessionGroup(g: SessionGroup): HTMLElement {
  const kind = (KINDS as Record<string, string>)[g.kind] ?? "group";
  const members = g.members.length ? ` with ${g.members.join(", ")}` : "";
  return h("li", {}, g.session && `${g.session}: `, g.name || `a ${kind}`, h("small", {}, g.name ? `, a ${kind}${members}` : members));
}

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
  const identity = me.identity;
  if (!identity) {
    return update(devicesBody, "none", () => {
      const name = h("input", { required: true });
      const device = h("input", { value: me.device.name, required: true });
      const create = h("button", { className: "primary" }, "Start");
      const started = async () => {
        await request({ cmd: "identity", op: { create: { name: name.value.trim() } } });
        if (device.value.trim() !== me.device.name) await request({ cmd: "identity", op: { rename: { name: device.value.trim(), device: true } } });
        render();
      };
      return [
        h("p", {}, "Start an identity to make signed identity claims and add your other devices. An identity is not verification of a person. Existing anonymous memberships stay anonymous until you leave and rejoin; new memberships use this identity."),
        form(
          () => name.reportValidity() && device.reportValidity() && busy(create, "Starting…", started),
          field("Your name", name),
          field("This device", device, "As in “Matthew · phone”, so you can tell your devices apart."),
          create
        ),
        h("p", { className: "muted" }, "To add this browser to an identity you have on another device, make a device link there and open it here, or paste it into Join.")
      ];
    });
  }
  const listed: Listed = await request({ cmd: "identity", op: "list" });
  update(devicesBody, JSON.stringify([identity, listed]), () => [
    h("p", {}, `The browsers and computers authorized to speak as ${identity.name}. Certified memberships carry their signed identity claims, not proof of a person.`),
    h(
      "ul",
      { className: "devices" },
      ...listed.devices.map(d =>
        h(
          "li",
          {},
          h(
            "div",
            {},
            h("span", { title: `key ${d.key}` }, d.name, d.you && h("small", {}, " this browser"), d.sessions.length > 0 && h("small", {}, ` runs ${d.sessions.join(", ")}`)),
            d.groups.length > 0 && h("ul", { className: "in-groups" }, ...d.groups.map(sessionGroup))
          ),
          d.you
            ? h("span", {}, h("button", { onclick: renameDialog }, "Rename"), h("button", { className: "danger", onclick: () => leaveDialog() }, "Leave"))
            : confirmed("Remove", `Remove ${d.name}?`, async () => {
                await request({ cmd: "identity", op: { remove: { device: d.key } } });
                shown.delete(devicesBody);
                render();
              })
        )
      )
    ),
    h("button", { className: "primary", onclick: () => inviteDialog(identity.id) }, "Add a device")
  ]);
}

function renameDialog() {
  const identity = h("input", { value: me.identity!.name, required: true });
  const name = h("input", { value: me.device.name, required: true, autofocus: true });
  const save = h("button", { className: "primary" }, "Rename");
  const dialog = modal(
    "Rename",
    form(
      () =>
        identity.reportValidity() &&
        name.reportValidity() &&
        busy(save, "Renaming…", async () => {
          if (identity.value.trim() !== me.identity!.name) await request({ cmd: "identity", op: { rename: { name: identity.value.trim() } } });
          if (name.value.trim() !== me.device.name) await request({ cmd: "identity", op: { rename: { name: name.value.trim(), device: true } } });
          render();
          dialog.close();
        }),
      field("Your name", identity, "Certified memberships share the new claim as devices and sessions resume and refresh. Anonymous memberships stay anonymous."),
      field("This device", name, "The signed device label updates in certified memberships as sessions resume and refresh."),
      h("div", { className: "buttons" }, save)
    )
  );
}

/** Takes this browser off its identity, saying first what that does; with a device link, then joins the identity it is of. */
async function leaveDialog(link?: string) {
  const identity = me.identity!;
  const listed: { devices: unknown[] } = await request({ cmd: "identity", op: "list" });
  const only = listed.devices.length === 1;
  const speaking = groups.filter(g => g.members.some(m => m.you && m.identity?.id === identity.id)).map(g => title(g.group));
  const go = h("button", { className: "danger", autofocus: true }, link ? "Move this browser" : `Leave ${identity.name}`);
  const dialog = modal(
    link ? "Move this browser to another identity" : `Leave ${identity.name}`,
    link && h("p", {}, "This link adds this browser to the identity of whoever made it. A browser is a device of one identity at a time, so it moves:"),
    h(
      "ul",
      {},
      h("li", {}, only ? `It leaves ${identity.name}, which ends: this browser is its only device.` : `It leaves ${identity.name}; your other devices stay on it.`),
      h("li", {}, speaking.length ? `It leaves the groups it is in as ${identity.name}: ${speaking.join(", ")}.` : `It is in no group as ${identity.name}.`),
      link && h("li", {}, "Then it joins the identity that made this link.")
    ),
    h("div", { className: "buttons" }, go)
  );
  go.onclick = () =>
    busy(go, link ? "Moving…" : "Leaving…", async () => {
      await request({ cmd: "identity", op: "leave" });
      me = JSON.parse(await lmk.me());
      dialog.close();
      if (link) await redeem(link);
      else render();
    });
}

// Invites: a link and its QR code, single use, within 10 minutes. A device link adds a device to an identity.

/** Makes a link to `target` and shows it in `body`, with its QR code and the command an agent joins with; once they
 * joined, says so and closes `dialog`. */
async function showLink(target: { gid: string } | { identity: string }, body: HTMLElement, dialog: HTMLDialogElement) {
  const device = "identity" in target;
  const g = device ? undefined : group(target.gid);
  const kind = g ? KINDS[g.settings.kind] : "";
  // "devices" also tells of the identity's devices being heard from: the one added is a key the list did not have.
  const keys = async () => ((await request({ cmd: "identity", op: "list" })) as Listed).devices.map(d => d.key);
  const before = device ? await keys() : [];
  // Invite presentation stays on the trusted frontend origin, never the backend's.
  const made = new URL((await request(device ? { cmd: "identity", op: { invite: {} } } : { cmd: "invite", group: target.gid })).link);
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
        : `Send this link to a person or an agent. Whoever opens it first joins the ${kind}.`
    ),
    h("div", { className: "qr" }, svg),
    copyable(link),
    h("p", {}, device ? "On a computer, an agent's session adds it with:" : "An agent joins with:"),
    copyable(`letmeknow ${device ? "identity join" : "join"} '${link}'`),
    h("p", { className: "expiry" }, "It works once, within 10 minutes, while this browser is open.")
  );
  const joined = async (event: client.Event) => {
    const added = device
      ? event.type === "devices" && event.identity === target.identity && (await keys()).some(key => !before.includes(key))
      : event.type === "joined" && event.group === target.gid;
    if (!added || !dialog.open) return;
    body.replaceChildren(h("p", { className: "done" }, device ? "Added. The device can now join your chats and documents." : `They joined the ${kind}.`));
    setTimeout(() => dialog.close(), 1_500);
  };
  client.listen(joined);
  dialog.addEventListener("close", () => client.unlisten(joined));
}

/** Adds a device to the identity, by a device link. */
function inviteDialog(identity: string) {
  const body = h("div", { className: "invite" });
  showLink({ identity }, body, modal("Add a device", body)).catch(toast);
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
  private peopleDetails?: HTMLElement;
  private peopleHeading?: HTMLElement;

  constructor(readonly gid: string) {
    this.el = h(
      "section",
      { className: "group" },
      h(
        "header",
        { className: "group-head" },
        back(),
        h("div", { className: "title" }, this.heading, this.people),
        h("button", { className: "icon quiet", title: "Settings", ariaLabel: "Settings", onclick: () => this.settingsDialog() }, icon("more"))
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
    const warned = this.members.some(m => m.identity?.error || bindingWarning(m));
    const names = [...new Set(others.map(m => (m.away ? `${m.name} (away)` : m.name)))];
    this.people.replaceChildren(warned ? "⚠ " : "", ...(others.length ? [names.join(", "), " and you"] : ["Only you so far"]));
    this.people.classList.toggle("warn", warned);
    if (this.peopleHeading) set(this.peopleHeading, `People (${this.members.length})`);
    this.peopleDetails?.replaceChildren(...this.members.map(m =>
      h("li", {},
        h("div", {},
          who(m),
          m.you && h("small", { className: "muted" }, " you"),
          m.away && h("small", { className: "muted" }, " away: not heard from for as long as members carry messages"),
          h("p", { className: m.identity?.error ? "warn" : "muted" }, standing(m)),
          bindingWarning(m) && h("p", { className: "warn identity-warning" }, bindingWarning(m)),
          m.identity && copyable(m.identity.id),
          m.identity?.observed && h("p", { className: "observed-names" }, `Names observed here, first to last: ${m.identity.observed.names.map(n => JSON.stringify(n)).join(", ")}`),
          ...((m.identity?.observed?.other_ids ?? []).map(id => h("div", {}, "Also claimed by identity:", copyable(id)))),
          m.added_by && h("p", { className: "muted" }, `added by ${this.members.find(a => a.fp === m.added_by!.fp)?.name ?? "a former member"} (${m.added_by.how})`)
        ),
        !m.you && confirmed("Remove", `Remove ${m.name}?`, () => request({ cmd: "remove", group: this.gid, member: m.fp }))
      )
    ));
  }

  show() {}

  destroy() {}

  /** A line for each of this identity's other devices the group does not have, to add it: each session it runs, or
   * the device. */
  private addDevices(gid: string): HTMLElement {
    const list = h("ul", { className: "people-list" }, h("li", { className: "muted" }, "…"));
    request({ cmd: "identity", op: "list" }).then((listed: Listed) => {
      const own = this.members.filter(m => m.identity?.how === "self" && !m.identity.error);
      const has = (device: string, session?: string) => own.some(m => m.device === device && (!session || m.handle === session));
      const others = listed.devices.filter(d => !d.you);
      const targets = others.flatMap(d =>
        d.sessions.length ? d.sessions.filter(s => !has(d.name, s)).map(s => [`${d.name} · ${s}`, `${d.name} (${s})`]) : has(d.name) ? [] : [[d.name, d.key]]
      );
      const add = ([label, target]: string[]) => {
        const button = h("button", { type: "button" }, "Add");
        button.onclick = () =>
          busy(button, "Adding…", async () => {
            await request({ cmd: "add", target, group: gid });
            toast(`${label} joins when it next runs, within a week.`);
          });
        return h("li", {}, h("div", {}, label), button);
      };
      const none = others.length ? "All your other devices are in already." : "Your other devices show here, once you add them under Your devices.";
      list.replaceChildren(...(targets.length ? targets.map(add) : [h("li", {}, h("p", { className: "muted" }, none))]));
    }, toast);
    return list;
  }

  /** The group's one screen: its name, its people and bringing in more, and leaving it. With `invite`, it makes a link at
   * once. */
  settingsDialog(invite = false) {
    const gid = this.gid;
    const settings = group(gid)!.settings;
    const kind = KINDS[settings.kind];
    const name = h("input", { value: settings.name, placeholder: title(gid), ariaLabel: "Name", autofocus: !settings.name });
    const save = h("button", {}, "Rename");
    const make = h("button", { type: "button" }, "Make a link");
    const link = h("div", { className: "invite" }, h("ul", { className: "people-list" }, h("li", {}, h("div", {}, "Invite someone else"), make)));
    const dialog = modal(
      kind[0].toUpperCase() + kind.slice(1),
      form(() => busy(save, "Renaming…", () => request({ cmd: "name", group: gid, name: name.value.trim() })), field("Name", h("div", { className: "row" }, name, save))),
      this.peopleHeading = h("h3"),
      link,
      me.identity && h("small", {}, "Add one of your devices"),
      me.identity && this.addDevices(gid),
      this.peopleDetails = h("ul", { className: "people-list identity-details" }),
      h(
        "div",
        { className: "buttons leave" },
        confirmed(`Leave ${kind}`, "Leave for good?", async () => {
          const left = await request({ cmd: "leave", group: gid });
          if (left.pending) toast("Asked the others to remove you; keep this page open until one of them does.");
          else if (left.status) toast("Asked the others to remove you; one of them removes you.");
          render();
          dialog.close();
        }),
        this.members.some(m => !m.you) &&
          confirmed("End for everyone", `Remove everyone and end this ${kind}?`, async () => {
            await request({ cmd: "leave", group: gid, end: true });
            render();
            dialog.close();
          })
      )
    );
    this.drawPeople();
    make.onclick = () => busy(make, "Making…", () => showLink({ gid }, link, dialog));
    if (invite) make.click();
  }
}

/** A chat: its timeline, and a composer that sends text and a file, to everyone or to some. */
class ChatView extends View {
  private list = h("ol", { className: "messages" });
  private newer = h("button", { className: "newer", hidden: true }, "New messages", icon("down"));
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
  /** Sends that failed, with their text, until sent again or dropped. */
  private failed: Message[] = [];

  constructor(gid: string) {
    super(gid);
    const send = h("button", { className: "primary send", onclick: () => this.submit() }, "Send");
    const attach = h("button", { className: "attach quiet icon", title: "Send a file", ariaLabel: "Attach a file", onclick: () => this.picker.click() }, icon("attach"));
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
    const items: Item[] = [...JSON.parse(await lmk.items(this.gid, document.visibilityState === "visible")), ...this.failed];
    const keep = new Set<string>();
    let added = false;
    let previous: Item | undefined;
    let at: Element | null = this.list.firstElementChild;
    for (const item of items) {
      const key = "id" in item ? item.id : `${item.type} ${item.at}`;
      const follows = item.type === "message" && previous?.type === "message" && previous.from.fp === item.from.fp && sentAt(item) - sentAt(previous) < 300_000 && !item.reply_to && ![item, previous].some(m => m.to?.length || m.urgent);
      const json = JSON.stringify([item, follows, item.type === "message" && item.failed?.error]);
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
    const at = timeOf(sentAt(item));
    switch (item.type) {
      case "message": {
        const parent = item.reply_to ? (items.find(i => i.type === "message" && i.id === item.reply_to) as Message | undefined) : undefined;
        const to = item.to?.map(fp => this.members.find(m => m.fp === fp)).filter(m => m != null);
        const classes = ["message", item.from.you && "mine", follows && "follows", item.to?.includes(me.fp) && "direct", item.urgent && "urgent", item.failed && "unsent"];
        const lostBy = item.lost_by?.length && h("p", { className: "tag" }, item.lost_by.map(p => p.name).join(", "), " could not read this; send it again if it matters");
        const readBy = item.read_by?.length ? ` · read by ${item.read_by.map(p => p.name).join(", ")}` : "";
        const unkept = item.only_here ? "; no commit keeps it yet: keep this page open" : "";
        const ticks =
          item.only_here !== undefined &&
          (item.held_by?.length
            ? h("small", { className: "ticks", title: `Held by ${item.held_by.map(p => p.name).join(", ")}${unkept}` }, "✓✓", readBy)
            : h("small", { className: "ticks", title: "Only on this device: keep this page open until another member has it" }, "✓"));
        return h(
          "li",
          { className: classes.filter(Boolean).join(" "), tabIndex: -1 },
          !follows &&
            h(
              "div",
              { className: "meta" },
              who(item.from),
              to?.length && h("span", { className: "muted" }, "to ", to.map(p => p.name).join(", ")),
              item.urgent && h("span", { className: "tag" }, "Urgent"),
              at
            ),
          item.reply_to &&
            h("blockquote", {}, parent ? [h("b", {}, parent.from.name), " ", (parent.content || parent.attachment?.name || "").slice(0, 160)] : "a message this browser does not hold"),
          item.content && h("div", { className: "text" }, item.content),
          item.attachment && this.attachmentView(item.attachment),
          lostBy,
          item.late && h("p", { className: "tag" }, "Late: delivered without messages it needed"),
          ticks,
          item.failed
            ? h(
                "p",
                { className: "tag" },
                `Not sent: ${item.failed.error} `,
                h("button", { className: "quiet", onclick: item.failed.retry }, "Retry"),
                h("button", { className: "quiet", onclick: item.failed.drop }, "Drop")
              )
            : h("div", { className: "actions" }, h("button", { className: "quiet", onclick: () => this.reply(item) }, "Reply"))
        );
      }
      case "missing": {
        const count = item.missing.flatMap(m => m.seqs).length;
        return h("li", { className: "event warn" }, `${count === 1 ? "A message" : `${count} messages`} before this could not be fetched`, at);
      }
      case "lost": {
        const count = item.messages.flatMap(m => m.seqs).length;
        const text = item.member.you
          ? `You could not read ${count === 1 ? "a message" : `${count} messages`}: no member online held them in time`
          : `${item.member.name} could not read ${count === 1 ? "a message" : `${count} messages`} of yours`;
        return h("li", { className: "event warn" }, text, at);
      }
      case "leave":
        return h("li", { className: "event" }, who(item.from), " asked to leave", item.only_here && h("small", { className: "ticks", title: "No commit keeps it yet: keep this page open until a member removes you" }, " ✓"), at);
      case "joined":
      case "left": {
        const self = item.by.fp === item.member.fp;
        const said =
          item.type === "joined" ? [who(item.by), " added ", who(item.member)] : self ? [who(item.member), " left"] : [who(item.by), " removed ", who(item.member)];
        return h("li", { className: "event" }, ...said, at);
      }
      case "revoked": {
        const list = (people: Person[]) => people.flatMap((p, i) => (i ? [", ", who(p)] : [who(p)]));
        const added = item.added.length ? [". They added ", ...list(item.added), ", who stay until removed"] : [];
        return h("li", { className: "event warn" }, "You removed ", ...list(item.removed), ": their device was taken off its identity", ...added, at);
      }
      case "settings": {
        const { before, settings: after } = item;
        const said = before && after.name !== before.name && (after.name ? `named it “${after.name}”` : "removed its name");
        return h("li", { className: "event" }, who(item.by), ` ${said || "changed the settings"}`, at);
      }
      // An item of a kind this page does not show, as a newer page may keep in the timeline.
      default:
        return h("li", { hidden: true });
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
      h("button", { className: "primary", onclick: () => this.settingsDialog(true) }, "Invite someone")
    );
    for (const fp of this.to) if (!others.some(m => m.fp === fp)) this.to.delete(fp);
    const everyone = h("button", { type: "button", onclick: () => (this.to.clear(), this.drawChips()) }, "Everyone");
    this.chipButtons = new Map([["", everyone]]);
    for (const m of others) {
      const chip = h("button", { type: "button", title: `key ${m.fp}`, onclick: () => (this.to.has(m.fp) ? this.to.delete(m.fp) : this.to.add(m.fp), this.drawChips()) }, m.name);
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
    const close = (job: () => void) => h("button", { className: "icon quiet", title: "Cancel", onclick: () => (job(), this.drawContext()) }, icon("close"));
    const { replyTo, attachment } = this;
    this.context.replaceChildren(
      ...kids([
        replyTo &&
          h(
            "div",
            {},
            h("span", {}, "Replying to ", h("b", {}, replyTo.from.name), ": ", (replyTo.content || replyTo.attachment?.name || "").slice(0, 80)),
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
    await this.send(content, replyTo, to, urgent, attachment);
  }

  /** Sends a message; one that fails stays in the timeline with its text, to retry. */
  private async send(content: string, replyTo: Message | undefined, to: string[], urgent: boolean, attachment: File | undefined) {
    try {
      const bytes = attachment && new Uint8Array(await attachment.arrayBuffer());
      const sent = lmk.send(this.gid, content, replyTo?.id, to, urgent, attachment?.name, attachment?.type, bytes);
      setTimeout(render, 50);
      const answer = JSON.parse(await sent);
      if (answer.attachment?.pending) toast(`No other member holds ${attachment!.name} yet: it is available only while this browser is open.`);
    } catch (error) {
      const from = this.members.find(m => m.you)!;
      const drop = () => ((this.failed = this.failed.filter(f => f !== item)), render());
      const retry = () => (drop(), this.send(content, replyTo, to, urgent, attachment));
      const item: Message = { type: "message", id: `failed ${Date.now()} ${this.failed.length}`, at: Date.now(), from, content, to, reply_to: replyTo?.id, urgent, failed: { error: error instanceof Error ? error.message : String(error), retry, drop } };
      if (attachment) item.content ||= attachment.name;
      this.failed.push(item);
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
    editors.set(gid, this);
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

type ColumnType = "text" | "number" | "date" | "checkbox" | "choice";
type Column = { id: string; name: string; type: ColumnType; choices: string[]; map: Yjs.Map<unknown> };
const COLUMN_TYPES: Record<ColumnType, string> = { text: "Text", number: "Number", date: "Date", checkbox: "Checkbox", choice: "Choice" };
/** The origin of what the table kind's plugin hands over, which goes no further. */
const REMOTE = "lmk";

/** A command of the table kind's in-page plugin. */
const tableCommand = async (...args: string[]) => JSON.parse(await lmk.command("table", JSON.stringify(args)));

/** A new row's or column's id, as the table plugin makes them: 8 lowercase letters and digits. */
const newId = () => Array.from(crypto.getRandomValues(new Uint8Array(8)), byte => "abcdefghijklmnopqrstuvwxyz0123456789"[byte % 36]).join("");

/** A value as a column of type `type` reads it, where it can; else as it was. */
function convert(value: unknown, type: ColumnType): unknown {
  const text = String(value).trim();
  if (type === "number") return text !== "" && Number.isFinite(Number(text)) ? Number(text) : value;
  if (type === "checkbox") return /^(true|yes|x)$/i.test(text) ? true : /^(false|no)$/i.test(text) ? false : value;
  return type === "date" ? value : String(value);
}

/** The order of two cells' values: numbers by size, the rest as text, and empty cells last. */
function compare(a: unknown, b: unknown): number {
  if (a === undefined || b === undefined) return Number(a === undefined) - Number(b === undefined);
  return typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b), undefined, { numeric: true });
}

/** A table: its rows as a grid of typed cells, which everyone in it edits at once. How the grid is sorted, filtered and
 * grouped is this viewer's own. */
class TableView extends View {
  private Y?: typeof Yjs;
  private doc?: Yjs.Doc;
  private grid = h("table", { className: "grid" });
  private filter = h("input", { type: "search", placeholder: "Filter", ariaLabel: "Filter rows" });
  private grouping = h("select", { ariaLabel: "Group by" });
  private sorted?: { column: string; down: boolean };

  constructor(gid: string) {
    super(gid);
    editors.set(gid, this);
    this.filter.oninput = () => this.draw();
    this.grouping.onchange = () => this.draw();
    const tools = h("div", { className: "table-tools" }, this.filter, this.grouping, h("button", { onclick: () => this.columnDialog() }, icon("plus"), "Column"));
    const add = h("button", { className: "quiet", onclick: () => this.addRow() }, icon("plus"), "Row");
    this.el.append(h("div", { className: "body table-body" }, tools, h("div", { className: "grid-wrap" }, this.grid), h("div", {}, add)));
    import("yjs").then(async Y => {
      const doc = new Y.Doc();
      Y.applyUpdate(doc, client.unb64((await tableCommand("state", gid)).state), REMOTE);
      doc.on("update", (update: Uint8Array, origin: unknown) => {
        if (origin !== REMOTE) tableCommand("edit", gid, client.b64(update)).catch(toast);
        this.draw();
      });
      [this.Y, this.doc] = [Y, doc];
      this.draw();
    }, toast);
  }

  edited() {
    const { Y, doc } = this;
    if (Y && doc) tableCommand("diff", this.gid, client.b64(Y.encodeStateVector(doc))).then(({ diff }) => Y.applyUpdate(doc, client.unb64(diff), REMOTE), toast);
  }

  destroy() {
    this.doc?.destroy();
  }

  private columns(): Column[] {
    return this.doc!.getArray<Yjs.Map<unknown>>("columns")
      .toArray()
      .map(map => ({ id: map.get("id") as string, name: map.get("name") as string, type: (map.get("type") as ColumnType) ?? "text", choices: (map.get("choices") as string[]) ?? [], map }));
  }

  private rows() {
    return this.doc!.getArray<Yjs.Map<unknown>>("rows");
  }

  /** Draws the grid anew; a cell being edited keeps its text, focus and selection. */
  private draw() {
    if (!this.doc) return;
    const columns = this.columns();
    const active = document.activeElement;
    const editing = active instanceof HTMLInputElement && active.dataset.cell && this.grid.contains(active) ? { cell: active.dataset.cell, text: active.value, from: active.selectionStart, to: active.selectionEnd } : undefined;
    const choices = columns.filter(c => c.type === "choice");
    const by = choices.find(c => c.id === this.grouping.value);
    update(this.grouping, JSON.stringify([choices.map(c => [c.id, c.name]), by?.id]), () => [h("option", { value: "" }, "No grouping"), ...choices.map(c => h("option", { value: c.id, selected: c === by }, `Group by ${c.name}`))]);
    this.grouping.hidden = !choices.length;
    const needle = this.filter.value.trim().toLowerCase();
    const rows = this.rows().toArray().filter(row => !needle || columns.some(c => String(row.get(c.id) ?? "").toLowerCase().includes(needle)));
    const sort = this.sorted && columns.find(c => c.id === this.sorted!.column);
    if (sort) rows.sort((a, b) => compare(a.get(sort.id), b.get(sort.id)) * (this.sorted!.down ? -1 : 1));
    const value = (row: Yjs.Map<unknown>) => String(row.get(by!.id) ?? "");
    const sections = by ? [...new Set([...by.choices, ...rows.map(value)])].sort((a, b) => Number(a === "") - Number(b === "")) : [];
    const bodies = by
      ? sections.map(section => {
          const inside = rows.filter(row => value(row) === section);
          const head = h("tr", { className: "section" }, h("th", { colSpan: columns.length + 1 }, section || "No value", h("small", {}, String(inside.length))));
          return inside.length > 0 && h("tbody", {}, head, ...inside.map(row => this.row(row, columns)));
        })
      : [h("tbody", {}, ...rows.map(row => this.row(row, columns)))];
    const empty = !columns.length && h("tbody", {}, h("tr", {}, h("td", { className: "empty-table muted" }, "No columns yet: add one, or have an agent fill the table from a CSV file.")));
    this.grid.replaceChildren(...kids([h("thead", {}, h("tr", {}, ...columns.map(c => this.header(c)), h("th", { className: "actions" }))), bodies, empty]));
    const input = editing && this.grid.querySelector<HTMLInputElement>(`[data-cell="${editing.cell}"]`);
    if (input) {
      input.value = editing.text;
      input.focus();
      if (input.type === "text") input.setSelectionRange(editing.from, editing.to);
    }
  }

  private header(column: Column) {
    const sorting = this.sorted?.column === column.id ? (this.sorted.down ? " ↓" : " ↑") : "";
    const sort = h("button", { className: "quiet name", title: "Sort", onclick: () => this.sortBy(column.id) }, column.name, sorting);
    return h("th", {}, h("div", {}, sort, h("button", { className: "icon quiet", title: "Column", ariaLabel: `Column ${column.name}`, onclick: () => this.columnDialog(column) }, icon("more"))));
  }

  /** Sorts by a column, rising, then falling, then not. */
  private sortBy(id: string) {
    const was = this.sorted?.column === id ? this.sorted : undefined;
    this.sorted = !was ? { column: id, down: false } : was.down ? undefined : { column: id, down: true };
    this.draw();
  }

  private row(row: Yjs.Map<unknown>, columns: Column[]) {
    const remove = () => this.doc!.transact(() => this.rows().delete(this.rows().toArray().indexOf(row), 1));
    return h("tr", {}, ...columns.map(c => h("td", {}, this.cell(row, c))), h("td", { className: "actions" }, h("button", { className: "icon quiet", title: "Delete row", ariaLabel: "Delete row", onclick: remove }, icon("close"))));
  }

  /** A cell's editor, by its column's type; a text field takes its change once left. */
  private cell(row: Yjs.Map<unknown>, column: Column): HTMLElement {
    const value = row.get(column.id);
    const put = (next: unknown) => this.doc!.transact(() => (next === undefined ? row.delete(column.id) : row.set(column.id, next)));
    if (column.type === "checkbox") return h("input", { type: "checkbox", checked: value === true, ariaLabel: column.name, onchange: (event: Event) => put((event.target as HTMLInputElement).checked) });
    if (column.type === "choice") {
      const options = [...new Set([...column.choices, ...(typeof value === "string" ? [value] : [])])];
      const select = h("select", { ariaLabel: column.name }, h("option", { value: "" }), ...options.map(choice => h("option", { value: choice, selected: choice === value }, choice)));
      select.onchange = () => put(select.value || undefined);
      return select;
    }
    // A value that does not fit its column, as one written before the column had its type, shows as text.
    const fits = value === undefined || (column.type === "number" ? typeof value === "number" : column.type !== "date" || /^\d{4}-\d{2}-\d{2}$/.test(String(value)));
    const input = h("input", { type: fits && column.type !== "text" ? column.type : "text", value: value === undefined ? "" : String(value), ariaLabel: column.name });
    if (input.type === "number") input.step = "any";
    input.dataset.cell = `${row.get("id")}/${column.id}`;
    const shown = input.value;
    input.onblur = () => {
      const text = input.value.trim();
      if (input.value !== shown) put(text === "" ? undefined : column.type === "number" ? convert(text, "number") : input.value);
    };
    input.onkeydown = (event: KeyboardEvent) => event.key === "Enter" && input.blur();
    return input;
  }

  private addRow() {
    if (!this.Y || !this.doc) return;
    const row = new this.Y.Map<unknown>();
    const id = newId();
    row.set("id", id);
    this.filter.value = "";
    this.doc.transact(() => this.rows().push([row]));
    this.grid.querySelector<HTMLElement>(`[data-cell^="${id}/"]`)?.focus();
  }

  /** A column's name, type and choices, or a new column's; and deleting it. Changing a column's type converts the
   * values that read as the new type. */
  private columnDialog(column?: Column) {
    const doc = this.doc!;
    const columns = doc.getArray<Yjs.Map<unknown>>("columns");
    const name = h("input", { value: column?.name ?? "", autofocus: true });
    const type = h("select", {}, ...Object.entries(COLUMN_TYPES).map(([value, label]) => h("option", { value, selected: value === (column?.type ?? "text") }, label)));
    const choices = h("textarea", { rows: 4, value: (column?.choices ?? []).join("\n") });
    const choicesField = field("Choices", choices, "One per line.");
    type.onchange = () => (choicesField.hidden = type.value !== "choice");
    choicesField.hidden = type.value !== "choice";
    const save = () => {
      const named = name.value.trim();
      if (!named || named === "id" || this.columns().some(c => c.map !== column?.map && c.name === named)) return toast("Give the column a name that no other column has, other than id.");
      const kind = type.value as ColumnType;
      doc.transact(() => {
        const map = column?.map ?? new this.Y!.Map<unknown>();
        if (!column) {
          map.set("id", newId());
          columns.push([map]);
        }
        const id = map.get("id") as string;
        const rows = this.rows().toArray().filter(row => row.has(id));
        if (column && column.type !== kind) for (const row of rows) row.set(id, convert(row.get(id), kind));
        map.set("name", named);
        map.set("type", kind);
        const list = choices.value.split("\n").map(c => c.trim()).filter(Boolean);
        if (kind === "choice") map.set("choices", [...new Set([...list, ...rows.map(row => String(row.get(id)))])]);
        else map.delete("choices");
      });
      dialog.close();
    };
    const remove =
      column &&
      confirmed("Delete column", "Delete it for everyone", async () => {
        doc.transact(() => columns.delete(columns.toArray().indexOf(column.map), 1));
        dialog.close();
      });
    const dialog = modal(column ? column.name : "New column", form(save, field("Name", name), field("Type", type), choicesField, h("div", { className: "buttons" }, remove, h("button", { className: "primary" }, column ? "Save" : "Add"))));
  }
}

/** When an item happened: a message as its sender's clock says it was sent, if it says; else when it arrived. */
const sentAt = (item: Item) => (item.type === "message" && item.sent_at) || item.at;

function timeOf(at: number): HTMLElement {
  return h("time", { dateTime: new Date(at).toISOString(), title: new Date(at).toLocaleString() }, new Date(at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }));
}

function download(bytes: Uint8Array, name: string) {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
  h("a", { href: url, download: name }).click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
