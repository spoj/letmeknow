// Browser end-to-end test: URL serves the trusted static build, separately from the real local backend.
// With the native binary (BIN), Matt's laptop uses the build's configured backend and joins Ann's
// chat from a link, becoming his identity's first device as it does, and they talk and pass files both ways; it joins
// her doc and her table and they edit them both ways; Matthew's desk adds his phone by a device link, the phone joins a chat by a link
// and is renamed, and a kiosk on an identity of its own moves to his; the laptop keeps everything
// across a reload, a second tab works through the first and takes over when it closes; refusals, files kept and
// deleted, and the service worker's updates.
import { execFile, execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { chromium } from "playwright";
import * as Y from "yjs";

const { URL: SITE, BIN, LETMEKNOW_RELAY, LETMEKNOW_MEMBERSHIP, FRONTEND_DIST } = process.env;
const tmp = mkdtempSync(join(tmpdir(), "lmk-browser-"));
const check = (condition, message) => {
  if (!condition) throw new Error(`FAIL: ${message}`);
  console.log(`ok - ${message}`);
};
const local = link => SITE + new URL(link).pathname + new URL(link).hash;

const natives = [];
let passed = false;
/** A native session in a home of its own: its own device. */
function native(name) {
  const env = { ...process.env, LETMEKNOW_HOME: join(tmp, name) };
  const proc = spawn(BIN, ["--session", name, "listen", "--hold", "0"], { env, stdio: ["ignore", "pipe", "inherit"] });
  natives.push(proc);
  const exited = new Promise(resolve => proc.once("exit", resolve));
  const events = [];
  const waiters = new Set();
  createInterface({ input: proc.stdout }).on("line", line => {
    events.push(JSON.parse(line));
    for (const wake of waiters) wake();
  });
  return {
    /** Stops it; resolves once its process has ended, so that another may start on its home. */
    stop: () => (proc.kill(), exited),
    run: (...args) => JSON.parse(execFileSync(BIN, ["--session", name, ...args], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] })),
    /** As `run`, while the test goes on watching the pages. */
    start: (...args) =>
      new Promise((resolve, reject) =>
        execFile(BIN, ["--session", name, ...args], { env, encoding: "utf8" }, (error, stdout) => (error ? reject(error) : resolve(JSON.parse(stdout))))
      ),
    /** The first event it printed that `predicate` accepts. */
    printed: (predicate, ms = 30_000) =>
      new Promise((resolve, reject) => {
        const look = () => {
          const event = events.find(predicate);
          if (!event) return;
          clearTimeout(timer);
          waiters.delete(look);
          resolve(event);
        };
        const timer = setTimeout(() => (waiters.delete(look), reject(new Error(`FAIL: ${name} printed no such event; it printed ${JSON.stringify(events.slice(-5))}`))), ms);
        waiters.add(look);
        look();
      })
  };
}

let ann = native("ann");
const desk = native("desk");
const browser = await chromium.launch({ args: ["--ignore-certificate-errors"] });
const pages = {};
const pageErrors = [];
const requests = [];
const sockets = [];
function watch(name, page) {
  pages[name] = page;
  page.on("request", request => requests.push([request.url(), request.resourceType()]));
  page.on("websocket", socket => sockets.push(socket.url()));
  page.on("console", message => message.type() === "error" && console.log(`${name}: ${message.text()}`));
  page.on("pageerror", error => { pageErrors.push(`${name}: ${error}`); console.log(`${name}: ${error}`); });
  return page;
}
/** Tests both explicit localStorage backend choices and the trusted build's defaults (`own`). */
async function open(name, options, own = false) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true, permissions: ["clipboard-read", "clipboard-write"], ...options });
  await context.addInitScript(
    ([relay, membership]) => {
      if (relay) localStorage.setItem("lmk relay", relay);
      if (membership) localStorage.setItem("lmk membership", membership);
      window.toasts = [];
      new MutationObserver(records => records.forEach(r => r.addedNodes.forEach(node => node.className === "toast" && window.toasts.push(node.textContent)))).observe(document, {
        childList: true,
        subtree: true
      });
    },
    own ? [] : [LETMEKNOW_RELAY, LETMEKNOW_MEMBERSHIP]
  );
  return watch(name, await context.newPage());
}
/** The hashes of the files a browser keeps in IndexedDB. */
const kept = page =>
  page.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const db = indexedDB.open("lmk5");
        db.onsuccess = () => {
          const request = db.result.transaction("files").objectStore("files").getAllKeys();
          request.onsuccess = () => (db.result.close(), resolve(request.result));
          request.onerror = () => reject(request.error);
        };
      })
  );
const text = page => page.locator(".cm-content").evaluate(content => content.cmTile.view.state.doc.toString());
const call = (page, method, ...args) => page.evaluate(([method, args]) => new Promise((resolve, reject) => {
  const channel = new BroadcastChannel("lmk5");
  const id = crypto.randomUUID();
  const timer = setTimeout(() => { channel.close(); reject(new Error(`no answer to ${method}`)); }, 30_000);
  channel.onmessage = ({ data }) => {
    if (data.ready) channel.postMessage({ id, method, args });
    if (data.id !== id || data.method) return;
    clearTimeout(timer);
    channel.close();
    if (data.error !== undefined) reject(new Error(data.error));
    else resolve(data.result);
  };
  channel.postMessage({ id, method, args });
}), [method, args]);
const outcome = promise => promise.then(value => ({ value }), error => ({ error: String(error) }));

/** Holds the transaction containing a real mutation, not the preceding node save. */
async function holdSave(page, target) {
  await page.evaluate(target => {
    window.storageFault = { target, phase: "armed", events: [], attempts: { records: 0, files: 0 }, committed: { records: 0, files: 0 }, strict: true };
    if (window.storageFaultInstalled) return;
    window.storageFaultInstalled = true;
    const transaction = IDBDatabase.prototype.transaction;
    IDBDatabase.prototype.transaction = function (stores, mode, options) {
      const tx = transaction.call(this, stores, mode, options);
      const fault = window.storageFault;
      if (mode === "readwrite" && ["records", "files"].includes(stores)) {
        fault.strict &&= options?.durability === "strict";
        fault.attempts[stores]++;
        tx.addEventListener("complete", () => fault.committed[stores]++);
      }
      return tx;
    };
    const put = IDBObjectStore.prototype.put;
    IDBObjectStore.prototype.put = function (value, key) {
      const request = put.call(this, value, key);
      const fault = window.storageFault;
      const target = fault.target;
      const name = typeof key === "string" ? key : new TextDecoder().decode(key);
      if (fault.phase !== "armed" || this.name !== target.store || (target.key && name !== target.key) || (target.prefix && !name.startsWith(target.prefix)) || (target.text && !new TextDecoder().decode(value).includes(target.text))) return request;
      fault.phase = "held";
      fault.key = typeof key === "string" ? key : [...(key instanceof ArrayBuffer ? new Uint8Array(key) : key)];
      fault.bytes = [...value];
      const tx = this.transaction;
      tx.addEventListener("complete", () => { fault.phase = "committed"; });
      tx.addEventListener("abort", () => { fault.phase = "aborted"; });
      const spin = () => {
        if (fault.release === "abort") tx.abort();
        else if (fault.release !== "commit") this.get(key).onsuccess = spin;
      };
      request.addEventListener("success", spin);
      return request;
    };
    const post = BroadcastChannel.prototype.postMessage;
    BroadcastChannel.prototype.postMessage = function (message) {
      if (message.event) window.storageFault.events.push({ ...message.event, phase: window.storageFault.phase });
      return post.call(this, message);
    };
  }, target);
}

async function recover(page) {
  const deadline = Date.now() + 30_000;
  for (;;) {
    await page.evaluate(() => { window.recoveryAttempt = window.toasts.length; });
    await page.getByRole("button", { name: "Retry saving and reload" }).click();
    await page.waitForFunction(() => window.recoveryAttempt === undefined || window.toasts.slice(window.recoveryAttempt).includes("local state changed during the recovery save; retry saving again before reloading"));
    if (await page.evaluate(() => window.recoveryAttempt === undefined)) return;
    check(Date.now() < deadline, "recovery explicitly refuses a concurrent background write; another explicit retry is required");
  }
}

const record = (page, store, key) => page.evaluate(([store, key]) => new Promise((resolve, reject) => {
  const request = indexedDB.open("lmk5");
  request.onsuccess = () => {
    const db = request.result;
    const value = db.transaction(store).objectStore(store).get(typeof key === "string" ? key : new Uint8Array(key));
    value.onsuccess = () => { db.close(); resolve(value.result && [...value.result]); };
    value.onerror = () => reject(value.error);
  };
  request.onerror = () => reject(request.error);
}), [store, key]);

async function until(produce, accept, ms = 20_000) {
  const deadline = Date.now() + ms;
  let value = await produce();
  while (!accept(value) && Date.now() < deadline) {
    await new Promise(resolve => setTimeout(resolve, 200));
    value = await produce();
  }
  return value;
}

try {
  await ann.printed(e => e.type === "ready");
  await desk.printed(e => e.type === "ready");
  ann.run("identity", "create", "Ann");
  desk.run("identity", "create", "Matthew");

  // Another version's database is left as it is; this version's, incomplete, is refused visibly, never reset.
  for (const [name, version] of [["lmk", 4], ["lmk5", 1]]) {
    const legacy = await open("legacy", { viewport: { width: 1280, height: 800 } }, true);
    const errors = [];
    legacy.on("pageerror", error => errors.push(error.message));
    await legacy.goto(`${SITE}/blank.html`);
    check(await legacy.locator("script").count() === 0 && await legacy.evaluate(() => !navigator.serviceWorker.controller), "legacy setup page has no app script or service worker");
    await legacy.evaluate(([name, version]) => new Promise((resolve, reject) => {
      const request = indexedDB.open(name, version);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("records").put(new Uint8Array([1]), new Uint8Array([1]).buffer);
        request.result.createObjectStore("files").put(new Uint8Array([1]), "00");
      };
      request.onsuccess = () => (request.result.close(), resolve());
      request.onerror = () => reject(request.error);
    }), [name, version]);
    await legacy.goto(SITE);
    if (name === "lmk") await legacy.getByLabel("Your name").waitFor();
    else await legacy.getByRole("alert").filter({ hasText: "stored session is incomplete" }).waitFor();
    const old = await legacy.evaluate(name => new Promise((resolve, reject) => {
      const request = indexedDB.open(name);
      request.onsuccess = () => {
        const db = request.result;
        const tx = db.transaction(["records", "files"]);
        const records = tx.objectStore("records").getAll();
        const files = tx.objectStore("files").getAllKeys();
        tx.oncomplete = () => { db.close(); resolve([db.version, [...records.result[0]], files.result]); };
        tx.onerror = () => reject(tx.error);
      };
      request.onerror = () => reject(request.error);
    }), name);
    check(JSON.stringify(old) === JSON.stringify([version, [1], ["00"]]), `browser database ${name} v${version} keeps its version, records and files`);
    check(!errors.length, `browser database ${name} startup errors reach the UI, not unhandled promises: ${errors}`);
    await legacy.context().close();
    delete pages.legacy;
  }

  // Invited by link: what it is, a name, Join, and the chat.
  let laptop = await open("laptop", { viewport: { width: 1280, height: 800 } }, true);
  const invite = ann.run("invite", "--name", "Plans");
  await laptop.goto(local(invite.link));
  await laptop.getByRole("heading", { name: "You're invited" }).waitFor();
  await laptop.getByLabel("Your name").fill("Matt");
  await laptop.getByRole("button", { name: "Join", exact: true }).click();
  await laptop.locator(".people", { hasText: "Ann" }).waitFor();
  check(new URL(laptop.url()).pathname === "/", "a browser joins from an invite link, with a click");
  await ann.printed(e => e.type === "joined");
  check(true, "the native session sees the browser join");
  const matt = await until(
    () => ann.run("members", `--group=${invite.group}`).members.find(m => !m.you),
    m => m?.identity?.name === "Matt"
  );
  check(matt.identity.how === "unknown" && matt.device === "laptop", "the welcome screen makes the browser its identity's first device, which others know by its own name");

  // Messages both ways, with a reply.
  const hello = ann.run("send", "hello from the terminal").id;
  await laptop.getByText("hello from the terminal").waitFor();
  check(true, "the browser shows a native session's message");
  await laptop.locator(".messages li", { hasText: "hello from the terminal" }).hover();
  await laptop.locator(".messages li", { hasText: "hello from the terminal" }).getByRole("button", { name: "Reply" }).click();
  await laptop.getByPlaceholder("Message").fill("hello from the browser");
  await laptop.getByPlaceholder("Message").press("Enter");
  const reply = await ann.printed(e => e.type === "message" && e.content === "hello from the browser");
  check(reply.reply_to === hello && reply.from.startsWith("Matt · "), "a native session gets the browser's reply");
  const ticks = laptop.locator(".messages li", { hasText: "hello from the browser" }).locator(".ticks");
  const receipt = await until(
    () => ticks.textContent(),
    t => t.includes("read by Ann")
  );
  check(receipt.startsWith("✓✓") && receipt.includes("read by Ann"), "the browser shows that another member holds its message, and who read it");

  // Members: Ann's identity is only her own claim to the laptop.
  await laptop.locator(".people").click();
  const annRow = laptop.locator("dialog .people-list li", { hasText: "Ann" });
  check((await annRow.textContent()).includes("their own name"), "members show an identity's name as its own claim");
  await laptop.locator("dialog").getByRole("button", { name: "Close" }).click();

  // Attachments both ways.
  const token = join(tmp, "token.txt");
  writeFileSync(token, "s3cret");
  ann.run("send", "--attach", token, "the token");
  const download = laptop.locator(".messages li", { hasText: "the token" }).locator(".download");
  await download.waitFor();
  const [saved] = await Promise.all([laptop.waitForEvent("download"), download.click()]);
  check(readFileSync(await saved.path(), "utf8") === "s3cret", "the browser fetches a native session's attachment");
  await laptop.locator(".composer input[type=file]").setInputFiles({ name: "notes.txt", mimeType: "text/plain", buffer: Buffer.from("from the browser") });
  await laptop.getByPlaceholder("Message").fill("my notes");
  await laptop.getByRole("button", { name: "Send" }).click();
  const withFile = await ann.printed(e => e.type === "message" && e.content === "my notes");
  const arrived = withFile.attachment.path ? withFile.attachment : await ann.printed(e => e.type === "attachment" && e.name === "notes.txt");
  check(readFileSync(arrived.path, "utf8") === "from the browser", "a native session gets the browser's attachment");

  // A doc, edited both ways.
  const notes = join(tmp, "notes.md");
  writeFileSync(notes, "- [ ] alpha\n- [ ] beta\n");
  const doc = ann.run("invite", "--kind", "doc", "--name", "Notes", notes);
  await laptop.getByRole("button", { name: "Join", exact: true }).first().click();
  await laptop.locator("dialog").getByLabel("Invite link").fill(doc.link);
  await laptop.locator("dialog").getByRole("button", { name: "Join", exact: true }).click();
  await laptop.locator(".cm-content").waitFor();
  check(
    (await until(
      () => text(laptop),
      t => t === "- [ ] alpha\n- [ ] beta\n"
    )) === "- [ ] alpha\n- [ ] beta\n",
    "the browser gets a doc's text when it joins"
  );
  await laptop.locator(".cm-line", { hasText: "beta" }).click();
  await laptop.keyboard.press("End");
  await laptop.keyboard.type(" (browser)");
  const edited = await until(
    () => readFileSync(notes, "utf8"),
    t => t.includes("beta (browser)")
  );
  check(edited === "- [ ] alpha\n- [ ] beta (browser)\n", "an edit in the browser reaches the native session's file");
  writeFileSync(notes, "- [x] alpha\n- [ ] beta (browser)\n- [ ] gamma\n");
  const both = await until(
    () => text(laptop),
    t => t === "- [x] alpha\n- [ ] beta (browser)\n- [ ] gamma\n"
  );
  check(both === "- [x] alpha\n- [ ] beta (browser)\n- [ ] gamma\n", "and the native session's edit reaches the browser");
  const spec = join(tmp, "spec.txt");
  writeFileSync(spec, "the spec");
  const attached = ann.run("doc", "attach", `--group=${doc.group}`, spec);
  writeFileSync(notes, `- [x] alpha\n- [ ] beta (browser)\n- [ ] gamma\n${attached.markdown}\n`);
  const specHash = attached.link.slice(4, 68);
  check((await until(() => kept(laptop), hashes => hashes.includes(specHash))).includes(specHash), "the browser keeps a file the doc links");

  // A table, edited both ways: the browser shows the native session's CSV as a grid of typed cells.
  const leads = join(tmp, "leads.csv");
  writeFileSync(leads, "Name,Size,Done\nAcme,12,false\nGlobex,3,true\n");
  const table = ann.run("invite", "--kind", "table", "--name", "Leads", leads);
  await laptop.getByRole("button", { name: "Join", exact: true }).first().click();
  await laptop.locator("dialog").getByLabel("Invite link").fill(table.link);
  await laptop.locator("dialog").getByRole("button", { name: "Join", exact: true }).click();
  const cells = name => laptop.locator(`.grid input[aria-label="${name}"]`).evaluateAll(inputs => inputs.map(i => (i.type === "checkbox" ? String(i.checked) : i.value)).join());
  check((await until(() => cells("Name"), v => v === "Acme,Globex")) === "Acme,Globex", "the browser gets a table's rows when it joins");
  const typed = (await laptop.locator('.grid input[aria-label="Size"]').first().getAttribute("type")) === "number" && (await cells("Done")) === "false,true";
  check(typed, "and shows each column's cells by its type");
  await laptop.locator('.grid input[aria-label="Name"]').first().fill("Acme Corp");
  await laptop.locator('.grid input[aria-label="Name"]').first().press("Enter");
  check((await until(() => readFileSync(leads, "utf8"), t => t.includes(",Acme Corp,12,false\n"))).includes(",Acme Corp,12,false\n"), "a cell edited in the browser reaches the native session's file");
  await laptop.getByRole("button", { name: "Column", exact: true }).click();
  await laptop.locator("dialog").getByLabel("Name").fill("Owner");
  await laptop.locator("dialog").getByRole("button", { name: "Add" }).click();
  check((await until(() => readFileSync(leads, "utf8"), t => t.startsWith("id,Name,Size,Done,Owner\n"))).startsWith("id,Name,Size,Done,Owner\n"), "and so does a column added there");
  writeFileSync(leads, readFileSync(leads, "utf8").replace(",Globex,3,", ",Globex,5,"));
  check((await until(() => cells("Size"), v => v === "12,5")) === "12,5", "and the native session's edit reaches the browser");
  await laptop.getByRole("button", { name: "Delete row" }).last().click();
  const rows = await until(() => readFileSync(leads, "utf8"), t => !t.includes("Globex"));
  check(!rows.includes("Globex") && rows.includes("Acme Corp") && (await cells("Name")) === "Acme Corp", "a row deleted in the browser goes from the native session's file");

  // A device link adds a phone to Matthew's identity, made on his desk; the phone then joins a chat by a link.
  const phone = await open("phone", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const deviceLink = desk.run("identity", "invite").link;
  await phone.goto(local(deviceLink));
  await phone.getByRole("heading", { name: "Add this browser to your devices" }).waitFor();
  check((await phone.getByLabel("Device name").inputValue()) === "phone", "a phone suggests its own device name");
  await phone.getByRole("button", { name: "Add this browser" }).click();
  await phone.locator(".devices li", { hasText: "phone" }).waitFor();
  const devices = desk.run("identity", "list").devices;
  check(devices.length === 2 && devices.some(d => d.name === "phone"), "a device link adds the browser to the identity's devices");
  const team = desk.run("invite", "--name", "Team");
  await phone.locator(".back:visible").click();
  await phone.getByRole("button", { name: "Join", exact: true }).first().click();
  await phone.locator("dialog").getByLabel("Invite link").fill(team.link);
  await phone.locator("dialog").getByRole("button", { name: "Join", exact: true }).click();
  await desk.printed(e => e.type === "joined" && e.member === "phone", 60_000);
  check(true, "the phone joins a chat by a link, as a device of Matthew's, which shows by its device's name alone");
  await phone.locator(".back:visible").click();
  await phone.locator(".group-list button", { hasText: "Team" }).waitFor();
  check(true, "and lists it");
  desk.run("send", `--group=${team.group}`, "welcome, phone");
  await phone.locator(".group-list button", { hasText: "Team" }).click();
  await phone.getByText("welcome, phone").waitFor();
  check(true, "and reads what is sent there");
  const report = join(tmp, "report.txt");
  writeFileSync(report, "for the team");
  const before = await kept(phone);
  desk.run("send", `--group=${team.group}`, "--attach", report, "the report");
  await phone.locator(".messages li", { hasText: "the report" }).getByRole("button", { name: "Download report.txt" }).waitFor();
  const [reportHash, ...others] = (await kept(phone)).filter(hash => !before.includes(hash));
  check(reportHash && !others.length, "the phone keeps a file a message attached");

  // The phone is renamed: Matthew's desk lists it so, and its session shows the new name in the chat at once.
  await phone.locator(".back:visible").click();
  await phone.locator(".me").click();
  await phone.locator(".devices li", { hasText: "this browser" }).getByRole("button", { name: "Rename" }).click();
  await phone.locator("dialog").getByLabel("This device").fill("pocket");
  await phone.locator("dialog").getByRole("button", { name: "Rename" }).click();
  await phone.locator(".devices li", { hasText: "pocket" }).waitFor();
  const listed = await until(
    () => desk.run("identity", "list").devices.map(d => d.name),
    names => names.includes("pocket")
  );
  check(listed.includes("pocket") && !listed.includes("phone"), "a renamed browser shows under its new name in another device's list");
  const renamed = await until(
    () => desk.run("members", `--group=${team.group}`).members.map(m => m.device),
    devices => devices.includes("pocket")
  );
  check(renamed.includes("pocket"), "and in a group's members");
  await phone.locator(".back:visible").click();
  await phone.locator(".group-list button", { hasText: "Team" }).click();
  await phone.getByRole("button", { name: "Settings" }).click();
  await phone.getByRole("button", { name: "Leave chat" }).click();
  await phone.getByRole("button", { name: "Leave for good?" }).click();
  await desk.printed(e => e.type === "left" && e.member === "pocket");
  await phone.locator(".group-list button", { hasText: "Team" }).waitFor({ state: "detached" });
  const told = await phone.evaluate(() => window.toasts.splice(0));
  check(told.every(t => t.startsWith("Asked the others to remove you") || t.startsWith("You were removed from Team")), `the phone leaves the chat (${told.length} notices)`);
  await phone.reload();
  await phone.getByRole("button", { name: "New chat" }).waitFor();
  const left = await until(
    () => kept(phone),
    hashes => !hashes.includes(reportHash)
  );
  check(!left.includes(reportHash) && before.every(hash => left.includes(hash)), "and deletes the file no group links any longer");

  // A kiosk starts a chat as Kim, its own identity, then opens a device link of Matthew's: it moves to his identity,
  // leaving Kim, which ends, and the chat.
  const kiosk = await open("kiosk", { viewport: { width: 1280, height: 800 } });
  await kiosk.goto(SITE);
  await kiosk.getByLabel("Your name").fill("Kim");
  await kiosk.getByLabel("Device name").fill("kiosk");
  await kiosk.getByRole("button", { name: "Continue" }).click();
  await kiosk.getByRole("button", { name: "New chat" }).click();
  await kiosk.locator("dialog").getByLabel("Name").fill("Kiosk notes");
  await kiosk.locator("dialog").getByRole("button", { name: "Rename" }).click();
  await kiosk.locator(".group-list button", { hasText: "Kiosk notes" }).waitFor();
  await kiosk.locator("dialog").getByRole("button", { name: "Close" }).click();
  check((await kiosk.locator(".me").textContent()).includes("Kim"), "the welcome screen makes the browser its identity's first device, and a new chat opens its settings");
  await kiosk.goto(local(desk.run("identity", "invite").link));
  const moving = kiosk.locator("dialog", { hasText: "Move this browser to another identity" });
  await moving.waitFor();
  const moveSaid = await moving.textContent();
  check(moveSaid.includes("It leaves Kim, which ends") && moveSaid.includes("as Kim: Kiosk notes"), "a device link opened in a browser on an identity says what moving does");
  await moving.getByRole("button", { name: "Move this browser" }).click();
  await kiosk.locator(".devices li", { hasText: "this browser" }).waitFor();
  check((await kiosk.locator(".me").textContent()).includes("Matthew"), "and moves the browser to the identity of the link");
  const moved = desk.run("identity", "list").devices.map(d => d.name);
  check(moved.includes("kiosk") && (await kiosk.locator(".group-list button", { hasText: "Kiosk notes" }).count()) === 0, "which lists it, and it left Kim's chat");

  check((await laptop.evaluate(() => window.toasts)).length === 0, "the laptop showed no error before its reload");

  // A reload keeps the laptop's groups, messages and doc, and it still talks.
  const recorded = await laptop.evaluate(
    gid =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open("lmk5");
        open.onsuccess = () => {
          const records = open.result.transaction("records").objectStore("records");
          const count = records.count(new TextEncoder().encode(`lmk/kind/doc/${gid}`));
          count.onsuccess = () => resolve(count.result === 1);
          count.onerror = () => reject(count.error);
        };
      }),
    doc.group
  );
  check(recorded, "the browser keeps its doc as the doc plugin's record");
  const stored = await laptop.evaluate(
    id =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open("lmk5");
        open.onsuccess = () => {
          const records = open.result.transaction("records").objectStore("records");
          const bytes = id.match(/../g).map(byte => parseInt(byte, 16));
          // The id's start, as the CLI shows it: the record whose key begins with it.
          const at = prefix => {
            const start = [...new TextEncoder().encode(prefix), ...bytes];
            return records.get(IDBKeyRange.bound(new Uint8Array(start), new Uint8Array([...start, ...Array(32 - bytes.length).fill(255)])));
          };
          const [timeline, node] = [at("lmk/web/message/"), at("lmk/node/message/")];
          const content = record => record.result && JSON.parse(new TextDecoder().decode(record.result)).payload.content;
          node.onsuccess = () => resolve([content(timeline), content(node)]);
          node.onerror = () => reject(node.error);
        };
      }),
    hello
  );
  check(stored[0] === "hello from the terminal" && stored[1] === "", "the browser's timeline keeps the messages it showed, and the session forgets their text");
  await laptop.reload();
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  await laptop.getByText("hello from the terminal", { exact: true }).waitFor();
  check((await laptop.locator(".group-list button").count()) === 3, "a reloaded browser keeps its groups and their messages");
  ann.run("send", `--group=${invite.group}`, "after the reload");
  await laptop.getByText("after the reload").waitFor();
  await laptop.getByPlaceholder("Message").fill("still here");
  await laptop.getByPlaceholder("Message").press("Enter");
  await ann.printed(e => e.type === "message" && e.content === "still here");
  check(true, "and still exchanges messages");
  await laptop.locator(".group-list button", { hasText: "Notes" }).click();
  check(
    (
      await until(
        () => text(laptop),
        t => t.includes("gamma")
      )
    ).includes("gamma"),
    "and its doc"
  );

  // A second tab works through the session the first one runs, and runs it once the first closes.
  const second = watch("second tab", await laptop.context().newPage());
  await second.goto(SITE);
  await second.locator(".group-list button", { hasText: "Plans" }).click();
  await second.getByText("still here").waitFor();
  check(true, "a second tab shows the session's groups and messages");
  await second.locator("textarea:visible").fill("from the second tab");
  await second.locator("textarea:visible").press("Enter");
  await ann.printed(e => e.type === "message" && e.content === "from the second tab");
  check(true, "and sends through it");
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  ann.run("send", `--group=${invite.group}`, "to both tabs");
  await laptop.getByText("to both tabs").waitFor();
  await second.getByText("to both tabs").waitFor();
  check(true, "every tab hears the session's events");
  check((await laptop.evaluate(() => window.toasts)).length === 0, "the first tab showed no error");
  await laptop.close();
  delete pages.laptop;
  laptop = second;
  ann.run("send", `--group=${invite.group}`, "after the first tab closed");
  await laptop.getByText("after the first tab closed").waitFor({ timeout: 60_000 });
  await laptop.locator("textarea:visible").fill("the second tab runs it");
  await laptop.locator("textarea:visible").press("Enter");
  await ann.printed(e => e.type === "message" && e.content === "the second tab runs it");
  check(true, "when the first tab closes, the second runs the session");

  // The laptop's device link adds a native session's device to its identity.
  await laptop.locator(".me").click();
  await laptop.locator(".devices li", { hasText: "this browser" }).waitFor();
  await laptop.getByRole("button", { name: "Add a device" }).click();
  const link = await laptop.locator("dialog .copy code").first().textContent();
  check(link.includes("#5.d.") && (await laptop.locator("dialog .qr path").getAttribute("d")).length > 100, "the browser makes a device link, with a QR code");
  const tablet = native("tablet");
  await tablet.printed(e => e.type === "ready");
  const joining = tablet.start("identity", "join", link);
  await laptop.getByText("Added. The device can now join your chats and documents.").waitFor();
  await joining;
  await until(
    () => laptop.locator(".devices li").count(),
    n => n === 2
  );
  check(tablet.run("identity", "list").name === "Matt", "a native device joins the browser's identity by its link");

  // The laptop starts a chat, and the tablet joins it by the link the laptop shows.
  await laptop.getByRole("button", { name: "New chat" }).click();
  await laptop.locator("dialog").getByLabel("Name").fill("Ideas");
  await laptop.locator("dialog").getByRole("button", { name: "Rename" }).click();
  await laptop.locator(".group-list button.on", { hasText: "Ideas" }).waitFor();
  await laptop.locator("dialog").getByRole("button", { name: "Make a link" }).click();
  const ideasLink = await laptop.locator("dialog .copy code").first().textContent();
  check(tablet.run("join", ideasLink).members.length === 2, "a native session joins a chat the browser started, by its link");
  await laptop.getByText("They joined the chat.").waitFor();
  await laptop.locator("dialog").waitFor({ state: "detached" });
  const ideas = tablet.run("groups").find(g => g.name === "Ideas");
  check(JSON.stringify(ideas.membership).includes(LETMEKNOW_RELAY), "on the membership service compiled into the trusted frontend");
  const browsers = await until(
    () => tablet.run("identity", "list").devices.find(d => !d.you).groups ?? [],
    groups => groups.some(g => g.name === "Ideas")
  );
  const shown = browsers.find(g => g.name === "Ideas");
  check(shown && !shown.session && shown.kind === "chat" && shown.members.length === 1, "a native device hears which groups the browser is in, and with whom");
  const line = laptop.locator(".devices .in-groups li", { hasText: "tablet: Ideas" });
  await until(
    async () => (await laptop.locator(".me").click(), await line.count()),
    n => n > 0
  );
  check((await line.count()) === 1, "the browser's devices page shows the groups of a native device's sessions");
  await laptop.locator(".group-list button", { hasText: "Ideas" }).click();
  await laptop.locator(".people", { hasText: "Matt · " }).waitFor();
  await laptop.getByRole("button", { name: "Settings" }).click();
  await laptop.getByRole("button", { name: "End for everyone" }).click();
  await laptop.getByRole("button", { name: "Remove everyone and end this chat?" }).click();
  await laptop.locator(".group-list button", { hasText: "Ideas" }).waitFor({ state: "detached" });
  await tablet.printed(e => e.type === "removed" && e.by === "laptop");
  check(!tablet.run("groups").some(g => g.name === "Ideas"), "the browser ends a chat for everyone");
  await tablet.stop();

  // Ann adds Carl, whom the laptop knows only by his identity's own name.
  const carl = native("carl");
  await carl.printed(e => e.type === "ready");
  carl.run("identity", "create", "Carl");
  carl.run("join", ann.run("invite", `--group=${invite.group}`).link);
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  const added = laptop.locator(".messages li.event", { hasText: "added Carl" });
  await added.waitFor();
  check((await added.locator(".who").last().textContent()).includes("Carl · ") && (await added.locator(".who").last().textContent()).endsWith("(unverified)"), "the browser shows another identity's name as unverified");

  // A message larger than members take is not sent: the timeline keeps its text, says why, and offers Retry.
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  const tooLong = `too long ${"x".repeat(1_100_000)}`;
  await laptop.locator("textarea:visible").fill(tooLong);
  await laptop.locator("textarea:visible").press("Enter");
  const failed = laptop.locator(".messages li.unsent", { hasText: "too long" });
  await failed.waitFor();
  check((await failed.textContent()).includes("over the 1 MiB members take"), "a message larger than members take is not sent, and the timeline keeps it, saying why");
  check((await failed.getByRole("button", { name: "Retry" }).count()) === 1, "with Retry");
  await failed.getByRole("button", { name: "Drop" }).click();
  await until(() => failed.count(), n => n === 0);
  check(true, "and drops it when asked");
  await carl.stop();

  // Observe the actual consumer mutations, after the node's earlier receive-state transaction succeeded.
  for (const kind of ["doc", "table", "timeline"]) {
    for (const decision of ["commit", "abort"]) {
      const gid = kind === "doc" ? doc.group : kind === "table" ? table.group : invite.group;
      const marker = kind === "timeline" ? `Plans durable ${decision}` : `durable-${kind}-${decision}`;
      await laptop.locator(".group-list button", { hasText: kind === "doc" ? "Notes" : kind === "table" ? "Leads" : "Plans" }).click();
      await call(laptop, "flush", false);
      const target = kind === "timeline"
        ? { store: "records", prefix: "lmk/web/timeline/", text: marker }
        : { store: "records", key: `lmk/kind/${kind}/${gid}` };
      await holdSave(laptop, target);
      if (kind === "doc") writeFileSync(notes, readFileSync(notes, "utf8") + `${marker}\n`);
      else if (kind === "table") writeFileSync(leads, readFileSync(leads, "utf8").replace(/,Acme Corp,|,durable-table-commit,/, `,${marker},`));
      else ann.run("name", `--group=${gid}`, marker);
      await laptop.waitForFunction(() => window.storageFault.phase === "held");
      await call(laptop, "me");
      const eventType = kind === "timeline" ? "settings" : "edited";
      check(await laptop.evaluate(([type, group]) => !window.storageFault.events.some(e => e.type === type && e.group === group), [eventType, gid]), `${kind} callback waits for the transaction containing its mutation`);
      const failedKey = await laptop.evaluate(() => window.storageFault.key);
      await laptop.evaluate(decision => { window.storageFault.release = decision; }, decision);
      if (decision === "commit") {
        await laptop.waitForFunction(([type, group]) => window.storageFault.events.some(e => e.type === type && e.group === group), [eventType, gid]);
        check(await laptop.evaluate(([type, group]) => window.storageFault.strict && window.storageFault.events.filter(e => e.type === type && e.group === group).every(e => e.phase === "committed"), [eventType, gid]), `${kind} callback follows strict transaction completion`);
      } else {
        await laptop.getByRole("button", { name: "Retry saving and reload" }).waitFor();
        const refused = await outcome(call(laptop, "flush", false));
        check(refused.error?.includes("could not be saved") && await laptop.evaluate(([type, group]) => !window.storageFault.events.some(e => e.type === type && e.group === group), [eventType, gid]), `${kind} callback cannot escape a real transaction abort`);
        await recover(laptop);
        await laptop.locator(".group-list button", { hasText: kind === "doc" ? "Notes" : kind === "table" ? "Leads" : "Plans" }).click();
        const bytes = await record(laptop, "records", failedKey);
        check(new TextDecoder().decode(new Uint8Array(bytes)).includes(marker), `${kind} retry preserves the actual failed consumer record across reload`);
      }
      if (kind === "doc") check((await until(() => text(laptop), value => value.includes(marker))).includes(marker), "the document consumer reads the persisted peer edit");
      else if (kind === "table") check((await until(() => cells("Name"), value => value === marker)) === marker, "the table consumer reads the persisted peer edit");
      else check(JSON.parse(await call(laptop, "items", gid, false)).some(item => item.type === "settings" && item.settings.name === marker), "the timeline consumer reads its one-time persisted settings entry");
    }
  }

  // Only files abort: the received link and record saves succeed, but the browser cannot claim to hold the bytes.
  const fileChat = ann.run("invite", "--name", "File durability");
  await call(laptop, "request", JSON.stringify({ cmd: "join", target: fileChat.link }));
  await laptop.locator(".group-list button", { hasText: "File durability" }).click();
  const original = "original ciphertext retry bytes\n";
  const retryFile = join(tmp, "durable-file.txt");
  writeFileSync(retryFile, original);
  await holdSave(laptop, { store: "files" });
  const sendingFile = outcome(ann.start("send", `--group=${fileChat.group}`, "--attach", retryFile, "file transaction abort"));
  await laptop.waitForFunction(() => window.storageFault.phase === "held");
  check(await laptop.evaluate(() => window.storageFault.committed.records > 0), "record transactions complete while the ciphertext transaction is held");
  const fileHash = await laptop.evaluate(() => window.storageFault.key);
  await laptop.evaluate(() => { window.storageFault.release = "abort"; });
  await laptop.getByRole("button", { name: "Retry saving and reload" }).waitFor();
  const sentFile = await sendingFile;
  check(!sentFile.error && sentFile.value.attachment.pending === true && !sentFile.value.attachment.held_by, "the real sender receives no browser holder acknowledgement after a files-only abort");
  const failedItems = JSON.parse(await call(laptop, "items", fileChat.group, false));
  const failedAttachment = failedItems.find(item => item.content === "file transaction abort").attachment;
  check(!failedAttachment.kept && !(await kept(laptop)).includes(fileHash), "neither the browser nor IndexedDB claims the aborted ciphertext is kept");
  check(await laptop.evaluate(hash => !window.storageFault.events.some(e => e.type === "file" && e.hash === hash), fileHash), "no file-ready callback escapes the ciphertext abort");
  await holdSave(laptop, { store: "files", key: fileHash });
  const retryingFiles = outcome(call(laptop, "flush", true));
  await laptop.waitForFunction(() => window.storageFault.phase === "held");
  ann.run("send", `--group=${fileChat.group}`, "arrived during ciphertext recovery");
  check((await until(() => call(laptop, "items", fileChat.group, false), items => items.includes("arrived during ciphertext recovery"))).includes("arrived during ciphertext recovery"), "records change while the ciphertext recovery transaction is in flight");
  await laptop.evaluate(() => { window.storageFault.release = "commit"; });
  check((await retryingFiles).error?.includes("changed during the recovery save"), "a ciphertext retry also refuses reload when records changed during its transaction");
  check((await kept(laptop)).includes(fileHash) && await call(laptop, "file", failedAttachment.link) === undefined, "a committed recovery file is not published by the terminally failed process before reload");
  await ann.stop();
  await recover(laptop);
  await laptop.locator(".group-list button", { hasText: "File durability" }).click();
  check((await kept(laptop)).includes(fileHash) && new TextDecoder().decode(new Uint8Array(await call(laptop, "file", failedAttachment.link))) === original, "with the only peer offline, retry and reload recover the original plaintext from retained ciphertext");
  ann = native("ann");
  await ann.printed(e => e.type === "ready");

  // A direct add must reject too, rather than returning its link before the ciphertext commit.
  await holdSave(laptop, { store: "files" });
  const addingFile = outcome(call(laptop, "add_file", fileChat.group, [...Buffer.from("unacknowledged addition")]));
  await laptop.waitForFunction(() => window.storageFault.phase === "held");
  await laptop.evaluate(() => { window.storageFault.release = "abort"; });
  const addedFile = await addingFile;
  check(addedFile.error?.includes("saving files to IndexedDB") && !addedFile.value, "an aborted ciphertext transaction cannot return a successful add-file link");
  const [addedHash, ciphertext] = await laptop.evaluate(() => [window.storageFault.key, window.storageFault.bytes]);
  await holdSave(laptop, { store: "files", key: addedHash });
  await laptop.getByRole("button", { name: "Retry saving and reload" }).click();
  await laptop.waitForFunction(() => window.storageFault.phase === "held");
  check(JSON.stringify(await laptop.evaluate(() => window.storageFault.bytes)) === JSON.stringify(ciphertext), "explicit retry re-submits the failed addition's original ciphertext bytes");
  await Promise.all([laptop.waitForEvent("load"), laptop.evaluate(() => { window.storageFault.release = "commit"; })]);
  await laptop.getByRole("button", { name: "New chat" }).waitFor();
  // Unlinked additions are eligible for collection on restart; the known linked file remains readable.
  check(new TextDecoder().decode(new Uint8Array(await call(laptop, "file", failedAttachment.link))) === original, "failed additions do not disturb already recovered linked files");

  // Admission creates a state file after committing the Add: failure must still refuse the Welcome.
  const stateGroup = await call(laptop, "create", "doc", "Welcome durability");
  const stateDoc = new Y.Doc();
  stateDoc.getText("text").insert(0, "state survives ciphertext abort\n");
  await call(laptop, "command", "doc", JSON.stringify(["edit", stateGroup, Buffer.from(Y.encodeStateAsUpdate(stateDoc)).toString("base64url")]));
  const stateInvite = JSON.parse(await call(laptop, "request", JSON.stringify({ cmd: "invite", group: stateGroup })));
  const joiner = native("durable-joiner");
  await joiner.printed(e => e.type === "ready");
  const joinedDoc = join(tmp, "durable-joiner.md");
  await holdSave(laptop, { store: "files" });
  const joiningState = outcome(joiner.start("join", stateInvite.link, joinedDoc));
  await laptop.waitForFunction(() => window.storageFault.phase === "held");
  await laptop.evaluate(() => { window.storageFault.release = "abort"; });
  await laptop.getByRole("button", { name: "Retry saving and reload" }).waitFor();
  const refusedWelcome = await joiningState;
  check(refusedWelcome.error?.includes("persistence failed") && !joiner.run("groups").some(group => group.name === "Welcome durability"), "a state-file transaction abort refuses the actual peer's Welcome despite successful record saves");
  await recover(laptop);
  await laptop.getByRole("button", { name: "New chat" }).waitFor();
  await joiner.stop();
  const joinerBack = native("durable-joiner");
  await joinerBack.printed(e => e.type === "ready");
  const recoveredJoin = await joinerBack.start("join", stateInvite.link, joinedDoc);
  check(recoveredJoin.group === stateGroup && (await until(() => readFileSync(joinedDoc, "utf8"), value => value === "state survives ciphertext abort\n")) === "state survives ciphertext abort\n", "after both peers restart the same logged Welcome retry delivers its original document state");
  await joinerBack.stop();

  // Recovery sees writes made DURING its transaction, refuses reload, and requires another explicit attempt.
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  const beforeFailure = JSON.parse(await call(laptop, "me")).fp;
  const follower = watch("recovery follower", await laptop.context().newPage());
  await follower.goto(SITE);
  await follower.locator(".group-list button", { hasText: "Plans" }).waitFor();
  const target = { store: "records", prefix: "lmk/web/message/", text: "survives the aborted background save" };
  await holdSave(laptop, target);
  ann.run("send", `--group=${invite.group}`, target.text);
  await laptop.waitForFunction(() => window.storageFault.phase === "held");
  await laptop.evaluate(() => { window.storageFault.release = "abort"; });
  await laptop.getByRole("button", { name: "Retry saving and reload" }).waitFor();
  await follower.getByRole("button", { name: "Retry saving and reload" }).waitFor();
  const [attempts, failedKey] = await laptop.evaluate(() => [window.storageFault.attempts.records, window.storageFault.key]);
  const refusedBarrier = await outcome(call(laptop, "flush", false));
  check(refusedBarrier.error?.includes("could not be saved") && await laptop.evaluate(() => window.storageFault.attempts.records) === attempts, "an empty barrier reports the prior background failure without silently retrying");
  const late = watch("late recovery follower", await laptop.context().newPage());
  await late.goto(SITE);
  await late.getByRole("button", { name: "Retry saving and reload" }).waitFor();
  check(true, "both an existing follower and a tab opened after failure show the latched storage diagnostic");
  ann.run("send", `--group=${invite.group}`, "arrived while saving was stopped");
  const intervening = await until(() => call(laptop, "items", invite.group, false), items => items.includes("arrived while saving was stopped"));
  check(intervening.includes("arrived while saving was stopped"), "intervening writes stay available in memory before the explicit retry");

  await holdSave(laptop, target);
  const retrying = outcome(call(follower, "flush", true));
  await laptop.waitForFunction(() => window.storageFault.phase === "held");
  ann.run("send", `--group=${invite.group}`, "arrived during the recovery transaction");
  const during = await until(() => call(laptop, "items", invite.group, false), items => items.includes("arrived during the recovery transaction"));
  check(during.includes("arrived during the recovery transaction"), "a real incoming message mutates records while the recovery transaction is in flight");
  await laptop.evaluate(() => { window.storageFault.release = "commit"; });
  const dirtyRetry = await retrying;
  check(dirtyRetry.error?.includes("changed during the recovery save") && await laptop.evaluate(() => !window.storageFault.events.some(e => e.type === "storage_saved")), "a dirty retry refuses reload and retains the intervening delta without clearing the terminal latch");
  for (const tab of [laptop, follower, late]) await tab.getByRole("button", { name: "Retry saving and reload" }).waitFor();
  await Promise.all([laptop.waitForEvent("load"), follower.waitForEvent("load"), recover(late)]);
  for (const tab of [laptop, follower, late]) {
    await tab.locator(".group-list button", { hasText: "Plans" }).click();
    for (const message of [target.text, "arrived while saving was stopped", "arrived during the recovery transaction"]) await tab.getByText(message, { exact: true }).waitFor();
    check(JSON.parse(await call(tab, "me")).fp === beforeFailure, "follower-initiated explicit retry reloads every tab with the same session and all pending messages");
  }
  check(new TextDecoder().decode(new Uint8Array(await record(laptop, "records", failedKey))).includes(target.text), "the failed batch itself, not just later writes, reached IndexedDB");
  check(await laptop.evaluate(async () => (await navigator.locks.query()).held.filter(lock => lock.name === "lmk5").length === 1), "after recovery exactly one tab owns the session");
  await follower.close();
  await late.close();
  delete pages["recovery follower"];
  delete pages["late recovery follower"];
  await laptop.locator("textarea:visible").fill("after recovery handoff");
  await laptop.locator("textarea:visible").press("Enter");
  await ann.printed(e => e.type === "message" && e.content === "after recovery handoff");
  check(true, "the surviving tab still sends to the real peer after the recovery handoff");

  // With Ann gone, what the laptop sends to her chat still counts on the group's log, held only by the laptop.
  await ann.stop();
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  await laptop.locator("textarea:visible").fill("anyone there?");
  await laptop.locator("textarea:visible").press("Enter");
  const lone = laptop.locator(".messages li", { hasText: "anyone there?" });
  await lone.waitFor();
  check(true, "a message sent with no other member online is listed once the group's log takes it");
  await lone.locator(".ticks", { hasText: /^✓$/ }).waitFor();
  check(true, "with a single tick, as no other member holds it");

  // Two renames move the chat two epochs on, and the laptop closes: Ann, back, cannot read the message, and says so.
  for (const name of ["Plans 2", "Plans 3"]) {
    await laptop.getByRole("button", { name: "Settings" }).click();
    await laptop.locator("dialog").getByLabel("Name").fill(name);
    await laptop.locator("dialog").getByRole("button", { name: "Rename" }).click();
    await laptop.locator(".group-list button", { hasText: name }).waitFor();
    await laptop.locator("dialog").getByRole("button", { name: "Close" }).click();
  }
  const context = laptop.context();
  const asked = new Promise(resolve => laptop.once("dialog", dialog => (resolve(dialog.type()), dialog.accept())));
  const closed = laptop.waitForEvent("close");
  await laptop.close({ runBeforeUnload: true });
  check((await asked) === "beforeunload", "closing the page while a message is held only there asks first");
  await closed;
  delete pages["second tab"];
  const annBack = native("ann");
  await annBack.printed(e => e.type === "lost" && e.member === "you", 60_000);
  laptop = watch("laptop", await context.newPage());
  laptop.on("dialog", dialog => dialog.accept());
  await laptop.goto(SITE);
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  const lost = laptop.locator(".messages li", { hasText: "anyone there?" });
  await lost.locator(".tag", { hasText: "could not read this" }).waitFor({ timeout: 60_000 });
  check((await lost.locator(".tag").textContent()).startsWith("Ann"), "the laptop shows who lost its message");
  const carlBack = native("carl");
  await lost.locator(".ticks", { hasText: "✓✓" }).waitFor({ timeout: 60_000 });
  check(true, "and two ticks once Carl, back, holds it");
  await carlBack.stop();

  // The tab that took over loaded no file; it loads the doc's file from IndexedDB when a new member wants it.
  await laptop.locator(".group-list button", { hasText: "Notes" }).click();
  await laptop.getByRole("button", { name: "Settings" }).click();
  await laptop.locator("dialog").getByRole("button", { name: "Make a link" }).click();
  const readerLink = await laptop.locator("dialog .copy code").first().textContent();
  const reader = native("reader");
  await reader.printed(e => e.type === "ready");
  reader.run("join", readerLink);
  const fetched = await until(
    () => {
      try {
        return reader.run("fetch", attached.link);
      } catch {
        return {};
      }
    },
    answer => answer.path,
    60_000
  );
  check(readFileSync(fetched.path, "utf8") === "the spec", "a tab serves a kept file, loading it from IndexedDB when a member wants it");

  for (const [name, page] of Object.entries(pages)) {
    const toasts = await page.evaluate(() => window.toasts);
    check(toasts.length === 0, `${name} showed no error${toasts.length ? `: ${toasts.join("; ")}` : ""}`);
  }

  // A new version waits until the person accepts it, then the tab reloads into it.
  const sw = join(FRONTEND_DIST, "sw.js");
  writeFileSync(sw, `${readFileSync(sw, "utf8")}\n// a new version\n`);
  await laptop.evaluate(() => ((window.before = true), navigator.serviceWorker.getRegistration().then(registration => registration.update())));
  await laptop.getByText("A new version of letmeknow is ready.").waitFor();
  await new Promise(resolve => setTimeout(resolve, 1_000));
  check(await laptop.evaluate(() => window.before && !!navigator.serviceWorker.controller), "a new version waits for the person to accept it");
  await Promise.all([laptop.waitForEvent("load"), laptop.getByRole("button", { name: "Reload" }).click()]);
  await laptop.locator(".group-list button", { hasText: "Plans" }).waitFor();
  check(await laptop.evaluate(() => !window.before && !document.querySelector(".banner")), "and once accepted, the tab reloads into it");

  // The service worker serves the app with the page server unreachable.
  check(await laptop.evaluate(() => !!navigator.serviceWorker.controller), "a service worker controls the page");
  await laptop.context().setOffline(true);
  await laptop.reload();
  await laptop.locator(".group-list button", { hasText: "Plans" }).waitFor();
  check(true, "and opens the app offline, groups and all");
  check(pageErrors.length === 0, `no unhandled browser errors: ${pageErrors.join("; ")}`);
  check(new URL(SITE).origin !== new URL(LETMEKNOW_RELAY).origin, "frontend and backend have distinct HTTPS origins");
  check(sockets.some(url => url.startsWith(LETMEKNOW_RELAY.replace("https:", "wss:") + "/relay")), "browser/native traffic uses cross-origin iroh-over-WSS");
  check(!requests.some(([url]) => new URL(url).pathname === "/membership"), "no runtime membership-key discovery");
  check(requests.filter(([, type]) => ["document", "script", "stylesheet"].includes(type)).every(([url]) => new URL(url).origin === SITE), "HTML, JavaScript and CSS come only from the trusted frontend");
  check(requests.filter(([url]) => new URL(url).pathname.endsWith(".wasm")).every(([url]) => new URL(url).origin === SITE), "WASM comes only from the trusted frontend");
  console.log("browser ok");
  passed = true;
} catch (error) {
  for (const [name, page] of Object.entries(pages)) {
    console.log(name, JSON.stringify(await page.evaluate(() => ({ fault: window.storageFault && { phase: window.storageFault.phase, events: window.storageFault.events.slice(-10), attempts: window.storageFault.attempts }, toasts: window.toasts }))));
    await page.screenshot({ path: join(tmp, `${name}.png`) });
  }
  console.log(`screenshots in ${tmp}`);
  throw error;
} finally {
  await browser.close();
  for (const proc of natives) proc.kill();
  // A failed run keeps its homes and screenshots.
  if (passed) rmSync(tmp, { recursive: true, force: true, maxRetries: 10 });
}
