// Browser end-to-end test, run by test/e2e.py against its local `letmeknow serve` (URL, serving dist/) with the native
// binary (BIN): Matthew's laptop joins Ann's chat from a link and they talk and pass files both ways; it joins her doc
// and they edit it both ways; his desk's identity adds his phone by a device link, and the phone joins a chat open to
// that identity by itself; the laptop keeps everything across a reload.
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { chromium } from "playwright";

const { URL: SITE, BIN, LETMEKNOW_RELAY, LETMEKNOW_MEMBERSHIP } = process.env;
const tmp = mkdtempSync(join(tmpdir(), "lmk-browser-"));
const check = (condition, message) => {
  if (!condition) throw new Error(`FAIL: ${message}`);
  console.log(`ok - ${message}`);
};
const local = link => SITE + new URL(link).pathname + new URL(link).hash;

/** A native session in a home of its own: its own device. */
function native(name) {
  const env = { ...process.env, LETMEKNOW_HOME: join(tmp, name) };
  const proc = spawn(BIN, ["--session", name, "listen", "--name", name[0].toUpperCase() + name.slice(1), "--hold", "0"], { env, stdio: ["ignore", "pipe", "inherit"] });
  const events = [];
  const waiters = new Set();
  createInterface({ input: proc.stdout }).on("line", line => {
    events.push(JSON.parse(line));
    for (const wake of waiters) wake();
  });
  return {
    proc,
    run: (...args) => JSON.parse(execFileSync(BIN, ["--session", name, ...args], { env, encoding: "utf8" })),
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

const ann = native("ann");
const desk = native("desk");
const browser = await chromium.launch({ args: ["--ignore-certificate-errors"] });
const pages = {};
async function open(name, options) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true, permissions: ["clipboard-read", "clipboard-write"], ...options });
  await context.addInitScript(
    ([relay, membership]) => {
      localStorage.setItem("lmk relay", relay);
      localStorage.setItem("lmk membership", membership);
      window.toasts = [];
      new MutationObserver(records => records.forEach(r => r.addedNodes.forEach(node => node.className === "toast" && window.toasts.push(node.textContent)))).observe(document, {
        childList: true,
        subtree: true
      });
    },
    [LETMEKNOW_RELAY, LETMEKNOW_MEMBERSHIP]
  );
  const page = await context.newPage();
  pages[name] = page;
  page.on("console", message => message.type() === "error" && console.log(`${name}: ${message.text()}`));
  page.on("pageerror", error => console.log(`${name}: ${error}`));
  return page;
}
const text = page => page.locator(".cm-content").evaluate(content => content.cmTile.view.state.doc.toString());
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

  // Invited by link: what it is, a name, Join, and the chat.
  const laptop = await open("laptop", { viewport: { width: 1280, height: 800 } });
  const invite = ann.run("invite", "--name", "Plans");
  await laptop.goto(local(invite.link));
  await laptop.getByRole("heading", { name: "You're invited" }).waitFor();
  await laptop.getByLabel("Your name").fill("Matthew");
  await laptop.getByRole("button", { name: "Join", exact: true }).click();
  await laptop.locator(".people", { hasText: "Ann" }).waitFor();
  check(new URL(laptop.url()).pathname === "/", "a browser joins from an invite link, with a click");
  const joined = await ann.printed(e => e.type === "joined" && e.member.name === "Matthew");
  check(joined.member.device === "laptop", "the native session sees the browser join, named with its device");

  // Messages both ways, with a reply.
  const hello = ann.run("send", "hello from the terminal").id;
  await laptop.getByText("hello from the terminal").waitFor();
  check(true, "the browser shows a native session's message");
  await laptop.locator(".messages li", { hasText: "hello from the terminal" }).hover();
  await laptop.locator(".messages li", { hasText: "hello from the terminal" }).getByRole("button", { name: "Reply" }).click();
  await laptop.getByPlaceholder("Message").fill("hello from the browser");
  await laptop.getByPlaceholder("Message").press("Enter");
  const reply = await ann.printed(e => e.type === "message" && e.content === "hello from the browser");
  check(reply.reply_to === hello && reply.from.name === "Matthew", "a native session gets the browser's reply");
  await laptop.locator(".messages li", { hasText: "hello from the browser" }).locator(".status").waitFor({ state: "detached" });
  check(true, "and the browser shows it held, not pending, once the receipt arrives");

  // Members: Ann's identity is only her own claim to the laptop.
  await laptop.locator(".people").click();
  const annRow = laptop.locator("dialog .people-list li", { hasText: "Ann" });
  check((await annRow.textContent()).includes("their own name, not a contact"), "members show an identity claim and how this browser knows it");
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

  // A device link adds a phone to Matthew's identity, made on his desk; the phone then joins a chat open to it.
  const phone = await open("phone", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const deviceLink = desk.run("invite", "--identity", "Matthew").link;
  await phone.goto(local(deviceLink));
  await phone.getByRole("heading", { name: "Add this browser to your devices" }).waitFor();
  check((await phone.getByLabel("Name this device").inputValue()) === "phone", "a phone suggests its own device name");
  await phone.getByRole("button", { name: "Add this browser" }).click();
  await phone.locator(".devices li", { hasText: "phone" }).waitFor();
  const devices = desk.run("identity", "list").identities[0].devices;
  check(devices.length === 2 && devices.some(d => d.name === "phone"), "a device link adds the browser to the identity's device list");
  const team = desk.run("invite", "--name", "Team");
  desk.run("open", `--group=${team.group}`, "Matthew");
  const opened = await desk.printed(e => e.type === "joined" && e.member.device === "phone", 60_000);
  check(opened.how === "open" && opened.member.identity.name === "Matthew", "the phone joins a chat open to its identity by itself");
  await phone.locator(".back:visible").click();
  await phone.locator(".group-list button", { hasText: "Team" }).waitFor();
  check(true, "and lists it");
  desk.run("send", `--group=${team.group}`, "welcome, phone");
  await phone.locator(".group-list button", { hasText: "Team" }).click();
  await phone.getByText("welcome, phone").waitFor();
  check(true, "and reads what is sent there");

  check((await laptop.evaluate(() => window.toasts)).length === 0, "the laptop showed no error before its reload");

  // A reload keeps the laptop's groups, messages and doc, and it still talks.
  await laptop.reload();
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  await laptop.getByText("hello from the terminal", { exact: true }).waitFor();
  check((await laptop.locator(".group-list button").count()) === 2, "a reloaded browser keeps its groups and their messages");
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

  // The laptop starts an identity of its own, and its device link adds a native session's device to it.
  await laptop.locator(".me").click();
  await laptop.getByLabel("Your name").fill("Matt");
  await laptop.getByRole("button", { name: "Start" }).click();
  await laptop.locator(".devices li", { hasText: "this browser" }).waitFor();
  await laptop.getByRole("button", { name: "Add a device" }).click();
  const link = await laptop.locator("dialog .copy code").first().textContent();
  check(link.includes("#1.d.") && (await laptop.locator("dialog .qr path").getAttribute("d")).length > 100, "the browser makes a device link, with a QR code");
  const tablet = native("tablet");
  await tablet.printed(e => e.type === "ready");
  tablet.run("join", link);
  await laptop.getByText("Added. The device now joins your chats and documents.").waitFor();
  await until(
    () => laptop.locator(".devices li").count(),
    n => n === 2
  );
  check(tablet.run("identity", "list").identities[0].name === "Matt", "a native device joins the browser's identity by its link");

  // The laptop opens a new chat to its identity, and the tablet, a device of it, joins without an invite.
  await laptop.getByRole("button", { name: "New chat" }).click();
  await laptop.locator("dialog").getByLabel("Name").fill("Ideas");
  await laptop.locator("dialog").getByRole("button", { name: "Start" }).click();
  await laptop.locator(".group-list button.on", { hasText: "Ideas" }).waitFor();
  await laptop.getByRole("button", { name: "Settings" }).click();
  await laptop.getByText("Your other devices can join").click();
  await laptop.locator("dialog input[type=checkbox]:checked:enabled").waitFor();
  await laptop.locator("dialog").getByRole("button", { name: "Close" }).click();
  const offered = await until(() => tablet.run("groups"), groups => groups.some(g => g.name === "Ideas" && g.joined === false));
  check(offered.some(g => g.name === "Ideas"), "a chat the browser opens to its identity reaches that identity's other devices");
  check(tablet.run("join", "Ideas").members.length === 2, "and the browser admits one that asks");
  await laptop.locator(".people", { hasText: "Matt · " }).waitFor();
  tablet.proc.kill();

  // With Ann gone, what the laptop sends to her chat is pending.
  ann.proc.kill();
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  await laptop.locator("textarea:visible").fill("anyone there?");
  await laptop.locator("textarea:visible").press("Enter");
  await laptop.locator(".messages li", { hasText: "anyone there?" }).locator(".status", { hasText: "Pending" }).waitFor();
  check(true, "a message no other member holds shows as pending");

  for (const [name, page] of Object.entries(pages)) check((await page.evaluate(() => window.toasts)).length === 0, `${name} showed no error`);

  // The service worker serves the app with the page server unreachable.
  check(await laptop.evaluate(() => !!navigator.serviceWorker.controller), "a service worker controls the page");
  await laptop.context().setOffline(true);
  await laptop.reload();
  await laptop.locator(".group-list button", { hasText: "Plans" }).waitFor();
  check(true, "and opens the app offline, groups and all");
  console.log("browser ok");
} catch (error) {
  for (const [name, page] of Object.entries(pages)) await page.screenshot({ path: join(tmp, `${name}.png`) });
  console.log(`screenshots in ${tmp}`);
  throw error;
} finally {
  await browser.close();
  ann.proc.kill();
  desk.proc.kill();
}
