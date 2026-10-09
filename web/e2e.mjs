// Browser end-to-end test, run by test/e2e.py against its local `letmeknow serve` (URL, serving dist/) with the native
// binary (BIN): Matt's laptop, which takes its relay and membership service from the server that served it, joins Ann's
// chat from a link, becoming his identity's first device as it does, and they talk and pass files both ways; it joins
// her doc and they edit it both ways; Matthew's desk adds his phone by a device link, the phone joins a chat open to that
// identity by itself and is renamed, and a kiosk on an identity of its own moves to his; the laptop keeps everything
// across a reload, a second tab works through the first and takes over when it closes; introductions, refusals, files
// kept and deleted, a git group's pushes and chat, and the service worker's updates.
import { execFile, execFileSync, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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

const natives = [];
/** A native session in a home of its own: its own device. */
function native(name) {
  const env = { ...process.env, LETMEKNOW_HOME: join(tmp, name) };
  const proc = spawn(BIN, ["--session", name, "listen", "--name", name[0].toUpperCase() + name.slice(1), "--hold", "0"], { env, stdio: ["ignore", "pipe", "inherit"] });
  natives.push(proc);
  const events = [];
  const waiters = new Set();
  createInterface({ input: proc.stdout }).on("line", line => {
    events.push(JSON.parse(line));
    for (const wake of waiters) wake();
  });
  return {
    proc,
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

const ann = native("ann");
const desk = native("desk");
const browser = await chromium.launch({ args: ["--ignore-certificate-errors"] });
const pages = {};
function watch(name, page) {
  pages[name] = page;
  page.on("console", message => message.type() === "error" && console.log(`${name}: ${message.text()}`));
  page.on("pageerror", error => console.log(`${name}: ${error}`));
  return page;
}
/** A browser profile; unless `own`, localStorage names the test's relay and membership service, as the server would. */
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
        const db = indexedDB.open("lmk");
        db.onsuccess = () => {
          const request = db.result.transaction("files").objectStore("files").getAllKeys();
          request.onsuccess = () => (db.result.close(), resolve(request.result));
          request.onerror = () => reject(request.error);
        };
      })
  );
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

  // Invited by link: what it is, a name, Join, and the chat. The profile holds what a letmeknow before 0.12 kept,
  // which the app sets aside.
  let laptop = await open("laptop", { viewport: { width: 1280, height: 800 } }, true);
  await laptop.goto(`${SITE}/ping`);
  await laptop.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const request = indexedDB.open("lmk", 1);
        request.onupgradeneeded = () => {
          request.result.createObjectStore("records").put(new Uint8Array([1]), new Uint8Array([1]).buffer);
          request.result.createObjectStore("files").put(new Uint8Array([1]), "00");
        };
        request.onsuccess = () => (request.result.close(), resolve());
        request.onerror = () => reject(request.error);
      })
  );
  const invite = ann.run("invite", "--name", "Plans", "--for", "Matt");
  await laptop.goto(local(invite.link));
  await laptop.getByRole("heading", { name: "You're invited" }).waitFor();
  await laptop.getByLabel("Your name").fill("Matt");
  await laptop.getByRole("button", { name: "Join", exact: true }).click();
  await laptop.locator(".people", { hasText: "Ann" }).waitFor();
  check(new URL(laptop.url()).pathname === "/", "a browser joins from an invite link, with a click");
  check(!(await kept(laptop)).includes("00"), "a profile that a letmeknow before 0.12 used starts afresh");
  await ann.printed(e => e.type === "joined" && e.member.name === "Matt");
  check(true, "the native session sees the browser join");
  const matt = await until(
    () => ann.run("members", `--group=${invite.group}`).members.find(m => m.name === "Matt"),
    m => m?.identity?.how === "verified"
  );
  check(matt.identity.name === "Matt" && matt.device === "laptop", "the welcome screen makes the browser its identity's first device, which the inviter records as the contact the link was for");

  // Messages both ways, with a reply.
  const hello = ann.run("send", "hello from the terminal").id;
  await laptop.getByText("hello from the terminal").waitFor();
  check(true, "the browser shows a native session's message");
  await laptop.locator(".messages li", { hasText: "hello from the terminal" }).hover();
  await laptop.locator(".messages li", { hasText: "hello from the terminal" }).getByRole("button", { name: "Reply" }).click();
  await laptop.getByPlaceholder("Message").fill("hello from the browser");
  await laptop.getByPlaceholder("Message").press("Enter");
  const reply = await ann.printed(e => e.type === "message" && e.content === "hello from the browser");
  check(reply.reply_to === hello && reply.from.name === "Matt", "a native session gets the browser's reply");
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
  const spec = join(tmp, "spec.txt");
  writeFileSync(spec, "the spec");
  const attached = ann.run("doc", "attach", `--group=${doc.group}`, spec);
  writeFileSync(notes, `- [x] alpha\n- [ ] beta (browser)\n- [ ] gamma\n${attached.markdown}\n`);
  const specHash = attached.link.slice(4, 68);
  check((await until(() => kept(laptop), hashes => hashes.includes(specHash))).includes(specHash), "the browser keeps a file the doc links");

  // A device link adds a phone to Matthew's identity, made on his desk; the phone then joins a chat open to it.
  const phone = await open("phone", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const deviceLink = desk.run("invite", "--identity", "Matthew").link;
  await phone.goto(local(deviceLink));
  await phone.getByRole("heading", { name: "Add this browser to your devices" }).waitFor();
  check((await phone.getByLabel("Name this device").inputValue()) === "phone", "a phone suggests its own device name");
  await phone.getByRole("button", { name: "Add this browser" }).click();
  await phone.locator(".devices li", { hasText: "phone" }).waitFor();
  const devices = desk.run("identity", "list").identities[0].devices;
  check(devices.length === 2 && devices.some(d => d.name === "phone"), "a device link adds the browser to the identity's devices");
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
    () => desk.run("identity", "list").identities[0].devices.map(d => d.name),
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
  await desk.printed(e => e.type === "left" && e.member.device === "pocket");
  await phone.locator(".group-list button", { hasText: "Team" }).waitFor({ state: "detached" });
  const told = await phone.evaluate(() => window.toasts.splice(0));
  check(told.every(t => t.startsWith("Asked the others to remove you") || t.startsWith("You were removed from Team")), `the phone leaves the chat (${told.length} notices)`);
  await phone.reload();
  await phone.getByRole("heading", { name: "Start", exact: true }).first().waitFor();
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
  await kiosk.getByLabel("This device").fill("kiosk");
  await kiosk.getByPlaceholder("e.g. Q3 plan").fill("Kiosk notes");
  await kiosk.getByRole("button", { name: "New chat" }).click();
  await kiosk.locator(".group-list button", { hasText: "Kiosk notes" }).waitFor();
  check((await kiosk.locator(".me").textContent()).includes("Kim"), "a chat started from the welcome screen makes the browser its identity's first device");
  await kiosk.goto(local(desk.run("invite", "--identity", "Matthew").link));
  const moving = kiosk.locator("dialog", { hasText: "Move this browser to another identity" });
  await moving.waitFor();
  const moveSaid = await moving.textContent();
  check(moveSaid.includes("It leaves Kim, which ends") && moveSaid.includes("as Kim: Kiosk notes"), "a device link opened in a browser on an identity says what moving does");
  await moving.getByRole("button", { name: "Move this browser" }).click();
  await kiosk.locator(".devices li", { hasText: "this browser" }).waitFor();
  check((await kiosk.locator(".me").textContent()).includes("Matthew"), "and moves the browser to the identity of the link");
  const moved = desk.run("identity", "list").identities[0].devices.map(d => d.name);
  check(moved.includes("kiosk") && (await kiosk.locator(".group-list button", { hasText: "Kiosk notes" }).count()) === 0, "which lists it, and it left Kim's chat");

  check((await laptop.evaluate(() => window.toasts)).length === 0, "the laptop showed no error before its reload");

  // A reload keeps the laptop's groups, messages and doc, and it still talks.
  const recorded = await laptop.evaluate(
    gid =>
      new Promise((resolve, reject) => {
        const open = indexedDB.open("lmk");
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
  check(link.includes("#2.d.") && (await laptop.locator("dialog .qr path").getAttribute("d")).length > 100, "the browser makes a device link, with a QR code");
  const tablet = native("tablet");
  await tablet.printed(e => e.type === "ready");
  const joining = tablet.start("join", link);
  await laptop.getByText("Added. The device now joins your chats and documents.").waitFor();
  await joining;
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
  const ideas = tablet.run("groups").find(g => g.name === "Ideas");
  check(JSON.stringify(ideas.membership).includes(LETMEKNOW_RELAY), "on the membership service of the server that served the browser");
  await laptop.locator(".people", { hasText: "Matt · " }).waitFor();
  tablet.proc.kill();

  // Ann adds Carl, whom she made an invite for: her word on who Carl is reaches the laptop, which accepts it.
  const carl = native("carl");
  await carl.printed(e => e.type === "ready");
  carl.run("identity", "create", "Carl");
  carl.run("join", ann.run("invite", `--group=${invite.group}`, "--for", "Carl (Acme)").link);
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  await laptop.locator(".messages li", { hasText: "introduced Carl (Acme)" }).waitFor();
  await laptop.locator(".people:visible").click();
  await laptop.locator("dialog").getByRole("button", { name: "Accept as Carl (Acme)" }).click();
  await laptop.locator("dialog").waitFor({ state: "detached" });
  await laptop.locator(".me").click();
  await laptop.locator(".devices li", { hasText: "Carl (Acme)" }).waitFor();
  check(true, "the browser accepts an introduction, and the introduced identity becomes a contact");

  // A git group: Ann pushes with git, Carl takes the bundle, and the browser shows the push beside the group's chat.
  const repo = join(tmp, "ann-repo");
  const annGit = (...args) =>
    execFileSync("git", ["-c", "init.defaultBranch=main", ...args], { cwd: repo, env: { ...process.env, LETMEKNOW_HOME: join(tmp, "ann"), LETMEKNOW_SESSION: "ann" }, stdio: "pipe" });
  mkdirSync(repo);
  annGit("init", "-q");
  writeFileSync(join(repo, "README.md"), "hello\n");
  annGit("add", "README.md");
  annGit("commit", "-qm", "first commit");
  const code = ann.run("invite", "--kind", "git", "--name", "Code");
  carl.run("join", code.link);
  annGit("remote", "add", "team", code.remote);
  await laptop.getByRole("button", { name: "Join", exact: true }).first().click();
  await laptop.locator("dialog").getByLabel("Invite link").fill(ann.run("invite", `--group=${code.group}`).link);
  await laptop.locator("dialog").getByRole("button", { name: "Join", exact: true }).click();
  await laptop.locator(".group-list button.on", { hasText: "Code" }).waitFor();
  check(true, "the browser joins a git group");
  annGit("push", "-q", "team", "main");
  await laptop.locator(".messages li.pushed", { hasText: "first commit" }).waitFor();
  check((await laptop.locator(".messages li.pushed").textContent()).includes("pushed to main"), "and shows a push to it, with its commits' subjects");
  ann.run("send", `--group=${code.group}`, "the build is green");
  await laptop.getByText("the build is green").waitFor();
  await laptop.locator("textarea:visible").fill("thanks");
  await laptop.locator("textarea:visible").press("Enter");
  await ann.printed(e => e.type === "message" && e.group === code.group && e.content === "thanks");
  check(true, "and its chat, both ways");

  // A message larger than members take is not sent: the page says why, and keeps the text.
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  const tooLong = `too long ${"x".repeat(1_100_000)}`;
  await laptop.locator("textarea:visible").fill(tooLong);
  await laptop.locator("textarea:visible").press("Enter");
  const tooLarge = await until(() => laptop.evaluate(() => window.toasts.splice(0)), told => told.length > 0);
  check(tooLarge.length === 1 && tooLarge[0].includes("over the 1 MiB members take"), `a message larger than members take is not sent, and the page says why (${tooLarge.join("; ")})`);
  check((await laptop.locator("textarea:visible").inputValue()) === tooLong, "its text stays in the box");
  check((await laptop.locator(".messages li", { hasText: "too long" }).count()) === 0, "and it is not listed");
  carl.proc.kill();

  // With Ann gone, what the laptop sends to her chat is pending.
  ann.proc.kill();
  await laptop.locator(".group-list button", { hasText: "Plans" }).click();
  await laptop.locator("textarea:visible").fill("anyone there?");
  await laptop.locator("textarea:visible").press("Enter");
  await laptop.locator(".messages li", { hasText: "anyone there?" }).locator(".status", { hasText: "Pending" }).waitFor();
  check(true, "a message no other member holds shows as pending");

  // The tab that took over loaded no file; it loads the doc's file from IndexedDB when a new member wants it.
  await laptop.locator(".group-list button", { hasText: "Notes" }).click();
  await laptop.getByRole("button", { name: "Invite" }).click();
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
  const sw = join("dist", "sw.js");
  writeFileSync(sw, `${readFileSync(sw, "utf8")}\n// a new version\n`);
  for (const compressed of [`${sw}.br`, `${sw}.gz`]) rmSync(compressed);
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
  console.log("browser ok");
} catch (error) {
  for (const [name, page] of Object.entries(pages)) await page.screenshot({ path: join(tmp, `${name}.png`) });
  console.log(`screenshots in ${tmp}`);
  throw error;
} finally {
  await browser.close();
  for (const proc of natives) proc.kill();
}
