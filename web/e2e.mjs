// Browser end-to-end test, run by test/e2e.py against its local relay (RELAY) with the session binary (BIN): Matthew
// joins an agent's group from his laptop, adds his phone, which joins his groups on its own, they chat, and all three
// edit one checklist at once. Ann starts on the page with a typed code, and leaves or is removed.
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { chromium } from "playwright";

const { RELAY, BIN } = process.env;
const home = mkdtempSync(join(tmpdir(), "letmeknow-browser-"));
const env = { ...process.env, LETMEKNOW_HOME: home, LETMEKNOW_RELAY: RELAY };
const agent = (...args) => JSON.parse(execFileSync(BIN, ["--session", "agent", ...args], { env, encoding: "utf8" }));
const check = (condition, message) => {
  if (!condition) throw new Error(`FAIL: ${message}`);
  console.log(`ok - ${message}`);
};

const listener = spawn(BIN, ["--session", "agent", "listen", "--name", "Agent"], { env, stdio: ["ignore", "pipe", "inherit"] });
const events = [];
const waiters = [];
createInterface({ input: listener.stdout }).on("line", line => {
  events.push(JSON.parse(line));
  waiters.forEach(wake => wake());
});
/** The first event the agent printed that `predicate` accepts. */
function printed(predicate, ms = 30_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("FAIL: the agent printed no such event")), ms);
    const look = () => {
      const event = events.find(predicate);
      if (event) {
        clearTimeout(timer);
        resolve(event);
      }
    };
    waiters.push(look);
    look();
  });
}

const browser = await chromium.launch();
const pages = {};
const open = async (name, options) => {
  const page = await (await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"], ...options })).newPage();
  page.on("console", message => message.type() === "error" && console.log(`${name}: ${message.text()}`));
  page.on("pageerror", error => console.log(`${name}: ${error}`));
  pages[name] = page;
  return page;
};
try {
  await printed(e => e.type === "ready");
  const { link, group } = agent("invite");
  const laptop = await open("laptop", { viewport: { width: 1280, height: 800 } });
  const phone = await open("phone", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const editorLoads = [];
  laptop.on("request", request => request.url().includes("/assets/editor-") && editorLoads.push(request.url()));

  // Invited by link: what it is, a name, Join, and the group.
  await laptop.goto(link);
  await laptop.getByRole("heading", { name: "You're invited to a group chat" }).waitFor();
  await laptop.getByLabel("Your name").fill("Matthew");
  await laptop.getByRole("button", { name: "Join group" }).click();
  await laptop.locator(".people", { hasText: "Agent" }).waitFor();
  check(new URL(laptop.url()).pathname === "/", "a browser joins from an invite link, with a click");
  const joined = await printed(e => e.type === "joined" && e.member.name === "Matthew");
  check(joined.member.entity?.name === "Matthew", "the agent sees the browser member speak as the person it started");
  await laptop.getByText("Matthew let their other devices join").waitFor();
  check(true, "a group the browser joins lets its person's other devices join");

  // Adding a device: a link, a code and a QR code; the phone then joins Matthew's groups by itself.
  await laptop.getByRole("button", { name: /Your devices/ }).click();
  await laptop.getByRole("button", { name: "Add a device" }).click();
  const deviceLink = await laptop.locator("dialog .copy code").first().textContent();
  check(/^\d+-[a-z]+-[a-z]+$/.test(await laptop.locator("dialog .code").textContent()), "adding a device shows the link and its code");
  check((await laptop.locator("dialog .qr path").getAttribute("d")).length > 100, "and a QR code of the link");
  await phone.goto(deviceLink);
  await phone.getByRole("heading", { name: "Add this browser to your devices" }).waitFor();
  check((await phone.getByLabel("Name this device").inputValue()) === "phone", "a phone suggests its own device name");
  await phone.getByRole("button", { name: "Add this browser" }).click();
  await laptop.getByText("Added. The device now joins your groups.").waitFor();
  await laptop.locator(".devices li", { hasText: "phone" }).waitFor();
  check(true, "the laptop lists the phone among Matthew's devices");
  const second = await printed(e => e.type === "joined" && e.member.name === "phone");
  check(second.member.entity?.name === "Matthew", "the added phone joins Matthew's group on its own, as a second member speaking as Matthew");
  await phone.locator(".back:visible").click();
  await phone.locator(".group-list button", { hasText: "Agent" }).click();
  await phone.locator(".people", { hasText: "Matthew" }).waitFor();
  check((await phone.locator(".people").textContent()).includes("Agent"), "and lists who is who, by whose they are");

  await laptop.locator(".group-list button").first().click();
  const morning = agent("send", "Morning. Your priority list is ready.").id;
  for (const page of [laptop, phone]) await page.getByText("Morning. Your priority list is ready.").waitFor();
  console.log("ok - both browsers show the agent's message");
  await laptop.locator(".chips button", { hasText: "Agent" }).click();
  await laptop.getByPlaceholder("Message").fill("Thanks, on it");
  await laptop.getByPlaceholder("Message").press("Enter");
  const direct = await printed(e => e.type === "message" && e.content === "Thanks, on it");
  check(direct.direct && direct.from.entity.name === "Matthew", "a browser sends a direct message to the agent");
  await phone.locator(".messages li", { hasText: "Morning." }).click();
  await phone.locator(".messages li", { hasText: "Morning." }).getByRole("button", { name: "Reply" }).click();
  await phone.getByText("Urgent", { exact: true }).click();
  await phone.getByPlaceholder("Message").fill("Call me");
  await phone.getByRole("button", { name: "Send" }).click();
  const reply = await printed(e => e.type === "message" && e.content === "Call me");
  check(reply.urgent && reply.reply_to === morning, "a browser sends an urgent reply");
  await laptop.locator(".messages li.urgent", { hasText: "Call me" }).waitFor();
  console.log("ok - the other browser shows it too");

  // Background activity moves nothing a person is using: the draft, its focus and selection, and the scroll position.
  for (let i = 0; i < 20; i++) agent("send", `status line ${i}`);
  await laptop.getByText("status line 19").waitFor();
  const input = laptop.getByPlaceholder("Message");
  await input.fill("half a thought");
  await input.evaluate(element => ((element.marker = true), element.setSelectionRange(2, 6)));
  const list = laptop.locator(".group:visible .messages");
  await list.evaluate(element => (element.scrollTop = 100));
  agent("send", "while you scroll");
  await laptop.getByRole("button", { name: "New messages ↓" }).waitFor();
  await laptop.waitForTimeout(6_000); // a few background rounds: polling, join requests
  const kept = await input.evaluate(element => [element.marker, document.activeElement === element, element.value, element.selectionStart, element.selectionEnd]);
  check(JSON.stringify(kept) === JSON.stringify([true, true, "half a thought", 2, 6]), "background activity keeps the composer, its focus, text and selection");
  check((await list.evaluate(element => element.scrollTop)) === 100, "a new message appends without moving a list scrolled up");
  await laptop.getByRole("button", { name: "New messages ↓" }).click();
  const atBottom = () => list.evaluate(element => element.scrollHeight - element.scrollTop - element.clientHeight < 2);
  check(await atBottom(), "and New messages goes to the bottom");
  agent("send", "at the bottom");
  await laptop.getByText("at the bottom").waitFor();
  await laptop.waitForTimeout(300);
  check(await atBottom(), "a list at the bottom follows new messages");
  await input.fill("");

  // Files: beside the chat on the laptop, a tab on the phone, and loaded only when first shown.
  const path = join(home, "list.md");
  writeFileSync(path, "- [ ] reply to Ann\n- [ ] review budget\n- [ ] book flights\n");
  check(editorLoads.length === 0, "the editor is not loaded before files are shown");
  agent("file", "create", "checklist.md", path);
  const old = agent("file", "show", "checklist.md").version;
  for (const page of [laptop, phone]) {
    await page.getByRole("button", { name: /^Files · 1/ }).click();
    await page.getByRole("button", { name: "checklist.md" }).click();
    await page.locator(".cm-content").waitFor();
  }
  check(editorLoads.length === 1, "and is loaded once they are");
  check(await laptop.locator(".group:visible .chat").isVisible(), "files show beside the chat on a wide screen");
  check(!(await phone.locator(".group:visible .chat").isVisible()), "and instead of it on a phone");
  const text = page => page.locator(".cm-content").evaluate(content => content.cmTile.view.state.doc.toString());
  await laptop.locator(".cm-line", { hasText: "review budget" }).locator(".cm-task").click();
  await phone.locator(".cm-line", { hasText: "book flights" }).click();
  await phone.keyboard.press("End");
  await phone.keyboard.type(" (Tuesday)");
  writeFileSync(path, "- [x] reply to Ann\n- [ ] review budget\n- [ ] book flights\n- [ ] renew passport\n");
  const edit = agent("file", "edit", "--base", old, "checklist.md", path);
  check(edit.lost.length === 0, "the agent's edit from an older version loses nothing");
  const expected = "- [x] reply to Ann\n- [x] review budget\n- [ ] book flights (Tuesday)\n- [ ] renew passport\n";
  for (let i = 0; i < 50 && (await text(laptop)) !== expected; i++) await laptop.waitForTimeout(200);
  for (let i = 0; i < 50 && (await text(phone)) !== expected; i++) await phone.waitForTimeout(200);
  check((await text(laptop)) === expected && (await text(phone)) === expected, "both browsers converge on every edit");
  check(agent("file", "show", "checklist.md").text === expected, "and so does the agent");
  check(!events.some(e => e.type === "message" && !e.content), "file updates never print, so they never wake the agent");

  await phone.locator(".cm-line", { hasText: "renew passport" }).click();
  await phone.keyboard.press("Alt+ArrowUp");
  await phone.waitForTimeout(1500);
  await laptop.reload();
  await laptop.getByRole("button", { name: "checklist.md" }).click();
  const moved = "- [x] reply to Ann\n- [x] review budget\n- [ ] renew passport\n- [ ] book flights (Tuesday)\n";
  for (let i = 0; i < 50 && (await text(laptop)) !== moved; i++) await laptop.waitForTimeout(200);
  check((await text(laptop)) === moved, "Alt+↑ moves a line, and a reloaded browser keeps its files and catches up");
  agent("send", "after the reload");
  await laptop.getByText("after the reload").waitFor();
  check(await laptop.getByText("Thanks, on it").isVisible(), "a reloaded browser keeps its messages and can still read new ones");
  await phone.getByRole("button", { name: "Chat" }).click();
  const phoneList = phone.locator(".group:visible .messages");
  check(await phoneList.evaluate(e => e.scrollHeight - e.scrollTop - e.clientHeight < 2), "back from the files tab, the chat is still at the bottom");

  // Files and images in chat.
  const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "base64");
  await laptop.locator(".group:visible input[type=file]").setInputFiles({ name: "dot.png", mimeType: "image/png", buffer: png });
  await laptop.locator(".chips button", { hasText: "Agent" }).click();
  await laptop.getByPlaceholder("Message").fill("the diagram");
  await laptop.getByPlaceholder("Message").press("Enter");
  const image = await printed(e => e.type === "message" && e.content === "the diagram");
  check(image.attachment, "a browser sends an image as an attachment");
  await phone.locator(".messages img.image").waitFor();
  check((await phone.locator(".messages img.image").getAttribute("src")).startsWith("data:image/png;base64,"), "and the other browser shows it inline");
  const notes = join(home, "notes.txt");
  writeFileSync(notes, "plain notes");
  agent("send", "--attach", notes, "notes.txt");
  const download = phone.waitForEvent("download");
  await phone.getByRole("button", { name: "Download notes.txt" }).click();
  check((await download).suggestedFilename() === "notes.txt", "another file shows as a download");

  // A new group, named; the phone joins it from the list of groups open to Matthew's devices.
  await laptop.getByRole("button", { name: "New group" }).click();
  await laptop.getByLabel("Group name").fill("Trip");
  await laptop.getByRole("button", { name: "Start group" }).click();
  await laptop.getByText("Matthew named the group “Trip” and let their other devices join").waitFor();
  await phone.reload();
  await phone.locator(".opening", { hasText: "Trip" }).getByRole("button", { name: "Join" }).click();
  await phone.locator(".group:visible h2", { hasText: "Trip" }).waitFor();
  await phone.locator(".group:visible .people", { hasText: "Matthew and you" }).waitFor();
  check(true, "a device of Matthew joins a group open to his devices, admitted by a member online");

  await laptop.locator(".group-list button", { hasText: "Agent" }).click();
  await list.evaluate(element => (element.scrollTop = 100));
  await laptop.waitForTimeout(100);
  await laptop.locator(".group-list button", { hasText: "Trip" }).click();
  await laptop.locator(".group-list button", { hasText: "Agent" }).click();
  check((await list.evaluate(element => element.scrollTop)) === 100, "switching groups restores where each list was");
  await laptop.locator(".group-list button", { hasText: "Trip" }).click();

  // Ann starts on the page with a code, typed; she is then removed, and the phone leaves.
  await laptop.getByRole("button", { name: "Invite", exact: true }).click();
  const code = await laptop.locator("dialog .code").textContent();
  const ann = await open("ann", { viewport: { width: 1280, height: 800 } });
  await ann.goto(RELAY);
  await ann.getByLabel("Your name").fill("Ann");
  await ann.getByLabel("Invite code or link").fill(code);
  await ann.getByRole("button", { name: "Join", exact: true }).click();
  await ann.locator(".group:visible h2", { hasText: "Trip" }).waitFor();
  await laptop.getByText("They joined the group.").waitFor();
  check(true, "a first visit joins a group by its typed code");
  await laptop.getByRole("button", { name: "Group settings" }).click();
  await laptop.getByLabel("Group name").fill("Trip to Lisbon");
  await laptop.getByRole("button", { name: "Rename" }).click();
  await ann.locator(".group:visible h2", { hasText: "Trip to Lisbon" }).waitFor();
  check(true, "a group is renamed for everyone");
  await laptop.locator("dialog li", { hasText: "Ann" }).getByRole("button", { name: "Remove" }).click();
  await laptop.locator("dialog li", { hasText: "Ann" }).getByRole("button", { name: "Remove Ann?" }).click();
  await ann.getByText("Matthew removed you from “Trip to Lisbon”").waitFor();
  check((await ann.locator(".group-list button").count()) === 0, "a member is removed, and the removed browser drops the group");
  await laptop.keyboard.press("Escape");
  await phone.getByRole("button", { name: "Group settings" }).click();
  await phone.getByRole("button", { name: "Leave group" }).click();
  await phone.getByRole("button", { name: "Leave for good?" }).click();
  await laptop.getByText("Matthew · phone left").waitFor();
  check(!(await phone.locator(".group-list button", { hasText: "Trip" }).count()), "a browser leaves a group: it asks, and another member commits its removal");
  await phone.reload();
  await phone.locator(".group-list button", { hasText: "Agent" }).waitFor();
  check(!(await phone.locator(".opening", { hasText: "Trip" }).count()), "and the group it left is not offered again");

  const { fp } = agent("members", "--group", group).members.find(m => m.name === "phone");
  agent("remove", fp, "--group", group);
  await phone.getByText("Agent removed you from a group").waitFor();
  check((await phone.locator(".group-list button").count()) === 0, "a browser removed from a group drops it");
} catch (error) {
  for (const [name, page] of Object.entries(pages)) {
    console.log(`${name} shows:`, JSON.stringify(await page.locator("#app").innerText()));
  }
  throw error;
} finally {
  await browser.close();
  listener.kill();
}
console.log("browser: all passed");
