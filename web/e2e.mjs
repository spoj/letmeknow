// Browser end-to-end test, run by test/e2e.py against its local relay (RELAY) with the session binary (BIN): Matthew
// joins an agent's chat from his laptop, adds his phone, which joins his chats and docs on its own, they chat, and all
// three edit one checklist doc at once, with files in it. Ann starts on the page with a typed code, and leaves or is
// removed.
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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
  agent("entity", "create", "Acme");
  const { link, group } = agent("invite");
  const laptop = await open("laptop", { viewport: { width: 1280, height: 800 } });
  const phone = await open("phone", { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const editorLoads = [];
  laptop.on("request", request => request.url().includes("/assets/editor-") && editorLoads.push(request.url()));

  // Invited by link: what it is, a name, Join, and the chat.
  await laptop.goto(link);
  await laptop.getByRole("heading", { name: "You're invited" }).waitFor();
  await laptop.getByLabel("Your name").fill("Matthew");
  await laptop.getByRole("button", { name: "Join", exact: true }).click();
  await laptop.locator(".people", { hasText: "Agent" }).waitFor();
  check(new URL(laptop.url()).pathname === "/", "a browser joins from an invite link, with a click");
  const joined = await printed(e => e.type === "joined" && e.member.entity?.name === "Matthew");
  check(joined.member.name === "laptop", "the agent sees the browser member speak as the person it started, named as a device");
  await laptop.getByText("Matthew · laptop let their other devices join").waitFor();
  check(true, "a chat the browser joins lets its person's other devices join");

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
  await laptop.getByText("Added. The device now joins your chats and documents.").waitFor();
  await laptop.locator(".devices li", { hasText: "phone" }).waitFor();
  check(true, "the laptop lists the phone among Matthew's devices");
  const second = await printed(e => e.type === "joined" && e.member.name === "phone");
  check(second.member.entity?.name === "Matthew", "the added phone joins Matthew's group on its own, as a second member speaking as Matthew");
  await phone.locator(".back:visible").click();
  await phone.locator(".group-list button", { hasText: "Acme" }).click();
  await phone.locator(".people", { hasText: "your laptop" }).waitFor();
  check((await phone.locator(".people").textContent()).includes("Acme · Agent"), "and lists who is who, by whose they are");
  check((await phone.locator(".group-list button span").first().textContent()) === "Acme", "and titles the chat by whose its other members are");

  await laptop.locator(".group-list button").first().click();
  const morning = agent("send", "Morning. Your priority list is ready.").id;
  for (const page of [laptop, phone]) await page.getByText("Morning. Your priority list is ready.").waitFor();
  console.log("ok - both browsers show the agent's message");
  const met = await phone.locator(".messages li", { hasText: "Morning." }).textContent();
  check(met.includes("Acme · Agent new"), "marked as from an entity the phone had not met, though it had listed its members");
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

  // A doc: the agent makes one and invites the laptop, whose phone joins it as Matthew's device. The editor loads only
  // once a doc shows.
  check(editorLoads.length === 0, "the editor is not loaded before a doc shows");
  const checklist = agent("invite", "--kind", "doc", "--name", "Checklist");
  await laptop.goto(checklist.link);
  await laptop.locator("dialog").getByRole("button", { name: "Join", exact: true }).click();
  await laptop.locator(".cm-content").waitFor();
  check(editorLoads.length === 1, "and is loaded once one does");
  await phone.reload();
  await phone.locator(".opening", { hasText: "Checklist" }).getByRole("button", { name: "Join" }).click();
  await phone.locator(".cm-content").waitFor();
  check(true, "the phone joins the doc as one of Matthew's devices");
  const path = join(home, "list.md");
  writeFileSync(path, "- [ ] reply to Ann\n- [ ] review budget\n- [ ] book flights\n");
  agent("doc", "edit", "--base", agent("doc", "show").version, path);
  const old = agent("doc", "show").version;
  const text = page => page.locator(".cm-content").evaluate(content => content.cmTile.view.state.doc.toString());
  await laptop.locator(".cm-line", { hasText: "review budget" }).locator(".cm-task").click();
  await phone.locator(".cm-line", { hasText: "book flights" }).click();
  await phone.keyboard.press("End");
  await phone.keyboard.type(" (Tuesday)");
  writeFileSync(path, "- [x] reply to Ann\n- [ ] review budget\n- [ ] book flights\n- [ ] renew passport\n");
  const edit = agent("doc", "edit", "--base", old, path);
  check(edit.lost.length === 0, "the agent's edit from an older version loses nothing");
  const expected = "- [x] reply to Ann\n- [x] review budget\n- [ ] book flights (Tuesday)\n- [ ] renew passport\n";
  for (let i = 0; i < 50 && (await text(laptop)) !== expected; i++) await laptop.waitForTimeout(200);
  for (let i = 0; i < 50 && (await text(phone)) !== expected; i++) await phone.waitForTimeout(200);
  check((await text(laptop)) === expected && (await text(phone)) === expected, "both browsers converge on every edit");
  check(agent("doc", "show").text === expected, "and so does the agent");
  check(events.filter(e => e.group === checklist.group).every(e => ["joined", "settings"].includes(e.type)), "edits never print, so they never wake the agent");
  await laptop.locator(".beside-picker").selectOption({ label: "💬 Acme" });
  await laptop.locator(".beside .messages").waitFor();
  check(await laptop.getByText("Thanks, on it").isVisible(), "on a wide screen, a chat picked for the doc shows beside it");
  check(!(await phone.locator(".beside-picker").isVisible()), "on a phone, the doc has the screen to itself");

  await phone.locator(".cm-line", { hasText: "renew passport" }).click();
  await phone.keyboard.press("Alt+ArrowUp");
  await phone.waitForTimeout(1500);
  // The laptop's key update on reload is a commit the relay takes, but its answer is lost on the way back.
  let lost = 0;
  await laptop.route(`**/g/${group}/messages`, async route => {
    const body = route.request().postDataBuffer();
    if (lost || route.request().method() !== "POST" || body[45] !== 3) return route.continue();
    lost++;
    await route.fetch();
    await route.abort();
  });
  const fetches = [];
  laptop.on("request", request => request.method() === "GET" && request.url().includes(`/g/${group}/messages`) && fetches.push(request.url()));
  await laptop.reload();
  const moved = "- [x] reply to Ann\n- [x] review budget\n- [ ] renew passport\n- [ ] book flights (Tuesday)\n";
  await laptop.locator(".cm-content").waitFor();
  for (let i = 0; i < 50 && (await text(laptop)) !== moved; i++) await laptop.waitForTimeout(200);
  check((await text(laptop)) === moved, "Alt+↑ moves a line, and a reloaded browser reopens the doc it showed, caught up");
  agent("send", "after the reload");
  await laptop.locator(".beside").getByText("after the reload").waitFor();
  check(await laptop.getByText("Thanks, on it").isVisible(), "with the chat beside it, which keeps its messages and still reads new ones");
  await phone.locator(".back:visible").click();
  await phone.locator(".group-list button", { hasText: "Acme" }).click();
  const phoneList = phone.locator(".group:visible .messages");
  check(await phoneList.evaluate(e => e.scrollHeight - e.scrollTop - e.clientHeight < 2), "back from the doc, the chat is still at the bottom");
  check(lost === 1, "even when the relay took its key update but the answer was lost");
  check(fetches.length === 1, `and catching up after the reload took one fetch (${fetches.length})`);
  check(!(await laptop.locator(".messages li", { hasText: "after the reload" }).textContent()).includes(" new"), "and later messages from it are not new");
  await laptop.unrouteAll();
  const requests = [];
  for (const page of [laptop, phone]) page.on("request", request => requests.push(request.url()));
  agent("send", "no fetch needed");
  await laptop.getByText("no fetch needed").waitFor();
  check(!requests.some(url => url.includes("/messages")), "a new message comes in its socket's notice, with no fetch");

  // Files in chat: images show, others download, up to 10 MB.
  await laptop.locator(".group-list button", { hasText: "Acme" }).click();
  const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", "base64");
  await laptop.locator(".group:visible input[type=file]").setInputFiles({ name: "dot.png", mimeType: "image/png", buffer: png });
  await laptop.locator(".chips button", { hasText: "Agent" }).click();
  await laptop.getByPlaceholder("Message").fill("the diagram");
  await laptop.getByPlaceholder("Message").press("Enter");
  const image = await printed(e => e.type === "message" && e.content === "the diagram");
  check(image.attachment?.name === "dot.png" && image.attachment.type === "image/png", "a browser sends an image as an attachment, with its name and type");
  check(readFileSync(agent("fetch", image.attachment.link).path).equals(png), "which the agent fetches");
  await phone.locator(".messages img.image").waitFor();
  check((await phone.locator(".messages img.image").getAttribute("src")).startsWith("data:image/png;base64,"), "and the other browser shows it inline");
  const notes = join(home, "notes.txt");
  writeFileSync(notes, "plain notes");
  agent("send", "--attach", notes, "notes");
  const download = phone.waitForEvent("download");
  await phone.getByRole("button", { name: /^Download notes\.txt/ }).click();
  check((await download).suggestedFilename() === "notes.txt", "another file shows as a download");
  const big = randomBytes(3 * 1024 * 1024);
  writeFileSync(join(home, "big.bin"), big);
  agent("send", "--attach", join(home, "big.bin"), "big");
  const bigDownload = laptop.waitForEvent("download");
  await laptop.getByRole("button", { name: /^Download big\.bin/ }).click();
  check(readFileSync(await (await bigDownload).path()).equals(big), "a large file arrives whole");

  // Images in the doc: the agent links one, the laptop pastes another, and a member added later sees both, as whoever
  // adds a member keeps the doc's files on the relay.
  const picture = (page, width, height) =>
    page.evaluate(async ([width, height]) => {
      const canvas = Object.assign(document.createElement("canvas"), { width, height });
      const context = canvas.getContext("2d");
      context.fillStyle = "#2563eb";
      context.fillRect(0, 0, width, height);
      context.fillStyle = "#f59e0b";
      context.fillRect(width / 4, height / 4, width / 2, height / 2);
      return canvas.toDataURL("image/png").split(",")[1];
    }, [width, height]);
  const chart = join(home, "chart.png");
  writeFileSync(chart, Buffer.from(await picture(laptop, 120, 80), "base64"));
  const attached = agent("doc", "attach", chart);
  const before = agent("doc", "show");
  writeFileSync(path, before.text + attached.markdown + "\n");
  agent("doc", "edit", "--base", before.version, path);
  await laptop.locator(".group-list button", { hasText: "Checklist" }).click();
  const shown = (page, count) =>
    page.waitForFunction(count => {
      const images = [...document.querySelectorAll(".cm-image img")];
      return images.length === count && images.every(image => image.complete && image.naturalWidth > 0 && image.src.startsWith("data:image/")) && images.map(image => image.naturalWidth);
    }, count);
  check((await (await shown(laptop, 1)).jsonValue())[0] === 120, "a browser shows the image an agent linked, inline, decrypted");
  check((await text(laptop)).includes(attached.markdown), "and keeps the link as editable text");
  await laptop.locator(".cm-line").last().click();
  await laptop.locator(".cm-content").evaluate(async (content, png) => {
    const data = new DataTransfer();
    data.items.add(new File([Uint8Array.from(atob(png), c => c.charCodeAt(0))], "screenshot.png", { type: "image/png" }));
    content.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
  }, await picture(laptop, 2400, 1200));
  check((await (await shown(laptop, 2)).jsonValue())[1] === 1600, "a pasted image is scaled down, uploaded and shown");
  let pasted;
  for (let i = 0; i < 50 && !pasted; i++) {
    pasted = /!\[screenshot\]\((lmk:[0-9a-f#]+)\)/.exec(agent("doc", "show").text)?.[1];
    if (!pasted) await laptop.waitForTimeout(200);
  }
  const fetched = agent("fetch", pasted);
  check(fetched.path.endsWith(".webp") && readFileSync(fetched.path).subarray(8, 12).toString() === "WEBP", "the agent fetches the pasted image, as WebP, from its link");
  await laptop.locator("main > .group:visible > .group-head").getByRole("button", { name: "Invite", exact: true }).click();
  const lateCode = await laptop.locator("dialog .code").textContent();
  const late = await open("bea", { viewport: { width: 1280, height: 800 } });
  await late.goto(RELAY);
  await late.getByLabel("Your name").fill("Bea");
  await late.getByLabel("Invite code or link").fill(lateCode);
  await late.getByRole("button", { name: "Join", exact: true }).click();
  await laptop.getByText("They joined the document.").waitFor();
  await laptop.keyboard.press("Escape");
  await late.locator(".group:visible h2", { hasText: "Checklist" }).waitFor();
  check(true, "a member added to a doc has its name at once, from its welcome");
  check((await (await shown(late, 2)).jsonValue()).join() === "120,1600", "and sees both images");
  await late.locator(".cm-content").evaluate(async (content, png) => {
    const data = new DataTransfer();
    data.items.add(new File([Uint8Array.from(atob(png), c => c.charCodeAt(0))], "photo.png", { type: "image/png" }));
    const { left, bottom } = [...content.querySelectorAll(".cm-line")].at(-1).getBoundingClientRect();
    content.dispatchEvent(new DragEvent("drop", { dataTransfer: data, clientX: left + 2, clientY: bottom - 2, bubbles: true, cancelable: true }));
  }, await picture(late, 300, 200));
  await shown(laptop, 3);
  check(/\)\n!\[photo\]\(lmk:[0-9a-f#]+\)$/.test(await text(laptop)), "an image dropped onto a line goes on its own line after it, and reaches the others");
  const current = agent("doc", "show");
  writeFileSync(path, `${current.text}\n${agent("doc", "attach", notes).markdown}\n`);
  agent("doc", "edit", "--base", current.version, path);
  const linked = laptop.waitForEvent("download");
  await laptop.locator(".cm-link", { hasText: "notes.txt" }).click();
  check((await linked).suggestedFilename() === "notes.txt", "another file the doc links downloads on a click");

  // A new chat, named; the phone joins it from the list of chats and docs open to Matthew's devices.
  await laptop.getByRole("button", { name: "New chat" }).click();
  await laptop.locator("dialog").getByLabel("Name").fill("Trip");
  await laptop.locator("dialog").getByRole("button", { name: "Start" }).click();
  await laptop.getByText("Matthew · laptop named the chat “Trip” and let their other devices join").waitFor();
  await phone.reload();
  await phone.locator(".opening", { hasText: "Trip" }).getByRole("button", { name: "Join" }).click();
  await phone.locator(".group:visible h2", { hasText: "Trip" }).waitFor();
  await phone.locator(".group:visible .people", { hasText: "your laptop and you" }).waitFor();
  check(true, "a device of Matthew joins a chat open to his devices, admitted by a member online");
  await laptop.waitForTimeout(2_000);
  requests.length = 0;
  await laptop.waitForTimeout(16_000);
  check(requests.length === 0, `idle browsers with working sockets send no requests, even in a chat open to them (${requests})`);

  await laptop.locator(".group-list button", { hasText: "Acme" }).click();
  await list.evaluate(element => (element.scrollTop = 100));
  await laptop.waitForTimeout(100);
  await laptop.locator(".group-list button", { hasText: "Trip" }).click();
  await laptop.locator(".group-list button", { hasText: "Acme" }).click();
  check((await list.evaluate(element => element.scrollTop)) === 100, "switching chats restores where each list was");
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
  await laptop.getByText("They joined the chat.").waitFor();
  check(true, "a first visit joins a chat by its typed code");
  await laptop.keyboard.press("Escape");
  await laptop.getByRole("button", { name: "Settings" }).click();
  await laptop.locator("dialog").getByLabel("Name").fill("Trip to Lisbon");
  await laptop.getByRole("button", { name: "Rename" }).click();
  await ann.locator(".group:visible h2", { hasText: "Trip to Lisbon" }).waitFor();
  check(true, "a chat is renamed for everyone");
  await laptop.locator("dialog li", { hasText: "Ann" }).getByRole("button", { name: "Remove" }).click();
  await laptop.locator("dialog li", { hasText: "Ann" }).getByRole("button", { name: "Remove Ann · laptop?" }).click();
  await ann.getByText("Matthew removed you from “Trip to Lisbon”").waitFor();
  check((await ann.locator(".group-list button").count()) === 0, "a member is removed, and the removed browser drops the chat");
  await laptop.keyboard.press("Escape");
  await phone.getByRole("button", { name: "Settings" }).click();
  await phone.getByRole("button", { name: "Leave chat" }).click();
  await phone.getByRole("button", { name: "Leave for good?" }).click();
  await laptop.getByText("Matthew · phone left").waitFor();
  check(!(await phone.locator(".group-list button", { hasText: "Trip" }).count()), "a browser leaves a chat: it asks, and another member commits its removal");
  await phone.reload();
  await phone.locator(".group-list button", { hasText: "Acme" }).waitFor();
  check(!(await phone.locator(".opening", { hasText: "Trip" }).count()), "and the chat it left is not offered again");

  // Taken off Matthew's devices, the phone still says it is his: the others see a plain warning.
  await laptop.getByRole("button", { name: /Your devices/ }).click();
  await laptop.locator(".devices li", { hasText: "phone" }).getByRole("button", { name: "Remove" }).click();
  await laptop.locator(".devices li", { hasText: "phone" }).getByRole("button", { name: "Remove phone?" }).click();
  await laptop.locator(".devices li", { hasText: "phone" }).waitFor({ state: "detached" });
  await laptop.locator(".group-list button", { hasText: "Acme" }).click();
  await phone.locator(".group-list button", { hasText: "Acme" }).click();
  await phone.getByPlaceholder("Message").fill("still me");
  await phone.getByRole("button", { name: "Send" }).click();
  const claim = laptop.locator(".messages li", { hasText: "still me" }).locator(".who");
  await claim.waitFor();
  check((await claim.getAttribute("class")).includes("warn") && (await claim.getAttribute("title")).startsWith("Says it is Matthew's, but is not on Matthew's list of devices."), "a member that claims to be someone's device but is not on their list shows a plain warning");

  const { fp } = agent("members", "--group", group).members.find(m => m.name === "phone");
  agent("remove", fp, "--group", group);
  await phone.getByText("Acme removed you from a chat").waitFor();
  check(!(await phone.locator(".group-list button", { hasText: "Acme" }).count()), "a browser removed from a chat drops it");

  // The laptop renames itself: each chat and doc learns the name from a key update, and Matthew's list holds it too.
  await laptop.getByRole("button", { name: /Your devices/ }).click();
  await laptop.locator(".devices li", { hasText: "this browser" }).getByRole("button", { name: "Rename" }).click();
  await laptop.getByLabel("Name this device").fill("desk");
  await laptop.locator("dialog").getByRole("button", { name: "Rename" }).click();
  await laptop.locator(".devices li", { hasText: "desk" }).waitFor();
  const renamed = () => agent("members", "--group", group).members.find(m => m.entity?.name === "Matthew")?.name;
  for (let i = 0; i < 50 && renamed() !== "desk"; i++) await laptop.waitForTimeout(200);
  check(renamed() === "desk", "a browser renames itself, in its groups and on its person's list of devices");
} catch (error) {
  for (const [name, page] of Object.entries(pages)) {
    console.log(`${name} shows:`, JSON.stringify(await page.locator("#app").innerText({ timeout: 1_000 }).catch(() => "")));
  }
  throw error;
} finally {
  await browser.close();
  listener.kill();
}
console.log("browser: all passed");
