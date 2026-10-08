// Browser end-to-end test, run by test/e2e.py against its local relay (RELAY) with the session binary (BIN): Matthew
// joins an agent's group from his laptop and his phone, they chat, and all three edit one checklist at once.
import { execFileSync, spawn } from "node:child_process";
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
function printed(predicate, ms = 15_000) {
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
try {
  await printed(e => e.type === "ready");
  const { link, group } = agent("invite");
  const laptop = await (await browser.newContext()).newPage();
  const phone = await (await browser.newContext()).newPage();
  Object.assign(pages, { laptop, phone });
  for (const [name, page] of Object.entries(pages)) {
    page.on("console", message => message.type() === "error" && console.log(`${name}: ${message.text()}`));
    page.on("pageerror", error => console.log(`${name}: ${error}`));
  }

  await laptop.goto(link);
  await laptop.getByPlaceholder("Your name").fill("Matthew");
  await laptop.getByRole("button", { name: "Join" }).click();
  await laptop.locator("header .members", { hasText: "Agent" }).waitFor();
  check(new URL(laptop.url()).pathname === "/", "a browser joins from an invite link, with a click");
  const joined = await printed(e => e.type === "joined" && e.member.name === "Matthew");
  check(joined.member.entity?.name === "Matthew", "the agent sees the browser member speak as the entity it started");

  // The phone becomes one of Matthew's devices, then joins from its own link and speaks as Matthew too.
  await laptop.getByRole("button", { name: "Matthew · devices" }).click();
  await laptop.getByRole("button", { name: "Link a device" }).click();
  const deviceLink = await laptop.locator(".invite code").nth(1).textContent();
  await phone.goto(deviceLink);
  await phone.getByPlaceholder("Your name").fill("Matthew's phone");
  await phone.getByRole("button", { name: "Add this browser" }).click();
  await laptop.getByText("Matthew's phone").waitFor();
  await phone.goto(agent("invite", "--group", group).link);
  await phone.getByRole("button", { name: "Join" }).click();
  await phone.locator("header .members", { hasText: "Agent" }).waitFor();
  const second = await printed(e => e.type === "joined" && e.member.name === "Matthew's phone");
  check(second.member.entity?.name === "Matthew", "a linked phone joins from another invite link as a second member speaking as Matthew");

  await laptop.getByRole("button", { name: /^group / }).click();
  const morning = agent("send", "Morning. Your priority list is ready.").id;
  for (const page of [laptop, phone]) await page.getByText("Morning. Your priority list is ready.").waitFor();
  console.log("ok - both browsers show the agent's message");
  await laptop.locator(".chips button", { hasText: "Agent" }).click();
  await laptop.getByPlaceholder(/^Message/).fill("Thanks, on it");
  await laptop.getByPlaceholder(/^Message/).press("Enter");
  const direct = await printed(e => e.type === "message" && e.content === "Thanks, on it");
  check(direct.direct && direct.from.entity.name === "Matthew", "a browser sends a direct message to the agent");
  await phone.locator(".messages li", { hasText: "Morning." }).hover();
  await phone.locator(".messages li", { hasText: "Morning." }).getByRole("button", { name: "Reply" }).click();
  await phone.getByText("urgent", { exact: true }).click();
  await phone.getByPlaceholder(/^Message/).fill("Call me");
  await phone.getByPlaceholder(/^Message/).press("Enter");
  const reply = await printed(e => e.type === "message" && e.content === "Call me");
  check(reply.urgent && reply.reply_to === morning, "a browser sends an urgent reply");
  await laptop.getByText("Call me").waitFor();
  console.log("ok - the other browser shows it too");

  // The checklist: the agent rewrites it from an older version while Matthew ticks and adds items in both browsers.
  const path = join(home, "list.md");
  writeFileSync(path, "- [ ] reply to Ann\n- [ ] review budget\n- [ ] book flights\n");
  agent("file", "create", "checklist.md", path);
  const old = agent("file", "show", "checklist.md").version;
  for (const page of [laptop, phone]) {
    await page.getByRole("button", { name: /^Files/ }).click();
    await page.getByRole("button", { name: "checklist.md" }).click();
  }
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
  await laptop.getByRole("button", { name: /^Files/ }).click();
  await laptop.getByRole("button", { name: "checklist.md" }).click();
  const moved = "- [x] reply to Ann\n- [x] review budget\n- [ ] renew passport\n- [ ] book flights (Tuesday)\n";
  for (let i = 0; i < 50 && (await text(laptop)) !== moved; i++) await laptop.waitForTimeout(200);
  check((await text(laptop)) === moved, "Alt+↑ moves a line, and a reloaded browser keeps its files and catches up");
  await laptop.getByRole("button", { name: "Chat" }).click();
  agent("send", "after the reload");
  await laptop.getByText("after the reload").waitFor();
  check(await laptop.getByText("Thanks, on it").isVisible(), "a reloaded browser keeps its messages and can still read new ones");

  // Images: the agent links one into the checklist, the laptop pastes another, and a browser added later sees both.
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
  const attached = agent("file", "attach", chart);
  const before = agent("file", "show", "checklist.md");
  writeFileSync(path, before.text + attached.markdown + "\n");
  agent("file", "edit", "--base", before.version, "checklist.md", path);
  await laptop.getByRole("button", { name: /^Files/ }).click();
  await laptop.getByRole("button", { name: "checklist.md" }).click();
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
    pasted = /!\[screenshot\]\((lmk:[0-9a-f#]+)\)/.exec(agent("file", "show", "checklist.md").text)?.[1];
    if (!pasted) await laptop.waitForTimeout(200);
  }
  const fetched = agent("file", "fetch", pasted);
  const webp = readFileSync(fetched.path);
  check(fetched.path.endsWith(".webp") && webp.subarray(8, 12).toString() === "WEBP", "the agent fetches the pasted image, as WebP, from its link");

  // The laptop adds a member, so it puts both images again; the new member fetches them.
  await laptop.getByRole("button", { name: "Invite" }).click();
  const lateLink = await laptop.locator(".invite code").nth(1).textContent();
  const late = await (await browser.newContext()).newPage();
  pages.late = late;
  await late.goto(lateLink);
  await late.getByPlaceholder("Your name").fill("Ann");
  await late.getByRole("button", { name: "Join" }).click();
  await late.locator("header .members", { hasText: "Agent" }).waitFor();
  await late.getByRole("button", { name: /^Files/ }).click();
  await late.getByRole("button", { name: "checklist.md" }).click();
  check((await (await shown(late, 2)).jsonValue()).join() === "120,1600", "a member added later sees both images");
  await laptop.getByRole("button", { name: "Chat" }).click();

  // An open group: the laptop starts a group open to Matthew; the phone joins it without an invite.
  await laptop.getByRole("button", { name: "+ New group" }).click();
  await laptop.getByRole("button", { name: "Open to Matthew" }).click();
  await laptop.getByText("opened it to Matthew").waitFor();
  await phone.reload();
  await phone.locator(".opening").getByRole("button", { name: "Join" }).click();
  await phone.getByText("opened it to Matthew").waitFor();
  check((await phone.locator("header .members").textContent()).includes("(you)"), "a device of Matthew joins a group open to Matthew, admitted by a member online");

  const { fp } = agent("members", "--group", group).members.find(m => m.name === "Matthew's phone");
  agent("remove", fp, "--group", group);
  await phone.getByText(`Agent removed you from group ${group.slice(0, 6)}`).waitFor();
  check((await phone.locator("nav button", { hasText: `group ${group.slice(0, 6)}` }).count()) === 0, "a browser removed from a group drops it");
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
