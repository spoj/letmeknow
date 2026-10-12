// Test the exact release directory; faults modify only disposable copies.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cp, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { resolve, extname, join } from "node:path";
import { chromium } from "playwright";

const dist = resolve(process.argv[2]);
const backend = JSON.parse(await readFile(process.env.LMK_FRONTEND_CONFIG ?? "backend.json", "utf8"));
const files = await readdir(dist);
const app = (await Promise.all(files.filter(file => file.endsWith(".js")).map(file => readFile(`${dist}/${file}`, "utf8")))).join("\n");
assert(app.includes(`${backend.membershipKey}@${new URL(backend.relay).origin}`));
assert.equal(await readFile(`${dist}/i/index.html`, "utf8"), await readFile(`${dist}/index.html`, "utf8"));
assert(!files.includes("CNAME"), "the frontend hostname belongs in the static host's configuration");
assert(!files.includes("membership"));
assert(files.some(file => file.endsWith(".wasm")));
const mime = { ".html": "text/html", ".js": "text/javascript", ".wasm": "application/wasm", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".webmanifest": "application/manifest+json" };
let legacy = false;
const oldHTML = '<h1>Old backend-installed app</h1>';
const oldWorker = `self.addEventListener("install", event => event.waitUntil(caches.open("old-backend").then(cache => cache.put("/", new Response(${JSON.stringify(oldHTML)}, {headers:{"Content-Type":"text/html"}}))))); self.addEventListener("fetch", event => { if (event.request.mode === "navigate") event.respondWith(caches.match("/")); });`;
const server = createServer(async (req, res) => {
  let path = new URL(req.url, "http://localhost").pathname;
  if (legacy) {
    res.writeHead(200, { "content-type": path === "/sw.js" ? "text/javascript" : "text/html", "cache-control": "max-age=31536000" }).end(path === "/sw.js" ? oldWorker : oldHTML);
    return;
  }
  if (path === "/i") {
    res.writeHead(301, { location: "/i/" }).end();
    return;
  }
  if (path.endsWith("/")) path += "index.html";
  try {
    const data = await readFile(dist + path);
    res.writeHead(200, { "content-type": mime[extname(path)] ?? "application/octet-stream" }).end(data);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    res.writeHead(404).end();
  }
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch();
const errors = [];
async function welcome(page) {
  await page.locator(".welcome h1").waitFor();
  assert.equal(await page.locator(".welcome h1").textContent(), "This is not a letmeknow invite", "artifact did not reach its healthy welcome");
  assert.equal(await page.locator('.welcome[role="alert"]').count(), 0);
  assert(await page.getByLabel("Your name", { exact: true }).isVisible());
  assert(await page.getByLabel("Device name", { exact: true }).isVisible());
  assert(await page.getByRole("button", { name: "Continue", exact: true }).isVisible());
}
try {
  const context = await browser.newContext();
  const requests = [];
  context.on("request", request => requests.push(request.url()));
  await context.route("**/*", route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort());
  const page = await context.newPage();
  page.on("pageerror", error => errors.push(error.message));
  await page.goto(`${origin}/i#invalid-test-invite`);
  assert.equal(new URL(page.url()).hash, "#invalid-test-invite");
  await welcome(page);
  await page.evaluate(() => navigator.serviceWorker.ready);
  await page.reload();
  await welcome(page);
  assert(await page.evaluate(() => !!navigator.serviceWorker.controller));
  await context.setOffline(true);
  await page.reload();
  await welcome(page);
  assert.deepEqual(errors, []);
  assert(requests.every(url => new URL(url).origin === origin));
  assert(!requests.some(url => new URL(url).pathname === "/membership"));
  await context.close();
  console.log("ok - release artifact: healthy online/SW/offline startup, pinned config, invite entry and same-origin code");

  const upgrade = await browser.newContext();
  const old = await upgrade.newPage();
  old.on("pageerror", error => errors.push(error.message));
  legacy = true;
  await old.goto(origin);
  await old.evaluate(async () => {
    localStorage.setItem("lmk membership", `${"11".repeat(32)}@https://old-backend.invalid`);
    localStorage.setItem("lmk relay", "https://old-relay.invalid");
    localStorage.setItem("unrelated preference", "keep");
    await new Promise((resolve, reject) => {
      const request = indexedDB.open("old-client-preservation-canary", 1);
      request.onupgradeneeded = () => request.result.createObjectStore("evidence");
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const tx = request.result.transaction("evidence", "readwrite", { durability: "strict" });
        tx.objectStore("evidence").put("preserved", "old local data");
        tx.oncomplete = () => { request.result.close(); resolve(); };
        tx.onabort = () => reject(tx.error);
      };
    });
    await navigator.serviceWorker.register("/sw.js");
    await navigator.serviceWorker.ready;
  });
  await old.reload();
  assert(await old.evaluate(() => !!navigator.serviceWorker.controller));
  legacy = false;
  await old.reload();
  assert.equal(await old.locator("h1").textContent(), "Old backend-installed app", "changing the server does not revoke installed code");
  assert(await old.evaluate(() => !!localStorage.getItem("lmk membership")));

  // Browser-controlled recovery, not an old page's Reload button. Preserve IndexedDB.
  const cdp = await upgrade.newCDPSession(old);
  await cdp.send("ServiceWorker.enable");
  await old.goto("about:blank");
  await cdp.send("ServiceWorker.unregister", { scopeURL: `${origin}/` });
  await cdp.send("Storage.clearDataForOrigin", { origin, storageTypes: "cache_storage" });
  await cdp.send("Network.clearBrowserCache");
  await old.goto(`${origin}/i#invalid-test-invite`);
  await welcome(old);
  assert(await old.evaluate(() => !!localStorage.getItem("lmk membership")));
  for (const key of ["lmk membership", "lmk relay"]) {
    await cdp.send("DOMStorage.removeDOMStorageItem", { storageId: { securityOrigin: origin, isLocalStorage: true }, key });
  }
  await old.reload();
  await welcome(old);
  assert.deepEqual(await old.evaluate(() => [localStorage.getItem("lmk membership"), localStorage.getItem("lmk relay"), localStorage.getItem("unrelated preference")]), [null, null, "keep"]);
  assert.equal(await old.evaluate(() => new Promise((resolve, reject) => {
    const request = indexedDB.open("old-client-preservation-canary", 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const data = request.result.transaction("evidence").objectStore("evidence").get("old local data");
      data.onsuccess = () => { request.result.close(); resolve(data.result); };
      data.onerror = () => reject(data.error);
    };
  })), "preserved");
  assert.deepEqual(errors, []);
  await upgrade.close();
  console.log("ok - inherited worker/HTTP caches and backend choices require trusted recovery; client IndexedDB survives");
} finally {
  await browser.close();
  await new Promise(resolve => server.close(resolve));
}

if (process.argv.includes("--negative-controls")) {
  for (const fault of ["wasm", "caught startup"]) {
    const copy = await mkdtemp(join(tmpdir(), "lmk-artifact-fault-"));
    try {
      await cp(dist, copy, { recursive: true });
      if (fault === "wasm") await writeFile(join(copy, files.find(file => file.endsWith(".wasm"))), "invalid wasm served with HTTP 200");
      else await writeFile(join(copy, "app.js"), 'IDBFactory.prototype.open = () => { throw new Error("injected caught initialization failure"); };\n' + await readFile(join(copy, "app.js"), "utf8"));
      const result = spawnSync(process.execPath, [import.meta.filename, copy], { encoding: "utf8", timeout: 60000 });
      assert.ifError(result.error);
      assert.notEqual(result.status, 0, `${fault} must not pass the artifact gate`);
      assert.match(result.stderr, /artifact did not reach its healthy welcome/);
      assert.match(result.stderr, /Could not open this session/);
      console.log(`ok - artifact gate rejects ${fault}`);
    } finally {
      await rm(copy, { recursive: true, force: true });
    }
  }
}
