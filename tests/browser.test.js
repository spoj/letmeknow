import assert from "node:assert/strict";
import { accessSync, constants, readFileSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { WebSocketServer } from "ws";
import { describe, it } from "node:test";

const firefox = "/usr/bin/firefox";
const geckodriver = "/usr/bin/geckodriver";
const runtimeFile = new URL("../src/runtime.client.js", import.meta.url);

function requireExecutable(path, name) {
  try {
    accessSync(path, constants.X_OK);
  } catch {
    throw new Error(`${name} is required for the browser smoke test: ${path}`);
  }
}

function request(port, method, path, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, method, path, headers: body === undefined ? {} : { "content-type": "application/json" } }, response => {
      const chunks = [];
      response.on("data", chunk => chunks.push(chunk));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString();
        let value;
        try { value = text ? JSON.parse(text) : undefined; } catch { value = text; }
        if (response.statusCode < 200 || response.statusCode >= 300) reject(new Error(`WebDriver ${method} ${path} returned ${response.statusCode}: ${text}`));
        else resolve(value);
      });
    });
    req.on("error", reject);
    if (body !== undefined) req.end(JSON.stringify(body));
    else req.end();
  });
}

async function waitFor(check, message, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  let last;
  while (Date.now() < deadline) {
    last = await check();
    if (last) return last;
    await new Promise(resolve => setTimeout(resolve, 40));
  }
  throw new Error(`${message}${last === undefined ? "" : ` (last value: ${JSON.stringify(last)})`}`);
}

function sleep(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function stopProcess(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([once(child, "exit"), sleep(2_000)]);
  if (child.exitCode === null) child.kill("SIGKILL");
}

function documentPage(pageEvent, title, body, dynamic = true) {
  const pageAttribute = dynamic ? ` data-letmeknow-page-event="${pageEvent}"` : "";
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}<script id="agent-script">window.agentScriptRuns = (window.agentScriptRuns || 0) + 1;</script><script type="module" src="/_letmeknow/client.js" data-letmeknow-runtime${pageAttribute}></script></body></html>`;
}

const initialPage = documentPage(0, "Initial", `
  <main id="letmeknow-root">
    <h1 id="heading">Initial</h1>
    <output id="counter">0</output>
    <form id="review" action="/review" method="post">
      <label>Message <textarea id="message" name="message"></textarea></label>
      <label>Other <input id="other" name="other"></label>
      <label><input id="tag-one" type="checkbox" name="tag" value="one"> One</label>
      <label><input id="tag-two" type="checkbox" name="tag" value="two"> Two</label>
      <button id="submit" name="decision" value="approve">Approve</button>
      <output id="status" data-letmeknow-status role="status"></output>
    </form>
    <details id="more"><summary>More</summary><p>Details</p></details>
    <section id="local-panel" data-letmeknow-local hidden>Local</section>
  </main>
`);

const recoveredPage = documentPage(52, "Recovered", `
  <main id="letmeknow-root">
    <h1 id="heading">Recovered</h1>
    <output id="counter">recovered</output>
    <form id="review" action="/review" method="post">
      <label>Message <textarea id="message" name="message"></textarea></label>
      <button id="submit" name="decision" value="approve">Approve</button>
      <output id="status" data-letmeknow-status role="status"></output>
    </form>
  </main>
`);

describe("browser runtime", () => {
  it("replaces targeted elements, keeps local state, and recovers invalid updates", async () => {
    requireExecutable(firefox, "Firefox");
    requireExecutable(geckodriver, "geckodriver");

    const runtimeSource = readFileSync(runtimeFile, "utf8");
    let currentPage = initialPage;
    let rootRequests = 0;
    let scriptHits = 0;
    const posts = [];
    const sockets = [];
    const wsServer = new WebSocketServer({ noServer: true });
    const httpServer = http.createServer((req, res) => {
      if (req.method === "GET" && req.url === "/_letmeknow/client.js") {
        res.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
        res.end(runtimeSource);
        return;
      }
      if (req.method === "GET" && req.url === "/script-hit") {
        scriptHits += 1;
        res.writeHead(204);
        res.end();
        return;
      }
      if (req.method === "GET" && req.url === "/static.html") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        res.end(documentPage(null, "Static", "<h1 id=\"static-heading\">Static</h1>", false));
        return;
      }
      if (req.method === "GET" && req.url === "/") {
        rootRequests += 1;
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        res.end(currentPage);
        return;
      }
      if (req.method === "POST" && req.url === "/_letmeknow/submit") {
        const chunks = [];
        req.on("data", chunk => chunks.push(chunk));
        req.on("end", () => {
          posts.push({ headers: req.headers, body: Buffer.concat(chunks).toString() });
          res.writeHead(202);
          res.end();
        });
        return;
      }
      res.writeHead(404);
      res.end("not found");
    });
    httpServer.on("upgrade", (req, socket, head) => {
      if (req.url !== "/_letmeknow/client") {
        socket.destroy();
        return;
      }
      wsServer.handleUpgrade(req, socket, head, client => {
        sockets.push(client);
        client.on("error", () => {});
        client.on("close", () => {});
        client.send(JSON.stringify({ type: "connected", producer_connected: true }));
      });
    });
    await once(httpServer.listen(0, "127.0.0.1"), "listening");
    const port = httpServer.address().port;

    let driver;
    let sessionId;
    let driverError = "";
    const driverPortServer = net.createServer();
    await once(driverPortServer.listen(0, "127.0.0.1"), "listening");
    const driverPort = driverPortServer.address().port;
    await new Promise(resolve => driverPortServer.close(resolve));
    try {
      driver = spawn(geckodriver, ["--port", String(driverPort), "--host", "127.0.0.1"], { stdio: ["ignore", "pipe", "pipe"] });
      driver.stderr.on("data", chunk => { driverError += chunk.toString(); });
      driver.on("error", error => { driverError += error.message; });
      await waitFor(async () => {
        try {
          const status = await request(driverPort, "GET", "/status");
          return status?.value?.ready;
        } catch {
          return false;
        }
      }, "geckodriver did not start", 10_000);
      const created = await request(driverPort, "POST", "/session", {
        capabilities: {
          alwaysMatch: {
            browserName: "firefox",
            "moz:firefoxOptions": { args: ["-headless"], binary: firefox }
          }
        }
      });
      sessionId = created.value?.sessionId || created.sessionId;
      if (!sessionId) throw new Error(`geckodriver did not return a session: ${JSON.stringify(created)}`);

      const command = (method, path, body) => request(driverPort, method, `/session/${sessionId}${path}`, body);
      const execute = script => command("POST", "/execute/sync", { script, args: [] }).then(result => result.value);
      const executeAsync = script => command("POST", "/execute/async", { script, args: [] }).then(result => result.value);
      const outboxCount = () => executeAsync(`const done = arguments[0]; const request = indexedDB.open("letmeknow-outbox-v2:" + location.origin); request.onerror = () => done(-1); request.onsuccess = () => { const transaction = request.result.transaction("submissions", "readonly"); const get = transaction.objectStore("submissions").getAll(); get.onerror = () => done(-1); get.onsuccess = () => done(get.result.length); };`);
      await command("POST", "/url", { url: `http://127.0.0.1:${port}/` });
      await waitFor(async () => (await execute("return document.readyState")) === "complete", "initial page did not load");
      await waitFor(() => sockets.length === 1, "browser did not connect to runtime");
      await waitFor(async () => await execute("return document.querySelector('#counter')?.textContent") === "0", "runtime did not load");
      assert.equal(rootRequests, 1, "initial connection must not reload the page");
      assert.equal(await execute("return window.agentScriptRuns"), 1);

      await execute("document.querySelector('#message').value = 'focused draft'; document.querySelector('#other').value = 'dirty draft'; document.querySelector('#other').dispatchEvent(new Event('input', { bubbles: true })); document.querySelector('#tag-one').checked = true; document.querySelector('#more').open = true; document.querySelector('#local-panel').hidden = false; document.querySelector('#message').focus();");
      for (let eventNumber = 1; eventNumber <= 40; eventNumber += 1) {
        sockets.at(-1).send(JSON.stringify({ type: "update_ui", event_number: eventNumber, target: "counter", html: `<output id="counter">${eventNumber}</output>` }));
      }
      await waitFor(async () => await execute("return document.querySelector('#counter')?.textContent") === "40", "sequential replacements were not all applied");
      const preserved = await execute(`return {
        message: document.querySelector('#message').value,
        other: document.querySelector('#other').value,
        focused: document.activeElement.id,
        checked: document.querySelector('#tag-one').checked,
        details: document.querySelector('#more').open,
        localHidden: document.querySelector('#local-panel').hidden,
        pageEvent: document.querySelector('script[data-letmeknow-runtime]').dataset.letmeknowPageEvent,
        agentScripts: window.agentScriptRuns
      }`);
      assert.deepEqual(preserved, { message: "focused draft", other: "dirty draft", focused: "message", checked: true, details: true, localHidden: false, pageEvent: "40", agentScripts: 1 });

      const baselinePosts = posts.length;
      await execute("document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click();");
      await waitFor(() => posts.length === baselinePosts + 10, "rapid submissions were not all delivered");
      const payloads = posts.slice(baselinePosts).map(post => JSON.parse(post.body));
      assert.equal(new Set(payloads.map(payload => payload.id)).size, 10);
      assert.ok(payloads.every(payload => payload.page_event === 40));

      sockets.at(-1).send(JSON.stringify({ type: "update_ui", event_number: 41, target: "letmeknow-root", html: "<main id=\"letmeknow-root\"><h1 id=\"heading\">Broad</h1><output id=\"counter\">broad</output><form id=\"review\"><input id=\"message\" name=\"message\"><button id=\"submit\">Go</button></form><details id=\"more\"><summary>More</summary></details><section id=\"local-panel\" data-letmeknow-local hidden></section></main>" }));
      await waitFor(async () => await execute("return document.querySelector('#heading')?.textContent") === "Broad", "root replacement was not applied");
      const broadState = await execute(`return {
        message: document.querySelector('#message').value,
        details: document.querySelector('#more').open,
        localHidden: document.querySelector('#local-panel').hidden,
        pageEvent: document.querySelector('script[data-letmeknow-runtime]').dataset.letmeknowPageEvent
      }`);
      assert.deepEqual(broadState, { message: "", details: false, localHidden: true, pageEvent: "41" });

      const invalidUpdate = "<output id=\"counter\">bad</output><script>fetch('/script-hit')</script>";
      const beforeRecovery = rootRequests;
      const beforeRecoverySockets = sockets.length;
      sockets.at(-1).send(JSON.stringify({ type: "update_ui", event_number: 42, target: "counter", html: invalidUpdate }));
      currentPage = recoveredPage;
      await waitFor(() => rootRequests > beforeRecovery, "invalid replacement did not trigger recovery");
      await waitFor(async () => await execute("return document.title") === "Recovered", "recovery did not load the canonical page");
      await sleep(100);
      assert.equal(scriptHits, 0, "scripts in rejected replacements must not execute");

      await waitFor(() => sockets.length > beforeRecoverySockets, "recovered page runtime did not connect");
      sockets.at(-1).send(JSON.stringify({ type: "producer", connected: false }));
      await waitFor(async () => await execute("return document.documentElement.hasAttribute('data-letmeknow-disconnected')"), "producer disconnect was not reflected");
      await execute("document.querySelector('#submit').click();");
      await waitFor(async () => await outboxCount() === 1, "offline submission was not queued");
      await execute("document.querySelector('#submit').click();");
      sockets.at(-1).send(JSON.stringify({ type: "closed", message: "Session expired" }));
      await waitFor(async () => await execute("return document.querySelector('[data-letmeknow-system-status]')?.textContent") === "Session expired", "terminal status was not shown");
      await waitFor(async () => await outboxCount() === 0, "terminal session did not clear the outbox");
      sockets.at(-1).send(JSON.stringify({ type: "producer", connected: true }));
      sockets.at(-1).send(JSON.stringify({ type: "update_ui", event_number: 53, target: "heading", html: "<h1 id=\"heading\">Unexpected</h1>" }));
      await sleep(100);
      assert.equal(await outboxCount(), 0);
      assert.equal(await execute("return document.querySelector('[data-letmeknow-system-status]')?.textContent"), "Session expired");
      assert.equal(await execute("return document.querySelector('#heading').textContent"), "Recovered");
      await execute("document.querySelector('#submit').click();");
      await sleep(100);
      assert.equal(await outboxCount(), 0);
      assert.equal(await execute("return document.querySelector('[data-letmeknow-system-status]')?.textContent"), "Session expired");

      const beforeStatic = sockets.length;
      await command("POST", "/url", { url: `http://127.0.0.1:${port}/static.html` });
      await waitFor(() => sockets.length > beforeStatic, "static page runtime did not connect");
      sockets.at(-1).send(JSON.stringify({ type: "update_ui", event_number: 43, target: "static-heading", html: "<h1 id=\"static-heading\">Changed</h1>" }));
      await sleep(100);
      assert.equal(await execute("return document.title"), "Static", "static pages must ignore dynamic updates");
      assert.equal(await execute("return document.querySelector('#static-heading').textContent"), "Static");
    } catch (error) {
      throw new Error(`${error.message}${driverError ? `\ngeckodriver: ${driverError}` : ""}`, { cause: error });
    } finally {
      if (driver && sessionId) {
        try { await request(driverPort, "DELETE", `/session/${sessionId}`); } catch {}
      }
      await stopProcess(driver);
      for (const socket of sockets) if (socket.readyState === 1) socket.close();
      await new Promise(resolve => wsServer.close(resolve));
      await new Promise(resolve => httpServer.close(resolve));
    }
  }, { timeout: 45_000 });
});
