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
const idiomorphFile = new URL("../src/idiomorph.client.js", import.meta.url);

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

function documentPage(pageEvent, title, body) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}<script type="module" src="/_letmeknow/client.js" data-letmeknow-runtime data-letmeknow-page-event="${pageEvent}"></script></body></html>`;
}

const initialPage = documentPage(10, "Initial", `
  <main id="letmeknow-root">
    <h1 id="heading">Initial</h1>
    <output id="counter">0</output>
    <form id="review" action="/review" method="post">
      <label>Message <textarea id="message" name="message"></textarea></label>
      <label><input id="tag-one" type="checkbox" name="tag" value="one"> One</label>
      <label><input id="tag-two" type="checkbox" name="tag" value="two"> Two</label>
      <button id="submit" name="decision" value="approve">Approve</button>
      <input id="file" type="file" name="attachment">
      <output id="status" data-letmeknow-status role="status"></output>
    </form>
  </main>
  <script id="agent-script">window.agentScriptRuns = (window.agentScriptRuns || 0) + 1;</script>
`);

const updatedPage = documentPage(20, "Updated", `
  <main id="letmeknow-root">
    <h1 id="heading">Updated</h1>
    <output id="counter">1</output>
    <form id="review" action="/review" method="post">
      <label>Message <textarea id="message" name="message"></textarea></label>
      <label><input id="tag-one" type="checkbox" name="tag" value="one"> One</label>
      <label><input id="tag-two" type="checkbox" name="tag" value="two"> Two</label>
      <button id="submit" name="decision" value="approve">Approve</button>
      <input id="file" type="file" name="attachment">
      <output id="status" data-letmeknow-status role="status"></output>
    </form>
  </main>
  <script id="agent-script">window.agentScriptRuns = (window.agentScriptRuns || 0) + 100;</script>
  <script>window.liveScriptRuns = (window.liveScriptRuns || 0) + 1;</script>
`);

const finalPage = documentPage(22, "Final", `
  <main id="letmeknow-root">
    <h1 id="heading">Final</h1>
    <output id="counter">2</output>
    <form id="review" action="/review" method="post">
      <label>Message <textarea id="message" name="message"></textarea></label>
      <label><input id="tag-one" type="checkbox" name="tag" value="one"> One</label>
      <label><input id="tag-two" type="checkbox" name="tag" value="two"> Two</label>
      <button id="submit" name="decision" value="approve">Approve</button>
      <input id="file" type="file" name="attachment">
      <output id="status" data-letmeknow-status role="status"></output>
    </form>
  </main>
`);

describe("browser runtime", () => {
  it("morphs pages, preserves the runtime, submits JSON events, and resynchronizes", async () => {
    requireExecutable(firefox, "Firefox");
    requireExecutable(geckodriver, "geckodriver");

    const runtimeSource = readFileSync(runtimeFile, "utf8");
    const idiomorphSource = readFileSync(idiomorphFile, "utf8");
    let currentPage = initialPage;
    let rootRequests = 0;
    let delayNextPage = false;
    const posts = [];
    const sockets = [];
    const wsServer = new WebSocketServer({ noServer: true });
    const httpServer = http.createServer((req, res) => {
      if (req.method === "GET" && req.url === "/_letmeknow/client.js") {
        res.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
        res.end(runtimeSource);
        return;
      }
      if (req.method === "GET" && req.url === "/_letmeknow/idiomorph.js") {
        res.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
        res.end(idiomorphSource);
        return;
      }
      if (req.method === "GET" && req.url === "/") {
        rootRequests += 1;
        const send = () => {
          res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
          res.end(currentPage);
        };
        if (delayNextPage) {
          delayNextPage = false;
          setTimeout(send, 250);
        } else send();
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
      await command("POST", "/url", { url: `http://127.0.0.1:${port}/` });
      await waitFor(async () => (await execute("return document.readyState")) === "complete", "initial page did not load");
      await waitFor(() => sockets.length === 1, "browser did not connect to runtime");
      await sleep(250);
      assert.equal(rootRequests, 1, "initial connection must not fetch the page again");

      const initialState = await execute(`return {
        title: document.title,
        heading: document.querySelector('#heading').textContent,
        pageEvent: document.querySelector('script[data-letmeknow-runtime]').dataset.letmeknowPageEvent,
        agentScriptRuns: window.agentScriptRuns,
        runtimeScripts: document.querySelectorAll('script[data-letmeknow-runtime]').length
      }`);
      assert.deepEqual(initialState, { title: "Initial", heading: "Initial", pageEvent: "10", agentScriptRuns: 1, runtimeScripts: 1 });

      await execute("document.querySelector('#message').value = 'draft'; document.querySelector('#tag-one').checked = true; document.querySelector('#tag-two').checked = true; document.querySelector('#message').focus();");
      sockets.at(-1).send(JSON.stringify({ type: "update_ui", event_number: 20, html: updatedPage }));
      await waitFor(async () => (await execute("return document.title")) === "Updated", "full-page update was not applied");
      const updatedState = await execute(`return {
        heading: document.querySelector('#heading').textContent,
        counter: document.querySelector('#counter').textContent,
        draft: document.querySelector('#message').value,
        one: document.querySelector('#tag-one').checked,
        two: document.querySelector('#tag-two').checked,
        agentScriptRuns: window.agentScriptRuns,
        liveScriptRuns: window.liveScriptRuns || 0,
        listeners: document.querySelectorAll('script[data-letmeknow-runtime]').length,
        pageEvent: document.querySelector('script[data-letmeknow-runtime]').dataset.letmeknowPageEvent
      }`);
      assert.deepEqual(updatedState, { heading: "Updated", counter: "1", draft: "draft", one: false, two: false, agentScriptRuns: 1, liveScriptRuns: 0, listeners: 1, pageEvent: "20" });

      sockets.at(-1).send(JSON.stringify({ type: "update_ui", event_number: 19, html: documentPage(19, "Old", "<main id=\"letmeknow-root\"><h1 id=\"heading\">Old</h1></main>") }));
      await sleep(100);
      assert.equal(await execute("return document.title"), "Updated", "older update must be ignored");

      const baselinePosts = posts.length;
      await execute("document.querySelector('#tag-one').checked = true; document.querySelector('#tag-two').checked = true; document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click(); document.querySelector('#submit').click();");
      await waitFor(() => posts.length === baselinePosts + 10, "rapid submissions were not all delivered");
      const payloads = posts.slice(baselinePosts).map(post => JSON.parse(post.body));
      assert.equal(new Set(payloads.map(payload => payload.id)).size, 10, "rapid submissions need distinct IDs");
      assert.ok(payloads.every(payload => payload.page_event === 20));
      assert.ok(payloads.every(payload => payload.form_id === "review"));
      assert.ok(payloads.every(payload => payload.action === "/review"));
      assert.ok(payloads.every(payload => payload.trigger.name === "decision" && payload.trigger.value === "approve"));
      assert.ok(payloads.every(payload => payload.values.tag?.join(",") === "one,two"));
      assert.ok(posts.slice(baselinePosts).every(post => post.headers["content-type"].startsWith("application/json")));

      currentPage = updatedPage;
      delayNextPage = true;
      const reconnectBaseline = rootRequests;
      const reconnectSocket = sockets.at(-1);
      reconnectSocket.close(1000, "test reconnect");
      await waitFor(() => sockets.length === 2, "browser did not reconnect", 8_000);
      const resyncSocket = sockets.at(-1);
      await waitFor(() => rootRequests === reconnectBaseline + 1, "reconnect resync did not request the current page");
      resyncSocket.send(JSON.stringify({ type: "update_ui", event_number: 21, html: documentPage(21, "Buffered", "<main id=\"letmeknow-root\"><h1 id=\"heading\">Buffered</h1><output id=\"counter\">1.5</output></main>") }));
      await waitFor(async () => (await execute("return document.title")) === "Buffered", "buffered update was not applied after resync");
      assert.equal(await execute("return window.agentScriptRuns"), 1, "live scripts must not execute");
      assert.equal(await execute("return document.querySelector('#counter').textContent"), "1.5");
      assert.equal(await execute("return document.querySelectorAll('script[data-letmeknow-runtime]').length"), 1, "runtime must survive morphing");
      assert.ok(rootRequests >= 2, "reconnect must fetch the current page");

      currentPage = finalPage;
      const beforeProducerResync = rootRequests;
      sockets.at(-1).send(JSON.stringify({ type: "producer", connected: false }));
      await sleep(50);
      sockets.at(-1).send(JSON.stringify({ type: "producer", connected: true }));
      await waitFor(() => rootRequests > beforeProducerResync, "producer reconnection did not resynchronize");
      await waitFor(async () => (await execute("return document.title")) === "Final", "producer resynchronization did not apply current page");
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
