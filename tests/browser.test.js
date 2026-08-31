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

function documentPage(history, title, body, dynamic = true) {
  const existingHistory = dynamic ? `<script type="application/json" data-letmeknow-history>[]</script>` : "";
  const historyScript = dynamic ? `<script type="application/json" data-letmeknow-history>${JSON.stringify(history).replace(/<\/script/gi, match => "\\u003c" + match.slice(1))}</script>` : "";
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>${body}${existingHistory}${historyScript}<script id="agent-script">window.agentScriptRuns = (window.agentScriptRuns || 0) + 1; document.addEventListener('submit', event => { if (event.target.id === 'app-owned') event.preventDefault(); });</script><script type="module" src="/_letmeknow/client.js" data-letmeknow-runtime></script></body></html>`;
}

const body = `
  <main id="letmeknow-root">
    <h1 id="heading">Initial</h1>
    <output id="count">0</output>
    <ul id="items"><li id="item-one">One</li><li id="item-two">Two</li></ul>
    <form id="review" action="/review" method="post">
      <label>Message <textarea id="message" name="message"></textarea></label>
      <label><input id="tag" type="checkbox" name="tag" value="one"> One</label>
      <button id="submit" name="decision" value="approve">Approve</button>
      <output id="status" data-letmeknow-status role="status"></output>
    </form>
    <form id="app-owned" action="/app-owned" method="post"><button id="app-submit">App-owned</button></form>
    <details id="more"><summary>More</summary><p>Details</p></details>
    <section id="local-panel" hidden>Local</section>
  </main>
`;

const history = [
  { event_number: 1, script: "window.historyRuns = (window.historyRuns || 0) + 1; document.querySelector('#heading').textContent = 'History';" }
];
const liveHistory = [
  ...history,
  { event_number: 2, script: "document.querySelector('#items').insertAdjacentHTML('beforeend', '<li id=\"item-three\">Three</li>');" },
  { event_number: 3, script: "document.querySelector('#items').prepend(document.querySelector('#item-two'));" },
  { event_number: 4, script: "document.querySelector('#count').textContent = '42'; document.querySelector('#item-two').setAttribute('data-state', 'changed'); document.querySelector('#local-panel').hidden = false;" },
  { event_number: 5, script: "document.querySelector('#item-three').remove();" },
  { event_number: 6, script: "document.querySelector('#message').value = 'partial'; throw new Error('intentional update failure');" },
  { event_number: 7, script: "document.querySelector('#heading').textContent = 'Corrected';" },
  { event_number: 8, script: "if (location.search === '?replay-submit') { document.querySelector('#message').value = 'replayed'; document.querySelector('#review').requestSubmit(); }" }
];

const initialPage = documentPage(history, "Initial", body);
const replayedPage = documentPage(liveHistory, "Initial", body);


describe("browser runtime", () => {
  it("executes and replays arbitrary UI scripts while preserving browser state", async () => {
    requireExecutable(firefox, "Firefox");
    requireExecutable(geckodriver, "geckodriver");

    const runtimeSource = readFileSync(runtimeFile, "utf8");
    let currentPage = initialPage;
    let rootRequests = 0;
    const posts = [];
    const sockets = [];
    const wsServer = new WebSocketServer({ noServer: true });
    const httpServer = http.createServer((req, res) => {
      if (req.method === "GET" && req.url === "/_letmeknow/client.js") {
        res.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
        res.end(runtimeSource);
        return;
      }
      if (req.method === "GET" && req.url === "/static.html") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        res.end(documentPage([], "Static", "<h1 id=\"static-heading\">Static</h1>", false));
        return;
      }
      if (req.method === "GET" && (req.url === "/" || req.url === "/?replay-submit")) {
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

      const command = (method, path, requestBody) => request(driverPort, method, `/session/${sessionId}${path}`, requestBody);
      const execute = script => command("POST", "/execute/sync", { script, args: [] }).then(result => result.value);
      await command("POST", "/url", { url: `http://127.0.0.1:${port}/` });
      await waitFor(async () => (await execute("return document.readyState")) === "complete", "initial page did not load");
      await waitFor(() => sockets.length === 1, "browser did not connect to runtime");
      await waitFor(async () => await execute("return document.querySelector('#heading')?.textContent") === "History", "history did not execute");
      assert.equal(rootRequests, 1);
      assert.equal(await execute("return window.historyRuns"), 1);
      assert.equal(await execute("return window.agentScriptRuns"), 1);
      const appPosts = posts.length;
      const appRequests = rootRequests;
      await execute("document.querySelector('#app-submit').click();");
      await sleep(100);
      assert.equal(posts.length, appPosts, "app-owned forms must not enter the structured outbox");
      assert.equal(rootRequests, appRequests, "app-owned forms must not navigate");
      assert.equal(await execute("return location.pathname"), "/");

      await execute("window.originalItemOne = document.querySelector('#item-one'); document.querySelector('#message').value = 'focused draft'; document.querySelector('#tag').checked = true; document.querySelector('#more').open = true; document.querySelector('#message').focus();");
      sockets.at(-1).send(JSON.stringify({ type: "run_ui", event_number: 2, script: "document.querySelector('#items').insertAdjacentHTML('beforeend', '<li id=\"item-three\">Three</li>');" }));
      sockets.at(-1).send(JSON.stringify({ type: "run_ui", event_number: 3, script: "document.querySelector('#items').prepend(document.querySelector('#item-two'));" }));
      sockets.at(-1).send(JSON.stringify({ type: "run_ui", event_number: 4, script: "document.querySelector('#count').textContent = '42'; document.querySelector('#item-two').setAttribute('data-state', 'changed'); document.querySelector('#local-panel').hidden = false;" }));
      sockets.at(-1).send(JSON.stringify({ type: "run_ui", event_number: 5, script: "document.querySelector('#item-three').remove();" }));
      await waitFor(async () => await execute("return document.querySelector('#count')?.textContent") === "42", "UI scripts did not execute");
      assert.deepEqual(await execute(`return {
        items: Array.from(document.querySelectorAll('#items > li')).map(item => item.id),
        message: document.querySelector('#message').value,
        focused: document.activeElement.id,
        checked: document.querySelector('#tag').checked,
        details: document.querySelector('#more').open,
        movedNodePreserved: document.querySelector('#item-one') === window.originalItemOne,
        attribute: document.querySelector('#item-two').dataset.state,
        localHidden: document.querySelector('#local-panel').hidden
      }`), { items: ["item-two", "item-one"], message: "focused draft", focused: "message", checked: true, details: true, movedNodePreserved: true, attribute: "changed", localHidden: false });

      const beforeErrorRequests = rootRequests;
      sockets.at(-1).send(JSON.stringify({ type: "run_ui", event_number: 6, script: "document.querySelector('#message').value = 'partial'; throw new Error('intentional update failure');" }));
      await waitFor(async () => (await execute("return document.querySelector('[data-letmeknow-system-status]')?.textContent"))?.includes("failed"), "failed UI script was not reported");
      assert.equal(rootRequests, beforeErrorRequests);
      const failedBaselinePosts = posts.length;
      await execute("document.querySelector('#submit').click();");
      await waitFor(() => posts.length === failedBaselinePosts + 1, "submission after failed UI script was not delivered");
      assert.equal(JSON.parse(posts.at(-1).body).page_event, 6);
      sockets.at(-1).send(JSON.stringify({ type: "run_ui", event_number: 7, script: "document.querySelector('#heading').textContent = 'Corrected';" }));
      await waitFor(async () => await execute("return document.querySelector('#heading')?.textContent") === "Corrected", "correction script did not execute");
      currentPage = replayedPage;

      const beforeReplayRequests = rootRequests;
      await command("POST", "/url", { url: `http://127.0.0.1:${port}/?replay-submit` });
      await waitFor(() => rootRequests > beforeReplayRequests, "replay page did not load");
      await waitFor(() => sockets.length > 1, "replay runtime did not connect");
      await waitFor(async () => await execute("return document.querySelector('#heading')?.textContent") === "Corrected", "history replay did not reach correction");
      assert.equal(await execute("return window.historyRuns"), 1);
      assert.equal(await execute("return document.querySelector('#items').textContent.trim()"), "TwoOne");
      await waitFor(() => posts.length > 1, "replayed requestSubmit was not intercepted");
      const replayedSubmission = JSON.parse(posts.at(-1).body);
      assert.equal(replayedSubmission.page_event, 8);
      assert.equal(replayedSubmission.values.message, "replayed");
      assert.equal(rootRequests, beforeReplayRequests + 1, "replayed requestSubmit must not navigate");

      const baselinePosts = posts.length;
      await execute("document.querySelector('#submit').click();");
      await waitFor(() => posts.length === baselinePosts + 1, "submission was not delivered");
      assert.equal(JSON.parse(posts.at(-1).body).page_event, 8);

      sockets.at(-1).send(JSON.stringify({ type: "producer", connected: false }));
      await waitFor(async () => await execute("return document.documentElement.hasAttribute('data-letmeknow-disconnected')"), "disconnect was not reflected");
      await execute("document.querySelector('#message').value = 'offline'; document.querySelector('#submit').click();");
      await sleep(100);
      assert.equal(posts.length, baselinePosts + 1);
      sockets.at(-1).send(JSON.stringify({ type: "closed", message: "Session closed" }));
      await waitFor(async () => await execute("return document.querySelector('[data-letmeknow-system-status]')?.textContent") === "Session closed", "terminal status was not shown");
      sockets.at(-1).send(JSON.stringify({ type: "producer", connected: true }));
      sockets.at(-1).send(JSON.stringify({ type: "run_ui", event_number: 9, script: "document.querySelector('#heading').textContent = 'Unexpected';" }));
      await sleep(100);
      assert.equal(posts.length, baselinePosts + 1);
      assert.equal(await execute("return document.querySelector('[data-letmeknow-system-status]')?.textContent"), "Session closed");
      assert.equal(await execute("return document.querySelector('#heading').textContent"), "Corrected");
      await execute("document.querySelector('#submit').click();");
      await sleep(100);
      assert.equal(posts.length, baselinePosts + 1);

      const beforeTerminalReload = rootRequests;
      await command("POST", "/url", { url: `http://127.0.0.1:${port}/` });
      await waitFor(() => rootRequests > beforeTerminalReload, "fresh runtime did not load after terminal close");
      await waitFor(async () => await execute("return document.querySelector('#heading')?.textContent") === "Corrected", "fresh runtime did not replay history");
      await sleep(200);
      assert.equal(posts.length, baselinePosts + 1, "terminal outbox submission was delivered after reload");

      const beforeStatic = sockets.length;
      await command("POST", "/url", { url: `http://127.0.0.1:${port}/static.html` });
      await waitFor(() => sockets.length > beforeStatic, "static runtime did not connect");
      sockets.at(-1).send(JSON.stringify({ type: "run_ui", event_number: 99, script: "document.querySelector('#static-heading').textContent = 'Changed';" }));
      await sleep(100);
      assert.equal(await execute("return document.title"), "Static");
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
