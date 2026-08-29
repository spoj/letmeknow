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
const clientFile = new URL("../src/client.ts", import.meta.url);

function requireExecutable(path, name) {
  try {
    accessSync(path, constants.X_OK);
  } catch {
    throw new Error(`${name} is required for the browser smoke test: ${path}`);
  }
}

function runtimeSource() {
  const source = readFileSync(clientFile, "utf8");
  const start = source.indexOf("String.raw`") + "String.raw`".length;
  const end = source.lastIndexOf("`;\n\nexport default client;");
  if (start < "String.raw`".length || end < start) throw new Error("could not extract browser runtime from src/client.ts");
  return source.slice(start, end);
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

const page = `<!doctype html>
<html><head><meta charset="utf-8"><title>LetMeKnow browser smoke test</title>
<style>body { min-height: 5000px; } form { margin-top: 20px; }</style></head><body>
<h1>Preview</h1>
<form id="review" action="/submit" method="post">
  <label>Message <textarea id="stable-text" name="message"></textarea></label>
  <label><input id="stable-check" type="checkbox" name="checked"> Checked</label>
  <label>Choice <select id="stable-select" name="choice"><option value="one">One</option><option value="two">Two</option></select></label>
  <label>Unstable <input name="unstable"></label>
  <button id="submit" formaction="/submit" name="decision" value="approve">Approve</button>
  <output id="status" data-letmeknow-status role="status"></output>
</form>
<script type="module" src="/_letmeknow/client.js"></script>
</body></html>`;

describe("browser runtime", () => {
  it("connects, submits, restores revisions, and recovers once after reconnect", async () => {
    requireExecutable(firefox, "Firefox");
    requireExecutable(geckodriver, "geckodriver");

    const source = runtimeSource();
    let rootRequests = 0;
    let post;
    const httpServer = http.createServer((req, res) => {
      if (req.method === "GET" && req.url === "/_letmeknow/client.js") {
        res.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
        res.end(source);
        return;
      }
      if (req.method === "GET" && req.url === "/") {
        rootRequests += 1;
        res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
        res.end(page);
        return;
      }
      if (req.method === "POST" && req.url === "/submit") {
        const chunks = [];
        req.on("data", chunk => chunks.push(chunk));
        req.on("end", () => {
          post = { headers: req.headers, body: Buffer.concat(chunks).toString() };
          setTimeout(() => { res.writeHead(202); res.end(); }, 150);
        });
        return;
      }
      res.writeHead(404);
      res.end("not found");
    });
    await once(httpServer.listen(0, "127.0.0.1"), "listening");
    const port = httpServer.address().port;

    const sockets = [];
    const wsServer = new WebSocketServer({ noServer: true });
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
      await sleep(300);
      assert.equal(rootRequests, 1, "initial connection must not reload the page");

      await execute(`
        document.querySelector("#stable-text").value = "remember this";
        document.querySelector("#stable-check").checked = true;
        document.querySelector("#stable-select").value = "two";
        document.querySelector("input:not([id])").value = "do not restore";
        window.scrollTo(0, 1200);
      `);
      await waitFor(async () => (await execute("return window.scrollY")) >= 900, "browser did not scroll");
      await execute("document.querySelector('#submit').click()");
      await waitFor(async () => (await execute("return document.querySelector('#status').textContent")) === "Sending…", "sending status was not shown");
      await waitFor(async () => (await execute("return document.querySelector('#status').textContent")) === "Sent. Waiting for an update…", "accepted status was not shown");
      assert.ok(post, "form request was not received");
      assert.equal(post.headers["x-letmeknow-trigger-name"], "decision");
      assert.equal(post.headers["x-letmeknow-trigger-value"], "approve");
      assert.match(post.body, /message=remember\+this/);
      assert.match(post.body, /decision=approve/);

      const revisionBaseline = rootRequests;
      const revisionSocket = sockets.at(-1);
      assert.equal(revisionSocket.readyState, 1, "revision socket is not open");
      revisionSocket.send(JSON.stringify({ type: "revision" }));
      await waitFor(() => rootRequests === revisionBaseline + 1, "revision did not cause one reload");
      await waitFor(async () => {
        const state = await execute(`return {
          text: document.querySelector("#stable-text").value,
          checked: document.querySelector("#stable-check").checked,
          choice: document.querySelector("#stable-select").value,
          unstable: document.querySelector("input:not([id])").value,
          scroll: window.scrollY
        }`);
        return state.text === "remember this" && state.checked && state.choice === "two" && state.unstable === "" && state.scroll >= 900 ? state : false;
      }, "revision did not restore stable state");
      await sleep(300);
      assert.equal(rootRequests, revisionBaseline + 1, "revision must not reload more than once");

      const reconnectBaseline = rootRequests;
      const reconnectSocket = sockets.at(-1);
      assert.equal(reconnectSocket.readyState, 1, "reconnect socket is not open");
      reconnectSocket.close(1000, "browser smoke test reconnect");
      await waitFor(() => rootRequests === reconnectBaseline + 1, "reconnect did not cause one recovery reload", 8_000);
      await sleep(300);
      assert.equal(rootRequests, reconnectBaseline + 1, "reconnect must cause at most one recovery reload");
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

