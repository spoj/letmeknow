import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { once } from "node:events";
import https from "node:https";
import net from "node:net";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { describe, it } from "node:test";

const root = new URL("..", import.meta.url).pathname;
const cli = new URL("../bin/letmeknow.js", import.meta.url).pathname;
const wrangler = new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url).pathname;

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, "127.0.0.1", resolve).once("error", reject));
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode) return Promise.resolve();
  child.kill("SIGTERM");
  return once(child, "exit");
}

function localWebSocketEnvironment(port) {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-integration-hook-"));
  const hook = join(folder, "redirect.mjs");
  const ws = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "../node_modules/ws/index.js"));
  writeFileSync(hook, `import WebSocket from ${JSON.stringify(ws.href)};
const OriginalWebSocket = WebSocket;
globalThis.WebSocket = class extends OriginalWebSocket {
  constructor(url, protocols) {
    const local = new URL(url);
    local.protocol = "wss:";
    local.port = process.env.LETMEKNOW_TEST_PORT;
    super(local, protocols, {
      rejectUnauthorized: false,
      headers: { Host: local.host },
      lookup: (_hostname, options, callback) => options.all ? callback(null, [{ address: "127.0.0.1", family: 4 }]) : callback(null, "127.0.0.1", 4)
    });
  }
};
`);
  return {
    env: {
      ...process.env,
      LETMEKNOW_TEST_PORT: String(port),
      NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${pathToFileURL(hook).href}`.trim()
    },
    close: () => rmSync(folder, { recursive: true, force: true })
  };
}

function localRequest(url, host, init = {}) {
  const headers = new Headers(init.headers);
  headers.set("Host", host);
  return new Promise((resolve, reject) => {
    const request = https.request({
      hostname: host,
      port: url.port,
      path: url.pathname + url.search,
      method: init.method || "GET",
      headers: Object.fromEntries(headers),
      rejectUnauthorized: false,
      lookup: (_hostname, options, callback) => options.all ? callback(null, [{ address: "127.0.0.1", family: 4 }]) : callback(null, "127.0.0.1", 4)
    }, response => {
      const chunks = [];
      response.on("data", chunk => chunks.push(chunk));
      response.on("end", () => {
        const responseHeaders = new Headers();
        for (const [name, value] of Object.entries(response.headers)) {
          if (value !== undefined) responseHeaders.set(name, Array.isArray(value) ? value.join(", ") : value);
        }
        resolve(new Response(Buffer.concat(chunks), { status: response.statusCode, headers: responseHeaders }));
      });
    });
    request.on("error", reject);
    if (init.body !== undefined) request.write(init.body);
    request.end();
  });
}

async function waitForJsonLine(lines, predicate, timeout = 10_000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const line = lines.find(predicate);
    if (line) return line;
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  throw new Error("timed out waiting for JSONL event");
}

describe("LetMeKnow integration", () => {
  it("routes hosted sessions through local Wrangler and forwards unchanged files and form data", async () => {
    const folder = mkdtempSync(join(tmpdir(), "letmeknow-integration-"));
    const persist = mkdtempSync(join(tmpdir(), "letmeknow-wrangler-"));
    const port = await freePort();
    const local = localWebSocketEnvironment(port);
    const source = `<!doctype html><html><head><script>const marker = "</body>";</script></head><body><form id="contact" action="/save" method="post"><input name="name"><button name="kind" value="send">Send</button></form></body></html>`;
    mkdirSync(join(folder, "nested"));
    writeFileSync(join(folder, "index.html"), source);
    writeFileSync(join(folder, "nested", "index.html"), "nested");
    const relay = spawn(process.execPath, [wrangler, "dev", "--local", "--local-protocol", "https", "--port", String(port), "--persist-to", persist], {
      cwd: root,
      env: { ...process.env, NO_PROXY: "*", no_proxy: "*" },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let relayOutput = "";
    const relayReady = new Promise((resolve, reject) => {
      const onData = chunk => {
        relayOutput += chunk.toString();
        if (/Ready on https:\/\//.test(relayOutput)) resolve();
      };
      relay.stdout.on("data", onData);
      relay.stderr.on("data", onData);
      relay.once("exit", code => reject(new Error(`local Worker exited (${code}): ${relayOutput}`)));
    });
    let cliProcess;
    const lines = [];
    let pending = "";
    let error = "";
    const previousTlsSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    try {
      await relayReady;
      const localOrigin = `https://127.0.0.1:${port}`;
      const homeUrl = new URL(`${localOrigin}/`);
      homeUrl.hostname = "letmeknow.dev";
      const home = await localRequest(homeUrl, "letmeknow.dev");
      assert.equal(home.status, 200);
      assert.match(await home.text(), /letmeknow-cli \.\/workspace/);

      cliProcess = spawn(process.execPath, [cli, folder], {
        cwd: root,
        env: { ...local.env, NODE_TLS_REJECT_UNAUTHORIZED: "0", NO_PROXY: "*", no_proxy: "*" },
        stdio: ["ignore", "pipe", "pipe"]
      });
      cliProcess.stdout.on("data", chunk => {
        pending += chunk.toString();
        const complete = pending.split("\n");
        pending = complete.pop();
        lines.push(...complete.filter(Boolean).map(line => JSON.parse(line)));
      });
      cliProcess.stderr.on("data", chunk => { error += chunk.toString(); });

      let ready;
      try {
        ready = await waitForJsonLine(lines, line => line.type === "ready");
      } catch (cause) {
        throw new Error(`${cause.message}; cli stderr: ${error}; relay: ${relayOutput}`);
      }
      assert.match(ready.url, /^https:\/\/[a-f0-9]{20}\.letmeknow\.dev\/$/);
      const publicUrl = new URL(ready.url);
      const code = publicUrl.hostname.split(".", 1)[0];
      const browserUrl = new URL(publicUrl);
      browserUrl.port = String(port);
      const browserHost = `${code}.letmeknow.dev`;

      const page = await localRequest(browserUrl, browserHost, { headers: { accept: "text/html" } });
      assert.equal(page.status, 200);
      const runtimeTag = `<script type="module" src="/_letmeknow/client.js" data-letmeknow-runtime></script>`;
      const bodyClose = source.lastIndexOf("</body>");
      const expectedPage = source.slice(0, bodyClose) + runtimeTag + source.slice(bodyClose);
      assert.equal(await page.text(), expectedPage);

      const clientScript = await localRequest(new URL("/_letmeknow/client.js", browserUrl), browserHost);
      assert.equal(clientScript.status, 200);
      assert.equal(clientScript.headers.get("content-type"), "text/javascript; charset=utf-8");
      const clientScriptText = await clientScript.text();
      assert.match(clientScriptText, /Sent\. Waiting for an update/);
      assert.doesNotMatch(clientScriptText, /const clientScript=/);

      const nestedRequest = new URL("/nested?view=source", browserUrl);
      const nestedRedirect = await localRequest(nestedRequest, browserHost, { headers: { accept: "text/html" }, redirect: "manual" });
      assert.equal(nestedRedirect.status, 301);
      assert.equal(nestedRedirect.headers.get("location"), "nested/?view=source");
      const nestedPage = await localRequest(new URL(nestedRedirect.headers.get("location"), nestedRequest), browserHost, { headers: { accept: "text/html" } });
      assert.equal(nestedPage.status, 200);
      assert.match(await nestedPage.text(), /nested/);

      const form = await localRequest(new URL("/save", browserUrl), browserHost, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "X-LetMeKnow-Submission": "1",
          "X-LetMeKnow-ID": "integration-test",
          "X-LetMeKnow-Form-ID": "contact",
          "X-LetMeKnow-Action": "%2Fsave",
          "X-LetMeKnow-Trigger-Name": "kind",
          "X-LetMeKnow-Trigger-Value": "send"
        },
        body: "name=Ada&kind=send"
      });
      assert.equal(form.status, 202);
      const submission = await waitForJsonLine(lines, line => line.type === "submit");
      assert.deepEqual(submission, {
        type: "submit",
        id: "integration-test",
        method: "POST",
        action: "/save",
        form_id: "contact",
        trigger: { id: null, name: "kind", value: "send" },
        values: { name: "Ada", kind: "send" }
      });
      assert.equal(cliProcess.exitCode, null, error);
    } finally {
      await stop(cliProcess);
      await stop(relay);
      local.close();
      if (previousTlsSetting === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTlsSetting;
      rmSync(folder, { recursive: true, force: true });
      rmSync(persist, { recursive: true, force: true });
    }
  }, { timeout: 30_000 });
});
