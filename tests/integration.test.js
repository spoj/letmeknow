import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { once } from "node:events";
import net from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
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
  it("serves a folder through the local Worker relay and forwards form data", async () => {
    const folder = mkdtempSync(join(tmpdir(), "letmeknow-integration-"));
    const persist = mkdtempSync(join(tmpdir(), "letmeknow-wrangler-"));
    const port = await freePort();
    writeFileSync(join(folder, "index.html"), `<!doctype html><html><body><form id="contact" action="/save" method="post"><input name="name"><button name="kind" value="send">Send</button></form></body></html>`);
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
    const previousTlsSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    try {
      await relayReady;
      cliProcess = spawn(process.execPath, [cli, folder], {
        cwd: root,
        env: { ...process.env, LETMEKNOW_URL: `https://127.0.0.1:${port}`, NODE_TLS_REJECT_UNAUTHORIZED: "0", NO_PROXY: "*", no_proxy: "*" },
        stdio: ["ignore", "pipe", "pipe"]
      });
      let output = "";
      let pending = "";
      let error = "";
      const lines = [];
      cliProcess.stdout.on("data", chunk => {
        output += chunk;
        pending += chunk.toString();
        const complete = pending.split("\n");
        pending = complete.pop();
        lines.push(...complete.filter(Boolean).map(line => JSON.parse(line)));
      });
      cliProcess.stderr.on("data", chunk => { error += chunk; });
      const ready = await waitForJsonLine(lines, line => line.type === "ready");
      const browserUrl = new URL(ready.url);
      const code = browserUrl.hostname.split(".", 1)[0];
      browserUrl.hostname = "127.0.0.1";
      browserUrl.port = String(port);
      browserUrl.pathname = `/s/${code}/`;
      const page = await fetch(browserUrl);
      assert.equal(page.status, 200);
      assert.match(await page.text(), /data-letmeknow-client/);

      const form = await fetch(new URL("save", browserUrl), {
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
      assert.equal(form.status, 204);
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
      assert.equal(cliProcess.exitCode, null);
      assert.match(output, /"type":"ready"/);
    } finally {
      await stop(cliProcess);
      await stop(relay);
      if (previousTlsSetting === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previousTlsSetting;
      rmSync(folder, { recursive: true, force: true });
      rmSync(persist, { recursive: true, force: true });
    }
  }, { timeout: 30_000 });
});
