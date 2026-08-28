import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { once } from "node:events";
import { describe, it } from "node:test";
import { WebSocketServer } from "ws";

const cli = new URL("../bin/letmeknow.js", import.meta.url);

async function runRelayScenario() {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-"));
  writeFileSync(join(folder, "index.html"), `<!doctype html><html><body><form id="contact" action="/save" method="post"><input name="name"><button name="kind" value="send">Send</button></form></body></html>`);
  writeFileSync(join(folder, "vite.config.js"), "throw new Error('project config must not execute')");
  const relay = new WebSocketServer({
    port: 0,
    handleProtocols(protocols) { return [...protocols][0]; }
  });
  await once(relay, "listening");
  const port = relay.address().port;
  const child = spawn(process.execPath, [cli.pathname, folder], {
    env: { ...process.env, LETMEKNOW_URL: `http://127.0.0.1:${port}` },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  let error = "";
  let pendingOutput = "";
  const lines = [];
  let pageResponse;
  let formResponse;
  const responses = new Promise((resolve, reject) => {
    relay.on("connection", socket => {
      socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
      socket.send(JSON.stringify({ type: "session", url: "http://127.0.0.1/s/0123456789abcdef0123/", expires_after_disconnect: 600 }));
      socket.on("message", data => {
        const packet = JSON.parse(data.toString());
        if (packet.type === "open") {
          socket.send(JSON.stringify({ type: "http_request", request_id: "page", method: "GET", path: "/", headers: { accept: "text/html", "sec-fetch-dest": "document" }, body: "" }));
        } else if (packet.type === "http_response" && packet.request_id === "page") {
          pageResponse = { ...packet, body: Buffer.from(packet.body, "base64").toString() };
          socket.send(JSON.stringify({
            type: "http_request",
            request_id: "form",
            method: "POST",
            path: "/save",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              "x-letmeknow-submission": "1",
              "x-letmeknow-id": "local-test",
              "x-letmeknow-form-id": "contact",
              "x-letmeknow-action": "%2Fsave",
              "x-letmeknow-trigger-name": "kind",
              "x-letmeknow-trigger-value": "send"
            },
            body: Buffer.from("name=Ada&kind=send").toString("base64")
          }));
        } else if (packet.type === "http_response" && packet.request_id === "form") {
          formResponse = packet;
          resolve();
        }
      });
    });
    relay.on("error", reject);
  });
  child.stdout.on("data", chunk => {
    output += chunk;
    pendingOutput += chunk.toString();
    const complete = pendingOutput.split("\n");
    pendingOutput = complete.pop();
    lines.push(...complete.filter(Boolean).map(line => JSON.parse(line)));
  });
  child.stderr.on("data", chunk => { error += chunk; });
  try {
    await Promise.race([responses, new Promise((_, reject) => setTimeout(() => reject(new Error(`relay timed out: ${error}`)), 5_000))]);
    const code = await new Promise(resolve => {
      child.once("exit", resolve);
      child.kill("SIGTERM");
    });
    return { code, output, pageResponse, formResponse, event: lines.find(line => line.type === "submit") };
  } finally {
    if (!child.killed) child.kill("SIGTERM");
    await new Promise(resolve => relay.close(resolve));
    rmSync(folder, { recursive: true, force: true });
  }
}

describe("LetMeKnow CLI", () => {
  it("prints the skill file without connecting", async () => {
    const child = spawn(process.execPath, [cli.pathname, "--skill"], {
      stdio: ["ignore", "pipe", "pipe"]
    });
    let output = "";
    let error = "";
    child.stdout.on("data", chunk => { output += chunk; });
    child.stderr.on("data", chunk => { error += chunk; });
    const [code] = await once(child, "exit");
    assert.equal(code, 0);
    assert.equal(error, "");
    assert.equal(output, readFileSync(new URL("../SKILL.md", import.meta.url), "utf8"));
  });

  it("serves through Vite middleware and prints submissions without a local listener", async () => {
    const result = await runRelayScenario();
    assert.equal(result.code, 0);
    assert.equal(result.pageResponse.status, 200);
    assert.match(result.pageResponse.body, /data-letmeknow-client/);
    assert.equal(result.formResponse.status, 204);
    assert.deepEqual(result.event, {
      type: "submit",
      id: "local-test",
      method: "POST",
      action: "/save",
      form_id: "contact",
      trigger: { id: null, name: "kind", value: "send" },
      values: { name: "Ada", kind: "send" }
    });
  }, { timeout: 10_000 });
});
