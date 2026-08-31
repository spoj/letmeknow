import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { once } from "node:events";
import { describe, it } from "node:test";
import { WebSocketServer } from "ws";

const cli = fileURLToPath(new URL("../bin/letmeknow.js", import.meta.url));
const MAX_BODY_BYTES = 1024 * 1024;

function localWebSocketEnvironment(port) {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-hook-"));
  const hook = join(folder, "redirect.mjs");
  const ws = pathToFileURL(join(dirname(cli), "../node_modules/ws/index.js"));
  writeFileSync(hook, `import WebSocket from ${JSON.stringify(ws.href)}; const OriginalWebSocket = WebSocket; globalThis.WebSocket = class extends OriginalWebSocket { constructor(url, protocols) { const local = new URL(url); local.protocol = "ws:"; local.hostname = "127.0.0.1"; local.port = process.env.LETMEKNOW_TEST_PORT; super(local, protocols); } };\n`);
  return {
    env: { ...process.env, LETMEKNOW_TEST_PORT: String(port), NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${pathToFileURL(hook).href}`.trim() },
    close: () => rmSync(folder, { recursive: true, force: true })
  };
}

async function runCommand(args, input) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", chunk => { stdout += chunk; });
  child.stderr.on("data", chunk => { stderr += chunk; });
  if (input === undefined) child.stdin.end();
  else child.stdin.end(input);
  const [code] = await once(child, "exit");
  return { code, stdout, stderr };
}

async function command(args, input) {
  const result = await runCommand(args, input);
  assert.equal(result.code, 0, `${args.join(" ")}: ${result.stderr}`);
  return JSON.parse(result.stdout);
}

async function startSession({ index = "<!doctype html><html><body><main id=\"letmeknow-root\">initial</main></body></html>" } = {}) {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-"));
  writeFileSync(join(folder, "index.html"), index);
  mkdirSync(join(folder, "assets"));
  writeFileSync(join(folder, "assets", "app.js"), "initial");
  const relay = new WebSocketServer({ port: 0, handleProtocols(protocols) { return [...protocols][0]; } });
  await once(relay, "listening");
  const local = localWebSocketEnvironment(relay.address().port);
  const child = spawn(process.execPath, [cli, "serve", folder], { env: local.env, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", chunk => { stderr += chunk; });
  let readyOutput = "";
  const ready = new Promise((resolve, reject) => {
    child.stdout.on("data", chunk => {
      readyOutput += chunk.toString();
      const lines = readyOutput.split("\n");
      readyOutput = lines.pop();
      for (const line of lines.filter(Boolean)) {
        try {
          const value = JSON.parse(line);
          if (value.type === "ready") resolve(value);
        } catch {}
      }
    });
    child.once("error", reject);
  });
  let producer;
  const updates = [];
  const responses = new Map();
  const waiters = new Map();
  const connected = new Promise((resolve, reject) => {
    relay.once("error", reject);
    relay.once("connection", socket => {
      producer = socket;
      socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
      socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/", expires_after_disconnect: 600 }));
      socket.on("message", data => {
        const packet = JSON.parse(data.toString());
        if (packet.type === "open") resolve();
        if (packet.type === "update_ui") updates.push(packet);
        if (packet.type !== "http_response") return;
        responses.set(packet.request_id, packet);
        const waiter = waiters.get(packet.request_id);
        if (waiter) {
          waiters.delete(packet.request_id);
          waiter(packet);
        }
      });
    });
  });
  await Promise.all([connected, ready]);
  let requestNumber = 0;
  const request = (method, path, headers = {}, body = Buffer.alloc(0)) => {
    const request_id = `request-${++requestNumber}`;
    return new Promise(resolve => {
      waiters.set(request_id, resolve);
      producer.send(JSON.stringify({ type: "http_request", request_id, method, path, headers, body: body.toString("base64") }));
    });
  };
  const stop = async () => {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await once(child, "exit");
    }
    await new Promise(resolve => relay.close(resolve));
    local.close();
    rmSync(folder, { recursive: true, force: true });
  };
  return { folder, child, request, updates, responses, ready: await ready, stderr: () => stderr, stop };
}

function decodeBody(packet) {
  return Buffer.from(packet.body, "base64").toString("utf8");
}

function jsonSubmission(id, pageEvent = 0, values = { amount: "1" }) {
  return Buffer.from(JSON.stringify({
    id,
    page_event: pageEvent,
    form_id: "counter",
    action: "/increment",
    trigger: { id: "increment", name: "amount", value: "1" },
    values
  }));
}

describe("LetMeKnow CLI", () => {
  it("uses the reduced command surface", async () => {
    const result = await runCommand(["ack", "/tmp"]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Usage:/);
  });

  it("serves the initial page canonically and other files live", async () => {
    const session = await startSession({ index: "<!doctype html><html><body><main id=\"letmeknow-root\">old</main></body></html>" });
    try {
      const page = await session.request("GET", "/", { accept: "text/html" });
      const index = await session.request("GET", "/index.html", { accept: "text/html" });
      const asset = await session.request("GET", "/assets/app.js");
      assert.equal(page.status, 200);
      assert.equal(decodeBody(page), "<!doctype html><html><body><main id=\"letmeknow-root\">old</main></body></html>");
      assert.equal(decodeBody(index), decodeBody(page));
      assert.equal(page.headers["X-LetMeKnow-Page-Event"], "0");
      assert.equal(decodeBody(asset), "initial");

      writeFileSync(join(session.folder, "index.html"), "changed draft");
      writeFileSync(join(session.folder, "assets", "app.js"), "changed asset");
      const unchangedPage = await session.request("GET", "/", { accept: "text/html" });
      const changedAsset = await session.request("GET", "/assets/app.js");
      assert.equal(decodeBody(unchangedPage), decodeBody(page));
      assert.equal(decodeBody(changedAsset), "changed asset");
    } finally {
      await session.stop();
    }
  });

  it("serves static paths securely", async () => {
    const session = await startSession();
    const outside = mkdtempSync(join(tmpdir(), "letmeknow-outside-"));
    try {
      writeFileSync(join(session.folder, "public.txt"), "public");
      writeFileSync(join(outside, "secret.txt"), "secret");
      symlinkSync(join(outside, "secret.txt"), join(session.folder, "escape.txt"));
      const publicFile = await session.request("GET", "/public.txt");
      const escape = await session.request("GET", "/escape.txt");
      const privateFile = await session.request("GET", "/.env");
      assert.equal(publicFile.status, 200);
      assert.equal(decodeBody(publicFile), "public");
      assert.equal(escape.status, 403);
      assert.equal(privateFile.status, 403);
    } finally {
      rmSync(outside, { recursive: true, force: true });
      await session.stop();
    }
  });

  it("accepts independent JSON submissions and numbers them globally", async () => {
    const session = await startSession();
    try {
      const invalid = await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission("not-a-uuid"));
      assert.equal(invalid.status, 400);
      const ids = Array.from({ length: 10 }, () => randomUUID());
      const submissions = await Promise.all(ids.map(id => session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(id))));
      assert.deepEqual(submissions.map(result => result.status), Array(10).fill(202));
      const duplicate = await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(ids[0]));
      assert.equal(duplicate.status, 202);
      const batch = await command(["pull", session.folder]);
      assert.equal(batch.page_event, 0);
      assert.equal(batch.frontier, 10);
      assert.equal(batch.events.length, 10);
      assert.deepEqual(new Set(batch.events.map(event => event.id)), new Set(ids));
      assert.deepEqual(batch.events.map(event => event.event_number).sort((a, b) => a - b), Array.from({ length: 10 }, (_, index) => index + 1));
      assert.equal(batch.events[0].page_event, 0);
      assert.equal(batch.events[0].values.amount, "1");
    } finally {
      await session.stop();
    }
  });

  it("pushes a complete page, exposes it with show, and handles retries", async () => {
    const session = await startSession();
    try {
      const first = await command(["pull", session.folder]);
      assert.equal(first.frontier, 0);
      assert.equal(first.page_event, 0);
      assert.equal(first.page_hash, createHash("sha256").update(decodeBody(await session.request("GET", "/"))).digest("hex"));
      const shown = await runCommand(["show", session.folder]);
      assert.equal(shown.code, 0);
      assert.equal(shown.stdout, decodeBody(await session.request("GET", "/")));

      const page = "<!doctype html><html><body><main id=\"letmeknow-root\">updated</main></body></html>";
      const pageFile = join(session.folder, "updated.html");
      writeFileSync(pageFile, page);
      const pushed = await command(["push", session.folder, "--batch", first.token, "--page", pageFile]);
      assert.equal(pushed.type, "committed");
      assert.equal(pushed.frontier, 1);
      assert.equal(pushed.page_event, 1);
      assert.equal(pushed.page_hash, createHash("sha256").update(page).digest("hex"));
      assert.deepEqual(session.updates, [{ type: "update_ui", event_number: 1, html: page }]);
      const current = await session.request("GET", "/");
      assert.equal(decodeBody(current), page);
      assert.equal(current.headers["X-LetMeKnow-Page-Event"], "1");
      const retried = await command(["push", session.folder, "--batch", first.token, "--page", pageFile]);
      assert.deepEqual(retried, pushed);
      const changedFile = join(session.folder, "changed.html");
      writeFileSync(changedFile, "different");
      const changedRetry = await runCommand(["push", session.folder, "--batch", first.token, "--page", changedFile]);
      assert.equal(changedRetry.code, 1);
      assert.match(changedRetry.stdout, /different page payload/);
      const shownAgain = await runCommand(["show", session.folder]);
      assert.equal(shownAgain.stdout, page);
    } finally {
      await session.stop();
    }
  });

  it("commits a browser batch and page update as one ordered operation", async () => {
    const session = await startSession();
    try {
      const id = randomUUID();
      assert.equal((await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(id))).status, 202);
      const batch = await command(["pull", session.folder]);
      const page = "<!doctype html><html><body><main id=\"letmeknow-root\">handled</main></body></html>";
      const pushed = await command(["push", session.folder, "--batch", batch.token, "--page", "-"], page);
      assert.equal(pushed.frontier, 2);
      assert.equal(pushed.page_event, 2);
      assert.deepEqual(pushed.events, [id]);
      assert.deepEqual(session.updates, [{ type: "update_ui", event_number: 2, html: page }]);
      const empty = await command(["pull", session.folder]);
      assert.deepEqual(empty.events, []);
      assert.equal(empty.frontier, 2);
      assert.equal(empty.page_event, 2);
      const noPage = await command(["push", session.folder, "--batch", empty.token]);
      assert.equal(noPage.type, "committed");
      assert.equal(noPage.frontier, 2);
      const noPageRetry = await command(["push", session.folder, "--batch", empty.token]);
      assert.deepEqual(noPageRetry, noPage);
    } finally {
      await session.stop();
    }
  });

  it("rejects malformed JSON submissions without creating events", async () => {
    const session = await startSession();
    try {
      for (const body of [Buffer.from("not json"), Buffer.from(JSON.stringify({ id: randomUUID() }))]) {
        const response = await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, body);
        assert.equal(response.status, 400);
      }
      const batch = await command(["pull", session.folder]);
      assert.deepEqual(batch.events, []);
      assert.equal(batch.frontier, 0);
    } finally {
      await session.stop();
    }
  });

  it("rejects oversized initial pages", async () => {
    const folder = mkdtempSync(join(tmpdir(), "letmeknow-large-"));
    writeFileSync(join(folder, "index.html"), Buffer.alloc(MAX_BODY_BYTES + 1, 97));
    const result = await runCommand(["serve", folder]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /index.html is too large/);
    rmSync(folder, { recursive: true, force: true });
  });
});
