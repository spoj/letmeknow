import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { once } from "node:events";
import { describe, it } from "node:test";
import { WebSocketServer } from "ws";

const cli = fileURLToPath(new URL("../bin/letmeknow.js", import.meta.url));
const MAX_BODY_BYTES = 1024 * 1024;
const UPDATE_BATCH_MAX_BYTES = 16 * MAX_BODY_BYTES;
const COMMAND_TIMEOUT_MS = 10_000;
const STARTUP_TIMEOUT_MS = 10_000;

function localWebSocketEnvironment(port) {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-hook-"));
  const hook = join(folder, "redirect.mjs");
  const ws = pathToFileURL(join(join(dirname(cli), "../node_modules/ws/index.js"))).href;
  writeFileSync(hook, `import WebSocket from ${JSON.stringify(ws)}; const OriginalWebSocket = WebSocket; globalThis.WebSocket = class extends OriginalWebSocket { constructor(url, protocols) { const local = new URL(url); local.protocol = "ws:"; local.hostname = "127.0.0.1"; local.port = process.env.LETMEKNOW_TEST_PORT; super(local, protocols); } };\n`);
  return {
    env: { ...process.env, LETMEKNOW_TEST_PORT: String(port), NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${pathToFileURL(hook).href}`.trim() },
    close: () => rmSync(folder, { recursive: true, force: true })
  };
}

function dirname(path) {
  return path.slice(0, path.lastIndexOf("/"));
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([once(child, "exit"), new Promise(resolve => setTimeout(resolve, 2_000))]);
  if (child.exitCode === null) {
    child.kill("SIGKILL");
    await once(child, "exit");
  }
}

async function runCommand(args, input) {
  const child = spawn(process.execPath, [cli, ...args], { stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    void stopChild(child);
  }, COMMAND_TIMEOUT_MS);
  child.stdout.on("data", chunk => { stdout += chunk; });
  child.stderr.on("data", chunk => { stderr += chunk; });
  child.once("error", cause => { stderr += `${cause.message}\n`; });
  if (input === undefined) child.stdin.end();
  else child.stdin.end(input);
  const [code] = await once(child, "close");
  clearTimeout(timer);
  return { code: timedOut ? 124 : code, stdout, stderr };
}

async function command(args, input) {
  const result = await runCommand(args, input);
  assert.equal(result.code, 0, `${args.join(" ")}: ${result.stderr}\n${result.stdout}`);
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
  let readyTimer;
  let readySettled = false;
  const ready = new Promise((resolve, reject) => {
    const fail = cause => {
      if (readySettled) return;
      readySettled = true;
      clearTimeout(readyTimer);
      reject(cause instanceof Error ? cause : new Error(String(cause)));
    };
    readyTimer = setTimeout(() => fail(new Error(`serve did not become ready${stderr ? `: ${stderr.trim()}` : ""}`)), STARTUP_TIMEOUT_MS);
    child.stdout.on("data", chunk => {
      readyOutput += chunk.toString();
      const lines = readyOutput.split("\n");
      readyOutput = lines.pop();
      for (const line of lines.filter(Boolean)) {
        try {
          const value = JSON.parse(line);
          if (value.type === "ready") {
            readySettled = true;
            clearTimeout(readyTimer);
            resolve(value);
          }
        } catch {}
      }
    });
    child.once("error", cause => fail(cause));
    child.once("close", (code, signal) => fail(new Error(`serve exited before ready${code === null ? ` (${signal})` : ` (code ${code})`}${stderr ? `: ${stderr.trim()}` : ""}`)));
  });
  let producer;
  const updates = [];
  const waiters = new Map();
  const connected = new Promise((resolve, reject) => {
    relay.once("error", reject);
    child.once("close", (code, signal) => reject(new Error(`serve exited before connecting${code === null ? ` (${signal})` : ` (code ${code})`}${stderr ? `: ${stderr.trim()}` : ""}`)));
    relay.once("connection", socket => {
      producer = socket;
      socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
      socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/", expires_after_disconnect: 600 }));
      socket.on("message", data => {
        const packet = JSON.parse(data.toString());
        if (packet.type === "open") resolve();
        if (packet.type === "update_ui") updates.push(packet);
        if (packet.type !== "http_response") return;
        const waiter = waiters.get(packet.request_id);
        if (waiter) {
          waiters.delete(packet.request_id);
          waiter(packet);
        }
      });
    });
  });
  const cleanup = async () => {
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await once(child, "exit");
    }
    await new Promise(resolve => relay.close(resolve));
    local.close();
    rmSync(folder, { recursive: true, force: true });
  };
  try {
    await Promise.all([connected, ready]);
  } catch (cause) {
    await cleanup();
    throw cause;
  }
  let requestNumber = 0;
  const request = (method, path, headers = {}, body = Buffer.alloc(0)) => {
    const request_id = `request-${++requestNumber}`;
    return new Promise(resolve => {
      waiters.set(request_id, resolve);
      producer.send(JSON.stringify({ type: "http_request", request_id, method, path, headers, body: body.toString("base64") }));
    });
  };
  const stop = cleanup;
  return { folder, child, request, updates, ready: await ready, stderr: () => stderr, stop };
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

function manifest(updates) {
  return JSON.stringify({ updates });
}

describe("LetMeKnow CLI", () => {
  it("uses the targeted update command surface", async () => {
    const result = await runCommand(["ack", "/tmp"]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Usage:/);
    const oldPage = await runCommand(["push", "/tmp", "--batch", "token", "--page", "page.html"]);
    assert.equal(oldPage.code, 1);
    assert.match(oldPage.stderr, /Unknown option|Usage:/);
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
    } finally {
      await session.stop();
    }
  });

  it("rejects non-regular and oversized update files before connecting", async () => {
    const folder = mkdtempSync(join(tmpdir(), "letmeknow-updates-"));
    const updatesDirectory = join(folder, "updates");
    mkdirSync(updatesDirectory);
    writeFileSync(join(folder, "index.html"), "unused");
    mkdirSync(join(updatesDirectory, "directory"));
    writeFileSync(join(updatesDirectory, "oversized.html"), "");
    truncateSync(join(updatesDirectory, "oversized.html"), UPDATE_BATCH_MAX_BYTES + 1);
    try {
      const nonRegular = await runCommand(["push", folder, "--batch", "token", "--updates", "-"], manifest([{ target: "count", file: join(updatesDirectory, "directory") }]));
      assert.equal(nonRegular.code, 1);
      assert.match(nonRegular.stderr, /must be a regular file/);
      const oversized = await runCommand(["push", folder, "--batch", "token", "--updates", "-"], manifest([{ target: "count", file: join(updatesDirectory, "oversized.html") }]));
      assert.equal(oversized.code, 1);
      assert.match(oversized.stderr, /updates are too large/);
    } finally {
      rmSync(folder, { recursive: true, force: true });
    }
  });

  it("applies dozens of replacements in order and resolves fragments relative to the manifest", async () => {
    const elements = Array.from({ length: 40 }, (_, index) => `<output id="value-${index}">old-${index}</output>`).join("");
    const session = await startSession({ index: `<!doctype html><html><body><main id="letmeknow-root"><section id="values">${elements}</section><div id="container">empty</div></main></body></html>` });
    try {
      const updatesDirectory = join(session.folder, "updates");
      mkdirSync(updatesDirectory);
      writeFileSync(join(updatesDirectory, "value-1.html"), `<output id="value-1">file-1</output>`);
      const updates = [
        { target: "value-0", html: `<output id="value-0">new-0</output>` },
        { target: "value-1", file: "value-1.html" },
        { target: "container", html: `<section id="container"><output id="introduced">first</output></section>` },
        { target: "introduced", html: `<output id="introduced">second</output>` },
        ...Array.from({ length: 36 }, (_, index) => ({ target: `value-${index + 2}`, html: `<output id="value-${index + 2}">new-${index + 2}</output>` }))
      ];
      const manifestPath = join(updatesDirectory, "batch.json");
      writeFileSync(manifestPath, manifest(updates));
      const first = await command(["pull", session.folder]);
      const pushed = await command(["push", session.folder, "--batch", first.token, "--updates", manifestPath]);
      assert.equal(pushed.updates.length, 40);
      assert.deepEqual(pushed.updates.map(update => update.event_number), Array.from({ length: 40 }, (_, index) => index + 1));
      assert.deepEqual(session.updates.map(({ target, event_number }) => ({ target, event_number })), pushed.updates);
      assert.equal(pushed.page_event, 40);
      const shown = await runCommand(["show", session.folder]);
      assert.equal(shown.code, 0);
      assert.match(shown.stdout, /id="value-1">file-1/);
      assert.match(shown.stdout, /id="introduced">second/);
      assert.match(shown.stdout, /id="value-37">new-37/);
      const current = await session.request("GET", "/");
      assert.equal(decodeBody(current), shown.stdout);
      assert.equal(current.headers["X-LetMeKnow-Page-Event"], "40");
    } finally {
      await session.stop();
    }
  });

  it("rejects a failed replacement batch atomically", async () => {
    const initial = "<!doctype html><html><body><main id=\"letmeknow-root\"><output id=\"count\">0</output></main></body></html>";
    const session = await startSession({ index: initial });
    try {
      const batch = await command(["pull", session.folder]);
      const updates = manifest([
        { target: "count", html: `<output id="count">1</output>` },
        { target: "missing", html: `<output id="missing">never</output>` }
      ]);
      const failed = await runCommand(["push", session.folder, "--batch", batch.token, "--updates", "-"], updates);
      assert.equal(failed.code, 1);
      assert.match(failed.stdout, /must match exactly one element/);
      assert.deepEqual(session.updates, []);
      assert.equal((await runCommand(["show", session.folder])).stdout, initial);

      const valid = await command(["push", session.folder, "--batch", batch.token, "--updates", "-"], manifest([{ target: "count", html: `<output id="count">1</output>` }]));
      assert.equal(valid.updates[0].event_number, 1);
      assert.equal((await runCommand(["show", session.folder])).stdout.includes('id="count">1'), true);
    } finally {
      await session.stop();
    }
  });

  it("rejects invalid fragments and forbidden targets", async () => {
    const initial = "<!doctype html><html><head><title>Test</title></head><body><main id=\"letmeknow-root\"><output id=\"count\">0</output><script id=\"agent-script\"></script></main></body></html>";
    const session = await startSession({ index: initial });
    try {
      for (const update of [
        { target: "count", html: `<output id="other">x</output>` },
        { target: "count", html: `<output id="count">x</output><output id="extra">y</output>` },
        { target: "count", html: `<output id="count"><script>alert(1)</script></output>` },
        { target: "script", html: `<script id="script"></script>` }
      ]) {
        const batch = await command(["pull", session.folder]);
        const failed = await runCommand(["push", session.folder, "--batch", batch.token, "--updates", "-"], manifest([update]));
        assert.equal(failed.code, 1);
      }
      assert.equal((await runCommand(["show", session.folder])).stdout, initial);
    } finally {
      await session.stop();
    }
  });

  it("rejects updates that would make the canonical page too large", async () => {
    const session = await startSession();
    try {
      const batch = await command(["pull", session.folder]);
      const failed = await runCommand(["push", session.folder, "--batch", batch.token, "--updates", "-"], manifest([{ target: "letmeknow-root", html: `<main id="letmeknow-root">${"x".repeat(MAX_BODY_BYTES)}</main>` }]));
      assert.equal(failed.code, 1);
      assert.match(failed.stdout, /updated page is too large/);
      assert.deepEqual(session.updates, []);
      assert.equal((await runCommand(["show", session.folder])).stdout, "<!doctype html><html><body><main id=\"letmeknow-root\">initial</main></body></html>");
    } finally {
      await session.stop();
    }
  });

  it("keeps later browser events for the next batch", async () => {
    const session = await startSession();
    try {
      const firstId = randomUUID();
      const secondId = randomUUID();
      assert.equal((await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(firstId))).status, 202);
      const batch = await command(["pull", session.folder]);
      assert.equal((await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(secondId))).status, 202);
      const pushed = await command(["push", session.folder, "--batch", batch.token, "--updates", "-"], manifest([{ target: "letmeknow-root", html: `<main id="letmeknow-root">handled</main>` }]));
      assert.deepEqual(pushed.events, [firstId]);
      assert.equal(pushed.updates[0].event_number, 3);
      const later = await command(["pull", session.folder]);
      assert.deepEqual(later.events.map(event => event.id), [secondId]);
      assert.equal(later.frontier, 3);
      const noUpdates = await command(["push", session.folder, "--batch", later.token]);
      assert.deepEqual(noUpdates.updates, []);
      assert.deepEqual(await command(["push", session.folder, "--batch", later.token]), noUpdates);
    } finally {
      await session.stop();
    }
  });

  it("rejects overlapping pulls after an earlier token commits", async () => {
    const session = await startSession();
    try {
      const firstId = randomUUID();
      const secondId = randomUUID();
      const submit = body => session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, body);
      assert.equal((await submit(jsonSubmission(firstId))).status, 202);
      const first = await command(["pull", session.folder]);
      assert.equal((await submit(jsonSubmission(secondId))).status, 202);
      const overlapping = await command(["pull", session.folder]);
      assert.deepEqual(overlapping.events.map(event => event.id), [firstId, secondId]);

      const committed = await command(["push", session.folder, "--batch", first.token]);
      assert.deepEqual(committed.events, [firstId]);
      const stale = await runCommand(["push", session.folder, "--batch", overlapping.token]);
      assert.equal(stale.code, 1);
      assert.match(stale.stdout, /old page or browser cursor/);

      const current = await command(["pull", session.folder]);
      assert.deepEqual(current.events.map(event => event.id), [secondId]);
    } finally {
      await session.stop();
    }
  });

  it("accepts a form without an ID or submitter", async () => {
    const session = await startSession();
    try {
      const id = randomUUID();
      const body = Buffer.from(JSON.stringify({ id, page_event: 0, form_id: null, action: "/", trigger: null, values: {} }));
      assert.equal((await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, body)).status, 202);
      const batch = await command(["pull", session.folder]);
      assert.equal(batch.events[0].form_id, null);
      assert.equal(batch.events[0].trigger, null);
    } finally {
      await session.stop();
    }
  });

  it("rejects malformed submissions without creating events", async () => {
    const session = await startSession();
    try {
      for (const body of [Buffer.from("not json"), Buffer.from(JSON.stringify({ id: randomUUID() }))]) {
        assert.equal((await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, body)).status, 400);
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
