import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
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
  const scripts = [];
  const waiters = new Map();
  const connected = new Promise((resolve, reject) => {
    relay.once("error", reject);
    child.once("close", (code, signal) => reject(new Error(`serve exited before connecting${code === null ? ` (${signal})` : ` (code ${code})`}${stderr ? `: ${stderr.trim()}` : ""}`)));
    relay.once("connection", socket => {
      producer = socket;
      socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
      socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/" }));
      socket.on("message", data => {
        const packet = JSON.parse(data.toString());
        if (packet.type === "open") resolve();
        if (packet.type === "run_ui") scripts.push(packet);
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
    await stopChild(child);
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
  return { folder, child, request, scripts, ready: await ready, stderr: () => stderr, stop: cleanup };
}

function decodeBody(packet) {
  return Buffer.from(packet.body, "base64").toString("utf8");
}

function historyFrom(page) {
  const matches = [...page.matchAll(/<script type="application\/json" data-letmeknow-history(?:="")?>([\s\S]*?)<\/script>/g)];
  assert.ok(matches.length, "replay history script is missing");
  return JSON.parse(matches.at(-1)[1]);
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
  it("uses the script update command surface", async () => {
    const result = await runCommand(["ack", "/tmp"]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Usage:/);
  });

  it("serves the initial replayable page and live assets", async () => {
    const session = await startSession({ index: "<!doctype html><html><body><script type=\"application/json\" data-letmeknow-history>[\"agent content\"]</script><main id=\"letmeknow-root\">old</main></body></html>" });
    try {
      const page = await session.request("GET", "/", { accept: "text/html" });
      const index = await session.request("GET", "/index.html", { accept: "text/html" });
      const asset = await session.request("GET", "/assets/app.js");
      assert.equal(page.status, 200);
      assert.deepEqual(historyFrom(decodeBody(page)), []);
      assert.match(decodeBody(page), /data-letmeknow-history="">\["agent content"\]<\/script>/);
      assert.equal(decodeBody(index), decodeBody(page));
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

  it("commits scripts from files and stdin in order", async () => {
    const session = await startSession();
    try {
      const file = join(session.folder, "append.js");
      const firstScript = "document.querySelector('#items').insertAdjacentHTML('beforeend', '<li id=\"one\">One</li>');";
      writeFileSync(file, firstScript);
      const first = await command(["pull", session.folder]);
      const firstPush = await command(["push", session.folder, "--batch", first.token, "--script", file]);
      assert.deepEqual(firstPush.run_ui, { event_number: 1 });
      assert.deepEqual(session.scripts, [{ type: "run_ui", event_number: 1, script: firstScript }]);

      const second = await command(["pull", session.folder]);
      const secondScript = "document.querySelector('#items').insertAdjacentHTML('beforeend', '<li id=\"two\">Two</li>');";
      const secondPush = await command(["push", session.folder, "--batch", second.token, "--script", "-"], secondScript);
      assert.deepEqual(secondPush.run_ui, { event_number: 2 });
      assert.deepEqual(session.scripts, [
        { type: "run_ui", event_number: 1, script: firstScript },
        { type: "run_ui", event_number: 2, script: secondScript }
      ]);

      const page = await session.request("GET", "/");
      const pageBody = decodeBody(page);
      assert.deepEqual(historyFrom(pageBody), session.scripts);
      assert.equal(secondPush.page_hash, createHash("sha256").update(pageBody).digest("hex"));
    } finally {
      await session.stop();
    }
  });

  it("keeps script text containing a closing tag inside escaped history JSON", async () => {
    const session = await startSession();
    try {
      const batch = await command(["pull", session.folder]);
      const script = "const html = '</ScRiPt><img src=x>';";
      await command(["push", session.folder, "--batch", batch.token, "--script", "-"], script);
      const page = decodeBody(await session.request("GET", "/"));
      assert.match(page, /\\u003c\/ScRiPt>/);
      assert.equal(historyFrom(page)[0].script, script);
    } finally {
      await session.stop();
    }
  });

  it("commits no-script batches idempotently and rejects a different retry", async () => {
    const session = await startSession();
    try {
      const batch = await command(["pull", session.folder]);
      const committed = await command(["push", session.folder, "--batch", batch.token]);
      assert.equal(committed.page_event, 0);
      assert.equal(committed.run_ui, undefined);
      assert.deepEqual(committed.events, []);
      assert.deepEqual(await command(["push", session.folder, "--batch", batch.token]), committed);

      const scriptFile = join(session.folder, "different.js");
      writeFileSync(scriptFile, "document.title = 'different';");
      const different = await runCommand(["push", session.folder, "--batch", batch.token, "--script", scriptFile]);
      assert.equal(different.code, 1);
      assert.match(different.stdout, /different script/);
      assert.deepEqual(session.scripts, []);
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

  it("accepts independent submissions and numbers them globally", async () => {
    const session = await startSession();
    try {
      const invalid = await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission("not-a-uuid"));
      assert.equal(invalid.status, 400);
      const ids = Array.from({ length: 3 }, () => randomUUID());
      const submissions = await Promise.all(ids.map(id => session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(id))));
      assert.deepEqual(submissions.map(result => result.status), Array(3).fill(202));
      const duplicate = await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(ids[0]));
      assert.equal(duplicate.status, 202);
      const batch = await command(["pull", session.folder]);
      assert.equal(batch.page_event, 0);
      assert.equal(batch.frontier, 3);
      assert.equal(batch.events.length, 3);
      assert.deepEqual(new Set(batch.events.map(event => event.id)), new Set(ids));
      assert.deepEqual(batch.events.map(event => event.event_number).sort((a, b) => a - b), [1, 2, 3]);
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

  it("accepts escaped scripts through the control envelope", async () => {
    const session = await startSession();
    try {
      const script = join(session.folder, "escaped.js");
      writeFileSync(script, Buffer.alloc(MAX_BODY_BYTES));
      const batch = await command(["pull", session.folder]);
      const result = await runCommand(["push", session.folder, "--batch", batch.token, "--script", script]);
      assert.equal(result.code, 1);
      assert.match(result.stdout, /page with replay history is too large/);
    } finally {
      await session.stop();
    }
  });

  it("rejects oversized initial pages and scripts", async () => {
    const folder = mkdtempSync(join(tmpdir(), "letmeknow-large-"));
    writeFileSync(join(folder, "index.html"), Buffer.alloc(MAX_BODY_BYTES + 1, 97));
    const result = await runCommand(["serve", folder]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /index.html is too large/);
    rmSync(folder, { recursive: true, force: true });

    const replayableFolder = mkdtempSync(join(tmpdir(), "letmeknow-replayable-large-"));
    const replayableIndex = `<!doctype html><html><body>${"a".repeat(MAX_BODY_BYTES - 50)}</body></html>`;
    assert.ok(Buffer.byteLength(replayableIndex) <= MAX_BODY_BYTES);
    writeFileSync(join(replayableFolder, "index.html"), replayableIndex);
    const replayable = await runCommand(["serve", replayableFolder]);
    assert.equal(replayable.code, 1);
    assert.match(replayable.stderr, /page with replay history is too large/);
    rmSync(replayableFolder, { recursive: true, force: true });

    const scriptFolder = mkdtempSync(join(tmpdir(), "letmeknow-large-script-"));
    writeFileSync(join(scriptFolder, "index.html"), "<!doctype html><html><body></body></html>");
    const script = join(scriptFolder, "large.js");
    writeFileSync(script, "x");
    truncateSync(script, MAX_BODY_BYTES + 1);
    try {
      const oversized = await runCommand(["push", scriptFolder, "--batch", "token", "--script", script]);
      assert.equal(oversized.code, 1);
      assert.match(oversized.stderr, /script is too large/);
    } finally {
      rmSync(scriptFolder, { recursive: true, force: true });
    }
  });
});
