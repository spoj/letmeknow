import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, renameSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import net from "node:net";
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
  const stream = [];
  const streamWaiters = [];
  let streamInput = "";
  let streamError;
  child.stdout.on("data", chunk => {
    streamInput += chunk.toString();
    const lines = streamInput.split("\n");
    streamInput = lines.pop();
    for (const line of lines.filter(Boolean)) {
      let value;
      try { value = JSON.parse(line); }
      catch { streamError = new Error(`invalid serve stream JSON: ${line}`); }
      if (streamError) {
        for (const waiter of streamWaiters.splice(0)) {
          clearTimeout(waiter.timer);
          waiter.reject(streamError);
        }
        return;
      }
      stream.push(value);
      for (let index = streamWaiters.length - 1; index >= 0; index -= 1) {
        if (!streamWaiters[index].predicate(value)) continue;
        const waiter = streamWaiters.splice(index, 1)[0];
        clearTimeout(waiter.timer);
        waiter.resolve(value);
      }
    }
  });
  const waitStream = (predicate, timeout = STARTUP_TIMEOUT_MS) => {
    if (streamError) return Promise.reject(streamError);
    const value = stream.find(predicate);
    if (value) return Promise.resolve(value);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const index = streamWaiters.findIndex(waiter => waiter.timer === timer);
        if (index >= 0) streamWaiters.splice(index, 1);
        reject(new Error(`serve stream timed out${stderr ? `: ${stderr.trim()}` : ""}`));
      }, timeout);
      streamWaiters.push({ predicate, resolve, reject, timer });
    });
  };
  const ready = waitStream(value => value.type === "ready");
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
    if (streamError) throw streamError;
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
  return { folder, child, request, scripts, stream, waitStream, ready: await ready, stderr: () => stderr, stop: cleanup };
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
  it("uses the serve and through command surface", async () => {
    const result = await runCommand(["ack", "/tmp"]);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /Usage:/);
    const missing = await runCommand(["commit", "/tmp"]);
    assert.equal(missing.code, 1);
    assert.match(missing.stderr, /--through is required/);
    const invalid = await runCommand(["commit", "/tmp", "--through", "1.5"]);
    assert.equal(invalid.code, 1);
    assert.match(invalid.stderr, /--through must be a non-negative safe integer/);
  });

  it("restarts after an unclean termination", async () => {
    const folder = mkdtempSync(join(tmpdir(), "letmeknow-restart-"));
    writeFileSync(join(folder, "index.html"), "<!doctype html><html><body>initial</body></html>");
    const root = realpathSync(folder);
    const controlSocket = join(tmpdir(), `letmeknow-control-${createHash("sha256").update(root).digest("hex").slice(0, 32)}.sock`);
    let first;
    let restarted;
    try {
      rmSync(controlSocket, { force: true });
      first = spawn(process.execPath, [cli, "serve", folder], { stdio: ["ignore", "ignore", "pipe"] });
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("serve did not create its control socket")), STARTUP_TIMEOUT_MS);
        const check = () => {
          if (existsSync(controlSocket)) {
            clearTimeout(timer);
            resolve();
          } else if (first.exitCode !== null) reject(new Error("serve exited before creating its control socket"));
          else setTimeout(check, 25);
        };
        check();
      });
      first.kill("SIGKILL");
      await once(first, "exit");

      restarted = spawn(process.execPath, [cli, "serve", folder], { stdio: ["ignore", "ignore", "pipe"] });
      await new Promise((resolve, reject) => {
        const deadline = Date.now() + STARTUP_TIMEOUT_MS;
        const check = () => {
          if (restarted.exitCode !== null || restarted.signalCode !== null) return reject(new Error("restarted serve exited"));
          const probe = net.createConnection(controlSocket);
          probe.once("connect", () => {
            probe.destroy();
            resolve();
          });
          probe.once("error", () => {
            probe.destroy();
            if (Date.now() >= deadline) reject(new Error("serve did not reclaim its control socket"));
            else setTimeout(check, 25);
          });
        };
        check();
      });
      assert.equal(restarted.exitCode, null);
    } finally {
      for (const child of [first, restarted]) {
        if (!child || child.exitCode !== null || child.signalCode !== null) continue;
        await new Promise(resolve => {
          child.once("exit", resolve);
          child.kill("SIGKILL");
        });
      }
      rmSync(controlSocket, { force: true });
      rmSync(folder, { recursive: true, force: true });
    }
  });

  it("applies stdout backpressure to accepted submissions", async () => {
    const session = await startSession();
    try {
      session.child.stdout.pause();
      const requests = Array.from({ length: 4096 }, () => session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(randomUUID(), 0, { value: "" })));
      let settled = false;
      const complete = Promise.all(requests).then(results => {
        settled = true;
        return results;
      });
      await new Promise(resolve => setTimeout(resolve, 1_000));
      assert.equal(settled, false);
      session.child.stdout.resume();
      const results = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("submissions did not drain after stdout resumed")), STARTUP_TIMEOUT_MS);
        complete.then(value => { clearTimeout(timer); resolve(value); }, cause => { clearTimeout(timer); reject(cause); });
      });
      assert.deepEqual(results.map(result => result.status), Array(requests.length).fill(202));
    } finally {
      session.child.stdout.resume();
      await session.stop();
    }
  });

  it("stops cleanly when stdout closes", async () => {
    const session = await startSession();
    try {
      session.child.stdout.destroy();
      void session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(randomUUID()));
      const [code, signal] = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("serve did not stop after stdout closed")), STARTUP_TIMEOUT_MS);
        session.child.once("exit", (...args) => { clearTimeout(timer); resolve(args); });
      });
      assert.equal(code, 1);
      assert.equal(signal, null);
      assert.doesNotMatch(session.stderr(), /Unhandled|write EPIPE|EPIPE/);
    } finally {
      await session.stop();
    }
  });

  it("serves the initial replayable page, stream metadata, and live assets", async () => {
    const session = await startSession({ index: "<!doctype html><html><body><script type=\"application/json\" data-letmeknow-history>[\"agent content\"]</script><main id=\"letmeknow-root\">old</main></body></html>" });
    try {
      assert.deepEqual(session.ready, { type: "ready", url: "https://0123456789abcdef0123.letmeknow.dev/", session_path: session.ready.session_path, frontier: 0, page_event: 0, page_hash: session.ready.page_hash });
      assert.match(session.ready.session_path, /^\/tmp\/letmeknow-[0-9a-f-]+$/);
      assert.ok(existsSync(join(session.ready.session_path, "events")));
      assert.ok(JSON.stringify(session.ready).length < 400);
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

  it("streams ordered submissions and acknowledges only the declared prefix", async () => {
    const session = await startSession();
    try {
      const firstId = randomUUID();
      const secondId = randomUUID();
      const firstResponse = await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(firstId));
      const first = await session.waitStream(event => event.type === "submit" && event.id === firstId);
      const secondResponse = await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(secondId));
      const second = await session.waitStream(event => event.type === "submit" && event.id === secondId);
      assert.equal(firstResponse.status, 202);
      assert.equal(secondResponse.status, 202);
      assert.deepEqual([first.event_number, second.event_number], [1, 2]);
      assert.deepEqual(Object.keys(first).sort(), ["event_number", "event_path", "id", "type"]);
      assert.ok(first.event_path.startsWith(join(session.ready.session_path, "events")));
      assert.deepEqual(JSON.parse(readFileSync(first.event_path)), { type: "submit", id: firstId, event_number: 1, page_event: 0, form_id: "counter", action: "/increment", trigger: { id: "increment", name: "amount", value: "1" }, values: { amount: "1" } });
      assert.deepEqual(session.stream.filter(event => event.type === "submit").map(event => event.id), [firstId, secondId]);

      const script = "document.body.dataset.first = 'ok';";
      const committed = await command(["commit", session.folder, "--through", "1", "--script", "-"], script);
      assert.deepEqual(committed, {
        ok: true,
        type: "committed",
        through: 1,
        considered_through: 1,
        frontier: 3,
        page_event: 3,
        page_hash: committed.page_hash,
        events: [firstId],
        run_ui: { event_number: 3, considered_through: 1 }
      });
      const runMetadata = await session.waitStream(event => event.type === "run_ui" && event.event_number === 3);
      assert.deepEqual(runMetadata, { type: "run_ui", event_number: 3, considered_through: 1, frontier: 3, page_event: 3, page_hash: committed.page_hash });
      assert.equal(existsSync(first.event_path), false);
      assert.equal(existsSync(second.event_path), true);
      assert.equal(session.stream.filter(event => event.type === "run_ui").length, 1);
      assert.deepEqual(session.scripts, [{ type: "run_ui", event_number: 3, considered_through: 1, script }]);

      const lateId = randomUUID();
      await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(lateId, 3));
      const late = await session.waitStream(event => event.type === "submit" && event.id === lateId);
      assert.equal(late.event_number, 4);

      const acknowledged = await command(["commit", session.folder, "--through", "2"]);
      assert.deepEqual(acknowledged.events, [secondId]);
      assert.equal(acknowledged.frontier, 4);
      assert.equal(acknowledged.page_event, 3);
      const later = await command(["commit", session.folder, "--through", "4", "--script", "-"], "document.body.dataset.second = 'ok';");
      assert.deepEqual(later.events, [lateId]);
      assert.deepEqual(later.run_ui, { event_number: 5, considered_through: 4 });
      await session.waitStream(event => event.type === "run_ui" && event.event_number === 5);
      assert.equal(existsSync(late.event_path), false);
      assert.equal(session.stream.filter(event => event.type === "run_ui").length, 2);
      assert.deepEqual(session.scripts.map(({ event_number, considered_through }) => ({ event_number, considered_through })), [
        { event_number: 3, considered_through: 1 },
        { event_number: 5, considered_through: 4 }
      ]);
    } finally {
      await session.stop();
    }
  });

  it("persists complete large submissions behind compact notifications", async () => {
    const session = await startSession();
    try {
      const id = randomUUID();
      const value = "x".repeat(10_000);
      assert.equal((await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(id, 0, { comment: value }))).status, 202);
      const notification = await session.waitStream(event => event.type === "submit" && event.id === id);
      assert.ok(JSON.stringify(notification).length < 400);
      assert.deepEqual(Object.keys(notification).sort(), ["event_number", "event_path", "id", "type"]);
      const event = JSON.parse(readFileSync(notification.event_path));
      assert.equal(event.id, id);
      assert.equal(event.values.comment, value);
      assert.equal(event.event_number, notification.event_number);
    } finally {
      await session.stop();
    }
  });

  it("retries persistence failures without consuming an event", async () => {
    const session = await startSession();
    const eventsDirectory = join(session.ready.session_path, "events");
    try {
      rmSync(eventsDirectory, { recursive: true, force: true });
      writeFileSync(eventsDirectory, "blocked");
      const id = randomUUID();
      const payload = jsonSubmission(id);
      const failed = await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, payload);
      assert.equal(failed.status, 503);
      assert.equal(session.stream.filter(event => event.type === "submit").length, 0);

      rmSync(eventsDirectory, { force: true });
      mkdirSync(eventsDirectory);
      assert.equal((await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, payload)).status, 202);
      const notification = await session.waitStream(event => event.type === "submit" && event.id === id);
      assert.equal(notification.event_number, 1);
      assert.equal(JSON.parse(readFileSync(notification.event_path)).id, id);

      const savedPath = `${notification.event_path}.saved`;
      renameSync(notification.event_path, savedPath);
      mkdirSync(notification.event_path);
      const commitFailure = await runCommand(["commit", session.folder, "--through", "1"]);
      assert.equal(commitFailure.code, 1);
      assert.equal(JSON.parse(commitFailure.stdout).ok, false);
      rmSync(notification.event_path, { recursive: true });
      renameSync(savedPath, notification.event_path);
      assert.deepEqual((await command(["commit", session.folder, "--through", "1"])).events, [id]);
      assert.equal(existsSync(notification.event_path), false);
    } finally {
      await session.stop();
    }
  });

  it("allows repeated cursors and rejects stale or future commits", async () => {
    const session = await startSession();
    try {
      const id = randomUUID();
      await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(id));
      await session.waitStream(event => event.type === "submit" && event.id === id);
      const acknowledged = await command(["commit", session.folder, "--through", "1"]);
      assert.deepEqual(acknowledged.events, [id]);
      assert.equal(acknowledged.page_event, 0);
      const repeatedAcknowledgement = await command(["commit", session.folder, "--through", "1"]);
      assert.equal(repeatedAcknowledgement.ok, true);
      assert.deepEqual(repeatedAcknowledgement.events, []);

      const firstScript = "document.body.dataset.retry = 'first';";
      const first = await command(["commit", session.folder, "--through", "1", "--script", "-"], firstScript);
      const second = await command(["commit", session.folder, "--through", "1", "--script", "-"], firstScript);
      assert.equal(first.run_ui.event_number, 2);
      assert.equal(second.run_ui.event_number, 3);
      assert.notDeepEqual(second, first);
      const different = await command(["commit", session.folder, "--through", "1", "--script", "-"], "document.body.dataset.retry = 'different';");
      assert.equal(different.run_ui.event_number, 4);
      await session.waitStream(event => event.type === "run_ui" && event.event_number === 4);
      assert.deepEqual(session.stream.filter(event => event.type === "run_ui").map(event => event.event_number), [2, 3, 4]);

      const stale = await runCommand(["commit", session.folder, "--through", "0"]);
      assert.equal(stale.code, 1);
      assert.match(stale.stdout, /before the acknowledged submission frontier/);
      const beyond = await runCommand(["commit", session.folder, "--through", "5"]);
      assert.equal(beyond.code, 1);
      assert.match(beyond.stdout, /beyond the current event frontier/);

      const noScriptRetry = await command(["commit", session.folder, "--through", "1"]);
      assert.equal(noScriptRetry.ok, true);
      assert.equal(noScriptRetry.run_ui, undefined);
      assert.deepEqual(noScriptRetry.events, []);
    } finally {
      await session.stop();
    }
  });

  it("keeps script text containing a closing tag inside escaped history JSON", async () => {
    const session = await startSession();
    try {
      const script = "const html = '</ScRiPt><img src=x>';";
      await command(["commit", session.folder, "--through", "0", "--script", "-"], script);
      const page = decodeBody(await session.request("GET", "/"));
      assert.match(page, /\\u003c\/ScRiPt>/);
      assert.equal(historyFrom(page)[0].script, script);
      assert.equal(historyFrom(page)[0].considered_through, 0);
    } finally {
      await session.stop();
    }
  });

  it("leaves a failed oversized script commit retryable", async () => {
    const filler = "a".repeat(MAX_BODY_BYTES - 4_000);
    const session = await startSession({ index: `<!doctype html><html><body>${filler}</body></html>` });
    try {
      const id = randomUUID();
      assert.equal((await session.request("POST", "/_letmeknow/submit", { "content-type": "application/json" }, jsonSubmission(id))).status, 202);
      await session.waitStream(event => event.type === "submit" && event.id === id);
      const oversized = await runCommand(["commit", session.folder, "--through", "1", "--script", "-"], "x".repeat(5_000));
      assert.equal(oversized.code, 1);
      assert.match(oversized.stdout, /page with replay history is too large/);
      assert.equal(session.scripts.length, 0);

      const script = "document.body.dataset.retry = 'ok';";
      const committed = await command(["commit", session.folder, "--through", "1", "--script", "-"], script);
      assert.deepEqual(committed.events, [id]);
      assert.deepEqual(committed.run_ui, { event_number: 2, considered_through: 1 });
      assert.equal(committed.page_event, 2);
      assert.deepEqual(session.scripts, [{ type: "run_ui", event_number: 2, considered_through: 1, script }]);
      assert.deepEqual(historyFrom(decodeBody(await session.request("GET", "/"))), session.scripts);
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
      assert.equal(session.stream.filter(event => event.type === "submit" && event.id === ids[0]).length, 1);
      const events = await Promise.all(ids.map(id => session.waitStream(event => event.type === "submit" && event.id === id)));
      assert.deepEqual(events.map(event => event.event_number).sort((a, b) => a - b), [1, 2, 3]);
      assert.deepEqual(new Set(events.map(event => event.id)), new Set(ids));
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
      assert.equal(session.stream.filter(event => event.type === "submit").length, 0);
      const committed = await command(["commit", session.folder, "--through", "0"]);
      assert.deepEqual(committed.events, []);
      assert.equal(committed.frontier, 0);
    } finally {
      const sessionPath = session.ready.session_path;
      await session.stop();
      assert.equal(existsSync(sessionPath), false);
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
      const oversized = await runCommand(["commit", scriptFolder, "--through", "0", "--script", script]);
      assert.equal(oversized.code, 1);
      assert.match(oversized.stderr, /script is too large/);
    } finally {
      rmSync(scriptFolder, { recursive: true, force: true });
    }
  });
});
