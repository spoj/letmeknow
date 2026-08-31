import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { once } from "node:events";
import { describe, it } from "node:test";
import { WebSocketServer } from "ws";

const cli = fileURLToPath(new URL("../bin/letmeknow.js", import.meta.url));
const COMMAND_TIMEOUT_MS = 10_000;
const STARTUP_TIMEOUT_MS = 10_000;

function localEnvironment(webSocketPort, httpPort) {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-hook-"));
  const hook = join(folder, "redirect.mjs");
  const ws = pathToFileURL(join(dirname(cli), "../node_modules/ws/index.js")).href;
  writeFileSync(hook, `import WebSocket from ${JSON.stringify(ws)}; const OriginalWebSocket = WebSocket; globalThis.WebSocket = class extends OriginalWebSocket { constructor(url, protocols) { const local = new URL(url); local.protocol = "ws:"; local.hostname = "127.0.0.1"; local.port = process.env.LETMEKNOW_TEST_WS_PORT; super(local, protocols); } }; const originalFetch = globalThis.fetch; globalThis.fetch = (input, init) => { const value = typeof input === "string" || input instanceof URL ? input : input.url; const url = new URL(value); if (!url.hostname.endsWith('.letmeknow.dev')) return originalFetch(input, init); url.protocol = 'http:'; url.hostname = '127.0.0.1'; url.port = process.env.LETMEKNOW_TEST_HTTP_PORT; return originalFetch(url, init); };\n`);
  return {
    env: { ...process.env, LETMEKNOW_TEST_WS_PORT: String(webSocketPort), LETMEKNOW_TEST_HTTP_PORT: String(httpPort), NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${pathToFileURL(hook).href}`.trim() },
    close: () => rmSync(folder, { recursive: true, force: true })
  };
}

function stopChild(child) {
  if (!child || child.exitCode !== null) return Promise.resolve();
  child.kill("SIGTERM");
  return Promise.race([once(child, "exit"), new Promise(resolve => setTimeout(resolve, 2_000))]).then(() => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill("SIGKILL");
    return once(child, "exit");
  });
}

async function runCommand(args, input, env) {
  const child = spawn(process.execPath, [cli, ...args], { env, stdio: ["pipe", "pipe", "pipe"] });
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

async function command(args, input, env) {
  const result = await runCommand(args, input, env);
  assert.equal(result.code, 0, `${args.join(" ")}: ${result.stderr}\n${result.stdout}`);
  return JSON.parse(result.stdout);
}

function serviceEvent(id, eventNumber, value = "one") {
  return { type: "submit", id, event_number: eventNumber, page_event: 0, form_id: "review", action: "/review", trigger: null, values: { value } };
}

async function startSession({ index = "<!doctype html><html><body><main id=app>initial</main></body></html>", files = { "assets/app.js": "initial" } } = {}) {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-"));
  writeFileSync(join(folder, "index.html"), index);
  for (const [pathname, value] of Object.entries(files)) {
    const filename = join(folder, pathname);
    const parent = filename.slice(0, filename.lastIndexOf("/"));
    if (parent !== folder) await import("node:fs/promises").then(fs => fs.mkdir(parent, { recursive: true }));
    writeFileSync(filename, value);
  }

  const state = { uploaded: new Map(), events: new Map(), nextEvent: 0, committedThrough: 0, workspaceVersion: 0, pageEvent: 0, acknowledgements: [], ackWaiters: new Map(), producer: undefined };
  const httpServer = createServer((request, response) => {
    const match = request.url?.match(/^\/_letmeknow\/workspace\/([0-9a-f]{64})$/);
    if (request.method !== "PUT" || !match) {
      response.writeHead(404);
      response.end();
      return;
    }
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => {
      const data = Buffer.concat(chunks);
      const hash = createHash("sha256").update(data).digest("hex");
      if (hash !== match[1]) {
        response.writeHead(400);
        response.end();
        return;
      }
      state.uploaded.set(match[1], { size: data.byteLength, data });
      response.writeHead(204);
      response.end();
    });
  });
  httpServer.listen(0);
  await once(httpServer, "listening");
  const relay = new WebSocketServer({ port: 0, handleProtocols(protocols) { return [...protocols][0]; } });
  await once(relay, "listening");
  const local = localEnvironment(relay.address().port, httpServer.address().port);
  const code = "0123456789abcdef0123";
  const url = `https://${code}.letmeknow.dev/`;
  let opened;
  let resolveConnection;
  const connected = new Promise(resolve => { resolveConnection = resolve; });
  relay.on("connection", socket => {
    state.producer = socket;
    resolveConnection(socket);
    socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
    socket.send(JSON.stringify({ type: "provisioned", url }));
    socket.on("message", async data => {
      const packet = JSON.parse(data.toString());
      if (packet.type === "workspace_manifest") {
        const items = [packet.index, ...(packet.hashes || [])].filter(Boolean);
        const missing = items.filter(item => state.uploaded.get(item.hash)?.size !== item.size);
        socket.send(JSON.stringify({ type: "workspace_manifest", id: packet.id, missing }));
      } else if (packet.type === "open") {
        opened = true;
        socket.send(JSON.stringify({ type: "session", id: packet.id, url, frontier: state.nextEvent, page_event: state.pageEvent, page_hash: "page-hash", workspace_version: state.workspaceVersion }));
      } else if (packet.type === "event_ack") {
        state.acknowledgements.push(packet.event_number);
        const waiters = state.ackWaiters.get(packet.event_number) || [];
        state.ackWaiters.delete(packet.event_number);
        for (const resolve of waiters) resolve();
      } else if (packet.type === "commit") {
        const ids = [];
        for (const event of state.events.values()) {
          if (event.type === "submit" && event.event_number <= packet.through && !event.committed) {
            event.committed = true;
            ids.push(event.id);
          }
        }
        state.committedThrough = packet.through;
        state.workspaceVersion += 1;
        let runUI;
        if (packet.script !== undefined) {
          const eventNumber = ++state.nextEvent;
          state.pageEvent = eventNumber;
          runUI = { type: "run_ui", event_number: eventNumber, considered_through: packet.through, frontier: eventNumber, page_event: eventNumber, page_hash: `page-${eventNumber}`, script: packet.script };
          state.events.set(eventNumber, runUI);
          socket.send(JSON.stringify(runUI));
        }
        socket.send(JSON.stringify({ ok: true, type: "committed", id: packet.id, through: packet.through, considered_through: packet.through, frontier: state.nextEvent, page_event: state.pageEvent, page_hash: runUI?.page_hash || "page-hash", workspace_version: state.workspaceVersion, events: ids, ...(runUI ? { run_ui: { event_number: runUI.event_number, considered_through: runUI.considered_through } } : {}) }));
      }
    });
  });

  const child = spawn(process.execPath, [cli, "serve", folder], { env: local.env, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", chunk => { stderr += chunk; });
  const stream = [];
  const waiters = [];
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
        for (const waiter of waiters.splice(0)) { clearTimeout(waiter.timer); waiter.reject(streamError); }
        return;
      }
      stream.push(value);
      for (let index = waiters.length - 1; index >= 0; index -= 1) {
        if (!waiters[index].predicate(value)) continue;
        const waiter = waiters.splice(index, 1)[0];
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
        const index = waiters.findIndex(waiter => waiter.timer === timer);
        if (index >= 0) waiters.splice(index, 1);
        reject(new Error(`serve stream timed out${stderr ? `: ${stderr.trim()}` : ""}`));
      }, timeout);
      waiters.push({ predicate, resolve, reject, timer });
    });
  };
  const ack = eventNumber => {
    if (state.acknowledgements.includes(eventNumber)) return Promise.resolve();
    return new Promise(resolve => {
      const waitersForEvent = state.ackWaiters.get(eventNumber) || [];
      waitersForEvent.push(resolve);
      state.ackWaiters.set(eventNumber, waitersForEvent);
    });
  };
  const sendEvent = async event => {
    state.events.set(event.event_number, event);
    state.nextEvent = Math.max(state.nextEvent, event.event_number);
    state.producer.send(JSON.stringify(event));
    await ack(event.event_number);
  };
  const cleanup = async () => {
    await stopChild(child);
    for (const socket of relay.clients) socket.terminate();
    await new Promise(resolve => relay.close(resolve));
    httpServer.closeAllConnections?.();
    await new Promise(resolve => httpServer.close(resolve));
    local.close();
    rmSync(folder, { recursive: true, force: true });
    if (streamError) throw streamError;
  };
  let connectedTimer;
  try {
    const connectionTimeout = new Promise((_, reject) => { connectedTimer = setTimeout(() => reject(new Error(`serve did not connect${stderr ? `: ${stderr.trim()}` : ""}`)), STARTUP_TIMEOUT_MS); });
    await Promise.race([connected, connectionTimeout]);
    clearTimeout(connectedTimer);
    await waitStream(value => value.type === "ready");
  } catch (cause) {
    clearTimeout(connectedTimer);
    await cleanup();
    throw cause;
  }
  return { folder, child, state, stream, waitStream, sendEvent, ack, ready: stream.find(value => value.type === "ready"), stderr: () => stderr, stop: cleanup, url, opened };
}

function controlPath(folder) {
  const root = realpathSync(folder);
  return join(tmpdir(), `letmeknow-control-${createHash("sha256").update(root).digest("hex").slice(0, 32)}.sock`);
}

describe("LetMeKnow CLI", () => {
  it("keeps the command surface", async () => {
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
    const socket = controlPath(folder);
    let first;
    let second;
    let duplicate;
    try {
      rmSync(socket, { force: true });
      first = spawn(process.execPath, [cli, "serve", folder], { stdio: ["ignore", "ignore", "ignore"] });
      for (let index = 0; index < STARTUP_TIMEOUT_MS / 25 && !existsSync(socket); index += 1) await new Promise(resolve => setTimeout(resolve, 25));
      assert.equal(existsSync(socket), true);
      duplicate = spawn(process.execPath, [cli, "serve", folder], { stdio: ["ignore", "ignore", "ignore"] });
      const [duplicateCode] = await once(duplicate, "exit");
      assert.equal(duplicateCode, 1);
      assert.equal(existsSync(socket), true);
      first.kill("SIGKILL");
      await once(first, "exit");
      second = spawn(process.execPath, [cli, "serve", folder], { stdio: ["ignore", "ignore", "ignore"] });
      for (let index = 0; index < STARTUP_TIMEOUT_MS / 25 && second.exitCode === null && !existsSync(socket); index += 1) await new Promise(resolve => setTimeout(resolve, 25));
      assert.equal(second.exitCode, null);
      assert.equal(existsSync(socket), true);
    } finally {
      for (const child of [first, second, duplicate]) {
        if (!child || child.exitCode !== null || child.signalCode !== null) continue;
        child.kill("SIGKILL");
        await once(child, "exit");
      }
      rmSync(socket, { force: true });
      rmSync(folder, { recursive: true, force: true });
    }
  });

  it("uploads the workspace and reports a compact ready notification", async () => {
    const session = await startSession();
    try {
      assert.equal(session.ready.type, "ready");
      assert.match(session.ready.url, /^https:\/\/[0-9a-f]{20}\.letmeknow\.dev\/$/);
      assert.match(session.ready.session_path, /^\/tmp\/letmeknow-[0-9a-f-]+$/);
      assert.ok(JSON.stringify(session.ready).length < 400);
      assert.ok(session.state.uploaded.size >= 2);
      assert.ok(session.stream.every(value => value.type === "ready"));
    } finally {
      await session.stop();
    }
  });

  it("persists complete events, handles redelivery, and cleans acknowledged files", async () => {
    const session = await startSession();
    try {
      const id = randomUUID();
      const event = serviceEvent(id, 1, "x".repeat(10_000));
      await session.sendEvent(event);
      const notification = await session.waitStream(value => value.type === "submit" && value.id === id);
      const artifact = JSON.parse(readFileSync(notification.event_path));
      assert.equal(artifact.values.value.length, 10_000);
      assert.deepEqual(Object.keys(notification).sort(), ["event_number", "event_path", "id", "type"]);
      await session.sendEvent(event);
      assert.equal(session.stream.filter(value => value.type === "submit" && value.id === id).length, 1);
      const result = await command(["commit", session.folder, "--through", "1"]);
      assert.deepEqual(result.events, [id]);
      assert.equal(existsSync(notification.event_path), false);
    } finally {
      await session.stop();
    }
  });

  it("publishes canonical UI events after earlier submissions", async () => {
    const session = await startSession();
    try {
      const id = randomUUID();
      await session.sendEvent(serviceEvent(id, 1));
      const script = "document.body.dataset.updated = 'yes';";
      const result = await command(["commit", session.folder, "--through", "1", "--script", "-"], script);
      const update = await session.waitStream(value => value.type === "run_ui" && value.event_number === 2);
      assert.deepEqual(result.events, [id]);
      assert.deepEqual(result.run_ui, { event_number: 2, considered_through: 1 });
      assert.deepEqual(session.stream.filter(value => value.type === "submit" || value.type === "run_ui").map(value => value.event_number), [1, 2]);
      assert.equal(update.page_hash, "page-2");
    } finally {
      await session.stop();
    }
  });

  it("stops on canonical event-number reuse", async () => {
    const session = await startSession();
    try {
      await session.sendEvent(serviceEvent(randomUUID(), 1));
      session.state.producer.send(JSON.stringify(serviceEvent(randomUUID(), 1, "different")));
      const [code] = await once(session.child, "exit");
      assert.equal(code, 1);
    } finally {
      await session.stop();
    }
  });

  it("stops cleanly when stdout closes", async () => {
    const session = await startSession();
    try {
      session.child.stdout.destroy();
      session.state.producer.send(JSON.stringify(serviceEvent(randomUUID(), 1)));
      const [code, signal] = await once(session.child, "exit");
      assert.equal(code, 1);
      assert.equal(signal, null);
      assert.doesNotMatch(session.stderr(), /Unhandled|write EPIPE|EPIPE/);
    } finally {
      await session.stop();
    }
  });
});
