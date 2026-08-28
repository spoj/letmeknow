import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { once } from "node:events";
import { afterEach, describe, it } from "node:test";
import { WebSocket, WebSocketServer } from "ws";

const cli = new URL("../bin/letmeknow.js", import.meta.url);
const servers = [];

async function runScenario(closeDuringReconnect) {
  const server = new WebSocketServer({
    port: 0,
    handleProtocols(protocols) { return [...protocols][0]; }
  });
  servers.push(server);
  await once(server, "listening");
  const port = server.address().port;
  const child = spawn(process.execPath, [cli.pathname], {
    env: { ...process.env, LETMEKNOW_URL: `http://127.0.0.1:${port}` },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let output = "";
  let connections = 0;
  let closeSent = false;
  let reconnectQuery;
  let reconnectProtocol;
  let deliveredClose = false;
  child.stdout.on("data", (chunk) => { output += chunk; });

  server.on("connection", (socket, request) => {
    connections++;
    if (connections === 1) {
      socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
      socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/", expires_after_disconnect: 600 }));
    } else {
      reconnectQuery = request.url;
      reconnectProtocol = request.headers["sec-websocket-protocol"];
      socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/", expires_after_disconnect: 600 }));
    }
    socket.on("message", (data) => {
      const packet = JSON.parse(data.toString());
      if (connections === 1 && packet.type === "open") {
        socket.close(1000, "unexpected clean close");
        if (closeDuringReconnect && !closeSent) {
          closeSent = true;
          setTimeout(() => child.stdin.write('{"type":"close","id":"queued-close"}\n'), 20);
        }
      }
      if (connections === 2 && packet.type === "close") {
        deliveredClose = true;
        socket.send(JSON.stringify({ type: "ack", id: packet.id }));
        socket.send(JSON.stringify({ type: "closing" }));
        socket.close(1000, "session closed");
      }
    });
    if (connections === 2 && !closeDuringReconnect) setTimeout(() => child.stdin.end(), 20);
  });

  child.stdin.write('{"type":"open"}\n');
  const [code] = await once(child, "exit");
  await new Promise((resolve) => server.close(resolve));
  return { code, output, connections, reconnectQuery, reconnectProtocol, deliveredClose };
}

afterEach(async () => {
  for (const server of servers.splice(0)) {
    if (server._server?.listening) await new Promise((resolve) => server.close(resolve));
  }
});

async function runSentCloseScenario() {
  const server = new WebSocketServer({
    port: 0,
    handleProtocols(protocols) { return [...protocols][0]; }
  });
  servers.push(server);
  await once(server, "listening");
  const port = server.address().port;
  const child = spawn(process.execPath, [cli.pathname], {
    env: { ...process.env, LETMEKNOW_URL: `http://127.0.0.1:${port}` },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let connections = 0;
  server.on("connection", (socket) => {
    connections++;
    socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
    socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/", expires_after_disconnect: 600 }));
    socket.on("message", (data) => {
      if (JSON.parse(data.toString()).type === "open") child.stdin.write('{"type":"close","id":"sent-close"}\n');
      else socket.close(1000, "lost closing");
    });
  });
  child.stdin.write('{"type":"open"}\n');
  const [code] = await once(child, "exit");
  return { code, connections };
}

async function runTerminalCloseScenario() {
  const server = new WebSocketServer({
    port: 0,
    handleProtocols(protocols) { return [...protocols][0]; }
  });
  servers.push(server);
  await once(server, "listening");
  const port = server.address().port;
  const child = spawn(process.execPath, [cli.pathname], {
    env: { ...process.env, LETMEKNOW_URL: `http://127.0.0.1:${port}` },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const packets = [];
  server.on("connection", (socket) => {
    socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
    socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/", expires_after_disconnect: 600 }));
    socket.on("message", (data) => {
      const packet = JSON.parse(data.toString());
      packets.push(packet);
      if (packet.type === "close") {
        socket.send(JSON.stringify({ type: "ack", id: packet.id }));
        socket.send(JSON.stringify({ type: "closing" }));
        socket.close(1000, "session closed");
      }
    });
  });
  child.stdin.end('{"type":"open"}\n{"type":"close","id":"close"}\n{"type":"put","path":"/late","body":"must not send"}\n');
  const [code] = await once(child, "exit");
  return { code, packets };
}

async function runServerProtocolFailure(payload) {
  const server = new WebSocketServer({ port: 0 });
  servers.push(server);
  await once(server, "listening");
  const port = server.address().port;
  const child = spawn(process.execPath, [cli.pathname], {
    env: { ...process.env, LETMEKNOW_URL: `http://127.0.0.1:${port}` },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let output = "";
  let error = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { error += chunk; });
  server.on("connection", (socket) => socket.send(payload));
  child.stdin.write('{"type":"open"}\n');
  const [code] = await once(child, "exit");
  return { code, output, error };
}

async function runHangingHandshakeScenario() {
  const sockets = [];
  const httpServer = http.createServer();
  httpServer.on("upgrade", (_request, socket) => {
    sockets.push(socket);
  });
  await new Promise((resolve) => httpServer.listen(0, resolve));
  const port = httpServer.address().port;
  const child = spawn(process.execPath, [cli.pathname], {
    env: { ...process.env, LETMEKNOW_URL: `http://127.0.0.1:${port}` },
    stdio: ["pipe", "pipe", "pipe"]
  });
  let error = "";
  child.stderr.on("data", (chunk) => { error += chunk; });
  child.stdin.write('{"type":"open"}\n');
  const [code] = await once(child, "exit");
  for (const socket of sockets) socket.destroy();
  await new Promise((resolve) => httpServer.close(resolve));
  return { code, error };
}

async function runDelayedAcceptScenario() {
  const httpServer = http.createServer();
  const server = new WebSocketServer({
    noServer: true,
    handleProtocols(protocols) { return [...protocols][0]; }
  });
  httpServer.on("upgrade", (request, socket, head) => {
    setTimeout(() => server.handleUpgrade(request, socket, head, (webSocket) => server.emit("connection", webSocket, request)), 50);
  });
  await new Promise((resolve) => httpServer.listen(0, resolve));
  const port = httpServer.address().port;
  const child = spawn(process.execPath, [cli.pathname], {
    env: { ...process.env, LETMEKNOW_URL: `http://127.0.0.1:${port}` },
    stdio: ["pipe", "pipe", "pipe"]
  });
  const packets = [];
  server.on("connection", (socket) => {
    socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
    socket.on("message", (data) => {
      packets.push(JSON.parse(data.toString()));
      if (packets.length === 2) socket.close(1000, "commands received");
    });
  });
  child.stdin.end('{"type":"open"}\n{"type":"render","body":"<h1>Ready</h1>"}\n');
  const [code] = await once(child, "exit");
  await new Promise((resolve) => httpServer.close(resolve));
  return { code, packets };
}

async function runLocalScenario() {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-"));
  writeFileSync(join(folder, "index.html"), `<!doctype html><html><body><form id="contact" action="/save" method="post"><input name="name"><button name="kind" value="send">Send</button></form></body></html>`);
  const child = spawn(process.execPath, [cli.pathname, folder, "--port", "0"], {
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  let error = "";
  const lines = [];
  let pending = "";
  child.stdout.on("data", chunk => {
    output += chunk;
    pending += chunk.toString();
    const complete = pending.split("\n");
    pending = complete.pop();
    lines.push(...complete.filter(Boolean).map(line => JSON.parse(line)));
  });
  child.stderr.on("data", chunk => { error += chunk; });
  try {
    let ready;
    for (let attempt = 0; !ready && attempt < 50; attempt++) {
      ready = lines.find(line => line.type === "ready");
      if (!ready) await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert(ready, `server did not start: ${error}`);
    const page = await fetch(ready.url);
    const html = await page.text();
    const response = await fetch(new URL("/save", ready.url), {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-LetMeKnow-Submission": "1",
        "X-LetMeKnow-ID": "local-test",
        "X-LetMeKnow-Form-ID": "contact",
        "X-LetMeKnow-Action": "%2Fsave",
        "X-LetMeKnow-Trigger-Name": "kind",
        "X-LetMeKnow-Trigger-Value": "send"
      },
      body: "name=Ada&kind=send"
    });
    for (let attempt = 0; !lines.some(line => line.type === "submit") && attempt < 50; attempt++) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    return { code: await new Promise(resolve => {
      child.once("exit", code => resolve(code));
      child.kill("SIGTERM");
    }), output, error, html, response, event: lines.find(line => line.type === "submit") };
  } finally {
    if (!child.killed) child.kill("SIGTERM");
    rmSync(folder, { recursive: true, force: true });
  }
}

async function runLocalHotUpdateScenario() {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-"));
  writeFileSync(join(folder, "index.html"), "<!doctype html><html><body><h1>Before</h1></body></html>");
  const child = spawn(process.execPath, [cli.pathname, folder, "--port", "0"], {
    stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  let pending = "";
  let error = "";
  const lines = [];
  child.stdout.on("data", chunk => {
    output += chunk;
    pending += chunk.toString();
    const complete = pending.split("\n");
    pending = complete.pop();
    lines.push(...complete.filter(Boolean).map(line => JSON.parse(line)));
  });
  child.stderr.on("data", chunk => { error += chunk; });
  let socket;
  try {
    let ready;
    for (let attempt = 0; !ready && attempt < 50; attempt++) {
      ready = lines.find(line => line.type === "ready");
      if (!ready) await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert(ready, `server did not start: ${error}`);
    const hmrUrl = new URL(ready.url);
    hmrUrl.protocol = hmrUrl.protocol === "https:" ? "wss:" : "ws:";
    socket = new WebSocket(hmrUrl, "vite-hmr");
    const connected = new Promise((resolve, reject) => {
      socket.once("error", reject);
      socket.on("message", data => {
        const message = JSON.parse(data.toString());
        if (message.type === "connected") resolve();
      });
    });
    await connected;
    const update = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("HMR update timed out")), 2_000);
      socket.on("message", data => {
        const message = JSON.parse(data.toString());
        if (message.type === "custom" || message.type === "full-reload") {
          clearTimeout(timer);
          resolve(message);
        }
      });
    });
    writeFileSync(join(folder, "index.html"), "<!doctype html><html><body><h1>After</h1></body></html>");
    const message = await update;
    socket.close();
    const code = await new Promise(resolve => {
      child.once("exit", resolve);
      child.kill("SIGTERM");
    });
    return { code, message, output };
  } finally {
    socket?.close();
    if (!child.killed) child.kill("SIGTERM");
    rmSync(folder, { recursive: true, force: true });
  }
}

describe("LetMeKnow local Vite server", () => {
  it("updates HTML through HMR without a full reload", async () => {
    const result = await runLocalHotUpdateScenario();
    assert.equal(result.code, 0);
    assert.deepEqual(result.message, {
      type: "custom",
      event: "letmeknow:html-update",
      data: { path: "/index.html" }
    });
  }, { timeout: 10_000 });

  it("serves a folder and prints form submissions as JSONL", async () => {
    const result = await runLocalScenario();
    assert.equal(result.code, 0);
    assert.equal(result.response.status, 204);
    assert.match(result.html, /data-letmeknow-client/);
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

describe("LetMeKnow CLI reconnect", () => {
  it("prints the packaged skill file without connecting", async () => {
    const child = spawn(process.execPath, [cli.pathname, "--skill"], {
      stdio: ["ignore", "pipe", "pipe"]
    });
    let output = "";
    let error = "";
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { error += chunk; });
    const [code] = await once(child, "exit");
    assert.equal(code, 0);
    assert.equal(error, "");
    assert.equal(output, readFileSync(new URL("../SKILL.md", import.meta.url), "utf8"));
  }, { timeout: 10_000 });

  it("reconnects after an unexpected clean close", async () => {
    const result = await runScenario(false);
    assert.equal(result.code, 0);
    assert.equal(result.connections, 2);
    assert(!result.output.includes("private-test-credential"));
    assert.equal(result.reconnectQuery, "/v1/connect?code=0123456789abcdef0123");
    assert.equal(result.reconnectProtocol, "private-test-credential");
  }, { timeout: 10_000 });

  it("delivers a close command queued during reconnect", async () => {
    const result = await runScenario(true);
    assert.equal(result.code, 0);
    assert.equal(result.connections, 2);
    assert.equal(result.reconnectQuery, "/v1/connect?code=0123456789abcdef0123");
    assert.equal(result.reconnectProtocol, "private-test-credential");
    assert.equal(result.deliveredClose, true);
  }, { timeout: 10_000 });

  it("exits successfully when a sent close loses its closing event", async () => {
    const result = await runSentCloseScenario();
    assert.equal(result.code, 0);
    assert.equal(result.connections, 1);
  }, { timeout: 10_000 });

  it("flushes piped commands after a delayed connection accepts", async () => {
    const result = await runDelayedAcceptScenario();
    assert.equal(result.code, 0);
    assert.deepEqual(result.packets, [
      { type: "open" },
      { type: "render", body: "<h1>Ready</h1>" }
    ]);
  }, { timeout: 10_000 });

  it("stops sending commands after a close command", async () => {
    const result = await runTerminalCloseScenario();
    assert.equal(result.code, 0);
    assert.deepEqual(result.packets, [
      { type: "open" },
      { type: "close", id: "close" }
    ]);
  }, { timeout: 10_000 });

  it("exits on malformed server text without corrupting stdout", async () => {
    const result = await runServerProtocolFailure("not json");
    assert.equal(result.code, 1);
    assert.equal(result.output, "");
    assert.match(result.error, /server protocol error: invalid JSON/);
  }, { timeout: 10_000 });

  it("exits on binary server frames without corrupting stdout", async () => {
    const result = await runServerProtocolFailure(Buffer.from('{"type":"session"}'));
    assert.equal(result.code, 1);
    assert.equal(result.output, "");
    assert.match(result.error, /server protocol error: binary WebSocket frame/);
  }, { timeout: 10_000 });

  it("exits on non-object server packets without corrupting stdout", async () => {
    const result = await runServerProtocolFailure("null");
    assert.equal(result.code, 1);
    assert.equal(result.output, "");
    assert.match(result.error, /server protocol error: packet must be a JSON object/);
  }, { timeout: 10_000 });

  it("rejects malformed credential control events", async () => {
    const result = await runServerProtocolFailure(JSON.stringify({ type: "credential", credential: "" }));
    assert.equal(result.code, 1);
    assert.equal(result.output, "");
    assert.match(result.error, /server protocol error: invalid credential/);
  }, { timeout: 10_000 });

  it("rejects malformed session URLs", async () => {
    const result = await runServerProtocolFailure(JSON.stringify({
      type: "session",
      url: "not-a-session-url",
      expires_after_disconnect: 600
    }));
    assert.equal(result.code, 1);
    assert.equal(result.output, "");
    assert.match(result.error, /server protocol error: invalid session URL/);
  }, { timeout: 10_000 });

  it("rejects malformed session expiration data", async () => {
    const result = await runServerProtocolFailure(JSON.stringify({
      type: "session",
      url: "https://0123456789abcdef0123.letmeknow.dev/",
      expires_after_disconnect: 0
    }));
    assert.equal(result.code, 1);
    assert.equal(result.output, "");
    assert.match(result.error, /server protocol error: invalid session expiration/);
  }, { timeout: 10_000 });

  it("times out a hanging WebSocket handshake", async () => {
    const result = await runHangingHandshakeScenario();
    assert.equal(result.code, 1);
    assert.match(result.error, /connection attempt timed out/);
  }, { timeout: 15_000 });
});
