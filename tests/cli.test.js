import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { basename, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { once } from "node:events";
import { describe, it } from "node:test";
import { WebSocketServer } from "ws";

const cli = new URL("../bin/letmeknow.js", import.meta.url);

const MAX_BODY_BYTES = 1024 * 1024;

function multipartBody(boundary, parts) {
  const chunks = [];
  for (const part of parts) {
    chunks.push(Buffer.from(`--${boundary}\r\n${part.headers}\r\n\r\n`));
    chunks.push(Buffer.isBuffer(part.body) ? part.body : Buffer.from(part.body));
    chunks.push(Buffer.from("\r\n"));
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`));
  return Buffer.concat(chunks);
}

function localWebSocketEnvironment(port) {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-hook-"));
  const hook = join(folder, "redirect.mjs");
  const ws = pathToFileURL(join(dirname(fileURLToPath(import.meta.url)), "../node_modules/ws/index.js"));
  writeFileSync(hook, `import WebSocket from ${JSON.stringify(ws.href)};\nconst OriginalWebSocket = WebSocket;\nglobalThis.WebSocket = class extends OriginalWebSocket { constructor(url, protocols) { const local = new URL(url); local.protocol = "ws:"; local.hostname = "127.0.0.1"; local.port = process.env.LETMEKNOW_TEST_PORT; super(local, protocols); } };\n`);
  return {
    env: { ...process.env, LETMEKNOW_TEST_PORT: String(port), NODE_OPTIONS: `${process.env.NODE_OPTIONS || ""} --import=${pathToFileURL(hook).href}`.trim() },
    close: () => rmSync(folder, { recursive: true, force: true })
  };
}

async function runRelayScenario() {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-"));
  const outside = mkdtempSync(join(tmpdir(), "letmeknow-outside-"));
  mkdirSync(join(folder, "nested"));
  mkdirSync(join(folder, "assets"));
  writeFileSync(join(folder, "index.html"), `<!doctype html><html><head><script>const marker = "</body>";</script><link rel="stylesheet" href="/assets/app.css"></head><body><form id="contact" action="/save" method="post"><input name="name"><button name="kind" value="send">Send</button></form></body></html>`);
  writeFileSync(join(folder, "page.htm"), "legacy html");
  writeFileSync(join(folder, "nested", "index.html"), "nested");
  writeFileSync(join(folder, "assets", "app.css"), "body { color: red }\n");
  writeFileSync(join(folder, "assets", "app.js"), "console.log('ok')\n");
  writeFileSync(join(folder, "space file.css"), "body {}\n");
  writeFileSync(join(folder, "credentials.PEM"), "secret");
  writeFileSync(join(folder, "large.bin"), "");
  truncateSync(join(folder, "large.bin"), MAX_BODY_BYTES + 1);
  mkdirSync(join(folder, "large-index"));
  writeFileSync(join(folder, "large-index", "index.html"), "");
  truncateSync(join(folder, "large-index", "index.html"), MAX_BODY_BYTES + 1);
  writeFileSync(join(outside, "secret.txt"), "outside");
  symlinkSync(join(outside, "secret.txt"), join(folder, "escape.txt"));
  const relay = new WebSocketServer({ port: 0, handleProtocols(protocols) { return [...protocols][0]; } });
  await once(relay, "listening");
  const port = relay.address().port;
  const local = localWebSocketEnvironment(port);
  const child = spawn(process.execPath, [cli.pathname, folder], {
    env: local.env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let error = "";
  const lines = [];
  let pendingOutput = "";
  const responses = new Map();
  const updates = [];
  let connectionUrl;
  const requests = [
    { request_id: "page", method: "GET", path: "/", headers: { accept: "text/html" } },
    { request_id: "legacyPage", method: "GET", path: "/page.htm", headers: {} },
    { request_id: "asset", method: "GET", path: "/assets/app.js?cache=1", headers: {} },
    { request_id: "head", method: "HEAD", path: "/assets/app.js?cache=1", headers: {} },
    { request_id: "redirect", method: "GET", path: "/nested", headers: {} },
    { request_id: "encodedUpper", method: "GET", path: "/nested%2F?view=upper", headers: {} },
    { request_id: "encodedLower", method: "GET", path: "/nested%2f?view=lower", headers: {} },
    { request_id: "directory", method: "GET", path: "/nested/", headers: {} },
    { request_id: "encoded", method: "GET", path: "/space%20file.css?x=1", headers: {} },
    { request_id: "missing", method: "GET", path: "/missing", headers: {} },
    { request_id: "escape", method: "GET", path: "/escape.txt", headers: {} },
    { request_id: "private", method: "GET", path: "/credentials.PEM", headers: {} },
    { request_id: "large", method: "GET", path: "/large.bin", headers: {} },
    { request_id: "largeIndex", method: "GET", path: "/large-index/", headers: {} },
    { request_id: "form", method: "POST", path: "/save", headers: {
      "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
      "x-letmeknow-submission": "1",
      "x-letmeknow-id": "local-test",
      "x-letmeknow-form-id": "contact",
      "x-letmeknow-action": "%2Fsave",
      "x-letmeknow-trigger-name": "kind",
      "x-letmeknow-trigger-value": "send"
    }, body: Buffer.from("name=Ada&kind=send").toString("base64") },
    { request_id: "multipart", method: "POST", path: "/review", headers: {
      "content-type": "multipart/form-data; boundary=----letmeknow-test",
      "x-letmeknow-submission": "1",
      "x-letmeknow-id": "multipart-test"
    }, body: multipartBody("----letmeknow-test", [
      { headers: 'Content-Disposition: form-data; name="comment"', body: "Review these files" },
      { headers: 'Content-Disposition: form-data; name="empty"; filename=""\r\nContent-Type: application/octet-stream', body: "" },
      { headers: 'Content-Disposition: form-data; name="upload"; filename="../../secret.txt"\r\nContent-Type: text/plain', body: Buffer.from([0, 1, 2, 255]) },
      { headers: 'Content-Disposition: form-data; name="upload"; filename="report.bin"\r\nContent-Type: application/octet-stream', body: Buffer.from("report bytes") }
    ]).toString("base64") }
  ];
  const done = new Promise((resolve, reject) => {
    relay.on("connection", (socket, request) => {
      connectionUrl = request.url;
      socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
      socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/", expires_after_disconnect: 600 }));
      const next = () => {
        const request = requests[responses.size];
        if (request) socket.send(JSON.stringify({ type: "http_request", body: "", ...request }));
        else {
          const timer = setTimeout(() => reject(new Error("revision timed out")), 5_000);
          socket.on("message", data => {
            const packet = JSON.parse(data.toString());
            if (packet.type === "revision") updates.push(packet);
          });
          writeFileSync(join(folder, "space file.css"), "body { color: blue }\n");
          writeFileSync(join(folder, "assets", "app.js"), "console.log('changed')\n");
          setTimeout(() => { clearTimeout(timer); resolve(); }, 500);
        }
      };
      socket.on("message", data => {
        const packet = JSON.parse(data.toString());
        if (packet.type === "open") next();
        else if (packet.type === "http_response") { responses.set(packet.request_id, packet); next(); }
      });
    });
    relay.on("error", reject);
  });
  child.stdout.on("data", chunk => {
    pendingOutput += chunk.toString();
    const complete = pendingOutput.split("\n");
    pendingOutput = complete.pop();
    lines.push(...complete.filter(Boolean).map(line => JSON.parse(line)));
  });
  child.stderr.on("data", chunk => { error += chunk; });
  try {
    await Promise.race([done, new Promise((_, reject) => setTimeout(() => reject(new Error(`relay timed out: ${error}`)), 10_000))]);
    const events = lines.filter(line => line.type === "submit");
    const attachmentPaths = events.flatMap(line => line.attachments || []).map(attachment => attachment.path);
    const attachmentBytes = attachmentPaths.map(path => readFileSync(path));
    const code = await new Promise(resolve => { child.once("exit", resolve); child.kill("SIGTERM"); });
    const decoded = request_id => ({ ...responses.get(request_id), body: Buffer.from(responses.get(request_id).body, "base64").toString() });
    return { code, response: decoded, responses, updates, connectionUrl, events, event: events[0], attachmentPaths, attachmentBytes };
  } finally {
    if (!child.killed) child.kill("SIGTERM");
    await new Promise(resolve => relay.close(resolve));
    rmSync(folder, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
    local.close();
  }
}

async function runStaticRequests(paths) {
  const folder = mkdtempSync(join(tmpdir(), "letmeknow-sensitive-"));
  const publicPaths = ["public.txt", "id_rsa.pub"];
  for (const path of [...paths, ...publicPaths]) {
    const file = join(folder, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, paths.includes(path) ? "private" : "public");
  }
  const relay = new WebSocketServer({ port: 0, handleProtocols(protocols) { return [...protocols][0]; } });
  await once(relay, "listening");
  const responses = new Map();
  const requestPaths = [...paths, ".ssh/", ...publicPaths];
  const requests = requestPaths.map(path => ({ request_id: path, method: "GET", path: "/" + path, headers: {} }));
  const done = new Promise((resolve, reject) => {
    relay.on("error", reject);
    relay.on("connection", socket => {
      socket.send(JSON.stringify({ type: "credential", credential: "private-test-credential" }));
      socket.send(JSON.stringify({ type: "session", url: "https://0123456789abcdef0123.letmeknow.dev/", expires_after_disconnect: 600 }));
      let opened = false;
      let index = 0;
      const next = () => {
        if (index === requests.length) return resolve(responses);
        socket.send(JSON.stringify({ type: "http_request", body: "", ...requests[index++] }));
      };
      socket.on("message", data => {
        const packet = JSON.parse(data.toString());
        if (packet.type === "open" && !opened) { opened = true; next(); }
        else if (packet.type === "http_response") { responses.set(packet.request_id, packet); next(); }
      });
    });
  });
  const local = localWebSocketEnvironment(relay.address().port);
  const child = spawn(process.execPath, [cli.pathname, folder], {
    env: local.env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let timer;
  try {
    return await Promise.race([done, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("sensitive-file request timed out")), 10_000); })]);
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null) {
      child.kill("SIGTERM");
      await once(child, "exit");
    }
    await new Promise(resolve => relay.close(resolve));
    rmSync(folder, { recursive: true, force: true });
    local.close();
  }
}

describe("LetMeKnow CLI", () => {
  it("requires exactly one preview directory", async () => {
    for (const args of [[], ["one", "two"]]) {
      const child = spawn(process.execPath, [cli.pathname, ...args], { stdio: ["ignore", "pipe", "pipe"] });
      let error = "";
      child.stderr.on("data", chunk => { error += chunk; });
      const [code] = await once(child, "exit");
      assert.equal(code, 1);
      assert.match(error, /exactly one directory must be provided/);
    }
  });

  it("denies SSH private-key paths but serves public files", async () => {
    const protectedPaths = [
      ".env", ".env.local", ".git/config",
      ".ssh/id_ed25519", ".ssh/id_rsa", ".ssh/id_ecdsa", ".ssh/id_dsa",
      "id_ed25519", "id_rsa", "id_ecdsa", "id_dsa",
      "server.key", "server.pem", "bundle.p12", "putty.ppk", "private.p8",
      "app.sqlite3", "cache.db3", "app.sqlite-wal", "app.sqlite-shm", "app.sqlite-journal"
    ];
    const responses = await runStaticRequests(protectedPaths);
    for (const path of protectedPaths) assert.equal(responses.get(path).status, 403, path);
    assert.equal(responses.get(".ssh/").status, 403);
    for (const path of ["public.txt", "id_rsa.pub"]) {
      const result = responses.get(path);
      assert.equal(result.status, 200, path);
      assert.equal(Buffer.from(result.body, "base64").toString(), "public");
    }
  });

  it("prints the skill file without connecting", async () => {
    const child = spawn(process.execPath, [cli.pathname, "--skill"], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    let error = "";
    child.stdout.on("data", chunk => { output += chunk; });
    child.stderr.on("data", chunk => { error += chunk; });
    const [code] = await once(child, "exit");
    assert.equal(code, 0);
    assert.equal(error, "");
    assert.equal(output, readFileSync(new URL("../SKILL.md", import.meta.url), "utf8"));
  });

  it("serves static files securely and forwards URL-encoded form submissions", async () => {
    const result = await runRelayScenario();
    assert.equal(result.code, 0);
    assert.equal(result.connectionUrl, "/v2/connect");
    assert.equal(result.response("page").status, 200);
    assert.equal(result.response("page").body, `<!doctype html><html><head><script>const marker = "</body>";</script><link rel="stylesheet" href="/assets/app.css"></head><body><form id="contact" action="/save" method="post"><input name="name"><button name="kind" value="send">Send</button></form></body></html>`);
    assert.equal(result.response("page").headers["Content-Type"], "text/html; charset=utf-8");
    assert.equal(result.response("legacyPage").body, "legacy html");
    assert.equal(result.response("legacyPage").headers["Content-Type"], "text/html; charset=utf-8");
    assert.equal(result.response("asset").status, 200);
    assert.equal(result.response("asset").headers["Content-Type"], "text/javascript; charset=utf-8");
    assert.equal(result.response("head").status, 200);
    assert.equal(result.response("head").body, "");
    assert.equal(result.response("head").headers["Content-Length"], String(Buffer.byteLength("console.log('ok')\n")));
    assert.equal(result.response("redirect").status, 301);
    assert.equal(result.response("redirect").headers.Location, "nested/");
    assert.equal(result.response("encodedUpper").status, 301);
    assert.equal(result.response("encodedUpper").headers.Location, "nested%2F/?view=upper");
    assert.equal(result.response("encodedLower").status, 301);
    assert.equal(result.response("encodedLower").headers.Location, "nested%2f/?view=lower");
    assert.equal(result.response("directory").body, "nested");
    assert.equal(result.response("encoded").status, 200);
    assert.equal(result.response("missing").status, 404);
    assert.equal(result.response("escape").status, 403);
    assert.equal(result.response("private").status, 403);
    assert.equal(result.response("large").status, 413);
    assert.equal(result.response("largeIndex").status, 413);
    assert.deepEqual(result.event, {
      type: "submit",
      id: "local-test",
      method: "POST",
      action: "/save",
      form_id: "contact",
      trigger: { id: null, name: "kind", value: "send" },
      values: { name: "Ada", kind: "send" }
    });
    assert.equal(result.responses.get("form").status, 202);
    const multipartEvent = result.events.find(line => line.id === "multipart-test");
    assert.deepEqual(multipartEvent.values, { comment: "Review these files" });
    assert.equal(multipartEvent.attachments.length, 2);
    assert.deepEqual(multipartEvent.attachments.map(({ field, name, type, size }) => ({ field, name, type, size })), [
      { field: "upload", name: "../../secret.txt", type: "text/plain", size: 4 },
      { field: "upload", name: "report.bin", type: "application/octet-stream", size: 12 }
    ]);
    assert.deepEqual(result.attachmentBytes[0], Buffer.from([0, 1, 2, 255]));
    assert.deepEqual(result.attachmentBytes[1], Buffer.from("report bytes"));
    assert.equal(dirname(multipartEvent.attachments[0].path), dirname(multipartEvent.attachments[1].path));
    assert.notEqual(basename(multipartEvent.attachments[0].path), "../../secret.txt");
    assert.equal(existsSync(multipartEvent.attachments[0].path), false);
    assert.equal(existsSync(multipartEvent.attachments[1].path), false);
    assert.equal(result.responses.get("multipart").status, 202);
    assert.equal(result.updates.length, 1);
    assert.deepEqual(result.updates[0], { type: "revision" });
  }, { timeout: 15_000 });
});
