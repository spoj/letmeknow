#!/usr/bin/env node

import { constants, existsSync, readFileSync, statSync, writeSync } from "node:fs";
import { chmod, open, readFile, realpath, stat, unlink } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import net from "node:net";
import { dirname, join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { parseArgs } from "node:util";
import { parse, serialize } from "parse5";
import { lookup } from "mrmime";

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_SCRIPT_BYTES = MAX_BODY_BYTES;
const MAX_BATCH_TOKENS = 100_000;
const MAX_UNIQUE_SUBMISSIONS = 100_000;
const MAX_RETAINED_SUBMISSION_BYTES = 256 * 1024 * 1024;
const CONTROL_MAX_BYTES = MAX_SCRIPT_BYTES * 2;
const RECONNECT_RETRY_SECONDS = 10 * 60;
const CONNECTION_TIMEOUT = 10_000;
const CONTROL_TIMEOUT = 35_000;
const CONTROL_PREFIX = "letmeknow-control-";
const CONTROL_URL = "https://letmeknow.dev";
const credentialPattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const privateNames = new Set([".env", ".git", ".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]);
const privateFilePattern = /^\.env\.|\.(?:key|pem|p12|ppk|p8|sqlite|sqlite3|db|db3)$|-(?:wal|shm|journal)$/i;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function getMimeType(filename) {
  const type = lookup(filename);
  if (!type) return "application/octet-stream";
  return type.startsWith("text/") || type === "application/json" || type === "application/xml" || type === "application/manifest+json"
    ? `${type}; charset=utf-8`
    : type;
}

function header(packet, name) {
  const entry = Object.entries(packet.headers || {}).find(([key]) => key.toLowerCase() === name);
  return typeof entry?.[1] === "string" && entry[1] !== "" ? entry[1] : null;
}

function response(packet, status, body = Buffer.alloc(0), headers = {}) {
  if (body.byteLength > MAX_BODY_BYTES) return response(packet, 413, Buffer.from("response body is too large"), { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
  const outputHeaders = { "Cache-Control": "no-store", ...headers };
  if (!Object.keys(outputHeaders).some(name => name.toLowerCase() === "content-length")) outputHeaders["Content-Length"] = String(body.byteLength);
  const method = typeof packet.method === "string" ? packet.method.toUpperCase() : "";
  return { type: "http_response", request_id: packet.request_id, status, headers: outputHeaders, body: method === "HEAD" ? "" : body.toString("base64") };
}

function errorResponse(packet, status, message) {
  return response(packet, status, Buffer.from(message), { "Content-Type": "text/plain; charset=utf-8" });
}

function deniedPath(pathname) {
  return pathname.split("/").filter(Boolean).some(part => privateNames.has(part) || privateFilePattern.test(part));
}

function inside(root, target) {
  const path = relative(root, target);
  return path === "" || (path !== ".." && !path.startsWith(".." + sep));
}

async function safeRealpath(root, candidate) {
  try {
    const target = await realpath(candidate);
    return inside(root, target) ? target : null;
  } catch (cause) {
    if (cause?.code === "EACCES" || cause?.code === "EPERM") return null;
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") {
      try {
        const parent = await realpath(dirname(candidate));
        if (!inside(root, parent)) return null;
      } catch {}
      return undefined;
    }
    throw cause;
  }
}

function requestUrl(packet) {
  if (typeof packet.path !== "string" || !packet.path.startsWith("/")) throw new Error("invalid request path");
  const url = new URL(packet.path, "http://letmeknow.local");
  if (url.origin !== "http://letmeknow.local") throw new Error("invalid request path");
  let pathname;
  try { pathname = decodeURIComponent(url.pathname); } catch { throw new Error("invalid request path"); }
  if (pathname.includes("\0") || pathname.includes("\\")) throw new Error("invalid request path");
  return { pathname, encodedPathname: url.pathname, search: url.search };
}

async function staticResponse(root, packet, page, pageEvent) {
  const published = (status, body = Buffer.alloc(0), headers = {}) => response(packet, status, body, headers);
  const method = typeof packet.method === "string" ? packet.method.toUpperCase() : "";
  if (method !== "GET" && method !== "HEAD") return errorResponse(packet, 405, "method not allowed");
  let request;
  try { request = requestUrl(packet); } catch { return errorResponse(packet, 400, "bad request"); }
  if (request.pathname === "/" || request.pathname === "/index.html") {
    return published(200, Buffer.from(page), { "Content-Type": "text/html; charset=utf-8", "X-LetMeKnow-Page-Event": String(pageEvent) });
  }
  if (deniedPath(request.pathname)) return errorResponse(packet, 403, "forbidden");
  const candidate = resolve(root, "." + request.pathname);
  if (!inside(root, candidate)) return errorResponse(packet, 403, "forbidden");
  let target;
  try { target = await safeRealpath(root, candidate); } catch { return errorResponse(packet, 500, "preview request failed"); }
  if (target === null) return errorResponse(packet, 403, "forbidden");
  if (target === undefined) return errorResponse(packet, 404, "not found");
  if (deniedPath("/" + relative(root, target).split(sep).join("/"))) return errorResponse(packet, 403, "forbidden");
  let info;
  try { info = await stat(target); } catch (cause) {
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return errorResponse(packet, 404, "not found");
    if (cause?.code === "EACCES" || cause?.code === "EPERM") return errorResponse(packet, 403, "forbidden");
    return errorResponse(packet, 500, "preview request failed");
  }
  if (info.isDirectory()) {
    if (!request.encodedPathname.endsWith("/")) {
      const location = request.encodedPathname.slice(request.encodedPathname.lastIndexOf("/") + 1) + "/" + request.search;
      return published(301, Buffer.from(`Redirecting to ${location}`), { Location: location, "Content-Type": "text/plain; charset=utf-8" });
    }
    const index = resolve(target, "index.html");
    try { target = await realpath(index); } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return errorResponse(packet, 404, "not found");
      return errorResponse(packet, 500, "preview request failed");
    }
    if (!inside(root, target)) return errorResponse(packet, 403, "forbidden");
    if (deniedPath("/" + relative(root, target).split(sep).join("/"))) return errorResponse(packet, 403, "forbidden");
    try { info = await stat(target); } catch (cause) {
      if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return errorResponse(packet, 404, "not found");
      if (cause?.code === "EACCES" || cause?.code === "EPERM") return errorResponse(packet, 403, "forbidden");
      return errorResponse(packet, 500, "preview request failed");
    }
  } else if (request.pathname.endsWith("/")) return errorResponse(packet, 404, "not found");
  let file;
  try { file = await open(target, constants.O_RDONLY | constants.O_NOFOLLOW); } catch (cause) {
    if (cause?.code === "ENOENT" || cause?.code === "ENOTDIR") return errorResponse(packet, 404, "not found");
    if (cause?.code === "EACCES" || cause?.code === "EPERM" || cause?.code === "ELOOP") return errorResponse(packet, 403, "forbidden");
    return errorResponse(packet, 500, "preview request failed");
  }
  try {
    info = await file.stat();
    if (!info.isFile()) return errorResponse(packet, 404, "not found");
    if (info.size > MAX_BODY_BYTES) return errorResponse(packet, 413, "response body is too large");
    const body = await file.readFile();
    if (body.byteLength > MAX_BODY_BYTES) return errorResponse(packet, 413, "response body is too large");
    return published(200, body, { "Content-Type": getMimeType(target) });
  } catch {
    return errorResponse(packet, 500, "preview request failed");
  } finally {
    await file.close();
  }
}

async function readInitialPage(root) {
  const candidate = join(root, "index.html");
  const target = await safeRealpath(root, candidate);
  if (target === null || target === undefined || deniedPath("/" + relative(root, target).split(sep).join("/"))) throw new Error("index.html is required");
  const info = await stat(target);
  if (!info.isFile()) throw new Error("index.html must be a file");
  if (info.size > MAX_BODY_BYTES) throw new Error("index.html is too large");
  return (await readFile(target)).toString("utf8");
}

function bodyElement(node) {
  if (node.nodeName === "body") return node;
  for (const child of node.childNodes || []) {
    const body = bodyElement(child);
    if (body) return body;
  }
}

function replayablePage(page, history) {
  const document = parse(page);
  const body = bodyElement(document);
  const value = JSON.stringify(history).replaceAll("<", "\\u003c");
  const script = {
    nodeName: "script",
    tagName: "script",
    attrs: [
      { name: "type", value: "application/json" },
      { name: "data-letmeknow-history", value: "" }
    ],
    namespaceURI: body.namespaceURI,
    childNodes: [{ nodeName: "#text", value }]
  };
  script.childNodes[0].parentNode = script;
  script.parentNode = body;
  body.childNodes.push(script);
  const result = serialize(document);
  if (Buffer.byteLength(result, "utf8") > MAX_BODY_BYTES) throw new Error("replayable page is too large");
  return result;
}

function scriptHash(script) {
  return createHash("sha256").update(JSON.stringify(script === undefined ? null : script)).digest("hex");
}

function validateScript(script) {
  if (script !== undefined && typeof script !== "string") throw new Error("script must be text");
  if (script !== undefined && Buffer.byteLength(script, "utf8") > MAX_SCRIPT_BYTES) throw new Error("script is too large");
  return script;
}

async function readScriptInput(filename) {
  if (filename === "-") {
    const chunks = [];
    let length = 0;
    for await (const chunk of process.stdin) {
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      length += value.byteLength;
      if (length > MAX_SCRIPT_BYTES) throw new Error("script is too large");
      chunks.push(value);
    }
    return Buffer.concat(chunks).toString("utf8");
  }
  const file = resolve(filename);
  const info = await stat(file);
  if (!info.isFile()) throw new Error("script file must be a regular file");
  if (info.size > MAX_SCRIPT_BYTES) throw new Error("script is too large");
  const source = await readFile(file);
  if (source.byteLength > MAX_SCRIPT_BYTES) throw new Error("script is too large");
  return source.toString("utf8");
}

async function submission(packet, recordInteraction) {
  const request = requestUrl(packet);
  const method = typeof packet.method === "string" ? packet.method.toUpperCase() : "";
  if (method !== "POST" || request.pathname !== "/_letmeknow/submit") throw new Error("invalid submission endpoint");
  const contentType = header(packet, "content-type")?.split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") throw new Error("JSON submission is required");
  const body = Buffer.from(typeof packet.body === "string" ? packet.body : "", "base64");
  if (body.byteLength > MAX_BODY_BYTES) throw new Error("submission is too large");
  let value;
  try { value = JSON.parse(body.toString("utf8")); } catch { throw new Error("invalid submission JSON"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("submission must be an object");
  if (typeof value.id !== "string" || !uuidPattern.test(value.id)) throw new Error("submission id must be a UUID");
  if (!Number.isSafeInteger(value.page_event) || value.page_event < 0) throw new Error("page_event must be a non-negative integer");
  if (value.form_id !== null && typeof value.form_id !== "string") throw new Error("form_id must be text or null");
  if (typeof value.action !== "string") throw new Error("action is required");
  if (value.trigger !== null && (typeof value.trigger !== "object" || Array.isArray(value.trigger))) throw new Error("trigger must be an object or null");
  if (!value.values || typeof value.values !== "object" || Array.isArray(value.values)) throw new Error("values are required");
  await recordInteraction({ type: "submit", id: value.id, page_event: value.page_event, form_id: value.form_id, action: value.action, trigger: value.trigger, values: value.values }, body.byteLength);
  return response(packet, 202);
}

async function handleRequest(root, page, pageEvent, packet, recordInteraction) {
  let request;
  try { request = requestUrl(packet); } catch { return errorResponse(packet, 400, "bad request"); }
  if (request.pathname === "/_letmeknow/submit") {
    try { return await submission(packet, recordInteraction); } catch (cause) { return errorResponse(packet, cause?.message === "submission is too large" ? 413 : 400, cause instanceof Error ? cause.message : "invalid submission"); }
  }
  return staticResponse(root, packet, page, pageEvent);
}

function options(directory) {
  const root = resolve(directory);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`directory does not exist: ${root}`);
  return realpath(root).then(root => ({ root }));
}

function controlPath(root) {
  const key = createHash("sha256").update(root).digest("hex").slice(0, 32);
  return join(tmpdir(), `${CONTROL_PREFIX}${key}.sock`);
}

function mutateQueue() {
  let chain = Promise.resolve();
  return operation => {
    const previous = chain;
    let release;
    chain = new Promise(resolve => { release = resolve; });
    return previous.then(operation).finally(release);
  };
}

function connectControl(root, packet) {
  const timeout = Math.max(CONTROL_TIMEOUT, ((packet.wait_seconds || 0) + 5) * 1_000);
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(controlPath(root));
    let output = "";
    let settled = false;
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("control request timed out"));
    }, timeout);
    const finish = (cause, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (cause) reject(cause);
      else resolve(value);
    };
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(JSON.stringify(packet) + "\n"));
    socket.on("data", chunk => {
      output += chunk;
      const newline = output.indexOf("\n");
      if (newline < 0) return;
      try { finish(null, JSON.parse(output.slice(0, newline))); } catch (cause) { finish(cause); }
      socket.destroy();
    });
    socket.on("error", cause => finish(new Error(`serve is not running: ${cause.message}`)));
    socket.on("close", () => { if (!settled) finish(new Error("serve closed the control connection")); });
  });
}

function pageHash(page) {
  return createHash("sha256").update(page).digest("hex");
}

async function start(directory) {
  const { root } = await options(directory);
  const basePage = await readInitialPage(root);
  let history = [];
  let page = replayablePage(basePage, history);
  let pageEvent = 0;
  let eventNumber = 0;
  const currentPageHash = () => pageHash(page);
  const browserEvents = [];
  const browserEventBytes = [];
  let retainedSubmissionBytes = 0;
  let committedBrowserCursor = 0;
  const seenEvents = new Set();
  const tokens = new Map();
  const pendingTokens = new Map();
  const pullWaiters = new Set();
  const mutate = mutateQueue();
  let controlServer;
  let send = () => false;
  let socket;
  let credential;
  let sessionUrl;
  let retryTimer;
  let connectionTimer;
  let retryDelay = 100;
  let retryUntil = 0;
  let stopped = false;
  let ready = false;
  let stopSession = () => {};

  const batch = () => {
    const start = committedBrowserCursor;
    const end = start + browserEvents.length;
    const key = `${pageEvent}:${start}:${end}`;
    let token = pendingTokens.get(key)?.token;
    if (!token) {
      if (tokens.size >= MAX_BATCH_TOKENS) {
        stopSession();
        throw new Error("session batch token limit exceeded");
      }
      token = randomUUID();
      tokens.set(token, { start, end, page_event: pageEvent, status: "pending", key, script_hash: null });
      pendingTokens.set(key, { token });
    }
    return { ok: true, type: "batch", token, frontier: eventNumber, page_event: pageEvent, page_hash: currentPageHash(), events: browserEvents.slice() };
  };

  const notifyPullWaiters = () => {
    for (const waiter of [...pullWaiters]) {
      if (browserEvents.length === 0) continue;
      pullWaiters.delete(waiter);
      clearTimeout(waiter.timer);
      waiter.resolve(batch());
    }
  };

  const pull = waitSeconds => {
    if (browserEvents.length > 0 || waitSeconds <= 0) return Promise.resolve(batch());
    return new Promise(resolve => {
      const waiter = { resolve, timer: setTimeout(() => { pullWaiters.delete(waiter); resolve(batch()); }, waitSeconds * 1_000) };
      pullWaiters.add(waiter);
    });
  };

  const commit = async (token, requestedScript) => {
    const record = tokens.get(token);
    if (!record) return { ok: false, error: "unknown batch token" };
    validateScript(requestedScript);
    const requestedScriptHash = scriptHash(requestedScript);
    if (record.status !== "pending") {
      if (record.script_hash === requestedScriptHash) return record.result;
      return { ok: false, error: "batch was already committed with a different script" };
    }
    if (record.page_event !== pageEvent || record.start !== committedBrowserCursor) {
      record.script_hash = requestedScriptHash;
      pendingTokens.delete(record.key);
      record.status = "failed";
      record.result = { ok: false, error: "batch is based on an old page or browser cursor", frontier: eventNumber, page_event: pageEvent, page_hash: currentPageHash() };
      return record.result;
    }
    const committedCount = record.end - record.start;
    const committedEvents = browserEvents.slice(0, committedCount).map(event => event.id);
    retainedSubmissionBytes -= browserEventBytes.slice(0, committedCount).reduce((total, bytes) => total + bytes, 0);
    let runEvent;
    let nextPage = page;
    if (requestedScript !== undefined) {
      runEvent = { type: "run_ui", event_number: eventNumber + 1, script: requestedScript };
      nextPage = replayablePage(basePage, [...history, runEvent]);
    }
    if (runEvent) {
      eventNumber = runEvent.event_number;
      pageEvent = runEvent.event_number;
      history.push(runEvent);
    }
    page = nextPage;
    browserEvents.splice(0, committedCount);
    browserEventBytes.splice(0, committedCount);
    committedBrowserCursor = record.end;
    pendingTokens.delete(record.key);
    record.status = "committed";
    record.script_hash = requestedScriptHash;
    record.result = {
      ok: true,
      type: "committed",
      token,
      frontier: eventNumber,
      page_event: pageEvent,
      page_hash: currentPageHash(),
      events: committedEvents,
      ...(runEvent ? { run_ui: { event_number: runEvent.event_number } } : {})
    };
    if (runEvent) send(runEvent);
    return record.result;
  };

  const dispatchControl = async request => {
    if (!request || typeof request !== "object") return { ok: false, error: "invalid control request" };
    if (request.type === "pull") return pull(Number.isFinite(request.wait_seconds) ? Math.max(0, request.wait_seconds) : 0);
    if (request.type === "push") {
      if (typeof request.token !== "string") return { ok: false, error: "batch token is required" };
      return commit(request.token, request.script);
    }
    return { ok: false, error: "unknown control request" };
  };

  const controlConnections = new Set();
  controlServer = net.createServer(connection => {
    controlConnections.add(connection);
    connection.setEncoding("utf8");
    let input = "";
    let handled = false;
    connection.on("data", async chunk => {
      input += chunk;
      if (Buffer.byteLength(input, "utf8") > CONTROL_MAX_BYTES || handled) return;
      const newline = input.indexOf("\n");
      if (newline < 0) return;
      handled = true;
      let result;
      try {
        const request = JSON.parse(input.slice(0, newline));
        result = request.type === "pull" ? await dispatchControl(request) : await mutate(() => dispatchControl(request));
      } catch (cause) { result = { ok: false, error: cause instanceof Error ? cause.message : "control request failed" }; }
      connection.end(JSON.stringify(result) + "\n");
    });
    connection.on("close", () => controlConnections.delete(connection));
    connection.on("error", () => controlConnections.delete(connection));
  });
  await new Promise((resolveListen, reject) => {
    controlServer.once("error", reject);
    controlServer.listen(controlPath(root), async () => {
      try { await chmod(controlPath(root), 0o600); } catch (cause) { controlServer.close(() => reject(cause)); return; }
      controlServer.off("error", reject);
      resolveListen();
    });
  }).catch(cause => { throw new Error(`cannot start local control channel: ${cause.message}`); });

  const recordInteraction = (event, bytes) => mutate(async () => {
    if (seenEvents.has(event.id)) return;
    if (seenEvents.size >= MAX_UNIQUE_SUBMISSIONS || retainedSubmissionBytes + bytes > MAX_RETAINED_SUBMISSION_BYTES) {
      stopSession();
      throw new Error("session submission limit exceeded");
    }
    seenEvents.add(event.id);
    retainedSubmissionBytes += bytes;
    eventNumber += 1;
    const numbered = { ...event, event_number: eventNumber };
    browserEvents.push(numbered);
    browserEventBytes.push(bytes);
    notifyPullWaiters();
  });

  const stop = async code => {
    if (stopped) return;
    stopped = true;
    clearTimeout(retryTimer);
    clearTimeout(connectionTimer);
    send({ type: "close" });
    try { socket?.close(); } catch {}
    for (const connection of controlConnections) connection.destroy();
    await new Promise(resolveClose => controlServer.close(() => resolveClose()));
    await unlink(controlPath(root)).catch(() => {});
    process.exit(code);
  };
  stopSession = () => { void stop(1); };
  process.once("SIGINT", () => void stop(0));
  process.once("SIGTERM", () => void stop(0));

  const retry = () => {
    if (stopped || Date.now() >= retryUntil) return void stop(1);
    retryTimer = setTimeout(() => { retryTimer = undefined; connect(); }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, 5_000);
  };

  const connect = () => {
    if (stopped) return;
    const reconnecting = Boolean(credential && sessionUrl);
    const current = socket = reconnecting ? new WebSocket(endpoint(credential, sessionUrl), credential) : new WebSocket(endpoint());
    connectionTimer = setTimeout(() => {
      if (socket !== current || current.readyState === WebSocket.OPEN || stopped) return;
      try { current.close(); } catch {}
      if (!reconnecting) void stop(1);
    }, CONNECTION_TIMEOUT);
    current.addEventListener("open", () => {
      if (socket !== current || stopped) return;
      clearTimeout(connectionTimer);
      retryDelay = 100;
      if (reconnecting) retryUntil = 0;
      send = packet => {
        if (current.readyState !== WebSocket.OPEN) return false;
        try { current.send(JSON.stringify(packet)); return true; } catch { return false; }
      };
      if (!reconnecting) send({ type: "open" });
    });
    current.addEventListener("message", event => {
      if (typeof event.data !== "string") return;
      let packet;
      try { packet = JSON.parse(event.data); } catch { return; }
      if (packet.type === "credential") {
        if (typeof packet.credential !== "string" || !credentialPattern.test(packet.credential)) return void stop(1);
        credential = packet.credential;
      } else if (packet.type === "session") {
        if (!validSessionUrl(packet.url)) return void stop(1);
        sessionUrl = packet.url;
        if (!ready) { ready = true; process.stdout.write(`${JSON.stringify({ type: "ready", url: sessionUrl, page_event: pageEvent, page_hash: currentPageHash() })}\n`); }
      } else if (packet.type === "http_request") {
        const requestPage = page;
        const requestPageEvent = pageEvent;
        void handleRequest(root, requestPage, requestPageEvent, packet, recordInteraction).then(result => send(result)).catch(() => send(errorResponse(packet, 500, "preview request failed")));
      } else if (packet.type === "closed") {
        void stop(0);
      } else if (packet.type === "error") {
        void stop(1);
      }
    });
    current.addEventListener("error", () => {});
    current.addEventListener("close", () => {
      if (socket !== current || stopped) return;
      clearTimeout(connectionTimer);
      send = () => false;
      socket = undefined;
      if (!credential || !sessionUrl) return void stop(1);
      if (!retryUntil) retryUntil = Date.now() + RECONNECT_RETRY_SECONDS * 1_000;
      retry();
    });
  };

  connect();
  await new Promise(() => {});
}

function endpoint(credential, sessionUrl) {
  const url = new URL(CONTROL_URL);
  url.protocol = "wss:";
  url.pathname = "/v2/connect";
  if (credential && sessionUrl) {
    const publicUrl = new URL(sessionUrl);
    const code = publicUrl.hostname.match(/^([a-f0-9]{20})\.letmeknow\.dev$/)?.[1];
    if (!code) throw new Error("invalid session URL");
    url.searchParams.set("code", code);
  }
  return url;
}

function validSessionUrl(value) {
  if (typeof value !== "string") return false;
  let url;
  try { url = new URL(value); } catch { return false; }
  return url.protocol === "https:" && /^[a-f0-9]{20}\.letmeknow\.dev$/.test(url.hostname) && url.pathname === "/" && !url.search && !url.hash;
}

function usage() {
  return "Usage:\n  npx letmeknow-cli serve <directory>\n  npx letmeknow-cli pull <directory> [--wait <seconds>]\n  npx letmeknow-cli push <directory> --batch <token> [--script <file|->]\n";
}

function commandArgs() {
  let parsed;
  try {
    parsed = parseArgs({
      args: process.argv.slice(2),
      options: {
        skill: { type: "boolean" },
        help: { type: "boolean", short: "h" },
        wait: { type: "string" },
        batch: { type: "string" },
        script: { type: "string" }
      },
      allowPositionals: true,
      strict: true
    });
  } catch (cause) {
    throw new Error(cause instanceof Error ? cause.message : "invalid arguments");
  }
  if (parsed.values.skill || parsed.values.help) {
    if (parsed.positionals.length || parsed.values.wait !== undefined || parsed.values.batch !== undefined || parsed.values.script !== undefined) throw new Error(usage());
    return { command: parsed.values.skill ? "skill" : "help" };
  }
  const [command, directory, ...extra] = parsed.positionals;
  if (!command || !directory || extra.length) throw new Error(usage());
  if (!["serve", "pull", "push"].includes(command)) throw new Error(usage());
  if (command === "serve" && (parsed.values.wait !== undefined || parsed.values.batch !== undefined || parsed.values.script !== undefined)) throw new Error(usage());
  if (command === "pull" && (parsed.values.batch !== undefined || parsed.values.script !== undefined)) throw new Error(usage());
  if (command === "push" && parsed.values.wait !== undefined) throw new Error(usage());
  let wait = 0;
  if (parsed.values.wait !== undefined) {
    wait = Number(parsed.values.wait);
    if (!Number.isFinite(wait) || wait < 0) throw new Error("--wait must be a non-negative number");
  }
  if (command === "push" && typeof parsed.values.batch !== "string") throw new Error("--batch is required");
  return { command, directory, wait, token: parsed.values.batch, script: parsed.values.script };
}


let command;
try {
  command = commandArgs();
  if (command.command === "skill") writeSync(1, readFileSync(new URL("../SKILL.md", import.meta.url)));
  else if (command.command === "help") process.stdout.write(usage());
  else if (command.command === "serve") await start(command.directory);
  else {
    const { root } = await options(command.directory);
    let packet;
    if (command.command === "pull") packet = { type: "pull", wait_seconds: command.wait };
    else {
      packet = { type: "push", token: command.token };
      if (command.script !== undefined) packet.script = await readScriptInput(command.script);
    }
    const result = await connectControl(root, packet);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (!result.ok) process.exitCode = 1;
  }
} catch (cause) {
  process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "command failed"}\n`);
  process.exitCode = 1;
}
