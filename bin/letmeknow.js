#!/usr/bin/env node

import { constants, existsSync, readFileSync, statSync, writeSync } from "node:fs";
import { chmod, copyFile, lstat, mkdtemp, mkdir, open, readdir, readlink, realpath, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import net from "node:net";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { tmpdir } from "node:os";
import { parseArgs } from "node:util";
import { lookup } from "mrmime";

const MAX_BODY_BYTES = 1024 * 1024;
const GRACE_SECONDS = 10 * 60;
const CONNECTION_TIMEOUT = 10_000;
const CONTROL_TIMEOUT = 35_000;
const MAX_RETRY_DELAY = 5_000;
const CONTROL_PREFIX = "letmeknow-control-";
const SNAPSHOT_PREFIX = "letmeknow-snapshot-";
const CONTROL_URL = "https://letmeknow.dev";
const credentialPattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const privateNames = new Set([".env", ".git", ".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]);
const privateFilePattern = /^\.env\.|\.(?:key|pem|p12|ppk|p8|sqlite|sqlite3|db|db3)$|-(?:wal|shm|journal)$/i;

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

function encodedHeader(packet, name) {
  const value = header(packet, name);
  if (value === null) return null;
  try { return decodeURIComponent(value); } catch { return null; }
}

function addValue(values, name, value) {
  if (Object.prototype.hasOwnProperty.call(values, name)) values[name] = Array.isArray(values[name]) ? [...values[name], value] : [values[name], value];
  else values[name] = value;
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

async function staticResponse(root, packet, workspaceId) {
  const published = (status, body = Buffer.alloc(0), headers = {}) => response(packet, status, body, { ...headers, "X-LetMeKnow-Workspace": workspaceId });
  const method = typeof packet.method === "string" ? packet.method.toUpperCase() : "";
  if (method !== "GET" && method !== "HEAD") return errorResponse(packet, 405, "method not allowed");
  let request;
  try { request = requestUrl(packet); } catch { return errorResponse(packet, 400, "bad request"); }
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

async function multipartSubmission(body, contentType, getAttachmentInbox) {
  const formData = await new Request("http://letmeknow.local", {
    method: "POST",
    headers: { "Content-Type": contentType },
    body
  }).formData();
  const values = Object.create(null);
  const attachments = [];
  for (const [name, value] of formData) {
    if (typeof value === "string") {
      addValue(values, name, value);
      continue;
    }
    if (value.name === "") continue;
    const bytes = Buffer.from(await value.arrayBuffer());
    const path = join(await getAttachmentInbox(), randomUUID());
    await writeFile(path, bytes, { mode: 0o600, flag: "wx" });
    attachments.push({ field: name, name: value.name, type: value.type, size: bytes.byteLength, path });
  }
  return { values, attachments };
}

async function submission(packet, getAttachmentInbox, recordInteraction) {
  const url = requestUrl(packet);
  const method = typeof packet.method === "string" ? packet.method.toUpperCase() : "";
  const values = Object.create(null);
  let attachments;
  if (method === "GET") {
    for (const [name, value] of new URLSearchParams(url.search)) addValue(values, name, value);
  } else if (method === "POST") {
    const body = Buffer.from(typeof packet.body === "string" ? packet.body : "", "base64");
    if (body.byteLength > MAX_BODY_BYTES) throw new Error("submission is too large");
    const contentTypeHeader = header(packet, "content-type");
    const contentType = contentTypeHeader?.split(";", 1)[0].trim().toLowerCase();
    if (contentType === "application/x-www-form-urlencoded") {
      for (const [name, value] of new URLSearchParams(body.toString("utf8"))) addValue(values, name, value);
    } else if (contentType === "multipart/form-data" && contentTypeHeader) {
      const parsed = await multipartSubmission(body, contentTypeHeader, getAttachmentInbox);
      Object.assign(values, parsed.values);
      attachments = parsed.attachments;
    } else throw new Error("unsupported submission encoding");
  } else throw new Error("unsupported submission method");
  const event = {
    type: "submit",
    id: encodedHeader(packet, "x-letmeknow-id") || randomUUID(),
    method,
    action: encodedHeader(packet, "x-letmeknow-action") || url.pathname,
    form_id: encodedHeader(packet, "x-letmeknow-form-id"),
    trigger: { id: encodedHeader(packet, "x-letmeknow-trigger-id"), name: encodedHeader(packet, "x-letmeknow-trigger-name"), value: encodedHeader(packet, "x-letmeknow-trigger-value") },
    values
  };
  const basedOn = encodedHeader(packet, "x-letmeknow-based-on");
  if (basedOn !== null) event.based_on = basedOn;
  if (attachments?.length) event.attachments = attachments;
  await recordInteraction(event);
  return response(packet, 202);
}

async function handleRequest(root, workspaceId, packet, getAttachmentInbox, recordInteraction) {
  if (header(packet, "x-letmeknow-submission") === "1") {
    try { return await submission(packet, getAttachmentInbox, recordInteraction); } catch (cause) { return errorResponse(packet, cause?.message === "submission is too large" ? 413 : 400, cause instanceof Error ? cause.message : "invalid submission"); }
  }
  return staticResponse(root, packet, workspaceId);
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

async function copyDirectory(source, target, root, visited = new Set()) {
  const sourceReal = await realpath(source);
  if (visited.has(sourceReal)) return;
  visited.add(sourceReal);
  await mkdir(target, { recursive: true });
  for (const entry of await readdir(sourceReal, { withFileTypes: true })) {
    const candidate = join(sourceReal, entry.name);
    const pathname = "/" + relative(root, candidate).split(sep).join("/");
    if (deniedPath(pathname)) continue;
    const targetPath = join(target, entry.name);
    const targetReal = await safeRealpath(root, candidate);
    if (targetReal === null) {
      if ((await lstat(candidate)).isSymbolicLink()) await symlink(await readlink(candidate), targetPath);
      continue;
    }
    if (targetReal === undefined) continue;
    if (deniedPath("/" + relative(root, targetReal).split(sep).join("/"))) continue;
    const info = await stat(targetReal);
    if (info.isDirectory()) await copyDirectory(targetReal, targetPath, root, visited);
    else if (info.isFile()) await copyFile(targetReal, targetPath);
  }
}

async function snapshotDirectory(root) {
  const snapshot = await mkdtemp(join(tmpdir(), SNAPSHOT_PREFIX));
  try {
    await copyDirectory(root, snapshot, root);
    return snapshot;
  } catch (cause) {
    await rm(snapshot, { recursive: true, force: true });
    throw cause;
  }
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

async function start(directory) {
  const { root } = await options(directory);
  let attachmentInboxPromise;
  const getAttachmentInbox = () => {
    attachmentInboxPromise ??= mkdtemp(join(tmpdir(), "letmeknow-attachments-"));
    return attachmentInboxPromise;
  };
  const socketPath = controlPath(root);
  let publishedRoot = await snapshotDirectory(root);
  let workspaceId = randomUUID();
  let workspaceSequence = 1;
  const workspaceIds = new Set([workspaceId]);
  const eventLog = [];
  let committedCursor = 0;
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
  let initialPublished = false;

  const batch = () => {
    const start = committedCursor;
    const end = eventLog.length;
    const key = `${workspaceId}:${start}:${end}`;
    const existing = pendingTokens.get(key);
    if (existing) return existing;
    const token = randomUUID();
    const events = eventLog.slice(start, end).map(event => ({
      ...event,
      context: {
        based_on: event.based_on ?? null,
        current: workspaceId,
        relationship: event.based_on === workspaceId ? "current" : workspaceIds.has(event.based_on) ? "stale" : "unknown"
      }
    }));
    tokens.set(token, { start, end, parent: workspaceId, status: "pending", key });
    const result = { ok: true, type: "batch", token, workspace: workspaceId, workspace_sequence: workspaceSequence, frontier: end, events };
    pendingTokens.set(key, result);
    return result;
  };

  const notifyPullWaiters = () => {
    for (const waiter of [...pullWaiters]) {
      if (eventLog.length === committedCursor) continue;
      pullWaiters.delete(waiter);
      clearTimeout(waiter.timer);
      waiter.resolve(batch());
    }
  };

  const pull = waitSeconds => {
    if (eventLog.length > committedCursor || waitSeconds <= 0) return Promise.resolve(batch());
    return new Promise(resolve => {
      const waiter = { resolve, timer: setTimeout(() => { pullWaiters.delete(waiter); resolve(batch()); }, waitSeconds * 1_000) };
      pullWaiters.add(waiter);
    });
  };

  const commit = async (token, publish) => {
    const record = tokens.get(token);
    if (!record) return { ok: false, error: "unknown batch token" };
    if (record.status !== "pending") return record.result;
    if (record.start < committedCursor && record.end <= committedCursor) {
      pendingTokens.delete(record.key);
      record.status = "committed";
      record.result = { ok: true, type: "already_committed", token, workspace: workspaceId, workspace_sequence: workspaceSequence, frontier: committedCursor };
      return record.result;
    }
    if (record.parent !== workspaceId || record.start !== committedCursor) {
      pendingTokens.delete(record.key);
      record.status = "failed";
      record.result = { ok: false, error: "batch is based on an old workspace or cursor", current_workspace: workspaceId, frontier: committedCursor };
      return record.result;
    }
    if (publish) {
      const nextRoot = await snapshotDirectory(root);
      const previousRoot = publishedRoot;
      publishedRoot = nextRoot;
      workspaceId = randomUUID();
      workspaceIds.add(workspaceId);
      workspaceSequence += 1;
      record.result = { ok: true, type: "published", token, workspace: workspaceId, workspace_sequence: workspaceSequence, parent: record.parent, frontier: record.end, events: eventLog.slice(record.start, record.end).map(event => event.id) };
      void rm(previousRoot, { recursive: true, force: true }).catch(() => {});
    } else {
      record.result = { ok: true, type: "acknowledged", token, workspace: workspaceId, workspace_sequence: workspaceSequence, frontier: record.end, events: eventLog.slice(record.start, record.end).map(event => event.id) };
    }
    committedCursor = record.end;
    pendingTokens.delete(record.key);
    record.status = "committed";
    if (publish) send({ type: "revision" });
    return record.result;
  };

  const dispatchControl = async request => {
    if (!request || typeof request !== "object") return { ok: false, error: "invalid control request" };
    if (request.type === "pull") return pull(Number.isFinite(request.wait_seconds) ? Math.max(0, request.wait_seconds) : 0);
    if (request.type === "push") return commit(typeof request.token === "string" ? request.token : "", true);
    if (request.type === "ack") return commit(typeof request.token === "string" ? request.token : "", false);
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
      if (input.length > MAX_BODY_BYTES || handled) return;
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
    controlServer.listen(socketPath, async () => {
      try { await chmod(socketPath, 0o600); } catch (cause) { controlServer.close(() => reject(cause)); return; }
      controlServer.off("error", reject);
      resolveListen();
    });
  }).catch(async cause => {
    await rm(publishedRoot, { recursive: true, force: true });
    throw new Error(`cannot start local control channel: ${cause.message}`);
  });

  const recordInteraction = event => mutate(async () => {
    if (seenEvents.has(event.id)) return;
    seenEvents.add(event.id);
    eventLog.push(event);
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
    await unlink(socketPath).catch(() => {});
    await rm(publishedRoot, { recursive: true, force: true });
    if (attachmentInboxPromise) {
      try { await rm(await attachmentInboxPromise, { recursive: true, force: true }); } catch {}
    }
    process.exit(code);
  };
  process.once("SIGINT", () => void stop(0));
  process.once("SIGTERM", () => void stop(0));

  const retry = () => {
    if (stopped || Date.now() >= retryUntil) return void stop(1);
    retryTimer = setTimeout(() => { retryTimer = undefined; connect(); }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, MAX_RETRY_DELAY);
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
        if (!initialPublished) {
          initialPublished = true;
          send({ type: "revision" });
        }
        if (!ready) { ready = true; process.stdout.write(`${JSON.stringify({ type: "ready", url: sessionUrl, workspace: workspaceId, workspace_sequence: workspaceSequence })}\n`); }
      } else if (packet.type === "http_request") {
        const requestRoot = publishedRoot;
        const requestWorkspace = workspaceId;
        void handleRequest(requestRoot, requestWorkspace, packet, getAttachmentInbox, recordInteraction).then(result => send(result)).catch(() => send(errorResponse(packet, 500, "preview request failed")));
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
      if (!retryUntil) retryUntil = Date.now() + GRACE_SECONDS * 1_000;
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
  return "Usage:\n  npx letmeknow-cli serve <directory>\n  npx letmeknow-cli pull <directory> [--wait <seconds>]\n  npx letmeknow-cli push <directory> --based-on <token>\n  npx letmeknow-cli ack <directory> --based-on <token>\n";
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
        "based-on": { type: "string" }
      },
      allowPositionals: true,
      strict: true
    });
  } catch (cause) {
    throw new Error(cause instanceof Error ? cause.message : "invalid arguments");
  }
  if (parsed.values.skill || parsed.values.help) {
    if (parsed.positionals.length || parsed.values.wait !== undefined || parsed.values["based-on"] !== undefined) throw new Error(usage());
    return { command: parsed.values.skill ? "skill" : "help" };
  }
  const [command, directory, ...extra] = parsed.positionals;
  if (!command || !directory || extra.length) throw new Error(usage());
  if (command === "serve" && (parsed.values.wait !== undefined || parsed.values["based-on"] !== undefined)) throw new Error(usage());
  if (command === "pull" && parsed.values["based-on"] !== undefined) throw new Error(usage());
  if ((command === "push" || command === "ack") && parsed.values.wait !== undefined) throw new Error(usage());
  if (!["serve", "pull", "push", "ack"].includes(command)) throw new Error(usage());
  let wait = 0;
  if (parsed.values.wait !== undefined) {
    wait = Number(parsed.values.wait);
    if (!Number.isFinite(wait) || wait < 0) throw new Error("--wait must be a non-negative number");
  }
  if ((command === "push" || command === "ack") && typeof parsed.values["based-on"] !== "string") throw new Error("--based-on is required");
  return { command, directory, wait, token: parsed.values["based-on"] };
}

let command;
try {
  command = commandArgs();
  if (command.command === "skill") writeSync(1, readFileSync(new URL("../SKILL.md", import.meta.url)));
  else if (command.command === "help") process.stdout.write(usage());
  else if (command.command === "serve") await start(command.directory);
  else {
    const { root } = await options(command.directory);
    const result = await connectControl(root, command.command === "pull" ? { type: "pull", wait_seconds: command.wait } : { type: command.command, token: command.token });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (!result.ok) process.exitCode = 1;
  }
} catch (cause) {
  process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "command failed"}\n`);
  process.exitCode = 1;
}
