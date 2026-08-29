#!/usr/bin/env node

import { constants, existsSync, readFileSync, statSync, writeSync } from "node:fs";
import { mkdtemp, open, realpath, rm, stat, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { parseArgs } from "node:util";
import chokidar from "chokidar";
import { lookup } from "mrmime";

const MAX_BODY_BYTES = 1024 * 1024;
const GRACE_SECONDS = 10 * 60;
const CONNECTION_TIMEOUT = 10_000;
const MAX_RETRY_DELAY = 5_000;
const REVISION_QUIET_MS = 200;
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

async function staticResponse(root, packet) {
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
      return response(packet, 301, Buffer.from(`Redirecting to ${location}`), { Location: location, "Content-Type": "text/plain; charset=utf-8" });
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
    return response(packet, 200, body, { "Content-Type": getMimeType(target) });
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

async function submission(packet, getAttachmentInbox) {
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
    id: encodedHeader(packet, "x-letmeknow-id"),
    method,
    action: encodedHeader(packet, "x-letmeknow-action") || url.pathname,
    form_id: encodedHeader(packet, "x-letmeknow-form-id"),
    trigger: { id: encodedHeader(packet, "x-letmeknow-trigger-id"), name: encodedHeader(packet, "x-letmeknow-trigger-name"), value: encodedHeader(packet, "x-letmeknow-trigger-value") },
    values
  };
  if (attachments?.length) event.attachments = attachments;
  process.stdout.write(`${JSON.stringify(event)}\n`);
  return response(packet, 202);
}

async function handleRequest(root, packet, getAttachmentInbox) {
  if (header(packet, "x-letmeknow-submission") === "1") {
    try { return await submission(packet, getAttachmentInbox); } catch (cause) { return errorResponse(packet, cause?.message === "submission is too large" ? 413 : 400, cause instanceof Error ? cause.message : "invalid submission"); }
  }
  return staticResponse(root, packet);
}

function options(directory) {
  const root = resolve(directory);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`directory does not exist: ${root}`);
  return realpath(root).then(root => ({ root }));
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

async function start(directory) {
  const { root } = await options(directory);
  let attachmentInboxPromise;
  const getAttachmentInbox = () => {
    attachmentInboxPromise ??= mkdtemp(join(tmpdir(), "letmeknow-attachments-"));
    return attachmentInboxPromise;
  };
  let send = () => false;
  let revisionTimer;
  const watchedPath = filename => {
    const file = resolve(root, String(filename));
    const path = relative(root, file).split(sep).join("/");
    return path && path !== ".." && !path.startsWith("../") && !deniedPath("/" + path);
  };
  const watcher = chokidar.watch(root, {
    ignoreInitial: true,
    ignored: filename => {
      const path = relative(root, resolve(root, String(filename))).split(sep).join("/");
      return path !== "" && (path === ".." || path.startsWith("../") || deniedPath("/" + path));
    }
  });
  const scheduleRevision = () => {
    clearTimeout(revisionTimer);
    revisionTimer = setTimeout(() => { revisionTimer = undefined; send({ type: "revision" }); }, REVISION_QUIET_MS);
  };
  watcher.on("all", (_event, filename) => {
    if (filename && !watchedPath(filename)) return;
    scheduleRevision();
  });
  let socket;
  let credential;
  let sessionUrl;
  let retryTimer;
  let connectionTimer;
  let retryDelay = 100;
  let retryUntil = 0;
  let stopped = false;
  let ready = false;
  const stop = async code => {
    if (stopped) return;
    stopped = true;
    clearTimeout(retryTimer);
    clearTimeout(connectionTimer);
    clearTimeout(revisionTimer);
    send({ type: "close" });
    try { socket?.close(); } catch {}
    await watcher.close();
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
        if (!ready) { ready = true; process.stdout.write(`${JSON.stringify({ type: "ready", url: sessionUrl })}\n`); }
      } else if (packet.type === "http_request") {
        void handleRequest(root, packet, getAttachmentInbox).then(result => send(result)).catch(() => send(errorResponse(packet, 500, "preview request failed")));
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

let parsed;
try {
  parsed = parseArgs({
    args: process.argv.slice(2),
    options: {
      skill: { type: "boolean" },
      help: { type: "boolean", short: "h" }
    },
    allowPositionals: true
  });
} catch (cause) {
  process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "invalid arguments"}\n`);
  process.exit(1);
}

if (parsed.values.skill) {
  if (parsed.positionals.length > 0) { process.stderr.write("Usage: npx letmeknow-cli --skill\n"); process.exit(1); }
  writeSync(1, readFileSync(new URL("../SKILL.md", import.meta.url)));
} else if (parsed.values.help) {
  process.stdout.write("Usage: npx letmeknow-cli <directory>\n\nServe a folder through the hosted LetMeKnow relay. The CLI does not listen on a network port. Form submissions are JSON lines on stdout.\n");
} else if (parsed.positionals.length !== 1) {
  process.stderr.write("letmeknow: exactly one directory must be provided\n");
  process.exit(1);
} else {
  try { await start(parsed.positionals[0]); } catch (cause) { process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "server failed"}\n`); process.exitCode = 1; }
}
