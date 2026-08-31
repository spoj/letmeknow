#!/usr/bin/env node

import { createReadStream, createWriteStream, existsSync, readFileSync, readdirSync, writeSync } from "node:fs";
import { chmod, mkdir, realpath, rename, rm, stat, unlink, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import net from "node:net";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { parseArgs } from "node:util";
import { lookup } from "mrmime";

const MAX_BODY_BYTES = 1024 * 1024;
const MAX_SCRIPT_BYTES = MAX_BODY_BYTES;
const MAX_UNIQUE_SUBMISSIONS = 100_000;
const MAX_RETAINED_SUBMISSION_BYTES = 256 * 1024 * 1024;
const MAX_PACKET_BYTES = 6 * MAX_BODY_BYTES + 4096;
const CONTROL_MAX_BYTES = MAX_PACKET_BYTES;
const RECONNECT_RETRY_SECONDS = 10 * 60;
const CONNECTION_TIMEOUT = 10_000;
const CONTROL_TIMEOUT = 35_000;
const STREAM_SHUTDOWN_TIMEOUT = 2_000;
const CONTROL_PREFIX = "letmeknow-control-";
const CONTROL_URL = "https://letmeknow.dev";
const credentialPattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const privateNames = new Set([".env", ".git", ".ssh", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"]);
const privateFilePattern = /^\.env\.|\.(?:key|pem|p12|ppk|p8|sqlite|sqlite3|db|db3)$|-(?:wal|shm|journal)$/i;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const hashPattern = /^[0-9a-f]{64}$/;

function getMimeType(filename) {
  const type = lookup(filename);
  if (!type) return "application/octet-stream";
  return type.startsWith("text/") || type === "application/json" || type === "application/xml" || type === "application/manifest+json"
    ? `${type}; charset=utf-8`
    : type;
}

function deniedPath(pathname) {
  return pathname.split("/").filter(Boolean).some(part => privateNames.has(part) || privateFilePattern.test(part));
}

function safeWorkspacePath(pathname) {
  return pathname && !pathname.startsWith("/") && !pathname.includes("\\") && !pathname.includes("\0") && !deniedPath(pathname) && pathname.split("/").every(part => part !== "" && part !== "." && part !== "..");
}

async function hashFile(filename) {
  const digest = createHash("sha256");
  let size = 0;
  for await (const chunk of createReadStream(filename)) {
    size += chunk.byteLength;
    digest.update(chunk);
  }
  return { hash: digest.digest("hex"), size };
}

async function scanWorkspace(root) {
  const files = {};
  const paths = new Map();
  let index;
  const visit = async (directory, prefix) => {
    const entries = readdirSync(directory, { withFileTypes: true });
    for (const entry of entries) {
      const pathname = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (!safeWorkspacePath(pathname)) {
        if (entry.isDirectory() && deniedPath(pathname)) continue;
        if (entry.name === "." || entry.name === "..") continue;
        throw new Error(`invalid workspace path: ${pathname}`);
      }
      const filename = join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(filename, pathname);
        continue;
      }
      if (!entry.isFile()) throw new Error(`workspace file is not regular: ${pathname}`);
      const infoBefore = await stat(filename);
      const file = { ...(await hashFile(filename)), content_type: getMimeType(pathname) };
      const infoAfter = await stat(filename);
      if (infoAfter.size !== infoBefore.size || file.size !== infoAfter.size) throw new Error(`workspace file changed while being read: ${pathname}`);
      paths.set(file.hash, { filename, size: file.size });
      if (pathname === "index.html") index = { ...file, filename };
      else files[pathname] = { hash: file.hash, size: file.size, content_type: file.content_type };
    }
  };
  await visit(root, "");
  if (!index) throw new Error("index.html is required");
  return { index, files, paths };
}

function controlPath(root) {
  const key = createHash("sha256").update(root).digest("hex").slice(0, 32);
  return join(tmpdir(), `${CONTROL_PREFIX}${key}.sock`);
}

async function removeStaleControlSocket(path) {
  if (!existsSync(path)) return;
  await new Promise(resolve => {
    const probe = net.createConnection(path);
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      probe.destroy();
      resolve();
    };
    probe.once("connect", finish);
    probe.once("error", cause => {
      if (cause?.code === "ECONNREFUSED" || cause?.code === "ENOENT") void unlink(path).then(finish, finish);
      else finish();
    });
  });
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
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(controlPath(root));
    let output = "";
    let settled = false;
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("control request timed out"));
    }, CONTROL_TIMEOUT);
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
  const root = await realpath(resolve(directory));
  const sessionDirectory = join(tmpdir(), `letmeknow-${randomUUID()}`);
  const eventsDirectory = join(sessionDirectory, "events");
  const attachmentsDirectory = join(sessionDirectory, "attachments");
  await mkdir(eventsDirectory, { recursive: true, mode: 0o700 });
  const socketPath = controlPath(root);
  await removeStaleControlSocket(socketPath);

  let controlServer;
  let socket;
  let credential;
  let resolveCredential;
  const credentialReady = new Promise(resolve => { resolveCredential = resolve; });
  let sessionUrl;
  let resolveProvision;
  const provisionReady = new Promise(resolve => { resolveProvision = resolve; });
  let ready = false;
  let stopped = false;
  let retryTimer;
  let connectionTimer;
  let retryDelay = 100;
  let retryUntil = 0;
  let streamFailure;
  let streamWrite = Promise.resolve();
  const streamBeforeReady = [];
  const mutate = mutateQueue();
  const pending = new Map();
  let lastEventIdentity;
  const eventFiles = new Map();
  let receivedThrough = 0;
  let retainedSubmissionBytes = 0;
  let submissionCount = 0;
  let publication = Promise.resolve();
  let stop = async () => {};

  const writeStream = value => {
    if (!ready) {
      streamBeforeReady.push(value);
      return Promise.resolve();
    }
    const pendingWrite = streamWrite.then(() => {
      if (streamFailure) throw streamFailure;
      return new Promise((resolveWrite, rejectWrite) => {
        try { process.stdout.write(`${JSON.stringify(value)}\n`, cause => cause ? rejectWrite(cause) : resolveWrite()); }
        catch (cause) { rejectWrite(cause); }
      });
    });
    streamWrite = pendingWrite.then(undefined, cause => { streamFailure ??= cause; throw cause; });
    streamWrite.catch(() => {});
    return pendingWrite;
  };

  process.stdout.once("error", cause => {
    streamFailure ??= cause;
    void stop(1);
  });

  const sendPacket = packet => {
    if (!socket || socket.readyState !== WebSocket.OPEN || stopped) return false;
    try { socket.send(JSON.stringify(packet)); return true; } catch { return false; }
  };

  const request = (packet, expected) => {
    const id = packet.id || packet.request_id || randomUUID();
    packet = { ...packet, id };
    return new Promise((resolveRequest, rejectRequest) => {
      pending.set(id, { expected, resolve: resolveRequest, reject: rejectRequest });
      if (!sendPacket(packet)) {
        pending.delete(id);
        rejectRequest(new Error("producer is not connected"));
      }
    });
  };

  const rejectPending = cause => {
    for (const { reject } of pending.values()) reject(cause);
    pending.clear();
  };

  const eventIdentity = event => createHash("sha256").update(JSON.stringify(event)).digest("hex");

  const materializeAttachments = async event => {
    if (!Array.isArray(event.attachments) || event.attachments.length === 0) return { event, attachmentBytes: 0, directory: undefined };
    let attachmentBytes = 0;
    for (const attachment of event.attachments) {
      if (!attachment || typeof attachment !== "object" || typeof attachment.field !== "string" || typeof attachment.name !== "string" || typeof attachment.content_type !== "string" || !hashPattern.test(attachment.hash) || !Number.isSafeInteger(attachment.size) || attachment.size < 0) throw new Error("invalid attachment metadata");
      attachmentBytes += attachment.size;
    }
    if (retainedSubmissionBytes + Buffer.byteLength(JSON.stringify(event)) + attachmentBytes > MAX_RETAINED_SUBMISSION_BYTES) throw new Error("local event storage limit exceeded");
    const directory = join(attachmentsDirectory, String(event.event_number).padStart(12, "0"));
    const persisted = [];
    try {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      for (const [index, attachment] of event.attachments.entries()) {
        const path = join(directory, String(index));
        const temporaryPath = `${path}.tmp-${randomUUID()}`;
        const response = await fetch(new URL(`_letmeknow/attachments/${attachment.hash}`, sessionUrl), { headers: { Authorization: `Bearer ${credential}` } });
        if (response.status !== 200 || !response.body) throw new Error("attachment download failed");
        const digest = createHash("sha256");
        let size = 0;
        const output = createWriteStream(temporaryPath, { mode: 0o600, flags: "wx" });
        try {
          for await (const chunk of response.body) {
            size += chunk.byteLength;
            if (size > attachment.size) throw new Error("attachment size is invalid");
            digest.update(chunk);
            await new Promise((resolve, reject) => {
              const onError = cause => reject(cause);
              output.once("error", onError);
              output.write(chunk, cause => {
                output.off("error", onError);
                if (cause) reject(cause); else resolve();
              });
            });
          }
          await new Promise((resolve, reject) => { output.end(cause => cause ? reject(cause) : resolve()); });
        } catch (cause) {
          output.destroy();
          await unlink(temporaryPath).catch(() => {});
          throw cause;
        }
        if (size !== attachment.size || digest.digest("hex") !== attachment.hash) {
          await unlink(temporaryPath).catch(() => {});
          throw new Error("attachment content is invalid");
        }
        await rename(temporaryPath, path);
        persisted.push({ ...attachment, path });
      }
      const persistedEvent = { ...event, attachments: persisted };
      if (retainedSubmissionBytes + Buffer.byteLength(JSON.stringify(persistedEvent)) + attachmentBytes > MAX_RETAINED_SUBMISSION_BYTES) throw new Error("local event storage limit exceeded");
      return { event: persistedEvent, attachmentBytes, directory };
    } catch (cause) {
      await rm(directory, { recursive: true, force: true });
      throw cause;
    }
  };

  const publish = event => {
    const next = publication.then(async () => {
      if (event.type === "submit") {
        await writeStream({ type: "submit", event_number: event.event_number, id: event.id, event_path: event.event_path });
      } else {
        await writeStream({ type: "run_ui", event_number: event.event_number, considered_through: event.considered_through, frontier: event.frontier, page_event: event.page_event, page_hash: event.page_hash });
      }
    });
    publication = next;
    next.catch(() => { void stop(1); });
    return next;
  };

  const persistEvent = async event => {
    if (!Number.isSafeInteger(event.event_number) || event.event_number < 1) throw new Error("event sequence is invalid");
    const identity = eventIdentity(event);
    if (event.event_number <= receivedThrough) {
      if (event.event_number !== receivedThrough || lastEventIdentity !== identity) throw new Error("event number was reused");
      sendPacket({ type: "event_ack", event_number: event.event_number });
      return;
    }
    if (event.event_number !== receivedThrough + 1) throw new Error("event sequence is invalid");
    let eventPath;
    let attachmentDirectory;
    let bytes = 0;
    if (event.type === "submit") {
      if (submissionCount >= MAX_UNIQUE_SUBMISSIONS) throw new Error("local event storage limit exceeded");
      const materialized = await materializeAttachments(event);
      event = materialized.event;
      attachmentDirectory = materialized.directory;
      eventPath = join(eventsDirectory, `${String(event.event_number).padStart(12, "0")}.json`);
      event = { ...event, event_path: eventPath };
      const serialized = JSON.stringify(event);
      bytes = Buffer.byteLength(serialized) + materialized.attachmentBytes;
      const temporaryPath = `${eventPath}.tmp-${randomUUID()}`;
      try {
        await writeFile(temporaryPath, serialized, { mode: 0o600 });
        await rename(temporaryPath, eventPath);
      } catch (cause) {
        await unlink(temporaryPath).catch(() => {});
        if (attachmentDirectory) await rm(attachmentDirectory, { recursive: true, force: true });
        throw cause;
      }
      retainedSubmissionBytes += bytes;
      submissionCount += 1;
    } else if (event.type !== "run_ui") {
      throw new Error("invalid event type");
    }
    const published = publish(event);
    lastEventIdentity = identity;
    receivedThrough = event.event_number;
    if (event.type === "submit") eventFiles.set(event.id, { event_number: event.event_number, event_path: eventPath, attachment_directory: attachmentDirectory, bytes, published });
    sendPacket({ type: "event_ack", event_number: event.event_number });
  };

  const cleanupEvents = async ids => {
    if (!Array.isArray(ids)) return;
    for (const id of ids) {
      const record = eventFiles.get(id);
      if (!record) continue;
      try {
        await record.published;
        await unlink(record.event_path).catch(cause => { if (cause?.code !== "ENOENT") throw cause; });
        if (record.attachment_directory) await rm(record.attachment_directory, { recursive: true, force: true });
        eventFiles.delete(id);
        retainedSubmissionBytes -= record.bytes;
        submissionCount -= 1;
      } catch (cause) {
        process.stderr.write(`letmeknow: could not remove event file ${record.event_path}: ${cause instanceof Error ? cause.message : "cleanup failed"}\n`);
      }
    }
  };

  const scanAndUpload = async snapshot => {
    const hashes = Object.values(snapshot.files).map(file => ({ hash: file.hash, size: file.size }));
    const result = await request({ type: "workspace_manifest", hashes, index: { hash: snapshot.index.hash, size: snapshot.index.size } }, "workspace_manifest");
    for (const item of result.missing) {
      const file = snapshot.paths.get(item.hash);
      if (!file || file.size !== item.size) throw new Error("workspace snapshot is inconsistent");
      const uploadUrl = new URL(`_letmeknow/workspace/${item.hash}`, sessionUrl);
      const response = await fetch(uploadUrl, { method: "PUT", headers: { Authorization: `Bearer ${credential}`, "Content-Length": String(file.size) }, body: createReadStream(file.filename), duplex: "half" });
      if (!response.ok) throw new Error(`workspace upload failed: ${response.status}`);
    }
  };

  const commitWorkspace = async (through, script) => {
    if (!ready || !socket || socket.readyState !== WebSocket.OPEN) throw new Error("serve is not connected");
    const snapshot = await scanWorkspace(root);
    await scanAndUpload(snapshot);
    const packet = {
      type: "commit",
      request_id: randomUUID(),
      through,
      index_hash: snapshot.index.hash,
      index_size: snapshot.index.size,
      manifest: { files: snapshot.files },
      ...(script === undefined ? {} : { script })
    };
    const result = await request(packet, "committed");
    await cleanupEvents(result.events);
    return result;
  };

  const dispatchControl = requestPacket => {
    if (!requestPacket || typeof requestPacket !== "object" || requestPacket.type !== "commit") return { ok: false, error: "unknown control request" };
    if (!Number.isSafeInteger(requestPacket.through) || requestPacket.through < 0) return { ok: false, error: "through must be a non-negative safe integer" };
    if (requestPacket.script !== undefined && (typeof requestPacket.script !== "string" || Buffer.byteLength(requestPacket.script, "utf8") > MAX_SCRIPT_BYTES)) return { ok: false, error: "script is too large" };
    return commitWorkspace(requestPacket.through, requestPacket.script);
  };

  controlServer = net.createServer(connection => {
    connection.setEncoding("utf8");
    let input = "";
    let handled = false;
    connection.on("data", async chunk => {
      input += chunk;
      if (handled) return;
      if (Buffer.byteLength(input, "utf8") > CONTROL_MAX_BYTES) {
        handled = true;
        connection.end(JSON.stringify({ ok: false, error: "control request is too large" }) + "\n");
        return;
      }
      const newline = input.indexOf("\n");
      if (newline < 0) return;
      handled = true;
      let result;
      try { result = await mutate(() => dispatchControl(JSON.parse(input.slice(0, newline)))); }
      catch (cause) { result = { ok: false, error: cause instanceof Error ? cause.message : "control request failed" }; }
      connection.end(JSON.stringify(await result) + "\n");
    });
  });

  let controlListening = false;
  await new Promise((resolveListen, rejectListen) => {
    controlServer.once("error", rejectListen);
    controlServer.listen(socketPath, async () => {
      controlListening = true;
      try { await chmod(socketPath, 0o600); } catch (cause) { controlServer.close(() => rejectListen(cause)); return; }
      controlServer.off("error", rejectListen);
      resolveListen();
    });
  }).catch(async cause => {
    if (controlListening) await unlink(socketPath).catch(() => {});
    await rm(sessionDirectory, { recursive: true, force: true }).catch(() => {});
    throw new Error(`cannot start local control channel: ${cause.message}`);
  });

  const initialize = async () => {
    await credentialReady;
    await provisionReady;
    const snapshot = await scanWorkspace(root);
    await scanAndUpload(snapshot);
    const session = await request({ type: "open", index_hash: snapshot.index.hash, index_size: snapshot.index.size, manifest: { files: snapshot.files } }, "session");
    if (!session.url) throw new Error("session URL is missing");
  };

  const handlePacket = packet => {
    if (typeof packet.id === "string" && pending.has(packet.id)) {
      const waiter = pending.get(packet.id);
      if (packet.type === "error") {
        pending.delete(packet.id);
        waiter.reject(new Error(packet.message || "producer request failed"));
        return;
      }
      if (packet.type === waiter.expected) {
        pending.delete(packet.id);
        waiter.resolve(packet);
      }
    }
    if (packet.type === "credential") {
      if (typeof packet.credential !== "string" || !credentialPattern.test(packet.credential)) return void stop(1);
      credential = packet.credential;
      resolveCredential(packet.credential);
    } else if (packet.type === "provisioned") {
      if (!validSessionUrl(packet.url)) return void stop(1);
      sessionUrl = packet.url;
      resolveProvision(packet.url);
    } else if (packet.type === "session") {
      if (!validSessionUrl(packet.url)) return void stop(1);
      sessionUrl = packet.url;
      if (!ready) {
        ready = true;
        void writeStream({ type: "ready", url: sessionUrl, session_path: sessionDirectory, frontier: packet.frontier, page_event: packet.page_event, page_hash: packet.page_hash });
        for (const value of streamBeforeReady) void writeStream(value);
        streamBeforeReady.length = 0;
      }
    } else if (packet.type === "submit" || packet.type === "run_ui") {
      receiptChain = receiptChain.then(() => persistEvent(packet)).catch(cause => { void stop(1); throw cause; });
    } else if (packet.type === "closed") {
      void stop(0);
    } else if (packet.type === "error" && typeof packet.message === "string") {
      void stop(1);
    }
  };

  let receiptChain = Promise.resolve();

  stop = async code => {
    if (stopped) return;
    stopped = true;
    clearTimeout(retryTimer);
    clearTimeout(connectionTimer);
    rejectPending(new Error("serve stopped"));
    try { socket?.close(); } catch {}
    await new Promise(resolveClose => controlServer.close(() => resolveClose()));
    await unlink(socketPath).catch(() => {});
    await Promise.race([streamWrite.catch(() => {}), new Promise(resolveTimeout => setTimeout(resolveTimeout, STREAM_SHUTDOWN_TIMEOUT))]);
    await rm(sessionDirectory, { recursive: true, force: true }).catch(() => {});
    process.exit(code);
  };

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
      if (!reconnecting) void initialize().catch(cause => { process.stderr.write(`letmeknow: ${cause.message}\n`); void stop(1); });
    });
    current.addEventListener("message", event => {
      if (typeof event.data !== "string") return;
      let packet;
      try { packet = JSON.parse(event.data); } catch { return; }
      handlePacket(packet);
    });
    current.addEventListener("error", () => {});
    current.addEventListener("close", () => {
      if (socket !== current || stopped) return;
      clearTimeout(connectionTimer);
      socket = undefined;
      rejectPending(new Error("producer connection closed"));
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

function readScriptInput(filename) {
  if (filename === "-") return readFileSync(0, "utf8");
  return readFileSync(resolve(filename), "utf8");
}

function usage() {
  return "Usage:\n  npx letmeknow serve <directory>\n  npx letmeknow commit <directory> --through <event-number> [--script <file|->]\n";
}

function commandArgs() {
  let parsed;
  try {
    parsed = parseArgs({ args: process.argv.slice(2), options: { skill: { type: "boolean" }, help: { type: "boolean", short: "h" }, through: { type: "string" }, script: { type: "string" } }, allowPositionals: true, strict: true });
  } catch (cause) { throw new Error(cause instanceof Error ? cause.message : "invalid arguments"); }
  if (parsed.values.skill || parsed.values.help) {
    if (parsed.positionals.length || parsed.values.through !== undefined || parsed.values.script !== undefined) throw new Error(usage());
    return { command: parsed.values.skill ? "skill" : "help" };
  }
  const [command, directory, ...extra] = parsed.positionals;
  if (!command || !directory || extra.length) throw new Error(usage());
  if (!["serve", "commit"].includes(command)) throw new Error(usage());
  if (command === "serve" && (parsed.values.through !== undefined || parsed.values.script !== undefined)) throw new Error(usage());
  if (command === "commit" && typeof parsed.values.through !== "string") throw new Error("--through is required");
  let through;
  if (command === "commit") {
    if (!/^\d+$/.test(parsed.values.through)) throw new Error("--through must be a non-negative safe integer");
    through = Number(parsed.values.through);
    if (!Number.isSafeInteger(through)) throw new Error("--through must be a non-negative safe integer");
  }
  return { command, directory, through, script: parsed.values.script };
}

let command;
try {
  command = commandArgs();
  if (command.command === "skill") writeSync(1, readFileSync(new URL("../SKILL.md", import.meta.url)));
  else if (command.command === "help") process.stdout.write(usage());
  else if (command.command === "serve") await start(command.directory);
  else {
    const result = await connectControl(await realpath(resolve(command.directory)), { type: "commit", through: command.through, ...(command.script === undefined ? {} : { script: readScriptInput(command.script) }) });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    if (!result.ok) process.exitCode = 1;
  }
} catch (cause) {
  process.stderr.write(`letmeknow: ${cause instanceof Error ? cause.message : "command failed"}\n`);
  process.exitCode = 1;
}
