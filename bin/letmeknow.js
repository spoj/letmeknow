#!/usr/bin/env node

import readline from "node:readline";

const control = new URL(process.env.LETMEKNOW_URL || "https://letmeknow.dev");
const graceSeconds = 10 * 60;
const connectionAttemptTimeout = 10_000;
const maxRetryDelay = 5_000;
let socket;
let input;
let credential;
let sessionUrl;
let retryTimer;
let connectionTimer;
let retryDelay = 100;
let stdinClosed = false;
let signalRequested = false;
let explicitSessionClosed = false;
let closeCommandAccepted = false;
let closeCommandSent = false;
let retryUntil = 0;
let connected = false;
let finished = false;
const queued = [];

function endpoint() {
  const url = new URL(control);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.pathname = "/v1/connect";
  url.search = "";
  url.hash = "";
  if (credential && sessionUrl) {
    const publicUrl = new URL(sessionUrl);
    const hostCode = publicUrl.hostname.match(/^([a-f0-9]{20})\.app\.letmeknow\.dev$/);
    const pathCode = publicUrl.pathname.match(/^\/s\/([a-f0-9]{20})(?:\/|$)/);
    const code = hostCode?.[1] || pathCode?.[1];
    if (code) {
      url.searchParams.set("code", code);
    }
  }
  return url;
}

function clearConnectionTimer() {
  if (connectionTimer) clearTimeout(connectionTimer);
  connectionTimer = undefined;
}

function finish(code) {
  if (finished) return;
  finished = true;
  if (retryTimer) clearTimeout(retryTimer);
  clearConnectionTimer();
  input?.close();
  process.exitCode = code;
}

function isCloseCommand(line) {
  try {
    const packet = JSON.parse(line);
    return packet !== null
      && typeof packet === "object"
      && !Array.isArray(packet)
      && packet.type === "close"
      && (packet.id === undefined || typeof packet.id === "string");
  } catch {
    return false;
  }
}

function send(line) {
  if (!socket || !connected || socket.readyState !== WebSocket.OPEN) return false;
  try {
    socket.send(line);
    if (isCloseCommand(line)) closeCommandSent = true;
    return true;
  } catch {
    try {
      socket.close();
    } catch {
      // The close event still determines whether reconnect is needed.
    }
    return false;
  }
}

function sendOrQueue(line) {
  if (finished || closeCommandAccepted) return;
  if (isCloseCommand(line)) closeCommandAccepted = true;
  if (!send(line)) queued.push(line);
}

function flush() {
  if (finished) return;
  while (queued.length && !closeCommandSent) {
    if (!send(queued[0])) break;
    queued.shift();
  }
  if (closeCommandSent) queued.length = 0;
  if (!queued.length && stdinClosed && !closeCommandSent && socket && connected) {
    socket.close(1000, "stdin closed");
  }
}

function protocolFailure(message) {
  if (finished) return;
  process.stderr.write(`letmeknow: server protocol error: ${message}\n`);
  const current = socket;
  if (current) {
    try {
      current.close(1000, "protocol error");
    } catch {
      // The process still exits below.
    }
  }
  finish(1);
}

function handleMessage(event) {
  if (finished) return;
  if (typeof event.data !== "string") {
    protocolFailure("binary WebSocket frame");
    return;
  }
  const text = event.data;
  let packet;
  try {
    packet = JSON.parse(text);
  } catch {
    protocolFailure("invalid JSON");
    return;
  }
  if (!packet || typeof packet !== "object" || Array.isArray(packet)) {
    protocolFailure("packet must be a JSON object");
    return;
  }
  if (typeof packet.type !== "string") {
    protocolFailure("packet type is required");
    return;
  }
  if (packet.type === "credential") {
    if (typeof packet.credential === "string") credential = packet.credential;
    return;
  }
  if (packet.type === "session") {
    if (typeof packet.url === "string") sessionUrl = packet.url;
    if (typeof packet.expires_after_disconnect === "number") retryDelay = 100;
  }
  if (packet.type === "closing") explicitSessionClosed = true;
  process.stdout.write(`${text}\n`);
}

function retry() {
  if (finished || signalRequested || explicitSessionClosed || closeCommandSent || (stdinClosed && !queued.length) || Date.now() >= retryUntil) {
    finish(explicitSessionClosed || signalRequested || closeCommandSent || (stdinClosed && !queued.length) ? 0 : 1);
    return;
  }
  retryTimer = setTimeout(() => {
    retryTimer = undefined;
    start();
  }, retryDelay);
  retryDelay = Math.min(retryDelay * 2, maxRetryDelay);
}

function start() {
  if (finished || signalRequested || explicitSessionClosed || closeCommandSent) return;
  const reconnecting = Boolean(credential && sessionUrl);
  const current = socket = reconnecting
    ? new WebSocket(endpoint(), credential)
    : new WebSocket(endpoint());
  connectionTimer = setTimeout(() => {
    if (socket !== current || connected || finished) return;
    clearConnectionTimer();
    process.stderr.write("letmeknow: WebSocket connection attempt timed out\n");
    try {
      current.close();
    } catch {
      // The close event is not available when construction failed.
    }
    socket = undefined;
    connected = false;
    if (reconnecting) retry();
    else finish(1);
  }, connectionAttemptTimeout);
  current.addEventListener("message", handleMessage);
  current.addEventListener("error", () => {
    if (!finished) process.stderr.write("letmeknow: WebSocket connection failed; retrying\n");
  });
  current.addEventListener("open", () => {
    if (socket !== current || finished) return;
    clearConnectionTimer();
    connected = true;
    retryDelay = 100;
    if (reconnecting) retryUntil = 0;
    flush();
  });
  current.addEventListener("close", (event) => {
    if (socket !== current) return;
    clearConnectionTimer();
    connected = false;
    if (finished) return;
    socket = undefined;
    if (closeCommandSent || signalRequested || explicitSessionClosed || (stdinClosed && !queued.length)) {
      finish(0);
      return;
    }
    if (!credential || !sessionUrl) {
      process.stderr.write(`letmeknow: connection closed (${event.code}${event.reason ? `: ${event.reason}` : ""})\n`);
      finish(1);
      return;
    }
    if (!retryUntil) retryUntil = Date.now() + graceSeconds * 1_000;
    retry();
  });
}

input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on("line", (line) => {
  if (!finished && line.trim() && !closeCommandAccepted) sendOrQueue(line);
});
input.on("close", () => {
  if (finished) return;
  stdinClosed = true;
  if (!socket) {
    if (!queued.length) finish(0);
    return;
  }
  if (connected) flush();
  else if (!queued.length) {
    const current = socket;
    clearConnectionTimer();
    try {
      current.close();
    } catch {
      // The process still exits below.
    }
    socket = undefined;
    finish(0);
  }
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    signalRequested = true;
    clearConnectionTimer();
    if (socket) {
      try {
        socket.close(1000, signal);
      } catch {
        // The process still exits below.
      }
    }
    finish(0);
  });
}

start();
