import { DurableObject } from "cloudflare:workers";

interface Env {
  SESSIONS: DurableObjectNamespace<Session>;
  CREATE_RATE_LIMIT: RateLimitBinding;
}

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

type Packet = Record<string, unknown>;
type StoredResource = {
  status: number;
  headers: Record<string, string[]>;
  encoding: "utf8" | "base64";
  body: string;
  bytes: number;
};
type PendingRequest = {
  resolve(response: Response): void;
  timer: ReturnType<typeof setTimeout>;
  head: boolean;
};
type Attachment = {
  url: string;
  opened: boolean;
  closing: boolean;
};

const CODE_LENGTH = 20;
const GRACE_MS = 10 * 60 * 1_000;
const OPEN_DEADLINE_MS = 30 * 1_000;
const REQUEST_TIMEOUT_MS = 30 * 1_000;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_RESOURCES = 100;
const MAX_STORED_BYTES = 10 * 1024 * 1024;
const MAX_DYNAMIC_REQUESTS = 32;
const encoder = new TextEncoder();

function error(message: string, status: number): Response {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

function token(length = CODE_LENGTH): string {
  let value = "";
  while (value.length < length) value += crypto.randomUUID().replaceAll("-", "");
  return value.slice(0, length);
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bodyBytes(packet: Packet): Uint8Array {
  const body = packet.body ?? "";
  const encoding = packet.encoding ?? "utf8";
  if (typeof body !== "string") throw new Error("body must be a string");
  if (encoding !== "utf8" && encoding !== "base64") throw new Error("encoding must be utf8 or base64");
  let bytes: Uint8Array;
  try {
    bytes = encoding === "base64" ? base64ToBytes(body) : encoder.encode(body);
  } catch {
    throw new Error("body is not valid base64");
  }
  if (bytes.byteLength > MAX_BODY_BYTES) throw new Error("body is too large");
  return bytes;
}

async function requestBody(request: Request, timeoutMs = REQUEST_TIMEOUT_MS): Promise<Uint8Array> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null && Number.isFinite(Number(contentLength)) && Number(contentLength) > MAX_BODY_BYTES) {
    throw new Error("request body is too large");
  }
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let length = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let readerCancelled = false;
  let cancellationError: Error | undefined;
  let rejectCancellation!: (cause: Error) => void;
  const cancellation = new Promise<never>((_, reject) => {
    rejectCancellation = reject;
  });
  const cancelReader = (reason: string): void => {
    if (readerCancelled) return;
    readerCancelled = true;
    void reader.cancel(reason).catch(() => {});
  };
  const cancel = (message: string): void => {
    if (cancellationError) return;
    cancellationError = new Error(message);
    rejectCancellation(cancellationError);
    cancelReader(message);
  };
  const onAbort = (): void => cancel("request body cancelled");
  timer = setTimeout(() => cancel("request body timed out"), timeoutMs);
  request.signal.addEventListener("abort", onAbort, { once: true });
  if (request.signal.aborted) onAbort();
  try {
    while (true) {
      const result = await Promise.race([cancellation, reader.read()]);
      if (cancellationError) throw cancellationError;
      const { done, value } = result;
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY_BYTES) {
        cancelReader("request body is too large");
        throw new Error("request body is too large");
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    request.signal.removeEventListener("abort", onAbort);
  }
}

function responseData(packet: Packet): StoredResource {
  const status = packet.status ?? 200;
  if (typeof status !== "number" || !Number.isInteger(status) || status < 200 || status > 599 || status === 101) {
    throw new Error("status must be an integer from 200 through 599 other than 101");
  }
  const input = packet.headers ?? {};
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("headers must be an object");
  const headers: Record<string, string[]> = {};
  for (const [name, value] of Object.entries(input)) {
    const values = typeof value === "string"
      ? [value]
      : Array.isArray(value) && value.every((item) => typeof item === "string")
        ? value
        : null;
    if (!values) throw new Error("header values must be strings or string arrays");
    const normalizedName = name.toLowerCase();
    for (const item of values) new Headers([[name, item]]);
    headers[normalizedName] = [...(headers[normalizedName] ?? []), ...values];
  }
  if (packet.content_type !== undefined) {
    if (typeof packet.content_type !== "string") throw new Error("content_type must be a string");
    new Headers([["content-type", packet.content_type]]);
    headers["content-type"] = [packet.content_type];
  }
  const encoding = packet.encoding ?? "utf8";
  const bytes = bodyBytes(packet);
  if (!headers["cache-control"]?.length) headers["cache-control"] = ["no-store"];
  return {
    status,
    headers,
    encoding: encoding as "utf8" | "base64",
    body: (packet.body ?? "") as string,
    bytes: bytes.byteLength
  };
}

function toResponse(resource: StoredResource, head = false): Response {
  const bytes = resource.encoding === "base64" ? base64ToBytes(resource.body) : encoder.encode(resource.body);
  const headers = new Headers();
  for (const [name, values] of Object.entries(resource.headers)) {
    for (const value of values) headers.append(name, value);
  }
  const bodyless = head || resource.status === 204 || resource.status === 205 || resource.status === 304;
  return new Response(bodyless ? null : bytes, { status: resource.status, headers });
}

function isProductionHost(hostname: string): boolean {
  return hostname === "letmeknow.dev" || new RegExp(`^[a-f0-9]{${CODE_LENGTH}}\\.letmeknow\\.dev$`).test(hostname);
}

function publicTarget(url: URL): { code: string; path: string } | null {
  const host = url.hostname.match(new RegExp(`^([a-f0-9]{${CODE_LENGTH}})\\.letmeknow\\.dev$`));
  if (host) return { code: host[1], path: url.pathname };
  const path = url.pathname.match(new RegExp(`^/s/([a-f0-9]{${CODE_LENGTH}})(/.*)?$`));
  if (!path || url.hostname === "letmeknow.dev") return null;
  return { code: path[1], path: path[2] || "/" };
}

function sessionUrl(url: URL, code: string): string {
  return url.hostname === "letmeknow.dev"
    ? `https://${code}.letmeknow.dev/`
    : `${url.origin}/s/${code}/`;
}

function requestHeaders(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of headers) {
    if (name === "host" || name === "content-length" || name.startsWith("cf-") || name.startsWith("x-letmeknow-")) continue;
    result[name] = value;
  }
  return result;
}

function isTextBody(contentType: string | null): boolean {
  if (!contentType) return false;
  const mediaType = contentType.split(";", 1)[0].trim().toLowerCase();
  return mediaType.startsWith("text/")
    || mediaType === "application/json"
    || mediaType.endsWith("+json")
    || mediaType === "application/xml"
    || mediaType.endsWith("+xml")
    || mediaType === "application/javascript"
    || mediaType === "application/x-javascript"
    || mediaType === "application/x-www-form-urlencoded";
}

function textBody(bytes: Uint8Array, contentType: string | null): string | null {
  if (!isTextBody(contentType)) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

export class Session extends DurableObject<Env> {
  private pending = new Map<string, PendingRequest>();
  private activeRequests = 0;

  async fetch(request: Request): Promise<Response> {
    const action = request.headers.get("x-letmeknow-action");
    if (action === "connect") return this.acceptProducer(request);
    if (action === "browser") return this.browserRequest(request);
    return error("not found", 404);
  }

  private async acceptProducer(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);

    const credential = request.headers.get("x-letmeknow-credential");
    const protocol = request.headers.get("sec-websocket-protocol");
    const storedCredential = await this.ctx.storage.get<string>("credential");
    const opened = await this.ctx.storage.get<boolean>("opened") ?? false;
    const reconnectRequested = request.headers.get("x-letmeknow-reconnect") === "true";
    const reconnect = storedCredential !== undefined;
    if (reconnectRequested) {
      if (!reconnect || credential !== storedCredential || protocol !== credential) return error("invalid producer credential", 401);
    } else {
      if (reconnect || !credential || protocol !== null) return error("producer credential is required", 401);
      await this.ctx.storage.put("credential", credential);
    }
    if (this.ctx.getWebSockets().length > 0) return error("a producer is already connected", 409);

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const attachment: Attachment = {
      url: request.headers.get("x-letmeknow-url")!,
      opened: reconnect && opened,
      closing: false
    };
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server);
    if (reconnect && opened) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Date.now() + OPEN_DEADLINE_MS);
    if (!reconnect) server.send(JSON.stringify({ type: "credential", credential }));
    if (reconnect && opened) {
      server.send(JSON.stringify({
        type: "session",
        url: attachment.url,
        expires_after_disconnect: GRACE_MS / 1000
      }));
    }
    return new Response(null, {
      status: 101,
      webSocket: client,
      ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {})
    });
  }

  private async browserRequest(request: Request, requestBodyTimeoutMs = REQUEST_TIMEOUT_MS): Promise<Response> {
    const opened = await this.ctx.storage.get<boolean>("opened");
    if (!opened) return error("session not found", 404);

    const path = request.headers.get("x-letmeknow-path")!;
    const stored = await this.ctx.storage.get<StoredResource>(`resource:${path}`);
    if (stored) return toResponse(stored, request.method === "HEAD");

    const producer = this.ctx.getWebSockets().find((socket) => (socket.deserializeAttachment() as Attachment).opened);
    if (!producer) return error("producer disconnected", 503);
    if (this.activeRequests >= MAX_DYNAMIC_REQUESTS) return error("too many pending requests", 503);
    this.activeRequests++;

    let bytes: Uint8Array;
    try {
      bytes = await requestBody(request, requestBodyTimeoutMs);
    } catch (cause) {
      this.activeRequests--;
      const message = cause instanceof Error ? cause.message : "request body could not be read";
      const status = message === "request body is too large" ? 413 : message === "request body timed out" ? 408 : 400;
      return error(message, status);
    }

    const activeProducer = this.ctx.getWebSockets().find((socket) => (socket.deserializeAttachment() as Attachment).opened);
    if (!activeProducer) {
      this.activeRequests--;
      return error("producer disconnected", 503);
    }

    const text = textBody(bytes, request.headers.get("content-type"));
    const url = new URL(request.url);
    const id = crypto.randomUUID();
    const response = new Promise<Response>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.activeRequests--;
        resolve(error("producer response timed out", 504));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, timer, head: request.method === "HEAD" });
    });
    try {
      activeProducer.send(JSON.stringify({
        type: "request",
        id,
        method: request.method,
        path,
        query: url.search.slice(1),
        headers: requestHeaders(request.headers),
        encoding: text !== null ? "utf8" : "base64",
        body: text !== null ? text : bytesToBase64(bytes)
      }));
    } catch {
      const pending = this.pending.get(id);
      if (pending) {
        clearTimeout(pending.timer);
        this.pending.delete(id);
      }
      this.activeRequests--;
      return error("producer disconnected", 503);
    }

    return response;
  }

  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    let packet: Packet | undefined;
    try {
      if (typeof message !== "string") throw new Error("packets must be text");
      let value: unknown;
      try {
        value = JSON.parse(message);
      } catch {
        throw new Error("invalid JSON");
      }
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("packet must be a JSON object");
      packet = value as Packet;
      await this.command(socket, packet);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "invalid packet";
      const id = packet?.id;
      try {
        socket.send(JSON.stringify({ type: "error", ...(typeof id === "string" ? { id } : {}), message }));
      } catch {
        // The producer may have closed while this packet was being handled.
      }
    }
  }

  private async command(socket: WebSocket, packet: Packet): Promise<void> {
    if (typeof packet.type !== "string") throw new Error("type is required");
    if (packet.id !== undefined && typeof packet.id !== "string") throw new Error("id must be a string");
    const attachment = socket.deserializeAttachment() as Attachment;
    if (attachment.closing) throw new Error("session is closing");

    if (packet.type === "open") {
      await this.ctx.storage.transaction(async (txn) => {
        if (await txn.get<boolean>("expired") || !(await txn.get<string>("credential"))) throw new Error("session expired");
        await txn.put("opened", true);
      });
      attachment.opened = true;
      socket.serializeAttachment(attachment);
      await this.ctx.storage.deleteAlarm();
      socket.send(JSON.stringify({
        type: "session",
        ...(packet.id !== undefined ? { id: packet.id } : {}),
        url: attachment.url,
        expires_after_disconnect: GRACE_MS / 1000
      }));
      return;
    }
    if (!attachment.opened) throw new Error("open must be the first command");

    if (packet.type === "put") {
      const path = this.packetPath(packet);
      const resource = responseData(packet);
      await this.ctx.storage.transaction(async (txn) => {
        const previous = await txn.get<StoredResource>(`resource:${path}`);
        const count = await txn.get<number>("resourceCount") ?? 0;
        const bytes = await txn.get<number>("resourceBytes") ?? 0;
        const nextCount = count + (previous ? 0 : 1);
        const nextBytes = bytes - (previous?.bytes ?? 0) + resource.bytes;
        if (nextCount > MAX_RESOURCES) throw new Error("too many stored resources");
        if (nextBytes > MAX_STORED_BYTES) throw new Error("stored resources are too large");
        await txn.put(`resource:${path}`, resource);
        await txn.put({ resourceCount: nextCount, resourceBytes: nextBytes });
      });
      this.ack(socket, packet);
      return;
    }
    if (packet.type === "delete") {
      const path = this.packetPath(packet);
      await this.ctx.storage.transaction(async (txn) => {
        const previous = await txn.get<StoredResource>(`resource:${path}`);
        if (previous) {
          const count = await txn.get<number>("resourceCount") ?? 0;
          const bytes = await txn.get<number>("resourceBytes") ?? 0;
          await txn.delete(`resource:${path}`);
          await txn.put({ resourceCount: count - 1, resourceBytes: bytes - previous.bytes });
        }
      });
      this.ack(socket, packet);
      return;
    }
    if (packet.type === "response") {
      if (typeof packet.request_id !== "string") throw new Error("request_id is required");
      const pending = this.pending.get(packet.request_id);
      if (!pending) throw new Error("request is not pending");
      const response = toResponse(responseData(packet), pending.head);
      clearTimeout(pending.timer);
      this.pending.delete(packet.request_id);
      this.activeRequests--;
      pending.resolve(response);
      this.ack(socket, packet);
      return;
    }
    if (packet.type === "close") {
      attachment.opened = false;
      attachment.closing = true;
      socket.serializeAttachment(attachment);
      this.ack(socket, packet);
      socket.send(JSON.stringify({ type: "closing" }));
      this.failPending("session closed");
      await this.ctx.storage.deleteAll();
      socket.close(1000, "session closed");
      return;
    }
    throw new Error("unknown command type");
  }

  private packetPath(packet: Packet): string {
    if (typeof packet.path !== "string" || !packet.path.startsWith("/") || packet.path.includes("?")) {
      throw new Error("path must be an absolute pathname without a query");
    }
    return packet.path;
  }

  private ack(socket: WebSocket, packet: Packet): void {
    socket.send(JSON.stringify({ type: "ack", ...(packet.id !== undefined ? { id: packet.id } : {}) }));
  }

  async webSocketClose(socket: WebSocket, code: number, reason: string): Promise<void> {
    socket.close(code, reason);
    const attachment = socket.deserializeAttachment() as Attachment;
    this.failPending("producer disconnected");
    if (attachment.opened && await this.ctx.storage.get<boolean>("opened")) {
      await this.ctx.storage.setAlarm(Date.now() + GRACE_MS);
    }
  }

  async webSocketError(socket: WebSocket, _error: unknown): Promise<void> {
    await this.webSocketClose(socket, 1011, "WebSocket error");
  }

  async alarm(): Promise<void> {
    const sockets = this.ctx.getWebSockets();
    for (const socket of sockets) {
      if (!(socket.deserializeAttachment() as Attachment).opened) socket.close(1000, "session expired");
    }
    if (sockets.some((socket) => (socket.deserializeAttachment() as Attachment).opened)) return;
    await this.ctx.storage.transaction(async (txn) => {
      await txn.put("expired", true);
    });
    this.failPending("session expired");
    await this.ctx.storage.deleteAll();
  }

  private failPending(message: string): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      this.activeRequests--;
      pending.resolve(error(message, 503));
    }
    this.pending.clear();
  }
}

function home(origin: string): Response {
  return new Response(`# LetMeKnow\n\nRun the NDJSON CLI transport from the repository:\n\n  npm install\n  LETMEKNOW_URL=${origin} ./bin/letmeknow.js\n\nSee https://github.com/spoj/letmeknow for setup. Write {"type":"open"} to stdin. Read protocol events from stdout.\n`, {
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.protocol === "http:" && isProductionHost(url.hostname)) {
      url.protocol = "https:";
      return new Response(null, { status: 308, headers: { Location: url.toString() } });
    }

    const target = publicTarget(url);
    if (target) {
      const headers = new Headers(request.headers);
      headers.set("x-letmeknow-action", "browser");
      headers.set("x-letmeknow-path", target.path);
      return env.SESSIONS.getByName(target.code).fetch(new Request(request, { headers }));
    }

    if (url.pathname === "/v1/connect") {
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
      const requestedCode = url.searchParams.get("code");
      if (requestedCode !== null && !new RegExp(`^[a-f0-9]{${CODE_LENGTH}}$`).test(requestedCode)) return error("invalid session code", 400);
      const reconnect = requestedCode !== null;
      if (url.searchParams.has("credential")) return error("invalid producer credentials", 401);
      const protocol = request.headers.get("sec-websocket-protocol");
      if (protocol && (protocol.includes(",") || protocol.trim() !== protocol)) return error("invalid producer credentials", 401);
      if (reconnect ? !protocol : protocol !== null) return error("invalid producer credentials", 401);
      const credential = reconnect ? protocol : token(CODE_LENGTH * 2);
      if (!reconnect) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        if (!(await env.CREATE_RATE_LIMIT.limit({ key: ip })).success) return error("too many sessions", 429);
      }
      const code = requestedCode || token();
      const producerCredential = credential || token(CODE_LENGTH * 2);
      const headers = new Headers(request.headers);
      headers.set("x-letmeknow-action", "connect");
      headers.set("x-letmeknow-url", sessionUrl(url, code));
      headers.set("x-letmeknow-credential", producerCredential);
      if (reconnect) headers.set("x-letmeknow-reconnect", "true");
      return env.SESSIONS.getByName(code).fetch(new Request(request, { headers }));
    }

    if (url.pathname === "/" && request.method === "GET") return home(url.origin);
    return error("not found", 404);
  }
};
