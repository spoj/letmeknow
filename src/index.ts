import { DurableObject } from "cloudflare:workers";

interface Env {
  SESSIONS: DurableObjectNamespace<Session>;
  CREATE_RATE_LIMIT: RateLimitBinding;
}

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

type Packet = Record<string, unknown>;
type ProducerAttachment = { role: "producer"; url: string; opened: boolean; closing: boolean };
type ClientAttachment = { role: "client"; probedAt: number };
type CandidateAttachment = { role: "candidate" };
type Attachment = ProducerAttachment | ClientAttachment | CandidateAttachment;
type PendingProxy = { resolve(response: Response): void; timer: ReturnType<typeof setTimeout> };
type Probe = {
  socket: WebSocket;
  nonce: string;
  promise: Promise<boolean>;
  timer?: ReturnType<typeof setTimeout>;
  settle(active: boolean): void;
};

const CODE_LENGTH = 20;
const PRODUCER_GRACE_MS = 10 * 60 * 1_000;
const CLIENT_GRACE_MS = 5 * 1_000;
const OPEN_DEADLINE_MS = 30 * 1_000;
const CHALLENGE_TIMEOUT_MS = 2 * 1_000;
const MAX_BODY_BYTES = 1024 * 1024;
const PROXY_TIMEOUT_MS = 30 * 1_000;
const encoder = new TextEncoder();
const hopHeaders = new Set(["connection", "host", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "x-forwarded-host", "x-letmeknow-path", "x-letmeknow-route"]);

function error(message: string, status: number): Response {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

function token(length = CODE_LENGTH): string {
  let value = "";
  while (value.length < length) value += crypto.randomUUID().replaceAll("-", "");
  return value.slice(0, length);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToBase64(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function proxyResponse(packet: Packet): Response {
  if (!Number.isInteger(packet.status) || (packet.status as number) < 200 || (packet.status as number) > 599) {
    throw new Error("invalid proxy response status");
  }
  if (typeof packet.body !== "string") throw new Error("proxy response body is required");
  const body = base64ToBytes(packet.body);
  if (body.byteLength > MAX_BODY_BYTES) throw new Error("proxy response body is too large");
  if (!packet.headers || typeof packet.headers !== "object" || Array.isArray(packet.headers)) throw new Error("proxy response headers are required");
  const headers = new Headers();
  for (const [name, value] of Object.entries(packet.headers)) {
    if (hopHeaders.has(name.toLowerCase())) continue;
    if (typeof value !== "string") throw new Error("proxy response headers must be strings");
    headers.set(name, value);
  }
  const empty = packet.status === 204 || packet.status === 205 || packet.status === 304;
  return new Response(empty ? null : body, { status: packet.status as number, headers });
}

function normalizedHostname(hostname: string): string {
  return hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
}

function isProductionHost(hostname: string): boolean {
  hostname = normalizedHostname(hostname);
  return hostname === "letmeknow.dev" || hostname.endsWith(".letmeknow.dev");
}

function publicTarget(url: URL): { code: string; path: string } | null {
  const hostname = normalizedHostname(url.hostname);
  const host = hostname.match(new RegExp(`^([a-f0-9]{${CODE_LENGTH}})\\.letmeknow\\.dev$`));
  if (host) return { code: host[1], path: url.pathname };
  const path = url.pathname.match(new RegExp(`^/s/([a-f0-9]{${CODE_LENGTH}})(/.*)?$`));
  if (!path || (isProductionHost(url.hostname) && normalizedHostname(url.hostname) !== "letmeknow.dev")) return null;
  return { code: path[1], path: path[2] || "/" };
}

function sessionUrl(url: URL, code: string): string {
  return normalizedHostname(url.hostname) === "letmeknow.dev"
    ? `https://${code}.letmeknow.dev/`
    : `${url.origin}/s/${code}/`;
}

export class Session extends DurableObject<Env> {
  private probe?: Probe;
  private stateMutation: Promise<void> = Promise.resolve();
  private readonly pendingProxy = new Map<string, PendingProxy>();

  async fetch(request: Request): Promise<Response> {
    const route = request.headers.get("x-letmeknow-route");
    if (route === "producer") return this.mutate(() => this.acceptProducer(request));
    if (route === "client") return this.mutate(() => this.acceptClient(request));
    if (route === "browser") return this.browserRequest(request);
    return error("not found", 404);
  }

  private async mutate<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.stateMutation;
    let release!: () => void;
    this.stateMutation = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  private producer(): WebSocket | undefined {
    return this.ctx.getWebSockets().find((socket) => (socket.deserializeAttachment() as Attachment).role === "producer");
  }

  private client(): WebSocket | undefined {
    return this.ctx.getWebSockets().find((socket) => (socket.deserializeAttachment() as Attachment).role === "client");
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
    if (this.producer()) return error("a producer is already connected", 409);

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const attachment: ProducerAttachment = {
      role: "producer",
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
      server.send(JSON.stringify({ type: "session", url: attachment.url, expires_after_disconnect: PRODUCER_GRACE_MS / 1000 }));
      this.sendClient({ type: "producer", connected: true });
    }
    return new Response(null, {
      status: 101,
      webSocket: client,
      ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {})
    });
  }

  private async challenge(socket: WebSocket): Promise<boolean> {
    const attachment = socket.deserializeAttachment() as ClientAttachment;
    if (Date.now() - attachment.probedAt < CLIENT_GRACE_MS) return true;
    if (this.probe?.socket === socket) return this.probe.promise;
    attachment.probedAt = Date.now();
    socket.serializeAttachment(attachment);
    const nonce = token(32);
    let resolvePromise!: (active: boolean) => void;
    const promise = new Promise<boolean>((resolve) => { resolvePromise = resolve; });
    const probe: Probe = {
      socket,
      nonce,
      promise,
      settle: (active): void => {
        if (this.probe !== probe) return;
        if (probe.timer) clearTimeout(probe.timer);
        this.probe = undefined;
        resolvePromise(active);
      }
    };
    probe.timer = setTimeout(() => probe.settle(false), CHALLENGE_TIMEOUT_MS);
    this.probe = probe;
    try {
      socket.send(JSON.stringify({ type: "challenge", nonce }));
    } catch {
      probe.settle(false);
    }
    return promise;
  }

  private busyClient(protocol: string | null, retryAfter: number): Response {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({ role: "candidate" } satisfies CandidateAttachment);
    this.ctx.acceptWebSocket(server);
    server.send(JSON.stringify({ type: "busy", retry_after: retryAfter }));
    server.close(4009, "session already open");
    return new Response(null, {
      status: 101,
      webSocket: client,
      ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {})
    });
  }

  private async acceptClient(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
    if (!(await this.ctx.storage.get<boolean>("opened"))) return error("session not found", 404);
    const protocol = request.headers.get("sec-websocket-protocol");
    if (protocol && (protocol.includes(",") || !/^[a-f0-9]{40}$/.test(protocol))) return error("invalid client credential", 401);

    const active = this.client();
    if (active && await this.challenge(active)) return this.busyClient(protocol, CLIENT_GRACE_MS / 1000);
    if (active) {
      active.close(4000, "connection lost");
      await this.ctx.storage.put("clientDisconnectedAt", Date.now());
    }

    const storedCredential = await this.ctx.storage.get<string>("clientCredential");
    const disconnectedAt = await this.ctx.storage.get<number>("clientDisconnectedAt") ?? 0;
    const reconnect = storedCredential !== undefined && protocol === storedCredential;
    if (!reconnect && storedCredential !== undefined && Date.now() - disconnectedAt < CLIENT_GRACE_MS) {
      return this.busyClient(protocol, Math.ceil((CLIENT_GRACE_MS - (Date.now() - disconnectedAt)) / 1000));
    }

    const credential = reconnect ? storedCredential : token(40);
    await this.ctx.storage.put("clientCredential", credential);
    await this.ctx.storage.delete("clientDisconnectedAt");
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({ role: "client", probedAt: Date.now() } satisfies ClientAttachment);
    this.ctx.acceptWebSocket(server);
    if (!reconnect) server.send(JSON.stringify({ type: "credential", credential }));
    server.send(JSON.stringify({ type: "connected", producer_connected: Boolean(this.producer()) }));
    return new Response(null, {
      status: 101,
      webSocket: client,
      ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {})
    });
  }

  private async browserRequest(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") return error("websockets are not supported", 426);
    if (!(await this.ctx.storage.get<boolean>("opened"))) return error("session not found", 404);
    return this.proxyRequest(request);
  }

  private async proxyRequest(request: Request): Promise<Response> {
    const producer = this.producer();
    if (!producer) return error("producer disconnected", 503);
    const body = new Uint8Array(await request.arrayBuffer());
    if (body.byteLength > MAX_BODY_BYTES) return error("request body is too large", 413);
    const headers: Record<string, string> = {};
    for (const [name, value] of request.headers) {
      if (!hopHeaders.has(name)) headers[name] = value;
    }
    const id = crypto.randomUUID();
    const response = new Promise<Response>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingProxy.delete(id);
        resolve(error("producer request timed out", 504));
      }, PROXY_TIMEOUT_MS);
      this.pendingProxy.set(id, { resolve, timer });
    });
    try {
      producer.send(JSON.stringify({
        type: "http_request",
        request_id: id,
        method: request.method,
        path: request.headers.get("x-letmeknow-path")!,
        headers,
        body: bytesToBase64(body)
      }));
    } catch {
      const pending = this.pendingProxy.get(id);
      if (pending) {
        clearTimeout(pending.timer);
        this.pendingProxy.delete(id);
        pending.resolve(error("producer disconnected", 503));
      }
    }
    return response;
  }

  private failProxyRequests(): void {
    for (const [id, pending] of this.pendingProxy) {
      clearTimeout(pending.timer);
      pending.resolve(error("producer disconnected", 503));
      this.pendingProxy.delete(id);
    }
  }

  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const attachment = socket.deserializeAttachment() as Attachment;
    if (attachment.role === "producer") return this.producerMessage(socket, attachment, message);
    if (attachment.role === "client") return this.clientMessage(socket, message);
  }

  private async producerMessage(socket: WebSocket, attachment: ProducerAttachment, message: string | ArrayBuffer): Promise<void> {
    let packet: Packet | undefined;
    try {
      packet = this.parseMessage(message);
      await this.mutate(() => this.producerCommand(socket, attachment, packet!));
    } catch (cause) {
      const text = cause instanceof Error ? cause.message : "invalid packet";
      try {
        socket.send(JSON.stringify({ type: "error", ...(typeof packet?.id === "string" ? { id: packet.id } : {}), message: text }));
      } catch {}
    }
  }

  private parseMessage(message: string | ArrayBuffer, maxBytes = MAX_BODY_BYTES * 2 + 4096): Packet {
    if (typeof message !== "string") throw new Error("packets must be text");
    if (encoder.encode(message).byteLength > maxBytes) throw new Error("packet is too large");
    let value: unknown;
    try {
      value = JSON.parse(message);
    } catch {
      throw new Error("invalid JSON");
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("packet must be a JSON object");
    return value as Packet;
  }

  private async producerCommand(socket: WebSocket, attachment: ProducerAttachment, packet: Packet): Promise<void> {
    if (typeof packet.type !== "string") throw new Error("type is required");
    if (packet.id !== undefined && typeof packet.id !== "string") throw new Error("id must be a string");
    if (attachment.closing) throw new Error("session is closing");

    if (packet.type === "open") {
      if (attachment.opened) throw new Error("open must be the first command");
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
        expires_after_disconnect: PRODUCER_GRACE_MS / 1000
      }));
      return;
    }
    if (!attachment.opened) throw new Error("open must be the first command");

    if (packet.type === "http_response") {
      if (typeof packet.request_id !== "string") throw new Error("request_id is required");
      const pending = this.pendingProxy.get(packet.request_id);
      if (!pending) throw new Error("proxy request is not pending");
      clearTimeout(pending.timer);
      this.pendingProxy.delete(packet.request_id);
      try {
        pending.resolve(proxyResponse(packet));
      } catch {
        pending.resolve(error("invalid proxy response", 502));
      }
      return;
    }
    if (packet.type === "file_update") {
      if (typeof packet.path !== "string" || !/^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-Fa-f]{2})*$/.test(packet.path)) throw new Error("invalid file update path");
      this.sendClient({ type: "file_update", path: packet.path });
      return;
    }
    throw new Error("unknown command type");
  }

  private async clientMessage(socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    try {
      const packet = this.parseMessage(message, 4096);
      if (packet.type !== "alive" || typeof packet.nonce !== "string") throw new Error("unknown client event");
      if (this.probe?.socket === socket && this.probe.nonce === packet.nonce) this.probe.settle(true);
    } catch (cause) {
      try {
        socket.send(JSON.stringify({ type: "error", message: cause instanceof Error ? cause.message : "invalid client event" }));
      } catch {}
    }
  }

  private sendClient(packet: Packet): void {
    try {
      this.client()?.send(JSON.stringify(packet));
    } catch {}
  }

  async webSocketClose(socket: WebSocket, code: number, reason: string): Promise<void> {
    const attachment = socket.deserializeAttachment() as Attachment;
    if (this.probe?.socket === socket) this.probe.settle(false);
    await this.mutate(async () => {
      if (attachment.role === "producer") {
        this.failProxyRequests();
        this.sendClient({ type: "producer", connected: false });
        if (attachment.opened && await this.ctx.storage.get<boolean>("opened")) {
          await this.ctx.storage.setAlarm(Date.now() + PRODUCER_GRACE_MS);
        }
      } else if (attachment.role === "client" && await this.ctx.storage.get<boolean>("opened")) {
        await this.ctx.storage.put("clientDisconnectedAt", Date.now());
      }
    });
    if (code === 1005 || code === 1006 || code === 1015) socket.close();
    else socket.close(code, reason);
  }

  async webSocketError(socket: WebSocket, _error: unknown): Promise<void> {
    await this.webSocketClose(socket, 1011, "WebSocket error");
  }

  async alarm(): Promise<void> {
    await this.mutate(async () => {
      const producer = this.producer();
      if (producer && (producer.deserializeAttachment() as ProducerAttachment).opened) return;
      this.failProxyRequests();
      this.sendClient({ type: "closed", message: "Session expired" });
      this.client()?.close(1000, "session expired");
      producer?.close(1000, "session expired");
      await this.ctx.storage.deleteAll();
    });
  }
}

function home(): Response {
  return new Response(`# LetMeKnow\n\nRun a live preview for an agent-managed folder:\n\n  npx letmeknow-cli ./workspace\n\nThe CLI connects to this service outbound and prints the preview URL and form submissions as JSON lines.\n`, {
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

    const slashlessSession = url.pathname.match(new RegExp(`^/s/[a-f0-9]{${CODE_LENGTH}}$`));
    if (slashlessSession && (!isProductionHost(url.hostname) || normalizedHostname(url.hostname) === "letmeknow.dev")) {
      url.pathname += "/";
      return new Response(null, { status: 308, headers: { Location: url.toString() } });
    }

    const target = publicTarget(url);
    if (target) {
      const headers = new Headers(request.headers);
      if (target.path === "/_letmeknow/client") {
        headers.set("x-letmeknow-route", "client");
      } else {
        headers.set("x-letmeknow-route", "browser");
        headers.set("x-letmeknow-path", target.path + url.search);
        const sessionBase = url.pathname.match(/^\/s\/[a-f0-9]{20}(?:\/|$)/)?.[0];
        if (sessionBase) headers.set("x-letmeknow-session-base", sessionBase.endsWith("/") ? sessionBase : `${sessionBase}/`);
      }
      return env.SESSIONS.getByName(target.code).fetch(new Request(request, { headers }));
    }

    if (url.pathname === "/v1/connect") {
      if (isProductionHost(url.hostname) && normalizedHostname(url.hostname) !== "letmeknow.dev") return error("not found", 404);
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
      headers.set("x-letmeknow-route", "producer");
      headers.set("x-letmeknow-url", sessionUrl(url, code));
      headers.set("x-letmeknow-credential", producerCredential);
      if (reconnect) headers.set("x-letmeknow-reconnect", "true");
      return env.SESSIONS.getByName(code).fetch(new Request(request, { headers }));
    }

    if (url.pathname === "/" && request.method === "GET") return home();
    return error("not found", 404);
  }
};
