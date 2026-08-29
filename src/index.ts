import { DurableObject } from "cloudflare:workers";
import clientSource from "./client";

interface Env {
  SESSIONS: DurableObjectNamespace<Session>;
  CREATE_RATE_LIMIT: RateLimitBinding;
}

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

type Packet = Record<string, unknown>;
type ProducerAttachment = { role: "producer"; url: string; opened: boolean; closing: boolean };
type ClientAttachment = { role: "client" };
type Attachment = ProducerAttachment | ClientAttachment;
type PendingProxy = { resolve(response: Response): void; timer: ReturnType<typeof setTimeout> };

const CODE_LENGTH = 20;
const PRODUCER_GRACE_MS = 10 * 60 * 1_000;
const OPEN_DEADLINE_MS = 30 * 1_000;
const MAX_BODY_BYTES = 1024 * 1024;
const PROXY_TIMEOUT_MS = 30 * 1_000;
const encoder = new TextEncoder();
const hopHeaders = new Set(["connection", "host", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "x-forwarded-host", "x-letmeknow-path", "x-letmeknow-route"]);
const runtimePath = "/_letmeknow/client.js";
const clientSocketPath = "/_letmeknow/client";

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
  if (!Number.isInteger(packet.status) || (packet.status as number) < 200 || (packet.status as number) > 599) throw new Error("invalid proxy response status");
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
  const match = hostname.match(new RegExp(`^([a-f0-9]{${CODE_LENGTH}})\\.letmeknow\\.dev$`));
  return match ? { code: match[1], path: url.pathname } : null;
}

function sessionUrl(url: URL, code: string): string {
  return `https://${code}.letmeknow.dev/`;
}

function runtimeTag(): string {
  return `<script type="module" src="${runtimePath}" data-letmeknow-runtime></script>`;
}

function runtimePage(title: string, message: string, status: number): Response {
  const body = `<!doctype html><html data-letmeknow-status-page><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1><p>${message}</p>${runtimeTag()}</body></html>`;
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
  });
}

function isDocumentRequest(request: Request): boolean {
  if (request.method !== "GET") return false;
  const destination = request.headers.get("sec-fetch-dest");
  if (destination !== null) return destination === "document";
  const accept = request.headers.get("accept");
  return accept === null || accept.includes("text/html");
}

function injectRuntime(response: Response, request: Request): Response {
  if (!isDocumentRequest(request) || response.status === 204 || response.status === 205 || response.status === 304) return response;
  const contentType = response.headers.get("content-type") || "";
  if (!contentType.toLowerCase().startsWith("text/html")) return response;
  const headers = new Headers(response.headers);
  headers.delete("content-length");
  const rewriter = new HTMLRewriter();
  let hasBody = false;
  rewriter.on("body", { element(element) { hasBody = true; element.append(runtimeTag(), { html: true }); } });
  rewriter.onDocument({ end(document) { if (!hasBody) document.append(runtimeTag(), { html: true }); } });
  return rewriter.transform(new Response(response.body, { status: response.status, statusText: response.statusText, headers }));
}

export class Session extends DurableObject<Env> {
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
    try { return await operation(); } finally { release(); }
  }

  private producer(): WebSocket | undefined {
    return this.ctx.getWebSockets().find((socket) => (socket.deserializeAttachment() as Attachment).role === "producer");
  }

  private clients(): WebSocket[] {
    return this.ctx.getWebSockets().filter((socket) => (socket.deserializeAttachment() as Attachment).role === "client");
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
    const attachment: ProducerAttachment = { role: "producer", url: request.headers.get("x-letmeknow-url")!, opened: reconnect && opened, closing: false };
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server);
    if (reconnect && opened) await this.ctx.storage.deleteAlarm();
    else await this.ctx.storage.setAlarm(Date.now() + OPEN_DEADLINE_MS);
    if (!reconnect) server.send(JSON.stringify({ type: "credential", credential }));
    if (reconnect && opened) {
      server.send(JSON.stringify({ type: "session", url: attachment.url, expires_after_disconnect: PRODUCER_GRACE_MS / 1000 }));
      this.sendClients({ type: "producer", connected: true });
    }
    return new Response(null, { status: 101, webSocket: client, ...(protocol ? { headers: { "Sec-WebSocket-Protocol": protocol } } : {}) });
  }

  private async acceptClient(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
    const opened = await this.ctx.storage.get<boolean>("opened");
    if (!opened) return error("session not found", 404);
    if (request.headers.get("Sec-WebSocket-Protocol")) return error("client credentials are not supported", 400);
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({ role: "client" } satisfies ClientAttachment);
    this.ctx.acceptWebSocket(server);
    server.send(JSON.stringify({ type: "connected", producer_connected: Boolean(this.producer()) }));
    return new Response(null, { status: 101, webSocket: client });
  }

  private async browserRequest(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() === "websocket") return error("websockets are not supported", 426);
    if (!(await this.ctx.storage.get<boolean>("opened"))) return isDocumentRequest(request) ? runtimePage("Session not found", "This preview is not available yet.", 404) : error("session not found", 404);
    if (!this.producer()) return isDocumentRequest(request) ? runtimePage("Connection lost", "Waiting for the preview producer to reconnect…", 503) : error("producer disconnected", 503);
    const response = await this.proxyRequest(request);
    return request.headers.get("x-letmeknow-submission") === "1" ? response : injectRuntime(response, request);
  }

  private async proxyRequest(request: Request): Promise<Response> {
    const producer = this.producer();
    if (!producer) return runtimePage("Connection lost", "Waiting for the preview producer to reconnect…", 503);
    const contentLength = request.headers.get("content-length");
    if (contentLength !== null && /^\d+$/.test(contentLength) && BigInt(contentLength) > BigInt(MAX_BODY_BYTES)) return error("request body is too large", 413);
    const reader = request.body?.getReader();
    const chunks: Uint8Array[] = [];
    let bodyLength = 0;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (bodyLength + value.byteLength > MAX_BODY_BYTES) {
          await reader.cancel();
          return error("request body is too large", 413);
        }
        chunks.push(value);
        bodyLength += value.byteLength;
      }
    }
    const body = new Uint8Array(bodyLength);
    let bodyOffset = 0;
    for (const chunk of chunks) { body.set(chunk, bodyOffset); bodyOffset += chunk.byteLength; }
    const headers: Record<string, string> = {};
    for (const [name, value] of request.headers) if (!hopHeaders.has(name)) headers[name] = value;
    const id = crypto.randomUUID();
    const response = new Promise<Response>((resolve) => {
      const timer = setTimeout(() => { this.pendingProxy.delete(id); resolve(error("producer request timed out", 504)); }, PROXY_TIMEOUT_MS);
      this.pendingProxy.set(id, { resolve, timer });
    });
    try {
      producer.send(JSON.stringify({ type: "http_request", request_id: id, method: request.method, path: request.headers.get("x-letmeknow-path")!, headers, body: bytesToBase64(body) }));
    } catch {
      const pending = this.pendingProxy.get(id);
      if (pending) { clearTimeout(pending.timer); this.pendingProxy.delete(id); pending.resolve(error("producer disconnected", 503)); }
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
  }

  private async producerMessage(socket: WebSocket, attachment: ProducerAttachment, message: string | ArrayBuffer): Promise<void> {
    let packet: Packet | undefined;
    try {
      packet = this.parseMessage(message);
      await this.mutate(() => this.producerCommand(socket, attachment, packet!));
    } catch (cause) {
      const text = cause instanceof Error ? cause.message : "invalid packet";
      try { socket.send(JSON.stringify({ type: "error", ...(typeof packet?.id === "string" ? { id: packet.id } : {}), message: text })); } catch {}
    }
  }

  private parseMessage(message: string | ArrayBuffer, maxBytes = MAX_BODY_BYTES * 2 + 4096): Packet {
    if (typeof message !== "string") throw new Error("packets must be text");
    if (encoder.encode(message).byteLength > maxBytes) throw new Error("packet is too large");
    let value: unknown;
    try { value = JSON.parse(message); } catch { throw new Error("invalid JSON"); }
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
      socket.send(JSON.stringify({ type: "session", ...(packet.id !== undefined ? { id: packet.id } : {}), url: attachment.url, expires_after_disconnect: PRODUCER_GRACE_MS / 1000 }));
      return;
    }
    if (!attachment.opened) throw new Error("open must be the first command");
    if (packet.type === "http_response") {
      if (typeof packet.request_id !== "string") throw new Error("request_id is required");
      const pending = this.pendingProxy.get(packet.request_id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pendingProxy.delete(packet.request_id);
      try { pending.resolve(proxyResponse(packet)); } catch { pending.resolve(error("invalid proxy response", 502)); }
      return;
    }
    if (packet.type === "revision") {
      this.sendClients({ type: "revision" });
      return;
    }
    if (packet.type === "close") {
      attachment.closing = true;
      socket.serializeAttachment(attachment);
      this.sendClients({ type: "closed", message: "Session closed" });
      for (const client of this.clients()) client.close(1000, "session closed");
      await this.ctx.storage.deleteAll();
      socket.close(1000, "session closed");
      return;
    }
    throw new Error("unknown command type");
  }

  private sendClients(packet: Packet): void {
    const message = JSON.stringify(packet);
    for (const client of this.clients()) try { client.send(message); } catch {}
  }

  async webSocketClose(socket: WebSocket, code: number, reason: string): Promise<void> {
    const attachment = socket.deserializeAttachment() as Attachment;
    await this.mutate(async () => {
      if (attachment.role === "producer") {
        const active = this.producer();
        if (active && active !== socket) return;
        this.failProxyRequests();
        this.sendClients({ type: "producer", connected: false });
        if (attachment.opened && await this.ctx.storage.get<boolean>("opened")) await this.ctx.storage.setAlarm(Date.now() + PRODUCER_GRACE_MS);
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
      this.sendClients({ type: "closed", message: "Session expired" });
      for (const client of this.clients()) client.close(1000, "session expired");
      producer?.close(1000, "session expired");
      await this.ctx.storage.deleteAll();
    });
  }
}

function home(): Response {
  return new Response(`# LetMeKnow\n\nRun a live preview for an agent-managed folder:\n\n  npx letmeknow-cli ./workspace\n\nThe CLI connects to this service outbound and prints the preview URL and form submissions as JSON lines.\n`, { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
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
      if (target.path === clientSocketPath) headers.set("x-letmeknow-route", "client");
      else if (target.path === runtimePath && request.method === "GET") return new Response(clientSource, { headers: { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" } });
      else {
        headers.set("x-letmeknow-route", "browser");
        headers.set("x-letmeknow-path", target.path + url.search);
      }
      return env.SESSIONS.getByName(target.code).fetch(new Request(request, { headers }));
    }
    if (url.pathname === "/v2/connect") {
      if (normalizedHostname(url.hostname) !== "letmeknow.dev") return error("not found", 404);
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return error("websocket upgrade required", 426);
      const requestedCode = url.searchParams.get("code");
      if (requestedCode !== null && !new RegExp(`^[a-f0-9]{${CODE_LENGTH}}$`).test(requestedCode)) return error("invalid session code", 400);
      const reconnect = requestedCode !== null;
      if (url.searchParams.has("credential")) return error("invalid producer credentials", 401);
      const protocol = request.headers.get("sec-websocket-protocol");
      if (protocol && (protocol.includes(",") || protocol.trim() !== protocol)) return error("invalid producer credentials", 401);
      if (reconnect ? !protocol : protocol !== null) return error("invalid producer credentials", 401);
      if (!reconnect) {
        const ip = request.headers.get("cf-connecting-ip") || "unknown";
        if (!(await env.CREATE_RATE_LIMIT.limit({ key: ip })).success) return error("too many sessions", 429);
      }
      const code = requestedCode || token();
      const producerCredential = reconnect ? protocol! : token(CODE_LENGTH * 2);
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
