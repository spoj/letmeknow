import { DurableObject } from "cloudflare:workers";

interface Env {
  GROUPS: DurableObjectNamespace<Group>;
  INVITES: DurableObjectNamespace<Invite>;
  BOXES: DurableObjectNamespace<Box>;
  ASSETS: Fetcher;
  WRITES: RateLimit;
}

type InviteState = { expires: number; owner: string; pake: string; join?: string; welcome?: string };

const ID = /^[0-9a-f]{32}$/;
const SLOT = /^[1-9][0-9]{0,2}$/;
const OWNER = /^[0-9a-f]{64}$/;
const RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_MESSAGE_BYTES = 1024 * 1024;
const PAGE_BYTES = 2 * MAX_MESSAGE_BYTES;
const MAX_INVITE_TTL_S = 24 * 60 * 60;
const MAX_PAKE_CHARS = 1024;
const MAX_WAIT_S = 30;
const COMMIT = 3;
const PRIVATE_MESSAGE = 2;

const ABOUT = `letmeknow: end-to-end encrypted group chat for agents and their people.
This relay stores MLS ciphertext for up to 7 days and holds no keys. People: open this address in a browser.

Agents: read the instructions with \`npx -y @letmeknow/cli@0.7 skill\`.
Source: https://github.com/spoj/letmeknow
`;

const INSTRUCTIONS = `This is a letmeknow invite into an end-to-end encrypted group chat. A person joins by opening this link in a browser; an agent as follows.

1. Read the instructions: npx -y @letmeknow/cli@0.7 skill
   (or, if letmeknow is installed: letmeknow skill)
2. Start your session (letmeknow listen) as they describe, then join with the complete link, including the part after '#':
   letmeknow join '<link>'

The link works once and expires within 10 minutes; a mistyped code also uses it up. If it failed, ask for a new one. The part after '#' is the secret code; it never reaches this server.
`;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const [kind, id, action] = url.pathname.split("/").slice(1);
    const page = request.method === "GET" && (url.pathname === "/" || (kind === "i" && SLOT.test(id ?? "") && action === undefined));
    if (page) {
      if (request.headers.get("Accept")?.includes("text/html")) return app(url);
      return new Response(url.pathname === "/" ? ABOUT : INSTRUCTIONS);
    }
    if (kind === "assets") return env.ASSETS.fetch(request);
    if (request.method !== "GET") {
      const { success } = await env.WRITES.limit({ key: request.headers.get("CF-Connecting-IP") ?? "" });
      if (!success) return text("too many writes from this address; try again in a minute", 429);
    }
    if (kind === "g" && ID.test(id ?? "")) return env.GROUPS.get(env.GROUPS.idFromName(id)).fetch(request);
    if (kind === "b" && ID.test(id ?? "")) return env.BOXES.get(env.BOXES.idFromName(id)).fetch(request);
    if (kind !== "i" || !SLOT.test(id ?? "")) return text("not found", 404);
    return env.INVITES.get(env.INVITES.idFromName(id)).fetch(request);
  }
};

// The browser client. Its code holds the member's keys, so it loads nothing but this origin's own scripts.
function app(url: URL): Response {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>letmeknow</title>
<link rel="stylesheet" href="/assets/app.css">
<script type="module" src="/assets/app.js"></script>
</head>
<body>
<main id="app"><pre id="agents">${escape(url.pathname === "/" ? ABOUT : INSTRUCTIONS)}</pre></main>
</body>
</html>
`;
  const host = url.host;
  const csp = [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    `connect-src 'self' wss://${host} ws://${host}`,
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'"
  ].join("; ");
  // no-transform: Cloudflare's proxy injects nothing (analytics beacon, email obfuscation) into a page holding keys.
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8", "Content-Security-Policy": csp, "Cache-Control": "no-cache, no-transform" }
  });
}

function escape(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

export class Group extends DurableObject<Env> {
  sql = this.ctx.storage.sql;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    this.sql.exec("CREATE TABLE IF NOT EXISTS messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, data BLOB NOT NULL)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS state (epoch INTEGER NOT NULL)");
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const [, , gid, action] = url.pathname.split("/");
    if (action === "ws") {
      if (request.headers.get("Upgrade") !== "websocket") return text("expected websocket", 426);
      const { 0: client, 1: server } = new WebSocketPair();
      this.ctx.acceptWebSocket(server);
      return new Response(null, { status: 101, webSocket: client });
    }
    if (action !== "messages") return text("not found", 404);
    if (request.method === "GET") {
      if (url.searchParams.has("wait")) return text("long-polling was removed; upgrade letmeknow", 410);
      return Response.json(page(this.sql, Number(url.searchParams.get("after") ?? 0)));
    }
    if (request.method !== "POST") return text("method not allowed", 405);

    const data = new Uint8Array(await request.arrayBuffer());
    if (data.length > MAX_MESSAGE_BYTES) return text("message too large (limit 1 MiB)", 413);
    let header: Header;
    try {
      header = parseHeader(data);
    } catch {
      return text("not an MLS private message", 400);
    }
    if (header.groupId !== gid) return text("group id mismatch", 400);
    const epoch = this.epoch();
    if (header.epoch !== epoch) return Response.json({ epoch }, { status: 409 });
    if (header.contentType === COMMIT) {
      this.sql.exec("DELETE FROM state");
      this.sql.exec("INSERT INTO state (epoch) VALUES (?)", epoch + 1);
    }
    const seq = this.sql.exec<{ seq: number }>(
      "INSERT INTO messages (at, data) VALUES (?, ?) RETURNING seq", Date.now(), data
    ).one().seq;
    for (const socket of this.ctx.getWebSockets()) socket.send(String(seq));
    if (await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(Date.now() + RETENTION_MS);
    return Response.json({ seq });
  }

  webSocketClose(socket: WebSocket) {
    socket.close();
  }

  async alarm() {
    this.sql.exec("DELETE FROM messages WHERE at <= ?", Date.now() - RETENTION_MS);
    const oldest = this.sql.exec<{ at: number }>("SELECT at FROM messages ORDER BY seq LIMIT 1").toArray()[0];
    if (oldest) await this.ctx.storage.setAlarm(oldest.at + RETENTION_MS);
  }

  private epoch(): number {
    return this.sql.exec<{ epoch: number }>("SELECT epoch FROM state").toArray()[0]?.epoch ?? 0;
  }

}

// A page stops before PAGE_BYTES, so a large backlog never has to fit in memory at once; clients fetch until a page is empty.
function page(sql: SqlStorage, after: number) {
  const rows: { seq: number; at: number; data: string }[] = [];
  let bytes = 0;
  for (const row of sql.exec<{ seq: number; at: number; data: ArrayBuffer }>("SELECT seq, at, data FROM messages WHERE seq > ? ORDER BY seq", after)) {
    bytes += row.data.byteLength;
    if (bytes > PAGE_BYTES) break;
    rows.push({ seq: row.seq, at: row.at, data: base64(new Uint8Array(row.data)) });
  }
  return rows;
}

// An append-only log of opaque entries, kept until deleted by nobody: entity lists, entity inboxes, join requests and
// their replies. Writers seal what they post; the order the relay gives is the order readers replay.
export class Box extends DurableObject<Env> {
  sql = this.ctx.storage.sql;
  waiters = new Set<() => void>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql.exec("CREATE TABLE IF NOT EXISTS messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, data BLOB NOT NULL)");
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === "GET") {
      const after = Number(url.searchParams.get("after") ?? 0);
      if (page(this.sql, after).length === 0) await wait(this.waiters, url);
      return Response.json(page(this.sql, after));
    }
    if (request.method !== "POST") return text("method not allowed", 405);
    const data = new Uint8Array(await request.arrayBuffer());
    if (data.length > MAX_MESSAGE_BYTES) return text("entry too large (limit 1 MiB)", 413);
    const seq = this.sql.exec<{ seq: number }>("INSERT INTO messages (at, data) VALUES (?, ?) RETURNING seq", Date.now(), data).one().seq;
    wake(this.waiters);
    return Response.json({ seq });
  }
}

export class Invite extends DurableObject<Env> {
  waiters = new Set<() => void>();

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const action = url.pathname.split("/")[3];
    // Read the body before any answer: workerd faults when a body forwarded from the Worker is still streaming in after the response.
    const body = request.method === "GET" ? "" : await request.text();
    let invite = await this.ctx.storage.get<InviteState>("invite");

    if (request.method === "PUT" && action === undefined) {
      if (invite && invite.expires > Date.now()) return text("invite exists", 409);
      const { ttl, owner, pake }: { ttl: unknown; owner: unknown; pake: unknown } = JSON.parse(body);
      if (!Number.isInteger(ttl) || (ttl as number) < 1 || (ttl as number) > MAX_INVITE_TTL_S) return text("bad ttl", 400);
      if (typeof owner !== "string" || !OWNER.test(owner)) return text("bad owner", 400);
      if (typeof pake !== "string" || pake.length > MAX_PAKE_CHARS) return text("bad pake", 400);
      const expires = Date.now() + (ttl as number) * 1000;
      await this.ctx.storage.put("invite", { expires, owner, pake });
      await this.ctx.storage.setAlarm(expires);
      return new Response(null, { status: 201 });
    }
    if (!invite || invite.expires <= Date.now()) return text("invite not found or expired", 404);

    if (request.method === "GET" && (action === "pake" || action === "join" || action === "welcome")) {
      if (!invite[action]) {
        await wait(this.waiters, url);
        invite = await this.ctx.storage.get<InviteState>("invite");
      }
      const data = invite?.[action];
      return data ? Response.json({ data }) : new Response(null, { status: 204 });
    }
    if (request.method !== "POST") return text("not found", 404);
    const { data }: { data: unknown } = JSON.parse(body);
    if (typeof data !== "string" || data.length > MAX_MESSAGE_BYTES) return text("bad data", 400);

    if (action === "join") {
      if (invite.join) return text("invite already used", 409);
      await this.ctx.storage.put("invite", { ...invite, join: data });
      wake(this.waiters);
      return new Response(null, { status: 204 });
    }
    if (action === "welcome") {
      if (request.headers.get("Authorization") !== `Bearer ${invite.owner}`) return text("forbidden", 403);
      if (!invite.join || invite.welcome) return text("no pending join", 409);
      await this.ctx.storage.put("invite", { ...invite, welcome: data });
      wake(this.waiters);
      return new Response(null, { status: 204 });
    }
    return text("not found", 404);
  }

  async alarm() {
    await this.ctx.storage.deleteAll();
    wake(this.waiters);
  }
}

// Long-poll: hold the request until wake() or `wait` seconds (max 30) pass.
function wait(waiters: Set<() => void>, url: URL): Promise<void> {
  const seconds = Math.min(Number(url.searchParams.get("wait") ?? 0) || 0, MAX_WAIT_S);
  if (seconds <= 0) return Promise.resolve();
  return new Promise(resolve => {
    const done = () => {
      clearTimeout(timer);
      waiters.delete(done);
      resolve();
    };
    const timer = setTimeout(done, seconds * 1000);
    waiters.add(done);
  });
}

function wake(waiters: Set<() => void>) {
  for (const done of [...waiters]) done();
}

type Header = { groupId: string; epoch: number; contentType: number };

// MLSMessage { version u16, wire_format u16, PrivateMessage { group_id<V>, epoch u64, content_type u8, ... } }
function parseHeader(data: Uint8Array): Header {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (view.getUint16(0) !== 1 || view.getUint16(2) !== PRIVATE_MESSAGE) throw new Error("wire format");
  let offset = 4;
  const prefix = data[offset] >> 6;
  if (prefix > 2) throw new Error("varint");
  const width = 1 << prefix;
  let length = data[offset] & 0x3f;
  for (let i = 1; i < width; i++) length = length * 256 + data[offset + i];
  offset += width;
  const groupId = new TextDecoder().decode(data.subarray(offset, offset + length));
  offset += length;
  const epoch = Number(view.getBigUint64(offset));
  const contentType = view.getUint8(offset + 8);
  return { groupId, epoch, contentType };
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function text(body: string, status: number): Response {
  return new Response(body, { status });
}
