import { SELF, runDurableObjectAlarm } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { createHash, randomUUID } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

type Event = Record<string, any>;
type Peer = {
  socket: WebSocket;
  credential?: string;
  next(): Promise<Event>;
  send(packet: Event): void;
};
type WorkspaceFile = { data: Uint8Array; content_type: string };

const origin = "https://letmeknow.dev";
const SESSION_LIFETIME_MS = 24 * 60 * 60 * 1_000;
const MAX_BODY_BYTES = 1024 * 1024;
const sockets: WebSocket[] = [];
let ipCounter = 0;

function peer(socket: WebSocket): Peer {
  socket.accept();
  sockets.push(socket);
  const queued: Event[] = [];
  const waiting: Array<(event: Event) => void> = [];
  let credential: string | undefined;
  socket.addEventListener("message", message => {
    const event = JSON.parse(message.data as string) as Event;
    if (event.type === "credential") {
      credential = event.credential;
      return;
    }
    const resolve = waiting.shift();
    if (resolve) resolve(event);
    else queued.push(event);
  });
  return {
    socket,
    get credential() { return credential; },
    next: () => queued.length ? Promise.resolve(queued.shift()!) : new Promise(resolve => waiting.push(resolve)),
    send: packet => socket.send(JSON.stringify(packet))
  };
}

async function connectProducer(code?: string, credential?: string): Promise<Peer> {
  const endpoint = new URL(`${origin}/v2/connect`);
  if (code) endpoint.searchParams.set("code", code);
  const headers: Record<string, string> = { Upgrade: "websocket", "CF-Connecting-IP": `192.0.2.${++ipCounter}` };
  if (credential) headers["Sec-WebSocket-Protocol"] = credential;
  const response = await SELF.fetch(new Request(endpoint, { headers }));
  expect(response.status).toBe(101);
  return peer(response.webSocket!);
}

function digest(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

async function nextType(producer: Peer, type: string): Promise<Event> {
  while (true) {
    const event = await producer.next();
    if (event.type === type) return event;
  }
}

async function uploadWorkspace(producer: Peer, url: string, index: Uint8Array, files: Record<string, WorkspaceFile>): Promise<{ index_hash: string; index_size: number; manifest: Event }> {
  const index_hash = digest(index);
  const hashes = Object.entries(files).map(([path, file]) => ({ hash: digest(file.data), size: file.data.byteLength }));
  producer.send({ type: "workspace_manifest", id: randomUUID(), index: { hash: index_hash, size: index.byteLength }, hashes });
  const manifestResponse = await nextType(producer, "workspace_manifest");
  const blobs = new Map<string, Uint8Array>([[index_hash, index], ...Object.entries(files).map(([, file]) => [digest(file.data), file.data] as const)]);
  for (const item of manifestResponse.missing) {
    const response = await SELF.fetch(new Request(new URL(`_letmeknow/workspace/${item.hash}`, url), {
      method: "PUT",
      headers: { Authorization: `Bearer ${producer.credential}` },
      body: blobs.get(item.hash)
    }));
    if (response.status !== 204) console.log("UPLOAD", response.status, await response.text());
    expect(response.status).toBe(204);
  }
  const manifest = { files: Object.fromEntries(Object.entries(files).map(([path, file]) => [path, { hash: digest(file.data), size: file.data.byteLength, content_type: file.content_type }])) };
  return { index_hash, index_size: index.byteLength, manifest };
}

async function open(options: { index?: string; files?: Record<string, WorkspaceFile> } = {}): Promise<{ producer: Peer; url: string; workspace: Event }> {
  const producer = await connectProducer();
  const provisioned = await nextType(producer, "provisioned");
  const index = new TextEncoder().encode(options.index || "<!doctype html><html><body><main id=app>initial</main></body></html>");
  const files = options.files || { "app.js": { data: new TextEncoder().encode("initial"), content_type: "text/javascript" } };
  const workspace = await uploadWorkspace(producer, provisioned.url, index, files);
  producer.send({ type: "open", id: "open", ...workspace });
  const session = await nextType(producer, "session");
  expect(session).toMatchObject({ type: "session", id: "open", url: provisioned.url, frontier: 0, page_event: 0, workspace_version: 0 });
  return { producer, url: session.url, workspace };
}

async function uploadAttachment(producer: Peer, url: string, data: Uint8Array): Promise<{ hash: string; size: number }> {
  const hash = digest(data);
  const reservation = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ hashes: [{ hash, size: data.byteLength }] })
  }));
  expect(reservation.status).toBe(200);
  expect(await reservation.json()).toEqual({ missing: [{ hash, size: data.byteLength }] });
  const upload = await SELF.fetch(new Request(new URL(`_letmeknow/attachments/${hash}`, url), { method: "PUT", body: data }));
  expect(upload.status).toBe(204);
  return { hash, size: data.byteLength };
}

async function connectClient(url: string): Promise<Peer> {
  const response = await SELF.fetch(new Request(new URL("_letmeknow/client", url), { headers: { Upgrade: "websocket" } }));
  expect(response.status).toBe(101);
  return peer(response.webSocket!);
}

async function commit(producer: Peer, workspace: Event, through: number, script?: string): Promise<Event> {
  const id = randomUUID();
  producer.send({ type: "commit", id, request_id: id, through, ...workspace, ...(script === undefined ? {} : { script }) });
  return nextType(producer, "committed");
}

afterEach(() => {
  vi.useRealTimers();
  for (const socket of sockets.splice(0)) socket.close(1000, "test complete");
});

describe("LetMeKnow service", () => {
  it("creates a hosted session and serves its committed workspace", async () => {
    const { producer, url } = await open({ files: { "app.js": { data: new TextEncoder().encode("initial"), content_type: "text/javascript" } } });
    const page = await SELF.fetch(new Request(url));
    expect(page.status).toBe(200);
    expect(await page.text()).toContain("data-letmeknow-runtime");
    const asset = await SELF.fetch(new Request(new URL("app.js", url)));
    expect(asset.status).toBe(200);
    expect(await asset.text()).toBe("initial");
    producer.socket.close(1000, "done");
  });

  it("serves a workspace file named __proto__", async () => {
    const files = Object.fromEntries([["__proto__", { data: new TextEncoder().encode("prototype-safe"), content_type: "text/plain" }]]);
    const { producer, url } = await open({ files });
    const response = await SELF.fetch(new Request(new URL("__proto__", url)));
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("prototype-safe");
    producer.socket.close(1000, "done");
  });

  it("serves the pinned index and switches assets only on commit", async () => {
    const { producer, url, workspace } = await open({ index: "<!doctype html><html><body>original</body></html>", files: { "app.js": { data: new TextEncoder().encode("one"), content_type: "text/javascript" } } });
    expect(await (await SELF.fetch(new Request(new URL("app.js", url)))).text()).toBe("one");
    const nextData = new TextEncoder().encode("two");
    const next = await uploadWorkspace(producer, url, new TextEncoder().encode("<!doctype html><html><body>original</body></html>"), { "app.js": { data: nextData, content_type: "text/javascript" } });
    expect((await SELF.fetch(new Request(new URL("app.js", url)))).status).toBe(200);
    expect(await (await SELF.fetch(new Request(new URL("app.js", url)))).text()).toBe("one");
    await commit(producer, next, 0);
    expect(await (await SELF.fetch(new Request(new URL("app.js", url)))).text()).toBe("two");
    const changedIndex = await uploadWorkspace(producer, url, new TextEncoder().encode("<!doctype html><html><body>changed</body></html>"), { "app.js": { data: nextData, content_type: "text/javascript" } });
    producer.send({ type: "commit", id: randomUUID(), request_id: randomUUID(), through: 0, ...changedIndex });
    expect(await nextType(producer, "error")).toMatchObject({ message: "index.html cannot change during a session" });
    expect((await SELF.fetch(new Request(url))).status).toBe(200);
  });

  it("reserves browser attachments, delivers metadata, and allows producer downloads only", async () => {
    const { producer, url } = await open();
    const data = new TextEncoder().encode("attachment bytes");
    const attachment = await uploadAttachment(producer, url, data);
    const wrongData = new TextEncoder().encode("different bytes!");
    const wrongHash = digest(wrongData);
    const wrongReservation = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hashes: [{ hash: wrongHash, size: wrongData.byteLength }] })
    }));
    expect((await wrongReservation.json() as Event).missing).toEqual([{ hash: wrongHash, size: wrongData.byteLength }]);
    expect((await SELF.fetch(new Request(new URL(`_letmeknow/attachments/${wrongHash}`, url), { method: "PUT", body: data }))).status).toBe(400);
    const path = new URL(`_letmeknow/attachments/${attachment.hash}`, url);
    expect((await SELF.fetch(new Request(path))).status).toBe(401);
    expect((await SELF.fetch(new Request(path, { headers: { Authorization: "Bearer wrong" } }))).status).toBe(401);
    const download = await SELF.fetch(new Request(path, { headers: { Authorization: `Bearer ${producer.credential}` } }));
    expect(download.status).toBe(200);
    expect(new Uint8Array(await download.arrayBuffer())).toEqual(data);
    const id = randomUUID();
    const response = await SELF.fetch(new Request(new URL("_letmeknow/submit", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, page_event: 0, form_id: "review", action: "/review", trigger: null, values: { comment: "see it" }, attachments: [{ field: "evidence", name: "../../report.txt", content_type: "text/plain", ...attachment }] })
    }));
    expect(response.status).toBe(202);
    const event = await nextType(producer, "submit");
    expect(event.attachments).toEqual([{ field: "evidence", name: "../../report.txt", content_type: "text/plain", ...attachment }]);
    producer.send({ type: "event_ack", event_number: event.event_number });
  });

  it("deduplicates attachment reservations and rejects invalid references", async () => {
    const { producer, url } = await open();
    const data = new TextEncoder().encode("same");
    const hash = digest(data);
    const reserve = () => SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hashes: [{ hash, size: data.byteLength }, { hash, size: data.byteLength }] })
    }));
    expect(await (await reserve()).json()).toEqual({ missing: [{ hash, size: data.byteLength }] });
    expect(await (await reserve()).json()).toEqual({ missing: [{ hash, size: data.byteLength }] });
    expect((await SELF.fetch(new Request(new URL("_letmeknow/submit", url), {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: randomUUID(), page_event: 0, form_id: null, action: "/", trigger: null, values: {}, attachments: [{ field: "file", name: "file", content_type: "text/plain", hash, size: data.byteLength }] })
    }))).status).toBe(400);
    expect((await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hashes: [{ hash, size: data.byteLength + 1 }] })
    }))).status).toBe(400);
    expect((await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hashes: [{ hash: "invalid", size: 0 }] })
    }))).status).toBe(400);
    producer.socket.close(1000, "done");
  });

  it("rejects browser attachment reservations beyond the aggregate quota", async () => {
    const { producer, url } = await open();
    const first = "1".repeat(64);
    const second = "2".repeat(64);
    const response = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hashes: [{ hash: first, size: 100 * 1024 * 1024 }, { hash: second, size: 1 }] })
    }));
    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({ error: "session blob quota exceeded" });
    producer.socket.close(1000, "done");
  });

  it("bounds browser attachment records, including zero-byte reservations", async () => {
    const { producer, url } = await open();
    const hashes = Array.from({ length: 1024 }, (_, index) => index.toString(16).padStart(64, "0"));
    for (let index = 0; index < hashes.length; index += 32) {
      const response = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ hashes: hashes.slice(index, index + 32).map(hash => ({ hash, size: 0 })) })
      }));
      expect(response.status).toBe(200);
      expect((await response.json() as Event).missing).toHaveLength(32);
    }
    const overflow = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hashes: [{ hash: "f".repeat(64), size: 0 }] })
    }));
    expect(overflow.status).toBe(413);
    expect(await overflow.json()).toEqual({ error: "attachment object limit exceeded" });
    producer.socket.close(1000, "done");
  });

  it("shares a workspace object with a browser attachment", async () => {
    const data = new TextEncoder().encode("shared workspace bytes");
    const { producer, url, workspace } = await open({ files: { "shared.bin": { data, content_type: "text/plain" } } });
    const attachment = { hash: digest(data), size: data.byteLength };
    const reservation = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hashes: [attachment] })
    }));
    expect(await reservation.json()).toEqual({ missing: [] });
    const id = randomUUID();
    expect((await SELF.fetch(new Request(new URL("_letmeknow/submit", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, page_event: 0, form_id: null, action: "/", trigger: null, values: {}, attachments: [{ field: "file", name: "file", content_type: "text/plain", ...attachment }] })
    }))).status).toBe(202);
    const event = await nextType(producer, "submit");
    producer.send({ type: "event_ack", event_number: event.event_number });
    await commit(producer, workspace, event.event_number);
    expect(await (await SELF.fetch(new Request(new URL("shared.bin", url)))).text()).toBe("shared workspace bytes");
  });

  it("promotes a browser object when a workspace later uses the same hash", async () => {
    const { producer, url } = await open();
    const data = new TextEncoder().encode("browser workspace bytes");
    await uploadAttachment(producer, url, data);
    const next = await uploadWorkspace(producer, url, new TextEncoder().encode("<!doctype html><html><body><main id=app>initial</main></body></html>"), { "shared.bin": { data, content_type: "text/plain" } });
    await commit(producer, next, 0);
    expect(await (await SELF.fetch(new Request(new URL("shared.bin", url)))).text()).toBe("browser workspace bytes");
  });

  it("keeps an existing shared object when a workspace upload fails", async () => {
    const { producer, url } = await open();
    const data = new TextEncoder().encode("existing shared workspace bytes");
    const hash = digest(data);
    const reservation = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hashes: [{ hash, size: data.byteLength }] })
    }));
    expect(await reservation.json()).toEqual({ missing: [{ hash, size: data.byteLength }] });
    const code = new URL(url).hostname.split(".")[0];
    const uploads = (env as unknown as { UPLOADS: { put(key: string, value: Uint8Array, options: { sha256: string }): Promise<unknown>; get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer> } | null> } }).UPLOADS;
    const key = `sessions/${code}/objects/${hash}`;
    await uploads.put(key, data, { sha256: hash });
    await uploadWorkspace(producer, url, new TextEncoder().encode("<!doctype html><html><body><main id=app>initial</main></body></html>"), { "shared.bin": { data, content_type: "text/plain" } });
    const bad = new Uint8Array(data.length).fill(120);
    const failed = await SELF.fetch(new Request(new URL(`_letmeknow/workspace/${hash}`, url), {
      method: "PUT",
      headers: { Authorization: `Bearer ${producer.credential}` },
      body: bad
    }));
    expect(failed.status).toBe(503);
    expect(new Uint8Array(await (await uploads.get(key))!.arrayBuffer())).toEqual(data);
    producer.socket.close(1000, "done");
  });

  it("reclaims abandoned attachment reservations after their lease", async () => {
    const now = Date.now();
    vi.useFakeTimers({ now });
    const { producer, url } = await open();
    const size = 60 * 1024 * 1024;
    const first = "a".repeat(64);
    const second = "b".repeat(64);
    const reserve = (hash: string) => SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hashes: [{ hash, size }] })
    }));
    expect((await reserve(first)).status).toBe(200);
    vi.setSystemTime(now + 30 * 60 * 1_000 + 1);
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(new URL(url).hostname.split(".")[0]))).toBe(true);
    expect((await reserve(second)).status).toBe(200);
    producer.socket.close(1000, "done");
  });

  it("reclaims an expired shared object abandoned by workspace staging", async () => {
    const now = Date.now();
    vi.useFakeTimers({ now });
    const data = new TextEncoder().encode("abandoned shared workspace bytes");
    const replacement = new TextEncoder().encode("replacement workspace bytes");
    const { producer, url } = await open();
    await uploadAttachment(producer, url, data);
    await uploadWorkspace(producer, url, new TextEncoder().encode("<!doctype html><html><body><main id=app>initial</main></body></html>"), { "stale.bin": { data, content_type: "text/plain" } });
    await uploadWorkspace(producer, url, new TextEncoder().encode("<!doctype html><html><body><main id=app>initial</main></body></html>"), { "replacement.bin": { data: replacement, content_type: "text/plain" } });
    vi.setSystemTime(now + 30 * 60 * 1_000 + 1);
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(new URL(url).hostname.split(".")[0]))).toBe(true);
    const uploads = (env as unknown as { UPLOADS: { head(key: string): Promise<unknown> } }).UPLOADS;
    const code = new URL(url).hostname.split(".")[0];
    expect(await uploads.head(`sessions/${code}/objects/${digest(data)}`)).toBeNull();
    producer.socket.close(1000, "done");
  });

  it("renews an attachment lease after a successful upload", async () => {
    const now = Date.now();
    vi.useFakeTimers({ now });
    const { producer, url } = await open();
    const data = new TextEncoder().encode("browser attachment lease");
    const hash = digest(data);
    const reservation = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hashes: [{ hash, size: data.byteLength }] })
    }));
    expect(await reservation.json()).toEqual({ missing: [{ hash, size: data.byteLength }] });
    vi.setSystemTime(now + 10 * 60 * 1_000);
    expect((await SELF.fetch(new Request(new URL(`_letmeknow/attachments/${hash}`, url), { method: "PUT", body: data }))).status).toBe(204);
    vi.setSystemTime(now + 30 * 60 * 1_000 + 1);
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(new URL(url).hostname.split(".")[0]))).toBe(true);
    const uploads = (env as unknown as { UPLOADS: { head(key: string): Promise<unknown> } }).UPLOADS;
    const code = new URL(url).hostname.split(".")[0];
    expect(await uploads.head(`sessions/${code}/objects/${hash}`)).not.toBeNull();
    producer.socket.close(1000, "done");
  });

  it("accepts a submission after reconciling an existing object for an expired attachment lease", async () => {
    const now = Date.now();
    vi.useFakeTimers({ now });
    const { producer, url } = await open();
    const data = new TextEncoder().encode("reconciled expired attachment");
    const hash = digest(data);
    const reservation = await SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hashes: [{ hash, size: data.byteLength }] })
    }));
    expect(await reservation.json()).toEqual({ missing: [{ hash, size: data.byteLength }] });
    vi.setSystemTime(now + 30 * 60 * 1_000 + 1);
    const code = new URL(url).hostname.split(".")[0];
    const uploads = (env as unknown as { UPLOADS: { put(key: string, value: Uint8Array, options: { sha256: string }): Promise<unknown> } }).UPLOADS;
    await uploads.put(`sessions/${code}/objects/${hash}`, data, { sha256: hash });
    expect((await SELF.fetch(new Request(new URL(`_letmeknow/attachments/${hash}`, url), { method: "PUT", body: data }))).status).toBe(204);
    const id = randomUUID();
    expect((await SELF.fetch(new Request(new URL("_letmeknow/submit", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, page_event: 0, form_id: null, action: "/", trigger: null, values: {}, attachments: [{ field: "file", name: "file", content_type: "text/plain", hash, size: data.byteLength }] })
    }))).status).toBe(202);
    const event = await nextType(producer, "submit");
    producer.send({ type: "event_ack", event_number: event.event_number });
    producer.socket.close(1000, "done");
  });

  it("reconciles an attachment object that exists before its metadata is marked stored", async () => {
    const { producer, url } = await open();
    const data = new TextEncoder().encode("orphaned attachment");
    const hash = digest(data);
    const reserve = () => SELF.fetch(new Request(new URL("_letmeknow/attachments", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hashes: [{ hash, size: data.byteLength }] })
    }));
    expect(await (await reserve()).json()).toEqual({ missing: [{ hash, size: data.byteLength }] });
    const code = new URL(url).hostname.split(".")[0];
    const uploads = (env as unknown as { UPLOADS: { put(key: string, value: Uint8Array, options: { sha256: string }): Promise<unknown> } }).UPLOADS;
    await uploads.put(`sessions/${code}/objects/${hash}`, data, { sha256: hash });
    expect(await (await reserve()).json()).toEqual({ missing: [] });
    const id = randomUUID();
    expect((await SELF.fetch(new Request(new URL("_letmeknow/submit", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, page_event: 0, form_id: null, action: "/", trigger: null, values: {}, attachments: [{ field: "file", name: "file", content_type: "text/plain", hash, size: data.byteLength }] })
    }))).status).toBe(202);
    const event = await nextType(producer, "submit");
    producer.send({ type: "event_ack", event_number: event.event_number });
  });

  it("releases accepted attachments after commit but preserves pending shared references", async () => {
    const { producer, url, workspace } = await open();
    const data = new TextEncoder().encode("shared attachment");
    const attachment = await uploadAttachment(producer, url, data);
    const submit = (id: string) => SELF.fetch(new Request(new URL("_letmeknow/submit", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, page_event: 0, form_id: null, action: "/", trigger: null, values: {}, attachments: [{ field: "file", name: "file", content_type: "text/plain", ...attachment }] })
    }));
    expect((await submit(randomUUID())).status).toBe(202);
    const first = await nextType(producer, "submit");
    producer.send({ type: "event_ack", event_number: first.event_number });
    expect((await submit(randomUUID())).status).toBe(202);
    const second = await nextType(producer, "submit");
    producer.send({ type: "event_ack", event_number: second.event_number });
    const code = new URL(url).hostname.split(".")[0];
    const uploads = (env as unknown as { UPLOADS: { head(key: string): Promise<unknown> } }).UPLOADS;
    const key = `sessions/${code}/objects/${attachment.hash}`;
    await commit(producer, workspace, first.event_number);
    expect(await uploads.head(key)).not.toBeNull();
    await commit(producer, workspace, second.event_number);
    expect(await uploads.head(key)).toBeNull();
  });

  it("retries attachment cleanup after a transient object deletion failure", async () => {
    const now = Date.now();
    vi.useFakeTimers({ now });
    const { producer, url, workspace } = await open();
    const data = new TextEncoder().encode("retry attachment cleanup");
    const attachment = await uploadAttachment(producer, url, data);
    const response = await SELF.fetch(new Request(new URL("_letmeknow/submit", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id: randomUUID(), page_event: 0, form_id: null, action: "/", trigger: null, values: {}, attachments: [{ field: "file", name: "file", content_type: "text/plain", ...attachment }] })
    }));
    expect(response.status).toBe(202);
    const event = await nextType(producer, "submit");
    producer.send({ type: "event_ack", event_number: event.event_number });
    const code = new URL(url).hostname.split(".")[0];
    const key = `sessions/${code}/objects/${attachment.hash}`;
    const uploads = (env as unknown as { UPLOADS: { delete(keys: string | string[]): Promise<void>; head(key: string): Promise<unknown> } }).UPLOADS;
    const deleteObject = vi.spyOn(uploads, "delete").mockRejectedValueOnce(new Error("temporary delete failure"));
    await commit(producer, workspace, event.event_number);
    expect(deleteObject).toHaveBeenCalledWith([key]);
    expect(await uploads.head(key)).not.toBeNull();
    deleteObject.mockRestore();
    vi.setSystemTime(now + 60 * 1_000 + 1);
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(code))).toBe(true);
    expect(await uploads.head(key)).toBeNull();
    producer.socket.close(1000, "done");
  });

  it("redelivers an in-flight event after producer reconnect", async () => {
    const { producer, url } = await open();
    const code = new URL(url).hostname.split(".")[0];
    const id = randomUUID();
    expect((await SELF.fetch(new Request(new URL("_letmeknow/submit", url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ id, page_event: 0, form_id: null, action: "/", trigger: null, values: {} })
    }))).status).toBe(202);
    expect((await nextType(producer, "submit")).id).toBe(id);
    producer.socket.close(1000, "restart");
    const replacement = await connectProducer(code, producer.credential);
    await nextType(replacement, "session");
    expect((await nextType(replacement, "submit")).id).toBe(id);
    replacement.socket.close(1000, "done");
  });

  it("accepts submissions while the producer is disconnected and redelivers them in order", async () => {
    const { producer, url } = await open();
    const code = new URL(url).hostname.split(".")[0];
    const first = randomUUID();
    const second = randomUUID();
    producer.socket.close(1000, "restart");
    const submit = (id: string, value: string) => SELF.fetch(new Request(new URL("_letmeknow/submit", url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id, page_event: 0, form_id: "review", action: "/review", trigger: null, values: { value } }) }));
    expect((await submit(first, "one")).status).toBe(202);
    expect((await submit(second, "two")).status).toBe(202);
    const replacement = await connectProducer(code, producer.credential);
    expect(await nextType(replacement, "session")).toMatchObject({ url });
    const eventOne = await nextType(replacement, "submit");
    replacement.send({ type: "event_ack", event_number: eventOne.event_number });
    const eventTwo = await nextType(replacement, "submit");
    replacement.send({ type: "event_ack", event_number: eventTwo.event_number });
    expect([eventOne.id, eventTwo.id]).toEqual([first, second]);
  });

  it("deduplicates identical submissions and rejects conflicting UUID reuse", async () => {
    const { producer, url } = await open();
    const id = randomUUID();
    const payload = { id, page_event: 0, form_id: null, action: "/save", trigger: null, values: { value: "one" } };
    const request = () => SELF.fetch(new Request(new URL("_letmeknow/submit", url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) }));
    expect((await request()).status).toBe(202);
    expect((await request()).status).toBe(202);
    const event = await nextType(producer, "submit");
    producer.send({ type: "event_ack", event_number: event.event_number });
    expect((await SELF.fetch(new Request(new URL("_letmeknow/submit", url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...payload, values: { value: "two" } }) }))).status).toBe(409);
  });

  it("sequences UI scripts with submissions and replays committed scripts", async () => {
    const { producer, url, workspace } = await open();
    const client = await connectClient(url);
    expect(await client.next()).toMatchObject({ type: "connected", producer_connected: true });
    const id = randomUUID();
    const response = await SELF.fetch(new Request(new URL("_letmeknow/submit", url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ id, page_event: 0, form_id: null, action: "/save", trigger: null, values: {} }) }));
    expect(response.status).toBe(202);
    const submission = await nextType(producer, "submit");
    producer.send({ type: "event_ack", event_number: submission.event_number });
    const resultPromise = commit(producer, workspace, submission.event_number, "document.body.dataset.updated = 'yes';");
    const update = await nextType(client, "run_ui");
    const result = await resultPromise;
    expect(result).toMatchObject({ ok: true, frontier: submission.event_number + 1, page_event: submission.event_number + 1, events: [id] });
    expect((await commit(producer, workspace, submission.event_number)).events).toEqual([]);
    expect(update).toMatchObject({ event_number: result.page_event, script: "document.body.dataset.updated = 'yes';" });
    const page = await SELF.fetch(new Request(url));
    const pageText = await page.text();
    expect(pageText).toContain("data-letmeknow-history");
    expect(pageText).toContain("updated");
  });

  it("keeps browser pages available while the producer reconnects", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    expect(await client.next()).toMatchObject({ type: "connected", producer_connected: true });
    const code = new URL(url).hostname.split(".")[0];
    producer.socket.close(1000, "restart");
    expect(await client.next()).toEqual({ type: "producer", connected: false });
    expect((await SELF.fetch(new Request(url))).status).toBe(200);
    const replacement = await connectProducer(code, producer.credential);
    expect(await nextType(replacement, "session")).toMatchObject({ url });
    expect(await client.next()).toEqual({ type: "producer", connected: true });
  });

  it("rejects invalid workspace paths and serves HEAD without a body", async () => {
    const { producer, url, workspace } = await open();
    const badHash = "0".repeat(64);
    producer.send({ type: "workspace_manifest", id: randomUUID(), index: { hash: badHash, size: 1 }, hashes: [{ hash: badHash, size: 1 }] });
    expect(await nextType(producer, "workspace_manifest")).toMatchObject({ missing: [{ hash: badHash, size: 1 }, { hash: badHash, size: 1 }] });
    producer.send({ type: "commit", id: randomUUID(), request_id: randomUUID(), through: 0, index_hash: workspace.index_hash, index_size: workspace.index_size, manifest: { files: { "../escape.js": { hash: badHash, size: 1, content_type: "text/javascript" } } } });
    expect(await nextType(producer, "error")).toMatchObject({ message: "invalid workspace path" });
    const head = await SELF.fetch(new Request(new URL("app.js", url), { method: "HEAD" }));
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    expect((await SELF.fetch(new Request(`${url}%2e%2e%2fapp.js`))).status).toBe(403);
  });

  it("streams a large pinned index without buffering the page", async () => {
    const index = `<!doctype html><html><body><main>${"x".repeat(2 * MAX_BODY_BYTES)}</main></body></html>`;
    const { producer, url } = await open({ index });
    const response = await SELF.fetch(new Request(url));
    const page = await response.text();
    expect(response.status).toBe(200);
    expect(page.startsWith("<!doctype html>")).toBe(true);
    expect(page).toContain("x".repeat(1024));
    expect(page).toContain('data-letmeknow-history');
    expect(page).toContain('/_letmeknow/client.js');
    expect(page.length).toBeGreaterThan(index.length);
    producer.socket.close(1000, "done");
  });

  it("cleans staged workspace objects after a failed commit", async () => {
    const { producer, url, workspace } = await open();
    const firstScript = "x".repeat(MAX_BODY_BYTES - 300);
    const first = await commit(producer, workspace, 0, firstScript);
    expect(first.ok).toBe(true);
    producer.send({ type: "event_ack", event_number: first.run_ui.event_number });

    const replacement = new TextEncoder().encode("staged but uncommitted");
    const nextWorkspace = await uploadWorkspace(producer, url, new TextEncoder().encode("<!doctype html><html><body><main id=app>initial</main></body></html>"), {
      "replacement.txt": { data: replacement, content_type: "text/plain" }
    });
    const code = new URL(url).hostname.split(".")[0];
    const uploads = (env as unknown as { UPLOADS: { head(key: string): Promise<unknown> } }).UPLOADS;
    const key = `sessions/${code}/objects/${digest(replacement)}`;
    expect(await uploads.head(key)).not.toBeNull();

    const id = randomUUID();
    producer.send({ type: "commit", id, request_id: id, through: 0, ...nextWorkspace, script: "small" });
    expect(await nextType(producer, "error")).toMatchObject({ message: "page history is too large" });
    expect(await uploads.head(key)).toBeNull();
  });

  it("expires the session idempotently when alarms race", async () => {
    const now = Date.now();
    vi.useFakeTimers({ now });
    const { producer, url } = await open();
    vi.setSystemTime(now + SESSION_LIFETIME_MS + 1);
    const responses = await Promise.all([SELF.fetch(new Request(url)), SELF.fetch(new Request(url))]);
    expect(responses.map(response => response.status)).toEqual([404, 404]);
    producer.socket.close(1000, "done");
  });

  it("expires the session and removes its public workspace and attachments", async () => {
    const now = Date.now();
    vi.useFakeTimers({ now });
    const { producer, url } = await open();
    const attachment = await uploadAttachment(producer, url, new TextEncoder().encode("temporary"));
    const code = new URL(url).hostname.split(".")[0];
    const uploads = (env as unknown as { UPLOADS: { head(key: string): Promise<unknown> } }).UPLOADS;
    expect(await uploads.head(`sessions/${code}/objects/${attachment.hash}`)).not.toBeNull();
    vi.setSystemTime(now + SESSION_LIFETIME_MS + 1);
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(code))).toBe(true);
    expect((await SELF.fetch(new Request(url))).status).toBe(404);
    expect(await uploads.head(`sessions/${code}/objects/${attachment.hash}`)).toBeNull();
    expect(producer.socket.readyState).not.toBe(WebSocket.OPEN);
  });
});
