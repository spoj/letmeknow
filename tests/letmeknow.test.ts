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

  it("rejects commits that would exceed the replay history bound", async () => {
    const { producer, workspace } = await open();
    const firstScript = "x".repeat(MAX_BODY_BYTES - 300);
    const first = await commit(producer, workspace, 0, firstScript);
    expect(first.ok).toBe(true);
    producer.send({ type: "event_ack", event_number: first.run_ui.event_number });
    const id = randomUUID();
    producer.send({ type: "commit", id, request_id: id, through: 0, ...workspace, script: "small" });
    expect(await nextType(producer, "error")).toMatchObject({ message: "page history is too large" });
  });

  it("expires the session and removes its public workspace", async () => {
    const now = Date.now();
    vi.useFakeTimers({ now });
    const { producer, url } = await open();
    const code = new URL(url).hostname.split(".")[0];
    vi.setSystemTime(now + SESSION_LIFETIME_MS + 1);
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(code))).toBe(true);
    expect((await SELF.fetch(new Request(url))).status).toBe(404);
    expect(producer.socket.readyState).not.toBe(WebSocket.OPEN);
  });
});
