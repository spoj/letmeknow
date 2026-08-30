import { SELF, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

type Event = Record<string, any>;
type Peer = {
  socket: WebSocket;
  credential?: string;
  next(): Promise<Event>;
  send(packet: Event): void;
};

const origin = "https://letmeknow.dev";
const workspace = "11111111-1111-4111-8111-111111111111";
const sockets: WebSocket[] = [];
let ipCounter = 0;

function peer(socket: WebSocket): Peer {
  socket.accept();
  sockets.push(socket);
  const queued: Event[] = [];
  const waiting: Array<(event: Event) => void> = [];
  let credential: string | undefined;
  socket.addEventListener("message", (message) => {
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
    next: () => queued.length ? Promise.resolve(queued.shift()!) : new Promise((resolve) => waiting.push(resolve)),
    send: (packet) => socket.send(JSON.stringify(packet))
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

async function open(): Promise<{ producer: Peer; url: string }> {
  const producer = await connectProducer();
  producer.send({ type: "open", id: "open" });
  const session = await producer.next();
  expect(session).toMatchObject({ type: "session", id: "open", expires_after_disconnect: 600 });
  return { producer, url: session.url };
}

async function connectClient(url: string): Promise<Peer> {
  const response = await SELF.fetch(new Request(new URL("_letmeknow/client", url), { headers: { Upgrade: "websocket" } }));
  expect(response.status).toBe(101);
  return peer(response.webSocket!);
}

afterEach(() => {
  for (const socket of sockets.splice(0)) socket.close(1000, "test complete");
});

describe("LetMeKnow outbound relay", () => {
  it("creates hosted subdomain sessions and rejects old or custom session routes", async () => {
    const { url } = await open();
    expect(url).toMatch(/^https:\/\/[a-f0-9]{20}\.letmeknow\.dev\/$/);
    expect((await SELF.fetch(new Request(`${origin}/s/01234567890123456789/`))).status).toBe(404);
    expect((await SELF.fetch(new Request("https://preview.example/v2/connect", { headers: { Upgrade: "websocket" } }))).status).toBe(404);
    expect((await SELF.fetch(new Request(`${origin}/v1/connect`, { headers: { Upgrade: "websocket" } }))).status).toBe(404);
  });

  it("allows multiple clients and broadcasts revisions and producer lifecycle", async () => {
    const { producer, url } = await open();
    const first = await connectClient(url);
    const second = await connectClient(url);
    expect(await first.next()).toEqual({ type: "connected", producer_connected: true });
    expect(await second.next()).toEqual({ type: "connected", producer_connected: true });
    producer.send({ type: "revision" });
    expect(await first.next()).toEqual({ type: "revision" });
    expect(await second.next()).toEqual({ type: "revision" });
    producer.socket.close(1000, "restart");
    expect(await first.next()).toEqual({ type: "producer", connected: false });
    expect(await second.next()).toEqual({ type: "producer", connected: false });
  });

  it("injects the relay runtime into HTML but not other responses or submissions", async () => {
    const { producer, url } = await open();
    const htmlRequest = SELF.fetch(new Request(url));
    const html = await producer.next();
    producer.send({ type: "http_response", request_id: html.request_id, status: 200, headers: { "content-type": "text/html", "x-letmeknow-workspace": workspace }, body: btoa("<html><body><h1>Preview</h1></body></html>") });
    const htmlResponse = await htmlRequest;
    expect(await htmlResponse.text()).toContain(`<script type="module" src="/_letmeknow/client.js" data-letmeknow-runtime data-letmeknow-workspace="${workspace}"></script>`);
    expect(htmlResponse.headers.get("x-letmeknow-workspace")).toBeNull();

    const cssRequest = SELF.fetch(new Request(new URL("style.css", url)));
    const css = await producer.next();
    producer.send({ type: "http_response", request_id: css.request_id, status: 200, headers: { "content-type": "text/css", "x-letmeknow-workspace": workspace }, body: btoa("body{}")} );
    const cssResponse = await cssRequest;
    expect(await cssResponse.text()).toBe("body{}");
    expect(cssResponse.headers.get("x-letmeknow-workspace")).toBeNull();

    const submission = SELF.fetch(new Request(new URL("save", url), { method: "POST", headers: { "X-LetMeKnow-Submission": "1" }, body: "ok" }));
    const submissionRequest = await producer.next();
    producer.send({ type: "http_response", request_id: submissionRequest.request_id, status: 202, headers: { "content-type": "text/html", "x-letmeknow-workspace": workspace }, body: btoa("accepted") });
    const submissionResponse = await submission;
    expect(await submissionResponse.text()).toBe("accepted");
    expect(submissionResponse.headers.get("x-letmeknow-workspace")).toBeNull();
  });

  it("rejects invalid workspace headers on HTML documents", async () => {
    const { producer, url } = await open();
    const page = SELF.fetch(new Request(url));
    const request = await producer.next();
    producer.send({ type: "http_response", request_id: request.request_id, status: 200, headers: { "content-type": "text/html", "x-letmeknow-workspace": "not-a-uuid" }, body: btoa("<html><body>bad</body></html>") });
    const response = await page;
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({ error: "invalid workspace header" });
  });

  it("turns producer document 404s into live pages but leaves missing assets alone", async () => {
    const { producer, url } = await open();
    const missingPage = SELF.fetch(new Request(new URL("missing", url), { headers: { Accept: "text/html" } }));
    const pageRequest = await producer.next();
    producer.send({ type: "http_response", request_id: pageRequest.request_id, status: 404, headers: { "content-type": "text/plain" }, body: btoa("missing") });
    const pageResponse = await missingPage;
    const pageBody = await pageResponse.text();
    expect(pageResponse.status).toBe(404);
    expect(pageResponse.headers.get("content-type")).toContain("text/html");
    expect(pageBody).toContain("This page does not exist yet");
    expect(pageBody).toContain("/_letmeknow/client.js");

    const missingAsset = SELF.fetch(new Request(new URL("missing.css", url), { headers: { Accept: "text/css", "Sec-Fetch-Dest": "style" } }));
    const assetRequest = await producer.next();
    producer.send({ type: "http_response", request_id: assetRequest.request_id, status: 404, headers: { "content-type": "text/plain" }, body: btoa("missing asset") });
    const assetResponse = await missingAsset;
    expect(assetResponse.status).toBe(404);
    expect(await assetResponse.text()).toBe("missing asset");
    expect(assetResponse.headers.get("content-type")).toBe("text/plain");
  });

  it("injects HTML once, removes stale lengths, and handles documents without a body", async () => {
    const { producer, url } = await open();
    const page = SELF.fetch(new Request(url));
    const pageRequest = await producer.next();
    producer.send({ type: "http_response", request_id: pageRequest.request_id, status: 200, headers: { "content-type": "text/html", "content-length": "4" }, body: btoa("<html><head></head><body>ok</body></html>") });
    const pageResponse = await page;
    const pageBody = await pageResponse.text();
    expect(pageResponse.headers.get("content-length")).toBeNull();
    expect(pageBody.match(/data-letmeknow-runtime/g)).toHaveLength(1);
    expect(pageBody.indexOf("data-letmeknow-runtime")).toBeLessThan(pageBody.indexOf("</body>"));

    const noBody = SELF.fetch(new Request(new URL("empty", url)));
    const noBodyRequest = await producer.next();
    producer.send({ type: "http_response", request_id: noBodyRequest.request_id, status: 200, headers: { "content-type": "text/html" }, body: "" });
    expect(await (await noBody).text()).toContain("/_letmeknow/client.js");
  });

  it("does not inject or return a body for HEAD HTML requests", async () => {
    const { producer, url } = await open();
    const head = SELF.fetch(new Request(url, { method: "HEAD" }));
    const request = await producer.next();
    expect(request.method).toBe("HEAD");
    producer.send({ type: "http_response", request_id: request.request_id, status: 200, headers: { "content-type": "text/html", "content-length": "4", "x-letmeknow-workspace": workspace }, body: btoa("body") });
    const response = await head;
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("");
    expect(response.headers.get("content-length")).toBe("4");
    expect(response.headers.get("x-letmeknow-workspace")).toBeNull();
  });

  it("keeps disconnected asset responses non-HTML", async () => {
    const { producer, url } = await open();
    const pendingPage = SELF.fetch(new Request(url));
    await producer.next();
    producer.socket.close(1000, "gone");
    const pendingResponse = await pendingPage;
    expect(pendingResponse.status).toBe(503);
    expect(pendingResponse.headers.get("content-type")).toContain("text/html");

    const response = await SELF.fetch(new Request(new URL("style.css", url), { headers: { Accept: "text/css", "Sec-Fetch-Dest": "style" } }));
    expect(response.status).toBe(503);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(await response.text()).not.toContain("<html");
  });

  it("serves the runtime with deliberate method handling", async () => {
    const { url } = await open();
    const runtimeUrl = new URL("_letmeknow/client.js", url);
    const runtime = await SELF.fetch(new Request(runtimeUrl));
    expect(runtime.status).toBe(200);
    expect(await runtime.text()).toContain("Sent. Waiting for an update");

    const head = await SELF.fetch(new Request(runtimeUrl, { method: "HEAD" }));
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");

    const post = await SELF.fetch(new Request(runtimeUrl, { method: "POST" }));
    expect(post.status).toBe(405);
    expect(post.headers.get("allow")).toBe("GET, HEAD");
  });

  it("serves the runtime and live disconnected pages", async () => {
    const { producer, url } = await open();
    const runtime = await SELF.fetch(new Request(new URL("_letmeknow/client.js", url)));
    expect(runtime.status).toBe(200);
    expect(runtime.headers.get("cache-control")).toBe("no-store");
    expect(runtime.headers.get("content-type")).toContain("text/javascript");
    expect(await runtime.text()).toContain("Sent. Waiting for an update");
    producer.socket.close(1000, "gone");
    const disconnected = await SELF.fetch(new Request(url));
    expect(disconnected.status).toBe(503);
    expect(disconnected.headers.get("content-type")).toContain("text/html");
    const body = await disconnected.text();
    expect(body).toContain('data-letmeknow-status-page="disconnected"');
    expect(body).toContain("/_letmeknow/client.js");
    expect(body).not.toContain("data-letmeknow-workspace");
  });

  it("relays requests and preserves late-response and size boundaries", async () => {
    const { producer, url } = await open();
    const page = SELF.fetch(new Request(url));
    const request = await producer.next();
    expect(request).toMatchObject({ type: "http_request", method: "GET", path: "/" });
    producer.send({ type: "http_response", request_id: request.request_id, status: 200, headers: {}, body: "" });
    expect((await page).status).toBe(200);

    const oversized = await SELF.fetch(new Request(url, { method: "POST", headers: { "Content-Length": String(1024 * 1024 + 1) } }));
    expect(oversized.status).toBe(413);
  });

  it("reconnects the producer securely and expires disconnected sessions", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    expect(await client.next()).toEqual({ type: "connected", producer_connected: true });
    const code = new URL(url).hostname.split(".")[0];
    producer.socket.close(1000, "restart");
    expect(await client.next()).toEqual({ type: "producer", connected: false });
    const replacement = await connectProducer(code, producer.credential);
    expect(await replacement.next()).toMatchObject({ type: "session", url });
    expect(await client.next()).toEqual({ type: "producer", connected: true });
    replacement.socket.close(1000, "gone");
    expect(await client.next()).toEqual({ type: "producer", connected: false });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(code))).toBe(true);
    expect(await client.next()).toEqual({ type: "closed", message: "Session expired" });
    const expired = await SELF.fetch(url);
    expect(expired.status).toBe(404);
    expect(await expired.text()).not.toContain("/_letmeknow/client.js");
  });

  it("ignores stale producer closes after replacement reconnects", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    await client.next();
    producer.socket.close(1000, "restart");
    await client.next();
    const code = new URL(url).hostname.split(".")[0];
    const replacement = await connectProducer(code, producer.credential);
    await replacement.next();
    await client.next();
    const page = SELF.fetch(new Request(url));
    const request = await replacement.next();
    const staleSocket = { deserializeAttachment: () => ({ role: "producer", url, opened: true, closing: false }), close: () => {} } as unknown as WebSocket;
    await runInDurableObject(env.SESSIONS.getByName(code), (instance) => instance.webSocketClose(staleSocket, 1000, "stale"));
    replacement.send({ type: "http_response", request_id: request.request_id, status: 200, headers: {}, body: "" });
    expect((await page).status).toBe(200);
    expect(await Promise.race([client.next(), new Promise((resolve) => setTimeout(() => resolve(undefined), 50))])).toBeUndefined();
  });
});
