import { SELF, runDurableObjectAlarm } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it } from "vitest";

type Event = Record<string, any>;
type Peer = {
  socket: WebSocket;
  credential?: string;
  next(): Promise<Event>;
  send(packet: Event): void;
};

const origin = "https://client.example";
const sockets: WebSocket[] = [];
let ipCounter = 0;

function peer(socket: WebSocket, answerChallenges = false): Peer {
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
    if (answerChallenges && event.type === "challenge") {
      socket.send(JSON.stringify({ type: "alive", nonce: event.nonce }));
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

async function connectProducer(base = origin, auth?: { code: string; credential: string }): Promise<Peer> {
  const endpoint = new URL(`${base}/v1/connect`);
  const headers: Record<string, string> = { Upgrade: "websocket", "CF-Connecting-IP": `192.0.2.${++ipCounter}` };
  if (auth) {
    endpoint.searchParams.set("code", auth.code);
    headers["Sec-WebSocket-Protocol"] = auth.credential;
  }
  const response = await SELF.fetch(new Request(endpoint, { headers }));
  expect(response.status).toBe(101);
  return peer(response.webSocket!);
}

async function open(base = origin): Promise<{ producer: Peer; url: string }> {
  const producer = await connectProducer(base);
  producer.send({ type: "open", id: "open" });
  const session = await producer.next();
  expect(session).toMatchObject({ type: "session", id: "open", expires_after_disconnect: 600 });
  return { producer, url: session.url };
}

async function connectClient(url: string, credential?: string): Promise<Peer> {
  const endpoint = new URL("_letmeknow/client", url);
  const headers: Record<string, string> = { Upgrade: "websocket" };
  if (credential) headers["Sec-WebSocket-Protocol"] = credential;
  const response = await SELF.fetch(new Request(endpoint, { headers }));
  expect(response.status).toBe(101);
  return peer(response.webSocket!, true);
}

async function render(producer: Peer, body: string, css = ""): Promise<string> {
  producer.send({ type: "render", id: "render", body, css });
  const ack = await producer.next();
  expect(ack).toMatchObject({ type: "ack", id: "render" });
  return ack.render_id;
}

function publicPath(url: string, path: string): string {
  return new URL(path.replace(/^\//, ""), url).toString();
}

function action(renderId: string, overrides: Event = {}): Event {
  return {
    type: "action",
    id: crypto.randomUUID(),
    render_id: renderId,
    action_id: "approve",
    form_id: "decision",
    target_id: "lmk-view",
    trigger: { id: "approve", name: "decision", value: "approve" },
    values: { comment: "Looks good", decision: "approve", tags: ["one", "two"] },
    ...overrides
  };
}

afterEach(() => {
  for (const socket of sockets.splice(0)) socket.close(1000, "test complete");
});

describe("LetMeKnow one-to-one HTML surface", () => {
  it("creates production subdomains and local path sessions", async () => {
    expect((await open()).url).toMatch(/^https:\/\/client\.example\/s\/[a-f0-9]{20}\/$/);
    expect((await open("https://letmeknow.dev")).url).toMatch(/^https:\/\/[a-f0-9]{20}\.letmeknow\.dev\/$/);
  });

  it("serves a blank shell with the browser WebSocket runtime", async () => {
    const { url } = await open();
    const response = await SELF.fetch(url);
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Security-Policy")).toContain("img-src 'self' data:");
    const html = await response.text();
    expect(html).toContain("Waiting for the agent…");
    expect(html).toContain("_letmeknow/client");
    expect(html).toContain("sessionStorage");
    expect(html).not.toContain("_letmeknow/view");
  });

  it("pushes a render to the single client and restores it on reconnect", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    expect(await client.next()).toMatchObject({ type: "state", producer_connected: true });
    const renderId = await render(producer, "<h1>Ready</h1>", "h1 { color: purple; }");
    expect(await client.next()).toEqual({
      type: "render",
      render_id: renderId,
      html: "<h1>Ready</h1>",
      css: "h1 { color: purple; }"
    });

    const credential = client.credential!;
    client.socket.close(1000, "reload");
    await new Promise((resolve) => setTimeout(resolve, 20));
    const replacement = await connectClient(url, credential);
    expect(await replacement.next()).toEqual({
      type: "state",
      view: { render_id: renderId, html: "<h1>Ready</h1>", css: "h1 { color: purple; }" },
      pending: [],
      producer_connected: true
    });
  });

  it("rejects a second active client after an on-demand liveness check", async () => {
    const { url } = await open();
    const first = await connectClient(url);
    await first.next();
    const second = await connectClient(url);
    expect(await second.next()).toEqual({ type: "busy", retry_after: 5 });
  });

  it("forwards one normalized action and pushes its targeted response", async () => {
    const { producer, url } = await open();
    const renderId = await render(producer, '<form id="decision" action="approve" method="post"></form><section id="result"></section>');
    const client = await connectClient(url);
    await client.next();
    const submitted = action(renderId, { target_id: "result" });
    client.send(submitted);
    expect(await producer.next()).toEqual({ type: "action", ...submitted });

    producer.send({ type: "response", id: "response", request_id: submitted.id, body: "<strong>Approved</strong>" });
    const ack = await producer.next();
    expect(ack).toMatchObject({ type: "ack", id: "response" });
    expect(await client.next()).toEqual({
      type: "update",
      request_id: submitted.id,
      target_id: "result",
      html: "<strong>Approved</strong>",
      render_id: ack.render_id
    });

    client.socket.close(1000, "reload");
    await new Promise((resolve) => setTimeout(resolve, 20));
    const replacement = await connectClient(url, client.credential);
    expect((await replacement.next()).view).toEqual({
      render_id: ack.render_id,
      html: '<form id="decision" action="approve" method="post"></form><section id="result"><strong>Approved</strong></section>',
      css: ""
    });
  });

  it("restores pending actions and committed results across a client reconnect", async () => {
    const { producer, url } = await open();
    const renderId = await render(producer, '<form id="job"></form><div id="result"></div>');
    const client = await connectClient(url);
    await client.next();
    const submitted = action(renderId, { form_id: "job", target_id: "result", action_id: "run" });
    client.send(submitted);
    await producer.next();
    const credential = client.credential!;
    client.socket.close(1000, "sleep");
    await new Promise((resolve) => setTimeout(resolve, 20));

    const replacement = await connectClient(url, credential);
    const state = await replacement.next();
    expect(state.pending).toEqual([{ id: submitted.id, action_id: "run", form_id: "job", target_id: "result" }]);
    producer.send({ type: "response", id: "done", request_id: submitted.id, body: "Complete" });
    const ack = await producer.next();
    expect(await replacement.next()).toEqual({
      type: "update",
      request_id: submitted.id,
      target_id: "result",
      html: "Complete",
      render_id: ack.render_id
    });
  });

  it("keeps independent targets pending while rejecting form and target conflicts", async () => {
    const { producer, url } = await open();
    const renderId = await render(producer, '<form id="one"></form><form id="two"></form><div id="a"></div><div id="b"></div>');
    const client = await connectClient(url);
    await client.next();
    const first = action(renderId, { id: "11111111-1111-4111-8111-111111111111", form_id: "one", target_id: "a" });
    client.send(first);
    await producer.next();

    const sameForm = action(renderId, { id: "22222222-2222-4222-8222-222222222222", form_id: "one", target_id: "b" });
    client.send(sameForm);
    expect(await client.next()).toMatchObject({ type: "action_error", request_id: sameForm.id, message: "interaction already pending" });
    const sameTarget = action(renderId, { id: "33333333-3333-4333-8333-333333333333", form_id: "two", target_id: "a" });
    client.send(sameTarget);
    expect(await client.next()).toMatchObject({ type: "action_error", request_id: sameTarget.id, message: "interaction already pending" });

    const independent = action(renderId, { id: "44444444-4444-4444-8444-444444444444", form_id: "two", target_id: "b" });
    client.send(independent);
    expect(await producer.next()).toEqual({ type: "action", ...independent });
  });

  it("cancels stale actions when a full render supersedes them", async () => {
    const { producer, url } = await open();
    const renderId = await render(producer, "<button>Before</button>");
    const client = await connectClient(url);
    await client.next();
    const submitted = action(renderId);
    client.send(submitted);
    await producer.next();
    await render(producer, "<h1>After</h1>");
    await client.next();
    producer.send({ type: "response", id: "late", request_id: submitted.id, body: "Late" });
    expect(await producer.next()).toEqual({ type: "error", id: "late", message: "interaction is not pending" });
  });

  it("sanitizes HTML while preserving standard form actions and custom CSS", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    await client.next();
    await render(producer, '<script>bad()</script><h1 style="color:red" onclick="bad()">Title</h1><form id="f" action="save" method="post" hx-post="old"><button formaction="approve" data-lmk-target="result">Go</button></form><div id="result"></div>', "h1 { color: green; }");
    const message = await client.next();
    expect(message.html).toContain('<form id="f" action="save" method="post">');
    expect(message.html).toContain('formaction="approve"');
    expect(message.html).not.toContain("script");
    expect(message.html).not.toContain("onclick");
    expect(message.html).not.toContain("hx-post");
    expect(message.css).toBe("h1 { color: green; }");
  });

  it("stores only bounded assets under /assets", async () => {
    const { producer, url } = await open();
    producer.send({ type: "put", id: "asset", path: "/assets/pixel.bin", content_type: "application/octet-stream", encoding: "base64", body: "AAEC/w==" });
    expect(await producer.next()).toEqual({ type: "ack", id: "asset" });
    const response = await SELF.fetch(publicPath(url, "/assets/pixel.bin"));
    expect(response.headers.get("Content-Type")).toBe("application/octet-stream");
    expect([...new Uint8Array(await response.arrayBuffer())]).toEqual([0, 1, 2, 255]);
    expect((await SELF.fetch(publicPath(url, "/assets/pixel.bin"), { method: "HEAD" })).status).toBe(200);
    producer.send({ type: "put", id: "root", path: "/", content_type: "text/html", body: "no" });
    expect(await producer.next()).toEqual({ type: "error", id: "root", message: "asset path must be under /assets/" });
  });

  it("shows producer disconnects and supports authenticated producer reconnect", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    await client.next();
    producer.socket.close(1000, "restart");
    expect(await client.next()).toEqual({ type: "producer", connected: false });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const code = new URL(url).pathname.split("/")[2];
    const replacement = await connectProducer(origin, { code, credential: producer.credential! });
    expect(await replacement.next()).toMatchObject({ type: "session", url });
    expect(await client.next()).toEqual({ type: "producer", connected: true });
  });

  it("expires after producer grace and destroys everything on close", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    await client.next();
    producer.send({ type: "close", id: "close" });
    expect(await producer.next()).toEqual({ type: "ack", id: "close" });
    expect(await producer.next()).toEqual({ type: "closing" });
    expect(await client.next()).toEqual({ type: "closed", message: "Session closed" });
    expect((await SELF.fetch(url)).status).toBe(404);

    const another = await open();
    another.producer.socket.close(1000, "gone");
    await new Promise((resolve) => setTimeout(resolve, 20));
    const code = new URL(another.url).pathname.split("/")[2];
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(code))).toBe(true);
    expect((await SELF.fetch(another.url)).status).toBe(404);
  });
});
