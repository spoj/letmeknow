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

async function connectProducer(base = origin): Promise<Peer> {
  const endpoint = new URL(`${base}/v1/connect`);
  const response = await SELF.fetch(new Request(endpoint, {
    headers: { Upgrade: "websocket", "CF-Connecting-IP": `192.0.2.${++ipCounter}` }
  }));
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

afterEach(() => {
  for (const socket of sockets.splice(0)) socket.close(1000, "test complete");
});

describe("LetMeKnow outbound relay", () => {
  it("creates production subdomains and local path sessions", async () => {
    expect((await open()).url).toMatch(/^https:\/\/client\.example\/s\/[a-f0-9]{20}\/$/);
    expect((await open("https://letmeknow.dev")).url).toMatch(/^https:\/\/[a-f0-9]{20}\.letmeknow\.dev\/$/);
  });

  it("redirects slashless path session roots to a relative-asset-safe URL", async () => {
    const { producer, url } = await open();
    const canonical = new URL(url);
    const slashless = new URL(canonical);
    slashless.pathname = slashless.pathname.slice(0, -1);
    slashless.search = "?view=source";

    const redirect = await SELF.fetch(new Request(slashless, { redirect: "manual" }));
    expect(redirect.status).toBe(308);
    const location = redirect.headers.get("location")!;
    const expected = new URL(slashless);
    expected.pathname += "/";
    expect(location).toBe(expected.toString());

    const asset = new URL("assets/app.css", location);
    expect(asset.pathname).toBe(`${canonical.pathname}assets/app.css`);
    const assetResponse = SELF.fetch(new Request(asset));
    const request = await producer.next();
    expect(request).toMatchObject({ type: "http_request", method: "GET", path: "/assets/app.css" });
    producer.send({ type: "http_response", request_id: request.request_id, status: 200, headers: {}, body: "" });
    expect((await assetResponse).status).toBe(200);
  });

  it("relays browser requests and file updates through one producer", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    expect(await client.next()).toEqual({ type: "connected", producer_connected: true });

    const page = SELF.fetch(new Request(url, { headers: { "Sec-Fetch-Dest": "document" } }));
    const request = await producer.next();
    expect(request).toMatchObject({
      type: "http_request",
      method: "GET",
      path: "/",
      headers: { "sec-fetch-dest": "document" }
    });
    expect(request.headers.host).toBeUndefined();
    producer.send({
      type: "http_response",
      request_id: request.request_id,
      status: 200,
      headers: { "content-type": "text/html" },
      body: btoa("<h1>From CLI</h1>")
    });
    const response = await page;
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("<h1>From CLI</h1>");

    producer.send({ type: "file_update", path: "/space%20file.css" });
    expect(await client.next()).toEqual({ type: "file_update", path: "/space%20file.css" });
  });

  it("ignores late responses for timed-out browser requests", async () => {
    const { producer, url } = await open();
    const page = SELF.fetch(new Request(url));
    const request = await producer.next();
    const code = new URL(url).pathname.split("/")[2];
    await runInDurableObject(env.SESSIONS.getByName(code), (instance) => {
      const session = instance as unknown as {
        pendingProxy: Map<string, { resolve(response: Response): void; timer: ReturnType<typeof setTimeout> }>
      };
      const pending = session.pendingProxy.get(request.request_id);
      clearTimeout(pending!.timer);
      session.pendingProxy.delete(request.request_id);
      pending!.resolve(new Response(null, { status: 504 }));
    });
    expect((await page).status).toBe(504);

    const lateEvents: Event[] = [];
    const lateListener = (message: MessageEvent) => lateEvents.push(JSON.parse(message.data as string));
    producer.socket.addEventListener("message", lateListener);
    producer.send({ type: "http_response", request_id: request.request_id, status: 200, headers: {}, body: "" });
    await new Promise((resolve) => setTimeout(resolve, 10));
    producer.socket.removeEventListener("message", lateListener);
    expect(lateEvents).toEqual([]);

    const nextPage = SELF.fetch(new Request(url));
    const nextRequest = await producer.next();
    producer.send({ type: "http_response", request_id: nextRequest.request_id, status: 200, headers: {}, body: "" });
    expect((await nextPage).status).toBe(200);
  });

  it("rejects oversized requests from Content-Length before proxying", async () => {
    const { producer, url } = await open();
    const response = await SELF.fetch(new Request(url, {
      method: "POST",
      headers: { "Content-Length": String(1024 * 1024 + 1) }
    }));
    expect(response.status).toBe(413);
    expect(await Promise.race([producer.next(), new Promise((resolve) => setTimeout(() => resolve(undefined), 50))])).toBeUndefined();
  });

  it("relays form submissions and preserves the session path", async () => {
    const { producer, url } = await open();
    const page = SELF.fetch(new Request(new URL("save", url), {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-LetMeKnow-Submission": "1",
        "X-LetMeKnow-ID": "submission",
        "X-LetMeKnow-Form-ID": "decision",
        "X-LetMeKnow-Action": "%2Fsave"
      },
      body: "answer=yes"
    }));
    const request = await producer.next();
    expect(request).toMatchObject({
      type: "http_request",
      method: "POST",
      path: "/save",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "x-letmeknow-submission": "1",
        "x-letmeknow-id": "submission"
      }
    });
    expect(atob(request.body)).toBe("answer=yes");
    producer.send({ type: "http_response", request_id: request.request_id, status: 204, headers: {}, body: "" });
    expect((await page).status).toBe(204);
  });

  it("allows only one producer and one browser consumer", async () => {
    const { producer, url } = await open();
    const code = new URL(url).pathname.split("/")[2];
    const second = await SELF.fetch(new Request(`${origin}/v1/connect?code=${code}`, {
      headers: {
        Upgrade: "websocket",
        "CF-Connecting-IP": `192.0.2.${++ipCounter}`,
        "Sec-WebSocket-Protocol": producer.credential!
      }
    }));
    expect(second.status).toBe(409);

    const first = await connectClient(url);
    await first.next();
    const replacement = await connectClient(url);
    expect(await replacement.next()).toEqual({ type: "busy", retry_after: 5 });
    producer.socket.close(1000, "done");
  });

  it("ignores a stale producer close after replacement reconnects", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    expect(await client.next()).toEqual({ type: "connected", producer_connected: true });
    producer.socket.close(1000, "restart");
    expect(await client.next()).toEqual({ type: "producer", connected: false });

    const code = new URL(url).pathname.split("/")[2];
    const replacement = await SELF.fetch(new Request(`${origin}/v1/connect?code=${code}`, {
      headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": producer.credential! }
    }));
    expect(replacement.status).toBe(101);
    const replacementProducer = peer(replacement.webSocket!);
    expect(await replacementProducer.next()).toMatchObject({ type: "session", url });
    expect(await client.next()).toEqual({ type: "producer", connected: true });

    const page = SELF.fetch(new Request(url));
    const request = await replacementProducer.next();
    const staleSocket = {
      deserializeAttachment: () => ({ role: "producer", url, opened: true, closing: false }),
      close: () => {}
    } as unknown as WebSocket;
    await runInDurableObject(env.SESSIONS.getByName(code), (instance) => instance.webSocketClose(staleSocket, 1000, "stale"));
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(code))).toBe(false);
    replacementProducer.send({ type: "http_response", request_id: request.request_id, status: 200, headers: {}, body: "" });
    expect((await page).status).toBe(200);
    expect(await Promise.race([client.next(), new Promise((resolve) => setTimeout(() => resolve(undefined), 50))])).toBeUndefined();
  });

  it("reconnects the producer and expires disconnected sessions", async () => {
    const { producer, url } = await open();
    const client = await connectClient(url);
    await client.next();
    producer.socket.close(1000, "restart");
    expect(await client.next()).toEqual({ type: "producer", connected: false });
    await new Promise((resolve) => setTimeout(resolve, 20));

    const code = new URL(url).pathname.split("/")[2];
    const replacement = await SELF.fetch(new Request(`${origin}/v1/connect?code=${code}`, {
      headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": producer.credential! }
    }));
    expect(replacement.status).toBe(101);
    const replacementProducer = peer(replacement.webSocket!);
    expect(await replacementProducer.next()).toMatchObject({ type: "session", url });
    expect(await client.next()).toEqual({ type: "producer", connected: true });

    replacementProducer.socket.close(1000, "gone");
    expect(await client.next()).toEqual({ type: "producer", connected: false });
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(code))).toBe(true);
    expect(await client.next()).toEqual({ type: "closed", message: "Session expired" });
    expect((await SELF.fetch(url)).status).toBe(404);
  });
});
