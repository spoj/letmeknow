import { SELF, runDurableObjectAlarm } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { Session } from "../src/index";
import { afterEach, describe, expect, it, vi } from "vitest";

type Event = Record<string, unknown>;
type Producer = {
  socket: WebSocket;
  credential?: string;
  next(): Promise<Event>;
  send(packet: Record<string, unknown>): void;
};

const origin = "https://client.example";
const sockets: WebSocket[] = [];
let ipCounter = 0;

async function connect(base = origin, auth?: { code: string; credential: string }): Promise<Producer> {
  const endpoint = new URL(`${base}/v1/connect`);
  const headers: Record<string, string> = {
    Upgrade: "websocket",
    "CF-Connecting-IP": `192.0.2.${++ipCounter}`
  };
  if (auth) headers["Sec-WebSocket-Protocol"] = auth.credential;
  if (auth) endpoint.searchParams.set("code", auth.code);
  const response = await SELF.fetch(new Request(endpoint, { headers }));
  expect(response.status).toBe(101);
  expect(response.headers.get("Sec-WebSocket-Protocol")).toBe(auth?.credential || null);
  const socket = response.webSocket!;
  socket.accept();
  sockets.push(socket);

  const queued: Event[] = [];
  const waiting: Array<(event: Event) => void> = [];
  let credential: string | undefined;
  socket.addEventListener("message", (message) => {
    const event = JSON.parse(message.data as string) as Event;
    if (event.type === "credential") {
      credential = event.credential as string;
      return;
    }
    const resolve = waiting.shift();
    if (resolve) resolve(event);
    else queued.push(event);
  });
  return {
    socket,
    get credential() { return credential; },
    next: () => {
      const event = queued.shift();
      return event ? Promise.resolve(event) : new Promise((resolve) => waiting.push(resolve));
    },
    send: (packet) => socket.send(JSON.stringify(packet))
  };
}

async function open(base = origin): Promise<{ producer: Producer; url: string }> {
  const producer = await connect(base);
  producer.send({ type: "open", id: "open-1" });
  const event = await producer.next();
  expect(event).toMatchObject({
    type: "session",
    id: "open-1",
    expires_after_disconnect: 600
  });
  return { producer, url: event.url as string };
}

async function reconnect(url: string, producer: Producer): Promise<Producer> {
  const publicUrl = new URL(url);
  const code = publicUrl.hostname.match(/^([a-f0-9]{20})\.letmeknow\.dev$/)?.[1]
    || publicUrl.pathname.match(/^\/s\/([a-f0-9]{20})\//)?.[1];
  expect(code).toBeDefined();
  expect(producer.credential).toBeDefined();
  const base = publicUrl.hostname.match(/^[a-f0-9]{20}\.letmeknow\.dev$/) ? "https://letmeknow.dev" : origin;
  const replacement = await connect(base, { code: code!, credential: producer.credential! });
  expect(await replacement.next()).toMatchObject({ type: "session", url });
  return replacement;
}

function path(url: string, pathname: string): string {
  return new URL(pathname.replace(/^\//, ""), url).toString();
}

afterEach(() => {
  for (const socket of sockets.splice(0)) socket.close(1000, "test complete");
});

describe("LetMeKnow agent web surface", () => {
  it("documents the NDJSON transport and requires a WebSocket upgrade", async () => {
    const home = await SELF.fetch(`${origin}/`);
    expect(home.status).toBe(200);
    expect(home.headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
    expect(await home.text()).toContain('{"type":"open"}');
    const apex = await SELF.fetch("https://letmeknow.dev/");
    expect(apex.status).toBe(200);
    expect(await apex.text()).toContain("LETMEKNOW_URL=https://letmeknow.dev");

    const connectResponse = await SELF.fetch(`${origin}/v1/connect`);
    expect(connectResponse.status).toBe(426);
    expect(await connectResponse.json()).toEqual({ error: "websocket upgrade required" });

    const dottedApexConnect = await SELF.fetch("https://letmeknow.dev./v1/connect");
    expect(dottedApexConnect.status).toBe(426);

    const queryCredential = await SELF.fetch(`${origin}/v1/connect?credential=private`, {
      headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": "letmeknow" }
    });
    expect(queryCredential.status).toBe(401);
  });

  it("uses an isolated production host and the path form in local environments", async () => {
    const local = await open();
    expect(local.url).toMatch(/^https:\/\/client\.example\/s\/[a-f0-9]{20}\/$/);

    const production = await open("https://letmeknow.dev");
    expect(production.url).toMatch(/^https:\/\/[a-f0-9]{20}\.letmeknow\.dev\/$/);
    production.producer.send({ type: "put", path: "/", body: "stored root" });
    await production.producer.next();
    expect(await (await SELF.fetch(production.url)).text()).toBe("stored root");
    const dottedSessionUrl = new URL(production.url);
    dottedSessionUrl.hostname += ".";
    expect(await (await SELF.fetch(dottedSessionUrl)).text()).toBe("stored root");

    const code = new URL(production.url).hostname.split(".")[0];
    const apexPath = await SELF.fetch(`https://letmeknow.dev/s/${code}/`);
    expect(apexPath.status).toBe(404);
    const productionPath = await SELF.fetch(`https://preview.letmeknow.dev/s/${code}/`);
    expect(productionPath.status).toBe(404);
    const dottedProductionPath = await SELF.fetch(`https://preview.letmeknow.dev./s/${code}/`);
    expect(dottedProductionPath.status).toBe(404);
    const productionConnect = await SELF.fetch("https://preview.letmeknow.dev/v1/connect");
    expect(productionConnect.status).toBe(404);

    production.producer.send({ type: "delete", path: "/" });
    await production.producer.next();
    const dynamic = SELF.fetch(production.url);
    const request = await production.producer.next();
    expect(request).toMatchObject({ type: "request", method: "GET", path: "/" });
    production.producer.send({ type: "response", request_id: request.id, body: "dynamic root" });
    await production.producer.next();
    expect(await (await dynamic).text()).toBe("dynamic root");

    production.producer.send({ type: "put", path: "/app.js", body: "root relative works" });
    await production.producer.next();
    expect(await (await SELF.fetch(new URL("/app.js", production.url))).text()).toBe("root relative works");

    production.producer.send({ type: "put", path: "/v1/connect", body: "stored connect path" });
    await production.producer.next();
    expect(await (await SELF.fetch(new URL("/v1/connect", production.url))).text()).toBe("stored connect path");

    production.producer.send({ type: "delete", path: "/v1/connect" });
    await production.producer.next();
    const dynamicConnect = SELF.fetch(new URL("/v1/connect", production.url));
    const connectRequest = await production.producer.next();
    expect(connectRequest).toMatchObject({ type: "request", method: "GET", path: "/v1/connect" });
    production.producer.send({ type: "response", request_id: connectRequest.id, body: "dynamic connect path" });
    await production.producer.next();
    expect(await (await dynamicConnect).text()).toBe("dynamic connect path");
  });

  it("redirects production HTTP requests to HTTPS without redirecting local hosts", async () => {
    const apex = await SELF.fetch(new Request("http://letmeknow.dev/form?step=2", {
      method: "POST",
      body: "answer=yes",
      redirect: "manual"
    }));
    expect(apex.status).toBe(308);
    expect(apex.headers.get("Location")).toBe("https://letmeknow.dev/form?step=2");

    const publicHost = await SELF.fetch(new Request("http://0123456789abcdef0123.letmeknow.dev/v1/connect?step=2", {
      method: "POST",
      body: "answer=yes",
      redirect: "manual"
    }));
    expect(publicHost.status).toBe(308);
    expect(publicHost.headers.get("Location")).toBe("https://0123456789abcdef0123.letmeknow.dev/v1/connect?step=2");

    const arbitraryProductionHost = await SELF.fetch(new Request("http://preview.letmeknow.dev/v1/connect", {
      redirect: "manual"
    }));
    expect(arbitraryProductionHost.status).toBe(308);
    expect(arbitraryProductionHost.headers.get("Location")).toBe("https://preview.letmeknow.dev/v1/connect");

    const dottedProductionHost = await SELF.fetch(new Request("http://preview.letmeknow.dev./anything", {
      redirect: "manual"
    }));
    expect(dottedProductionHost.status).toBe(308);
    expect(dottedProductionHost.headers.get("Location")).toBe("https://preview.letmeknow.dev./anything");

    const local = await SELF.fetch(new Request("http://localhost/v1/connect", {
      method: "POST",
      body: "answer=yes",
      redirect: "manual"
    }));
    expect(local.status).toBe(426);
  });

  it("stores, replaces, and deletes exact paths with ordinary commands", async () => {
    const { producer, url } = await open();

    producer.send({
      type: "put",
      id: "put-1",
      path: "/index.html",
      content_type: "text/html; charset=utf-8",
      headers: {
        "content-type": "text/plain",
        "set-cookie": ["first=1; Path=/", "second=2; Path=/"],
        "x-repeat": ["one", "two"]
      },
      body: "<h1>First</h1>"
    });
    expect(await producer.next()).toEqual({ type: "ack", id: "put-1" });

    const first = await SELF.fetch(path(url, "/index.html?view=full"));
    expect(first.status).toBe(200);
    expect(first.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(first.headers.getSetCookie()).toEqual(["first=1; Path=/", "second=2; Path=/"]);
    expect(first.headers.get("X-Repeat")).toBe("one, two");
    expect(first.headers.get("Cache-Control")).toBe("no-store");
    expect(await first.text()).toBe("<h1>First</h1>");

    producer.send({ type: "put", id: "put-2", path: "/index.html", status: 201, body: "Second" });
    expect(await producer.next()).toEqual({ type: "ack", id: "put-2" });
    const replaced = await SELF.fetch(path(url, "/index.html"));
    expect(replaced.status).toBe(201);
    expect(await replaced.text()).toBe("Second");

    producer.send({ type: "delete", id: "delete-1", path: "/index.html" });
    expect(await producer.next()).toEqual({ type: "ack", id: "delete-1" });

    const waiting = SELF.fetch(path(url, "/index.html"));
    expect(await producer.next()).toMatchObject({ type: "request", method: "GET", path: "/index.html" });
    producer.send({ type: "response", request_id: "missing", body: "no" });
    expect(await producer.next()).toMatchObject({ type: "error", message: "request is not pending" });
    producer.socket.close(1000, "done");
    expect((await waiting).status).toBe(503);
  });

  it("supports base64 resources", async () => {
    const { producer, url } = await open();
    producer.send({
      type: "put",
      id: "image",
      path: "/pixel.bin",
      content_type: "application/octet-stream",
      encoding: "base64",
      body: "AAEC/w=="
    });
    expect(await producer.next()).toEqual({ type: "ack", id: "image" });

    const response = await SELF.fetch(path(url, "/pixel.bin"));
    expect([...new Uint8Array(await response.arrayBuffer())]).toEqual([0, 1, 2, 255]);
  });

  it("forwards forms and returns arbitrary dynamic responses without storing them", async () => {
    const { producer, url } = await open();
    const browserResponse = SELF.fetch(path(url, "/answer?step=2"), {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Cookie: "visitor=abc",
        "HX-Request": "true"
      },
      body: "answer=yes"
    });

    const request = await producer.next();
    expect(request).toMatchObject({
      type: "request",
      method: "POST",
      path: "/answer",
      query: "step=2",
      encoding: "utf8",
      body: "answer=yes"
    });
    expect(request.headers).toMatchObject({
      "content-type": "application/x-www-form-urlencoded",
      cookie: "visitor=abc",
      "hx-request": "true"
    });

    producer.send({
      type: "response",
      id: "response-1",
      request_id: request.id,
      status: 202,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "hx-trigger": "answered",
        "set-cookie": ["done=yes; Path=/; Secure", "theme=dark; Path=/; Secure"]
      },
      body: "<strong>Accepted</strong>"
    });
    expect(await producer.next()).toEqual({ type: "ack", id: "response-1" });

    const response = await browserResponse;
    expect(response.status).toBe(202);
    expect(response.headers.get("HX-Trigger")).toBe("answered");
    expect(response.headers.getSetCookie()).toEqual(["done=yes; Path=/; Secure", "theme=dark; Path=/; Secure"]);
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(await response.text()).toBe("<strong>Accepted</strong>");

    const secondBrowserResponse = SELF.fetch(path(url, "/answer?step=3"));
    const secondRequest = await producer.next();
    expect(secondRequest).toMatchObject({ type: "request", path: "/answer", query: "step=3" });
    producer.send({ type: "response", request_id: secondRequest.id, status: 204 });
    expect(await producer.next()).toEqual({ type: "ack" });
    expect((await secondBrowserResponse).status).toBe(204);
  });

  it("encodes valid browser bodies without a content type as base64", async () => {
    const { producer, url } = await open();
    const browserResponse = SELF.fetch(path(url, "/upload"), {
      method: "POST",
      body: new Uint8Array([0x68, 0xc3, 0xa9])
    });
    const request = await producer.next();
    expect(request).toMatchObject({ encoding: "base64", body: "aMOp" });
    producer.send({ type: "response", request_id: request.id, body: "ok" });
    await producer.next();
    expect(await (await browserResponse).text()).toBe("ok");
  });

  it("preserves invalid UTF-8 browser bodies without a content type", async () => {
    const { producer, url } = await open();
    const browserResponse = SELF.fetch(path(url, "/upload"), {
      method: "POST",
      body: new Uint8Array([0xc3, 0x28])
    });
    const request = await producer.next();
    expect(request).toMatchObject({ encoding: "base64", body: "wyg=" });
    producer.send({ type: "response", request_id: request.id, body: "ok" });
    await producer.next();
    expect(await (await browserResponse).text()).toBe("ok");
  });

  it("falls back to base64 for invalid UTF-8 with a textual content type", async () => {
    const { producer, url } = await open();
    const browserResponse = SELF.fetch(path(url, "/upload"), {
      method: "POST",
      headers: { "Content-Type": "TEXT/PLAIN; charset=UTF-8" },
      body: new Uint8Array([0xc3, 0x28])
    });
    const request = await producer.next();
    expect(request).toMatchObject({ encoding: "base64", body: "wyg=" });
    producer.send({ type: "response", request_id: request.id, body: "ok" });
    await producer.next();
    expect(await (await browserResponse).text()).toBe("ok");
  });

  it("preserves a UTF-8 BOM for textual media types", async () => {
    const { producer, url } = await open();
    const browserResponse = SELF.fetch(path(url, "/bom"), {
      method: "POST",
      headers: { "Content-Type": "text/plain; charset=utf-8" },
      body: new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69])
    });
    const request = await producer.next();
    expect(request).toMatchObject({ encoding: "utf8", body: "\ufeffhi" });
    producer.send({ type: "response", request_id: request.id, body: "ok" });
    await producer.next();
    expect(await (await browserResponse).text()).toBe("ok");
  });

  it("recognizes textual media types case-insensitively", async () => {
    const { producer, url } = await open();
    const browserResponse = SELF.fetch(path(url, "/json"), {
      method: "POST",
      headers: { "Content-Type": "Application/JSON; charset=UTF-8" },
      body: "{\"ok\":true}"
    });
    const request = await producer.next();
    expect(request).toMatchObject({ encoding: "utf8", body: "{\"ok\":true}" });
    producer.send({ type: "response", request_id: request.id, body: "ok" });
    await producer.next();
    expect(await (await browserResponse).text()).toBe("ok");
  });

  it("forwards binary browser bodies as base64", async () => {
    const { producer, url } = await open();
    const browserResponse = SELF.fetch(path(url, "/upload"), {
      method: "PUT",
      headers: { "Content-Type": "application/octet-stream" },
      body: new Uint8Array([0, 255, 7])
    });
    const request = await producer.next();
    expect(request).toMatchObject({ encoding: "base64", body: "AP8H" });
    producer.send({ type: "response", request_id: request.id, body: "ok" });
    await producer.next();
    expect(await (await browserResponse).text()).toBe("ok");
  });

  it("preserves empty command IDs in session and acknowledgements", async () => {
    const producer = await connect();
    producer.send({ type: "open", id: "" });
    expect(await producer.next()).toMatchObject({ type: "session", id: "" });
    producer.send({ type: "put", id: "", path: "/empty-id", body: "ok" });
    expect(await producer.next()).toEqual({ type: "ack", id: "" });
  });

  it("reports protocol errors and requires open first", async () => {
    const producer = await connect();
    producer.send({ type: "put", id: "early", path: "/", body: "no" });
    expect(await producer.next()).toEqual({ type: "error", id: "early", message: "open must be the first command" });

    producer.socket.send("not json");
    expect(await producer.next()).toEqual({ type: "error", message: "invalid JSON" });
  });

  it("destroys a session on explicit close", async () => {
    const { producer, url } = await open();
    producer.send({ type: "put", path: "/", body: "alive" });
    expect(await producer.next()).toEqual({ type: "ack" });
    expect(await (await SELF.fetch(url)).text()).toBe("alive");

    producer.send({ type: "close", id: "close-1" });
    producer.send({ type: "put", path: "/late", body: "must not be stored" });
    expect(await producer.next()).toEqual({ type: "ack", id: "close-1" });
    expect(await producer.next()).toEqual({ type: "closing" });

    const response = await SELF.fetch(url);
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "session not found" });
  });

  it("allows an authenticated reconnect without another open command", async () => {
    const { producer, url } = await open();
    expect(producer.credential).toMatch(/^[a-f0-9]{40}$/);
    expect(producer.credential).not.toBe(new URL(url).hostname.split(".")[0]);
    producer.send({ type: "put", path: "/before", body: "before" });
    await producer.next();
    producer.socket.close(1000, "temporary disconnect");
    await new Promise((resolve) => setTimeout(resolve, 20));

    const replacement = await reconnect(url, producer);
    replacement.send({ type: "put", path: "/after", body: "after" });
    expect(await replacement.next()).toEqual({ type: "ack" });
    expect(await (await SELF.fetch(path(url, "/before"))).text()).toBe("before");
    expect(await (await SELF.fetch(path(url, "/after"))).text()).toBe("after");
  });

  it("reconnects on an exact production session host", async () => {
    const { producer, url } = await open("https://letmeknow.dev");
    producer.socket.close(1000, "temporary disconnect");
    await new Promise((resolve) => setTimeout(resolve, 20));

    const replacement = await reconnect(url, producer);
    expect(new URL(url).hostname).toMatch(/^[a-f0-9]{20}\.letmeknow\.dev$/);
    replacement.socket.close(1000, "test complete");
  });

  it("cleans up and schedules grace after a reserved close code", async () => {
    const session = Object.create(Session.prototype) as {
      activeRequests: number;
      pending: Map<string, { resolve(response: Response): void; timer: ReturnType<typeof setTimeout>; head: boolean }>;
      ctx: { storage: { get(key: string): Promise<unknown>; setAlarm(when: number): Promise<void> } };
      webSocketClose(socket: WebSocket, code: number, reason: string): Promise<void>;
    };
    let resolved = false;
    let alarmAt: number | undefined;
    let closeArguments: unknown[] | undefined;
    session.activeRequests = 1;
    session.pending = new Map([[
      "request",
      { resolve: () => { resolved = true; }, timer: setTimeout(() => {}, 60_000), head: false }
    ]]);
    session.ctx = {
      storage: {
        get: async (key) => key === "opened",
        setAlarm: async (when) => { alarmAt = when; }
      }
    };
    const socket = {
      deserializeAttachment: () => ({ opened: true }),
      close: (...args: unknown[]) => { closeArguments = args; }
    } as unknown as WebSocket;

    await session.webSocketClose(socket, 1006, "abnormal closure");

    expect(resolved).toBe(true);
    expect(session.pending.size).toBe(0);
    expect(session.activeRequests).toBe(0);
    expect(alarmAt).toBeTypeOf("number");
    expect(closeArguments).toEqual([]);
  });

  it("handles a client close before reconnecting and expiring", async () => {
    const { producer, url } = await open();
    producer.socket.close(1000, "client disconnect");
    await new Promise((resolve) => setTimeout(resolve, 20));

    const replacement = await reconnect(url, producer);
    replacement.socket.close(1000, "client disconnect");
    await new Promise((resolve) => setTimeout(resolve, 100));

    const publicUrl = new URL(url);
    const code = publicUrl.hostname.match(/^([a-f0-9]{20})\.letmeknow\.dev$/)?.[1]
      || publicUrl.pathname.split("/")[2];
    expect(await runDurableObjectAlarm(env.SESSIONS.getByName(code))).toBe(true);
    expect((await SELF.fetch(url)).status).toBe(404);
  });

  it("closes unopened producers and rejects a late open after the deadline alarm", async () => {
    const code = "b".repeat(20);
    const credential = "unopened-test-credential";
    const stub = env.SESSIONS.getByName(code);
    const response = await stub.fetch(new Request(`${origin}/v1/connect`, {
      headers: {
        Upgrade: "websocket",
        "x-letmeknow-action": "connect",
        "x-letmeknow-url": `${origin}/s/${code}/`,
        "x-letmeknow-credential": credential
      }
    }));
    expect(response.status).toBe(101);
    const socket = response.webSocket!;
    socket.accept();
    sockets.push(socket);
    await runDurableObjectAlarm(stub);
    expect(socket.readyState).toBe(WebSocket.CLOSING);
    await new Promise((resolve) => setTimeout(resolve, 20));

    const late = await SELF.fetch(`${origin}/v1/connect?code=${code}`, {
      headers: { Upgrade: "websocket", "Sec-WebSocket-Protocol": credential }
    });
    expect(late.status).toBe(401);
  });

  it("serves stored resources during disconnect grace and expires by alarm", async () => {
    const { producer, url } = await open();
    producer.send({ type: "put", path: "/", body: "still here" });
    await producer.next();
    producer.socket.close(1000, "disconnect");
    await new Promise((resolve) => setTimeout(resolve, 20));

    const stored = await SELF.fetch(url);
    expect(stored.status).toBe(200);
    expect(await stored.text()).toBe("still here");

    const dynamic = await SELF.fetch(path(url, "/dynamic"));
    expect(dynamic.status).toBe(503);
    expect(await dynamic.json()).toEqual({ error: "producer disconnected" });

    const code = new URL(url).pathname.split("/")[2];
    const stub = env.SESSIONS.getByName(code);
    expect(await runDurableObjectAlarm(stub)).toBe(true);

    const expired = await SELF.fetch(url);
    expect(expired.status).toBe(404);
    expect(await expired.json()).toEqual({ error: "session not found" });
  });

  it("preserves explicit cache policy and enforces stored resource limits", async () => {
    const { producer, url } = await open();
    producer.send({ type: "put", path: "/public", headers: { "cache-control": "public, max-age=60" }, body: "public" });
    expect(await producer.next()).toEqual({ type: "ack" });
    const publicResponse = await SELF.fetch(path(url, "/public"));
    expect(publicResponse.headers.get("Cache-Control")).toBe("public, max-age=60");

    for (let index = 0; index < 98; index++) {
      producer.send({ type: "put", path: `/resource-${index}`, body: String(index) });
      expect(await producer.next()).toEqual({ type: "ack" });
    }
    producer.send({ type: "put", path: "/resource-99", body: "99" });
    expect(await producer.next()).toEqual({ type: "ack" });
    producer.send({ type: "put", id: "too-many", path: "/resource-100", body: "overflow" });
    expect(await producer.next()).toEqual({ type: "error", id: "too-many", message: "too many stored resources" });
    producer.send({ type: "delete", path: "/resource-0" });
    expect(await producer.next()).toEqual({ type: "ack" });
    producer.send({ type: "put", path: "/resource-100", body: "now fits" });
    expect(await producer.next()).toEqual({ type: "ack" });
  });

  it("accounts for decoded bytes when replacing stored resources", async () => {
    const { producer } = await open();
    const body = "x".repeat(1024 * 1024);
    for (let index = 0; index < 10; index++) {
      producer.send({ type: "put", path: `/large-${index}`, body });
      expect(await producer.next()).toEqual({ type: "ack" });
    }
    producer.send({ type: "put", id: "too-large", path: "/large-new", body });
    expect(await producer.next()).toEqual({ type: "error", id: "too-large", message: "stored resources are too large" });
    producer.send({ type: "put", path: "/large-0", body: "" });
    expect(await producer.next()).toEqual({ type: "ack" });
    producer.send({ type: "put", path: "/large-new", body });
    expect(await producer.next()).toEqual({ type: "ack" });
  });

  it("waits five minutes for producer responses before timing out", async () => {
    vi.useFakeTimers();
    try {
      const session = Object.create(Session.prototype) as {
        activeRequests: number;
        pending: Map<string, unknown>;
        ctx: {
          storage: { get(key: string): Promise<unknown> };
          getWebSockets(): Array<{ deserializeAttachment(): { opened: boolean }; send(message: string): void }>;
        };
        browserRequest(request: Request, timeoutMs?: number): Promise<Response>;
      };
      let sent: Event | undefined;
      session.activeRequests = 0;
      session.pending = new Map();
      session.ctx = {
        storage: {
          get: async (key: string) => key === "opened" ? true : undefined
        },
        getWebSockets: () => [{
          deserializeAttachment: () => ({ opened: true }),
          send: (message) => { sent = JSON.parse(message) as Event; }
        }]
      };

      const request = new Request("https://client.example/wait");
      request.headers.set("x-letmeknow-path", "/wait");
      const waiting = session.browserRequest(request);
      for (let index = 0; index < 5 && !sent; index += 1) await Promise.resolve();
      expect(sent).toMatchObject({ type: "request", path: "/wait" });

      let settled = false;
      waiting.then(() => { settled = true; });
      vi.advanceTimersByTime(5 * 60 * 1_000 - 1);
      await Promise.resolve();
      expect(settled).toBe(false);

      vi.advanceTimersByTime(1);
      const response = await waiting;
      expect(response.status).toBe(504);
      expect(await response.json()).toEqual({ error: "producer response timed out" });
      expect(session.activeRequests).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("times out stalled request bodies and releases their dynamic slots", async () => {
    const session = Object.create(Session.prototype) as {
      activeRequests: number;
      ctx: {
        storage: { get(key: string): Promise<unknown> };
        getWebSockets(): Array<{ deserializeAttachment(): { opened: boolean } }>;
      };
      browserRequest(request: Request, timeoutMs: number): Promise<Response>;
    };
    session.activeRequests = 0;
    session.ctx = {
      storage: {
        get: async (key: string) => key === "opened" ? true : undefined
      },
      getWebSockets: () => [{ deserializeAttachment: () => ({ opened: true }) }]
    };
    let cancelled = false;
    const stalledBody = new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      }
    });
    const request = new Request("https://client.example/stalled", {
      method: "POST",
      body: stalledBody,
      duplex: "half"
    } as RequestInit & { duplex: "half" });
    request.headers.set("x-letmeknow-path", "/stalled");

    const response = await session.browserRequest(request, 1);

    expect(response.status).toBe(408);
    expect(await response.json()).toEqual({ error: "request body timed out" });
    expect(cancelled).toBe(true);
    expect(session.activeRequests).toBe(0);
  });

  it("rejects an already-aborted body before forwarding and releases its slot once", async () => {
    const session = Object.create(Session.prototype) as {
      activeRequests: number;
      ctx: {
        storage: { get(key: string): Promise<unknown> };
        getWebSockets(): Array<{ deserializeAttachment(): { opened: boolean }; send(): void }>;
      };
      browserRequest(request: Request, timeoutMs: number): Promise<Response>;
    };
    session.activeRequests = 0;
    let sent = 0;
    session.ctx = {
      storage: {
        get: async (key: string) => key === "opened" ? true : undefined
      },
      getWebSockets: () => [{
        deserializeAttachment: () => ({ opened: true }),
        send: () => { sent++; }
      }]
    };
    let cancellations = 0;
    const body = new ReadableStream<Uint8Array>({
      cancel() {
        cancellations++;
      }
    });
    const controller = new AbortController();
    controller.abort();
    const request = new Request("https://client.example/already-aborted", {
      method: "POST",
      body,
      signal: controller.signal,
      duplex: "half"
    } as RequestInit & { duplex: "half" });
    request.headers.set("x-letmeknow-path", "/already-aborted");

    const response = await session.browserRequest(request, 30_000);

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "request body cancelled" });
    expect(sent).toBe(0);
    expect(cancellations).toBe(1);
    expect(session.activeRequests).toBe(0);
  });

  it("limits dynamic request bodies and concurrent requests", async () => {
    const { producer, url } = await open();
    const tooLarge = await SELF.fetch(path(url, "/too-large"), {
      method: "POST",
      headers: { "Content-Length": String(1024 * 1024 + 1) },
      body: "small"
    });
    expect(tooLarge.status).toBe(413);

    const browserRequests: Promise<Response>[] = [];
    const requests: Event[] = [];
    for (let index = 0; index < 32; index++) {
      browserRequests.push(SELF.fetch(path(url, `/pending-${index}`)));
      requests.push(await producer.next());
    }
    expect(await SELF.fetch(path(url, "/pending-32"))).toMatchObject({ status: 503 });
    for (const request of requests) {
      producer.send({ type: "response", request_id: request.id, body: "ok" });
      expect(await producer.next()).toEqual({ type: "ack" });
    }
    const responses = await Promise.all(browserRequests);
    expect(responses.every((response) => response.status === 200)).toBe(true);

    const afterRelease = SELF.fetch(path(url, "/after-release"));
    const request = await producer.next();
    producer.send({ type: "response", request_id: request.id, body: "released" });
    await producer.next();
    expect(await (await afterRelease).text()).toBe("released");
  });
});
