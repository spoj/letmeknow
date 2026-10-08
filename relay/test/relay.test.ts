import { SELF, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

const origin = "https://letmeknow.dev";
const APPLICATION = 1;
const COMMIT = 3;

const hex = (bytes: number) => randomBytes(bytes).toString("hex");

function mls(gid: string, epoch: number, contentType: number, body = 16): Uint8Array {
  const id = new TextEncoder().encode(gid);
  const data = new Uint8Array(4 + 1 + id.length + 8 + 1 + body);
  const view = new DataView(data.buffer);
  view.setUint16(0, 1);
  view.setUint16(2, 2);
  data[4] = id.length;
  data.set(id, 5);
  view.setBigUint64(5 + id.length, BigInt(epoch));
  data[13 + id.length] = contentType;
  data.set(randomBytes(16), 14 + id.length);
  return data;
}

const post = (gid: string, body: Uint8Array) =>
  SELF.fetch(`${origin}/g/${gid}/messages`, { method: "POST", body });

const poll = (gid: string, after: number) =>
  SELF.fetch(`${origin}/g/${gid}/messages?after=${after}`).then(r => r.json<any[]>());

async function subscribe(path: string) {
  const socket = (await SELF.fetch(`${origin}${path}`, { headers: { Upgrade: "websocket" } })).webSocket!;
  socket.accept();
  const next = () => new Promise<string>(resolve => socket.addEventListener("message", e => resolve(e.data as string), { once: true }));
  return { socket, next };
}

describe("group", () => {
  it("accepts messages for the current epoch only; a commit moves it on", async () => {
    const gid = hex(16);
    expect(await (await post(gid, mls(gid, 0, COMMIT))).json()).toEqual({ seq: 1 });
    const stale = await post(gid, mls(gid, 0, COMMIT));
    expect(stale.status).toBe(409);
    expect(await stale.json()).toEqual({ epoch: 1 });
    expect((await post(gid, mls(gid, 0, APPLICATION))).status).toBe(409);
    expect(await (await post(gid, mls(gid, 1, APPLICATION))).json()).toEqual({ seq: 2 });
    expect(await (await post(gid, mls(gid, 1, COMMIT))).json()).toEqual({ seq: 3 });
  });

  it("rejects foreign or malformed messages", async () => {
    const gid = hex(16);
    expect((await post(gid, mls(hex(16), 0, COMMIT))).status).toBe(400);
    expect((await post(gid, new Uint8Array([1, 2, 3]))).status).toBe(400);
  });

  it("returns messages after a cursor", async () => {
    const gid = hex(16);
    const first = mls(gid, 0, COMMIT);
    await post(gid, first);
    await post(gid, mls(gid, 1, APPLICATION));

    const all = await poll(gid, 0);
    expect(all.map(m => m.seq)).toEqual([1, 2]);
    expect(Buffer.from(all[0].data, "base64")).toEqual(Buffer.from(first));
    expect(await poll(gid, 2)).toEqual([]);
    expect((await SELF.fetch(`${origin}/g/${gid}/messages?after=2&wait=30`)).status).toBe(410);
  });

  it("caps messages at 1 MiB and pages at 2 MiB", async () => {
    const gid = hex(16);
    expect((await post(gid, mls(gid, 0, APPLICATION, 1024 * 1024))).status).toBe(413);
    for (let i = 0; i < 3; i++) await post(gid, mls(gid, 0, APPLICATION, 800 * 1024));
    expect((await poll(gid, 0)).map(m => m.seq)).toEqual([1, 2]);
    expect((await poll(gid, 2)).map(m => m.seq)).toEqual([3]);
  });

  it("notifies websockets of new messages and answers pings", async () => {
    const gid = hex(16);
    const { socket, next } = await subscribe(`/g/${gid}/ws`);
    let message = next();
    await post(gid, mls(gid, 0, COMMIT));
    expect(await message).toBe("1");
    message = next();
    socket.send("ping");
    expect(await message).toBe("pong");
    socket.close();
  });

  it("puts a small message in the notice of sockets that ask for messages", async () => {
    const gid = hex(16);
    const bare = await subscribe(`/g/${gid}/ws`);
    const full = await subscribe(`/g/${gid}/ws?messages`);
    let [seq, notice] = [bare.next(), full.next()];
    const small = mls(gid, 0, APPLICATION);
    await post(gid, small);
    expect(await seq).toBe("1");
    const frame = JSON.parse(await notice);
    expect(frame.seq).toBe(1);
    expect(frame.at).toBeGreaterThan(0);
    expect(Buffer.from(frame.data, "base64")).toEqual(Buffer.from(small));
    [seq, notice] = [bare.next(), full.next()];
    await post(gid, mls(gid, 0, APPLICATION, 64 * 1024));
    expect(await seq).toBe("2");
    expect(JSON.parse(await notice)).toEqual({ seq: 2, at: expect.any(Number) });
    bare.socket.close();
    full.socket.close();
  });


  it("expires old messages but keeps the epoch", async () => {
    const gid = hex(16);
    await post(gid, mls(gid, 0, COMMIT));
    const stub = env.GROUPS.get(env.GROUPS.idFromName(gid));
    await runInDurableObject(stub, async (_, state) => {
      state.storage.sql.exec("UPDATE messages SET at = 0");
    });
    await runDurableObjectAlarm(stub);
    expect(await poll(gid, 0)).toEqual([]);
    expect((await post(gid, mls(gid, 0, COMMIT))).status).toBe(409);
  });
});

describe("blob", () => {
  const sha256 = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");
  const put = (gid: string, hash: string, body: Uint8Array) => SELF.fetch(`${origin}/g/${gid}/blobs/${hash}`, { method: "PUT", body });
  const get = (gid: string, hash: string) => SELF.fetch(`${origin}/g/${gid}/blobs/${hash}`);
  const keep = (gid: string, hash: string) => SELF.fetch(`${origin}/g/${gid}/blobs/${hash}`, { method: "POST" });
  const age = (gid: string) =>
    runInDurableObject(env.GROUPS.get(env.GROUPS.idFromName(gid)), async (_, state) => {
      state.storage.sql.exec("UPDATE blobs SET at = 0");
    });

  it("stores a blob under the SHA-256 of its bytes, in its group only", async () => {
    const gid = hex(16);
    const data = randomBytes(1000);
    expect((await put(gid, sha256(data), data)).status).toBe(204);
    expect(Buffer.from(await (await get(gid, sha256(data))).arrayBuffer())).toEqual(data);
    expect((await get(hex(16), sha256(data))).status).toBe(404);
    expect((await get(gid, sha256(randomBytes(8)))).status).toBe(404);
  });

  it("refuses a blob that does not match its hash, or is over 10 MiB sealed", async () => {
    const gid = hex(16);
    expect((await put(gid, sha256(randomBytes(8)), randomBytes(8))).status).toBe(400);
    const large = new Uint8Array(10 * 1024 * 1024 + 29);
    expect((await put(gid, sha256(large), large)).status).toBe(413);
    const largest = Buffer.from(new Uint8Array(10 * 1024 * 1024 + 28).map((_, i) => i % 251));
    expect((await put(gid, sha256(largest), largest)).status).toBe(204);
    expect(Buffer.from(await (await get(gid, sha256(largest))).arrayBuffer()).equals(largest)).toBe(true);
  });

  it("expires blobs with the messages, unless put again or kept since", async () => {
    const gid = hex(16);
    const [kept, put_again, dropped] = [randomBytes(64), randomBytes(64), randomBytes(64)];
    await put(gid, sha256(kept), kept);
    await put(gid, sha256(put_again), put_again);
    await put(gid, sha256(dropped), dropped);
    await age(gid);
    expect((await keep(gid, sha256(kept))).status).toBe(204);
    await put(gid, sha256(put_again), put_again);
    expect((await keep(gid, sha256(randomBytes(64)))).status).toBe(404);
    await runDurableObjectAlarm(env.GROUPS.get(env.GROUPS.idFromName(gid)));
    expect((await get(gid, sha256(dropped))).status).toBe(404);
    expect((await keep(gid, sha256(dropped))).status).toBe(404);
    expect((await get(gid, sha256(put_again))).status).toBe(200);
    expect(Buffer.from(await (await get(gid, sha256(kept))).arrayBuffer())).toEqual(kept);
    await age(gid);
    await runDurableObjectAlarm(env.GROUPS.get(env.GROUPS.idFromName(gid)));
    expect((await get(gid, sha256(kept))).status).toBe(404);
  });
});

describe("invite", () => {
  const owner = hex(32);
  const create = (id: string, ttl = 600) =>
    SELF.fetch(`${origin}/i/${id}`, { method: "PUT", body: JSON.stringify({ ttl, owner, pake: "a" }) });
  const send = (id: string, action: string, data: string, token?: string) =>
    SELF.fetch(`${origin}/i/${id}/${action}`, {
      method: "POST",
      body: JSON.stringify({ data }),
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });

  it("shows join instructions to plain GETs", async () => {
    const response = await SELF.fetch(`${origin}/i/417`);
    expect(await response.text()).toContain("letmeknow join");
  });

  it("only accepts short slot numbers", async () => {
    for (const id of ["0", "1000", "07", hex(16)]) expect((await create(id)).status).toBe(404);
  });

  it("carries the inviter's pake message, one join and one welcome", async () => {
    const id = "1";
    expect((await create(id)).status).toBe(201);
    expect((await create(id)).status).toBe(409);

    const receive = (action: string, wait = 0) =>
      SELF.fetch(`${origin}/i/${id}/${action}?wait=${wait}`).then(r => r.status === 204 ? null : r.json());

    expect(await receive("pake")).toEqual({ data: "a" });
    expect(await receive("join")).toBeNull();
    const join = receive("join", 10);
    expect((await send(id, "join", "kp")).status).toBe(204);
    expect(await join).toEqual({ data: "kp" });
    expect((await send(id, "join", "again")).status).toBe(409);

    expect((await send(id, "welcome", "w")).status).toBe(403);
    expect((await send(id, "welcome", "w", owner)).status).toBe(204);
    expect(await receive("welcome")).toEqual({ data: "w" });
  });

  it("refuses bodies that are not the JSON it expects", async () => {
    const id = "2";
    for (const body of ["{", "null"]) expect((await SELF.fetch(`${origin}/i/${id}`, { method: "PUT", body })).status).toBe(400);
    await create(id);
    for (const body of ["{", "null"]) expect((await SELF.fetch(`${origin}/i/${id}/join`, { method: "POST", body })).status).toBe(400);
  });

  it("disappears at expiry, freeing the slot", async () => {
    const id = "999";
    await create(id);
    await runDurableObjectAlarm(env.INVITES.get(env.INVITES.idFromName(id)));
    expect((await send(id, "join", "kp")).status).toBe(404);
    expect((await create(id)).status).toBe(201);
  });
});

describe("box", () => {
  const append = (id: string, data: string) => SELF.fetch(`${origin}/b/${id}`, { method: "POST", body: data }).then(r => r.json());
  const read = (id: string, after: number, wait = 0) =>
    SELF.fetch(`${origin}/b/${id}?after=${after}&wait=${wait}`).then(r => r.json<any[]>());

  it("keeps entries in the order it took them, with the time it took them", async () => {
    const id = hex(16);
    expect(await append(id, "a")).toEqual({ seq: 1 });
    expect(await append(id, "b")).toEqual({ seq: 2 });
    const entries = await read(id, 0);
    expect(entries.map(e => Buffer.from(e.data, "base64").toString())).toEqual(["a", "b"]);
    expect(entries[0].at).toBeGreaterThan(0);
    expect(await read(id, 2)).toEqual([]);
  });

  it("holds a read until an entry arrives", async () => {
    const id = hex(16);
    const waiting = read(id, 0, 10);
    await append(id, "late");
    expect((await waiting).map(e => e.seq)).toEqual([1]);
  });

  it("announces each new entry, with the entry, on its sockets", async () => {
    const id = hex(16);
    const { socket, next } = await subscribe(`/b/${id}/ws`);
    let message = next();
    await append(id, "a");
    const frame = JSON.parse(await message);
    expect([frame.seq, Buffer.from(frame.data, "base64").toString()]).toEqual([1, "a"]);
    expect(frame.at).toBeGreaterThan(0);
    message = next();
    socket.send("ping");
    expect(await message).toBe("pong");
    expect((await SELF.fetch(`${origin}/b/${id}/ws`)).status).toBe(426);
    socket.close();
  });
});

describe("page", () => {
  const html = { headers: { Accept: "text/html,application/xhtml+xml" } };

  it("serves the browser client to browsers, under a policy that loads only this origin's scripts", async () => {
    for (const path of ["/", "/i/417"]) {
      const response = await SELF.fetch(`${origin}${path}`, html);
      expect(response.headers.get("Content-Type")).toContain("text/html");
      expect(response.headers.get("Content-Security-Policy")).toContain("script-src 'self' 'wasm-unsafe-eval'");
      expect(response.headers.get("Cache-Control")).toContain("no-transform");
      expect(await response.text()).toContain('src="/assets/app.js"');
    }
  });

  it("still carries the agent instructions, for tools that read the page", async () => {
    const page = await (await SELF.fetch(`${origin}/i/417`, html)).text();
    expect(page).toContain("letmeknow join '&lt;link&gt;'");
    expect(await (await SELF.fetch(`${origin}/`)).text()).toContain("end-to-end encrypted group chat for agents");
  });
});
