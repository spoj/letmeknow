import { SELF, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

const origin = "https://letmeknow.dev";
const APPLICATION = 1;
const COMMIT = 3;

const hex = (bytes: number) => randomBytes(bytes).toString("hex");

function mls(gid: string, epoch: number, contentType: number): Uint8Array {
  const id = new TextEncoder().encode(gid);
  const data = new Uint8Array(4 + 1 + id.length + 8 + 1 + 16);
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

function frames(socket: WebSocket) {
  socket.accept();
  const queued: any[] = [];
  const waiting: Array<(frame: any) => void> = [];
  socket.addEventListener("message", event => {
    const frame = JSON.parse(event.data as string);
    const resolve = waiting.shift();
    if (resolve) resolve(frame);
    else queued.push(frame);
  });
  return () => queued.length ? Promise.resolve(queued.shift()) : new Promise<any>(resolve => waiting.push(resolve));
}

async function connect(path: string) {
  const response = await SELF.fetch(`${origin}${path}`, { headers: { Upgrade: "websocket" } });
  expect(response.status).toBe(101);
  return frames(response.webSocket!);
}

describe("group", () => {
  it("accepts one commit per epoch and any application message", async () => {
    const gid = hex(16);
    expect(await (await post(gid, mls(gid, 0, COMMIT))).json()).toEqual({ seq: 1 });
    const stale = await post(gid, mls(gid, 0, COMMIT));
    expect(stale.status).toBe(409);
    expect(await stale.json()).toEqual({ epoch: 1 });
    expect(await (await post(gid, mls(gid, 0, APPLICATION))).json()).toEqual({ seq: 2 });
    expect(await (await post(gid, mls(gid, 1, COMMIT))).json()).toEqual({ seq: 3 });
  });

  it("rejects foreign or malformed messages", async () => {
    const gid = hex(16);
    expect((await post(gid, mls(hex(16), 0, COMMIT))).status).toBe(400);
    expect((await post(gid, new Uint8Array([1, 2, 3]))).status).toBe(400);
  });

  it("replays after a cursor, then streams live", async () => {
    const gid = hex(16);
    const first = mls(gid, 0, COMMIT);
    await post(gid, first);
    await post(gid, mls(gid, 1, APPLICATION));

    const listed = await (await SELF.fetch(`${origin}/g/${gid}/messages?after=1`)).json<any[]>();
    expect(listed.map(m => m.seq)).toEqual([2]);

    const next = await connect(`/g/${gid}/ws?after=0`);
    const replayed = await next();
    expect(replayed.seq).toBe(1);
    expect(Buffer.from(replayed.data, "base64")).toEqual(Buffer.from(first));
    expect((await next()).seq).toBe(2);
    expect(await next()).toEqual({ synced: true });
    await post(gid, mls(gid, 1, APPLICATION));
    expect((await next()).seq).toBe(3);
  });

  it("expires old messages but keeps the epoch", async () => {
    const gid = hex(16);
    await post(gid, mls(gid, 0, COMMIT));
    const stub = env.GROUPS.get(env.GROUPS.idFromName(gid));
    await runInDurableObject(stub, async (_, state) => {
      state.storage.sql.exec("UPDATE messages SET at = 0");
    });
    await runDurableObjectAlarm(stub);
    expect(await (await SELF.fetch(`${origin}/g/${gid}/messages`)).json()).toEqual([]);
    expect((await post(gid, mls(gid, 0, COMMIT))).status).toBe(409);
  });
});

describe("invite", () => {
  const owner = hex(32);
  const create = (id: string, ttl = 600) =>
    SELF.fetch(`${origin}/i/${id}`, { method: "PUT", body: JSON.stringify({ ttl, owner }) });
  const send = (id: string, action: string, data: string, token?: string) =>
    SELF.fetch(`${origin}/i/${id}/${action}`, {
      method: "POST",
      body: JSON.stringify({ data }),
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });

  it("shows join instructions to plain GETs", async () => {
    const response = await SELF.fetch(`${origin}/i/${hex(16)}`);
    expect(await response.text()).toContain("letmeknow join");
  });

  it("carries one join and one welcome", async () => {
    const id = hex(16);
    expect((await create(id)).status).toBe(201);
    expect((await create(id)).status).toBe(409);

    const inviter = await connect(`/i/${id}/ws?role=inviter`);
    expect((await send(id, "join", "kp")).status).toBe(204);
    expect(await inviter()).toEqual({ join: "kp" });
    expect((await send(id, "join", "again")).status).toBe(409);

    expect((await send(id, "welcome", "w")).status).toBe(403);
    expect((await send(id, "welcome", "w", owner)).status).toBe(204);
    const joiner = await connect(`/i/${id}/ws?role=joiner`);
    expect(await joiner()).toEqual({ welcome: "w" });
  });

  it("disappears at expiry", async () => {
    const id = hex(16);
    await create(id);
    await runDurableObjectAlarm(env.INVITES.get(env.INVITES.idFromName(id)));
    expect((await send(id, "join", "kp")).status).toBe(404);
  });
});
