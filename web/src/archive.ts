type Block = { raw: number; refs: number; owner: string; size: number; children: string[] };
type Pins = [string, string | null][];
let archive: Promise<IDBDatabase> | undefined;

function database(): Promise<IDBDatabase> {
  return archive ??= new Promise((resolve, reject) => {
    const request = indexedDB.open("lmk-epoch-archive-0.16", 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      db.createObjectStore("blocks");
      const nodes = db.createObjectStore("nodes");
      nodes.createIndex("owner", "owner");
      nodes.createIndex("garbage", ["owner", "refs"]);
      db.createObjectStore("pins");
      const usage = db.createObjectStore("usage");
      usage.put(0, 0);
      usage.put(0, 1);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function done<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function change<T>(work: (tx: IDBTransaction) => Promise<T>): Promise<T> {
  const tx = (await database()).transaction(["blocks", "nodes", "pins", "usage"], "readwrite", { durability: "strict" });
  const finished = new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(new Error("Epoch archive transaction aborted", { cause: tx.error }));
  });
  const result = work(tx).catch(error => { if (!tx.error) tx.abort(); throw error; });
  return (await Promise.all([result, finished]))[0];
}

function visit(request: IDBRequest<IDBCursorWithValue | null>, each: (cursor: IDBCursorWithValue) => Promise<boolean>): Promise<void> {
  return new Promise((resolve, reject) => {
    request.onerror = () => reject(request.error);
    request.onsuccess = async () => {
      const cursor = request.result;
      if (!cursor) { resolve(); return; }
      try {
        if (await each(cursor)) cursor.continue();
        else resolve();
      } catch (error) { reject(error); }
    };
  });
}

async function pin(tx: IDBTransaction, slot: string, root: string | null): Promise<void> {
  const pins = tx.objectStore("pins"), nodes = tx.objectStore("nodes");
  const old: string | undefined = await done(pins.get(slot));
  if (old === root || old === undefined && root === null) return;
  if (old !== undefined) {
    const node: Block = await done(nodes.get(old));
    node.refs--;
    await done(nodes.put(node, old));
    await done(pins.delete(slot));
  }
  if (root !== null) {
    const node: Block = await done(nodes.get(root));
    node.refs++;
    await done(nodes.put(node, root));
    await done(pins.put(root, slot));
  }
}

async function collect(): Promise<void> {
  while (await change(async tx => {
    const nodes = tx.objectStore("nodes"), blocks = tx.objectStore("blocks"), usage = tx.objectStore("usage");
    let removed = 0;
    await visit(nodes.index("garbage").openCursor(IDBKeyRange.only(["", 0])), async cursor => {
      const node: Block = cursor.value;
      for (const child of node.children) {
        const item: Block = await done(nodes.get(child));
        item.refs--;
        await done(nodes.put(item, child));
      }
      await done(blocks.delete(cursor.primaryKey));
      await done(cursor.delete());
      await done(usage.put((await done(usage.get(node.raw))) - node.size, node.raw));
      return ++removed < 128;
    });
    return removed > 0;
  })) { /* Each pass releases the archive's write transaction. */ }
}

export async function archiveRead(hash: string): Promise<Uint8Array> {
  const bytes: Uint8Array | undefined = await done((await database()).transaction("blocks").objectStore("blocks").get(hash));
  if (bytes === undefined) throw new Error("Published epoch archive block is missing");
  return bytes;
}

export async function archiveWrite(batch: string, raw: boolean, hash: string, children: string[], bytes: Uint8Array): Promise<void> {
  await change(async tx => {
    const nodes = tx.objectStore("nodes"), usage = tx.objectStore("usage");
    if (await done(nodes.getKey(hash)) !== undefined) return;
    const kind = Number(raw), used: number = await done(usage.get(kind));
    if (used + bytes.length > (raw ? 4 * 2 ** 30 : 512 * 2 ** 20)) throw new Error("Cold epoch archive capacity exhausted");
    for (const child of children) {
      const node: Block = await done(nodes.get(child));
      node.refs++;
      await done(nodes.put(node, child));
    }
    await done(nodes.put({ raw: kind, refs: 0, owner: batch, size: bytes.length, children } satisfies Block, hash));
    await done(tx.objectStore("blocks").put(bytes, hash));
    await done(usage.put(used + bytes.length, kind));
  });
}

export async function archivePublish(batch: string, pins: Pins): Promise<void> {
  await change(async tx => {
    for (const [slot, root] of pins) await pin(tx, slot, root);
    await visit(tx.objectStore("nodes").index("owner").openCursor(IDBKeyRange.only(batch)), async cursor => {
      await done(cursor.update({ ...cursor.value, owner: "" }));
      return true;
    });
  });
  await collect();
}

export async function archiveDiscard(batch: string): Promise<void> {
  await archivePublish(batch, []);
}

export async function archiveRecover(pins: Pins): Promise<void> {
  const expected = new Map(pins);
  await change(async tx => {
    await visit(tx.objectStore("pins").openCursor(), async cursor => {
      if (!expected.has(cursor.key as string)) await pin(tx, cursor.key as string, null);
      return true;
    });
    for (const [slot, root] of pins) await pin(tx, slot, root);
    await visit(tx.objectStore("nodes").index("owner").openCursor(IDBKeyRange.lowerBound("", true)), async cursor => {
      await done(cursor.update({ ...cursor.value, owner: "" }));
      return true;
    });
  });
  await collect();
}
