export { archiveRead, archiveWrite, archivePublish, archiveDiscard, archiveRecover } from "./archive";

// IndexedDB: "records" holds the session's records, one per key, as the WebAssembly hands them over; "files" the
// ciphertext of the files it keeps, by hash (hex), which the session loads one at a time when it needs one.
let db: Promise<IDBDatabase> | undefined;
function database(): Promise<IDBDatabase> {
  return db ??= new Promise((resolve, reject) => {
    const request = indexedDB.open("lmk-0.16", 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore("records");
      request.result.createObjectStore("files");
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error?.name === "VersionError"
      ? new Error("This browser's stored session is from an incompatible version. Its local data was preserved; use that version to access it.")
      : request.error);
  });
}

function done<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** Whether this browser has a session. */
export async function has(): Promise<boolean> {
  return (await done((await database()).transaction("records").objectStore("records").count())) > 0;
}

/** The session's records, and the hashes of the files it keeps. */
export async function load(): Promise<{ records: [Uint8Array, Uint8Array][]; kept: string[] }> {
  const tx = (await database()).transaction(["records", "files"]);
  const records = tx.objectStore("records");
  const [keys, values, kept] = await Promise.all([done(records.getAllKeys()), done(records.getAll()), done(tx.objectStore("files").getAllKeys())]);
  return { records: keys.map((key, i) => [new Uint8Array(key as ArrayBuffer), values[i]]), kept: kept as string[] };
}

/** Resolves once the records are durable: the session sends nothing a step produced before. */
export async function save(puts: [Uint8Array, Uint8Array][], deletes: Uint8Array[]) {
  const tx = (await database()).transaction("records", "readwrite", { durability: "strict" });
  const records = tx.objectStore("records");
  for (const [key, value] of puts) records.put(value, key as Uint8Array<ArrayBuffer>);
  for (const key of deletes) records.delete(key as Uint8Array<ArrayBuffer>);
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(new Error("IndexedDB transaction aborted", { cause: tx.error }));
  });
}

export async function saveFiles(changes: [string, Uint8Array | null][]) {
  const tx = (await database()).transaction("files", "readwrite", { durability: "strict" });
  const files = tx.objectStore("files");
  for (const [hash, ciphertext] of changes) {
    if (ciphertext === null) files.delete(hash);
    else files.put(ciphertext, hash);
  }
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(new Error("IndexedDB files transaction aborted", { cause: tx.error }));
  });
}

export async function loadFile(hash: string): Promise<Uint8Array> {
  return done((await database()).transaction("files").objectStore("files").get(hash));
}

let scratch: Promise<IDBDatabase> | undefined;
function proofDatabase(): Promise<IDBDatabase> {
  return scratch ??= new Promise((resolve, reject) => {
    const request = indexedDB.open("lmk-epoch-proof-0.16", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("chunks");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function proofReset(): Promise<void> {
  await done((await proofDatabase()).transaction("chunks", "readwrite").objectStore("chunks").clear());
}

export async function proofWrite(target: string, after: number, bytes: Uint8Array): Promise<void> {
  const tx = (await proofDatabase()).transaction("chunks", "readwrite");
  tx.objectStore("chunks").put(bytes, [target, after]);
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(new Error("Proof scratch write failed", { cause: tx.error }));
  });
}

export async function proofRead(target: string, after: number): Promise<Uint8Array> {
  return done((await proofDatabase()).transaction("chunks").objectStore("chunks").get([target, after]));
}

export async function proofRemove(target: string): Promise<void> {
  await done((await proofDatabase()).transaction("chunks", "readwrite").objectStore("chunks").delete(IDBKeyRange.bound([target, 0], [target, Number.MAX_SAFE_INTEGER])));
}
