// IndexedDB: "records" holds the session's records, one per key, as the WebAssembly hands them over; "files" the
// ciphertext of the files it keeps, by hash (hex), which the session loads one at a time when it needs one.
let db: Promise<IDBDatabase> | undefined;
function database(): Promise<IDBDatabase> {
  return db ??= new Promise((resolve, reject) => {
    // This version's own database: another version's is left as it is.
    const request = indexedDB.open("lmk6", 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore("records");
      request.result.createObjectStore("files");
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

/** Whether this browser has a session. */
export async function has(): Promise<boolean> {
  return (await done((await database()).transaction("records").objectStore("records").count())) > 0;
}

/** Whether this browser keeps letmeknow 0.16's session, in its own database, which this version leaves as it is. */
export async function older(): Promise<boolean> {
  return (await indexedDB.databases()).some(({ name }) => name === "lmk5");
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
