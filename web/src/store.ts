// IndexedDB: "records" holds the session's records, one per key, as the WebAssembly hands them over; "files" the
// ciphertext of the files it keeps, by hash (hex), which the session loads one at a time when it needs one.
const db: Promise<IDBDatabase> = new Promise((resolve, reject) => {
  const request = indexedDB.open("lmk", 1);
  request.onupgradeneeded = () => {
    request.result.createObjectStore("records");
    request.result.createObjectStore("files");
  };
  request.onsuccess = () => resolve(request.result);
  request.onerror = () => reject(request.error);
});

function done<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

/** Whether this browser has a session. */
export async function has(): Promise<boolean> {
  return (await done((await db).transaction("records").objectStore("records").count())) > 0;
}

/** The session's records, and the hashes of the files it keeps. */
export async function load(): Promise<{ records: [Uint8Array, Uint8Array][]; kept: string[] }> {
  const tx = (await db).transaction(["records", "files"]);
  const records = tx.objectStore("records");
  const [keys, values, kept] = await Promise.all([done(records.getAllKeys()), done(records.getAll()), done(tx.objectStore("files").getAllKeys())]);
  return { records: keys.map((key, i) => [new Uint8Array(key as ArrayBuffer), values[i]]), kept: kept as string[] };
}

export async function save(puts: [Uint8Array, Uint8Array][], deletes: Uint8Array[]) {
  const tx = (await db).transaction("records", "readwrite");
  const records = tx.objectStore("records");
  for (const [key, value] of puts) records.put(value, key as Uint8Array<ArrayBuffer>);
  for (const key of deletes) records.delete(key as Uint8Array<ArrayBuffer>);
}

export async function saveFile(hash: string, ciphertext: Uint8Array) {
  (await db).transaction("files", "readwrite").objectStore("files").put(ciphertext, hash);
}

export async function loadFile(hash: string): Promise<Uint8Array> {
  return done((await db).transaction("files").objectStore("files").get(hash));
}

export async function deleteFile(hash: string) {
  (await db).transaction("files", "readwrite").objectStore("files").delete(hash);
}
