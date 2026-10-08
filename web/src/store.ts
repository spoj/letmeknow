// IndexedDB: "records" holds the session's records, one per key, as the WebAssembly hands them over; "files" the
// ciphertext of the files it holds, by hash (hex).
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

export async function load(): Promise<{ records: [Uint8Array, Uint8Array][]; files: Map<string, Uint8Array> }> {
  const tx = (await db).transaction(["records", "files"]);
  const records = tx.objectStore("records");
  const files = tx.objectStore("files");
  const [keys, values, hashes, sealed] = await Promise.all([done(records.getAllKeys()), done(records.getAll()), done(files.getAllKeys()), done(files.getAll())]);
  return {
    records: keys.map((key, i) => [new Uint8Array(key as ArrayBuffer), values[i]]),
    files: new Map(hashes.map((hash, i) => [hash as string, sealed[i]]))
  };
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
