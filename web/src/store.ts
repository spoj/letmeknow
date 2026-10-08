// IndexedDB, as four key-value stores: "state" (the member, this browser's entities, groups), "items" (what each chat
// showed, kept so a person can scroll back), "docs" (each doc's Yjs state) and "blobs" (the sealed files they link).
const db: Promise<IDBDatabase> = new Promise((resolve, reject) => {
  const request = indexedDB.open("letmeknow", 3);
  request.onupgradeneeded = () => {
    const names = request.result.objectStoreNames;
    if (names.contains("files")) request.result.deleteObjectStore("files");
    for (const name of ["state", "items", "docs", "blobs"]) {
      if (!names.contains(name)) request.result.createObjectStore(name);
    }
  };
  request.onsuccess = () => resolve(request.result);
  request.onerror = () => reject(request.error);
});

function done(request: IDBRequest | IDBTransaction): Promise<any> {
  return new Promise((resolve, reject) => {
    if (request instanceof IDBTransaction) {
      request.oncomplete = () => resolve(undefined);
      request.onabort = () => reject(request.error);
    } else {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    }
  });
}

export async function get<T>(store: string, key: string): Promise<T | undefined> {
  return done((await db).transaction(store).objectStore(store).get(key));
}

/// Values whose keys start with `prefix`, in key order.
export async function all<T>(store: string, prefix: string): Promise<T[]> {
  const range = IDBKeyRange.bound(prefix, prefix + "\uffff");
  return done((await db).transaction(store).objectStore(store).getAll(range));
}

export async function keys(store: string, prefix: string): Promise<string[]> {
  const range = IDBKeyRange.bound(prefix, prefix + "\uffff");
  return done((await db).transaction(store).objectStore(store).getAllKeys(range));
}

/// Writes several values at once: either all are stored or none.
export async function put(writes: [store: string, key: string, value: unknown][]): Promise<void> {
  const tx = (await db).transaction([...new Set(writes.map(w => w[0]))], "readwrite");
  for (const [store, key, value] of writes) tx.objectStore(store).put(value, key);
  await done(tx);
}

export async function remove(store: string, prefix: string): Promise<void> {
  const tx = (await db).transaction(store, "readwrite");
  tx.objectStore(store).delete(IDBKeyRange.bound(prefix, prefix + "\uffff"));
  await done(tx);
}
