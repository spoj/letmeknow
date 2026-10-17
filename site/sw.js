// The app that once lived here registered a service worker at this path. This one takes its place, deletes what the app
// kept in this browser, and unregisters, so its pages load this site from the network.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", event => event.waitUntil((async () => {
  await Promise.all((await caches.keys()).map(name => caches.delete(name)));
  await Promise.all((await indexedDB.databases()).map(({ name }) => new Promise(done => {
    const deleting = indexedDB.deleteDatabase(name);
    deleting.onsuccess = deleting.onerror = deleting.onblocked = done;
  })));
  await self.registration.unregister();
  for (const client of await self.clients.matchAll({ type: "window" })) client.navigate(client.url);
})()));
