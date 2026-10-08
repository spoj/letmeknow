/// <reference lib="webworker" />
// The service worker: it serves this version of the app from its cache, so the app opens without the page server, and
// a new version waits until the page asks it to take over ("skip"), once the person accepts it.
declare const FILES: string[];
declare const VERSION: string;
const sw = self as unknown as ServiceWorkerGlobalScope;

sw.addEventListener("install", event => event.waitUntil(caches.open(VERSION).then(cache => cache.addAll(FILES))));

sw.addEventListener("activate", event =>
  event.waitUntil(
    caches
      .keys()
      .then(names => Promise.all(names.filter(name => name !== VERSION).map(name => caches.delete(name))))
      .then(() => sw.clients.claim())
  )
);

sw.addEventListener("message", event => event.data === "skip" && sw.skipWaiting());

sw.addEventListener("fetch", event => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || url.origin !== location.origin) return;
  const path = event.request.mode === "navigate" ? "/index.html" : url.pathname;
  if (!FILES.includes(path)) return;
  event.respondWith(caches.open(VERSION).then(cache => cache.match(path)).then(cached => cached ?? fetch(event.request)));
});
