// FileKey reference — service worker.
// Precaches the app shell so FileKey installs as a PWA and runs fully offline
// (the crypto is all client-side). Strategy: network-first, so an online reload
// always gets fresh code, falling back to cache when offline.
const CACHE = "filekey-ref-v4";
const SHELL = ["/", "/index.html", "/dist/app.js", "/recover.html", "/manifest.json", "/icon.svg", "/logo.svg", "/fonts/inter.woff2"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  // Let cross-origin requests (e.g. the web font) go straight to the network.
  if (new URL(req.url).origin !== self.location.origin) return;
  event.respondWith(
    fetch(req)
      .then((resp) => {
        const copy = resp.clone();
        caches.open(CACHE).then((c) => c.put(req, copy));
        return resp;
      })
      .catch(() => caches.match(req).then((cached) => cached || caches.match("/index.html"))),
  );
});
