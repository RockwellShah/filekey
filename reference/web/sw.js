// FileKey reference — service worker.
// Precaches the app shell so FileKey installs as a PWA and runs fully offline
// (the crypto is all client-side). Strategy: network-first, so an online reload
// always gets fresh code, falling back to cache when offline.
const CACHE = "filekey-ref-v5";
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
        // Only cache a complete, successful response. Caching a 404/500 would poison the offline shell
        // with an error page; status===200 also skips 206 partials (range requests for the font/media).
        if (resp.ok && resp.status === 200) {
          const copy = resp.clone();
          caches.open(CACHE).then((c) => c.put(req, copy));
        }
        return resp;
      })
      .catch(() =>
        caches.match(req).then((cached) => {
          if (cached) return cached;
          // Offline and uncached: substitute the app shell only for a navigation (the SPA entry point).
          // For a missed sub-resource, return a real 504 rather than passing index.html off as that asset.
          if (req.mode === "navigate") return caches.match("/index.html");
          return new Response("offline", { status: 504, statusText: "Offline" });
        }),
      ),
  );
});
