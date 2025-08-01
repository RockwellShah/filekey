let change_variable = "g";
self.addEventListener('install', event => {
    event.waitUntil(caches.open('v1').then(cache => {
        return cache.addAll(['/', ]);
    }
    ));
}
);
self.addEventListener('activate', event => {
    const cacheWhitelist = ['v1'];
    event.waitUntil(caches.keys().then(cacheNames => {
        return Promise.all(cacheNames.map(cacheName => {
            if (!cacheWhitelist.includes(cacheName)) {
                return caches.delete(cacheName);
            }
        }
        ));
    }
    ));
}
);
self.addEventListener('fetch', event => {
    event.respondWith(caches.match(event.request).then(cachedResponse => {
        if (cachedResponse) {
            return cachedResponse;
        }
        return fetch(event.request).then(networkResponse => {
            return caches.open('v1').then(cache => {
                cache.put(event.request, networkResponse.clone());
                return networkResponse;
            }
            );
        }
        );
    }
    ));
}
);
self.addEventListener('install', event => {
    self.skipWaiting();
}
);
self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
}
);
self.addEventListener('message', messageReceiver);
function messageReceiver(msg) {
    if (msg.ports) {
        switch (msg.data.type) {
        case "check_change_variable":
            msg.ports[0].postMessage({
                change_variable
            });
            break;
        }
    }
}
