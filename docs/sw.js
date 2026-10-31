const CACHE_NAME = "mcp-vuln-cache-v1";

const MAX_SHARDS_UPDATES = 50;

async function manageLRU(cacheName) {
  const cache = await caches.open(cacheName);
  const keys = await cache.keys();
  
  const dynamicKeys = keys.filter(req => {
    const url = new URL(req.url);
    return url.pathname.includes('/shards/') || url.pathname.includes('/updates/') || url.pathname.endsWith('vulnerabilities.json');
  });

  if (dynamicKeys.length > MAX_SHARDS_UPDATES) {
    // Delete the oldest entries (assuming they are first in the list)
    const toDelete = dynamicKeys.slice(0, dynamicKeys.length - MAX_SHARDS_UPDATES);
    for (const req of toDelete) {
      await cache.delete(req);
    }
  }
}

const CORE_ASSETS = [
  "./",
  "./index.html",
  "./updates.html",
  "./analytics.html",
  "./style.css",
  "./app.js",
  "./updates.js",
  "./analytics.js",
  "./favicon.svg",
  "./manifest.json"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(CORE_ASSETS);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName.startsWith("mcp-vuln-cache-") && cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Stale-While-Revalidate for mcp_catalog_index.json and analytics.json
  if (url.pathname.endsWith("mcp_catalog_index.json") || url.pathname.endsWith("analytics.json")) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        const fetchPromise = fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.ok) {
            const clone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, clone).then(() => manageLRU(CACHE_NAME));
            });
          }
          return networkResponse;
        }).catch(() => {
          // Ignore network errors for stale-while-revalidate if we have cache
        });
        return cachedResponse || fetchPromise;
      })
    );
    return;
  }

  // Cache-First for shards, updates, and vulnerabilities
  if ((url.pathname.includes("/shards/") || url.pathname.includes("/updates/")) && url.pathname.endsWith(".json") || url.pathname.endsWith("vulnerabilities.json")) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        return fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.ok) {
            const clone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, clone).then(() => manageLRU(CACHE_NAME));
            });
          }
          return networkResponse;
        });
      })
    );
    return;
  }

  // Cache-First for core static shell assets
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request).catch(() => {
        // Offline fallback
        return new Response("Offline mode active. This resource is not cached.", {
          status: 503,
          statusText: "Service Unavailable",
          headers: new Headers({
            "Content-Type": "text/plain"
          })
        });
      });
    })
  );
});
