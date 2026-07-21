// ─────────────────────────────────────────────────────────────────────────────
// MediReport Mobile — Service Worker
// Stratégie : Cache-First pour les assets statiques, Network-First pour le HTML
// ─────────────────────────────────────────────────────────────────────────────

const CACHE_NAME = "medireport-v1";
const OFFLINE_URL = "./mobile.html";

// Fichiers à mettre en cache immédiatement à l'installation
const PRECACHE_ASSETS = [
  "./mobile.html",
  "./manifest.json"
];

// ── INSTALL ──────────────────────────────────────────────────────────────────
self.addEventListener("install", (event) => {
  console.log("[SW] Installation...");
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log("[SW] Mise en cache des assets statiques");
      return cache.addAll(PRECACHE_ASSETS);
    }).then(() => {
      // Prendre le contrôle immédiatement sans attendre le rechargement
      return self.skipWaiting();
    })
  );
});

// ── ACTIVATE ─────────────────────────────────────────────────────────────────
self.addEventListener("activate", (event) => {
  console.log("[SW] Activation...");
  event.waitUntil(
    Promise.all([
      // Supprimer les anciens caches
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => {
              console.log("[SW] Suppression ancien cache:", name);
              return caches.delete(name);
            })
        );
      }),
      // Prendre le contrôle de tous les clients ouverts
      self.clients.claim()
    ])
  );
});

// ── FETCH ─────────────────────────────────────────────────────────────────────
self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Ignorer les requêtes non-GET et les requêtes cross-origin
  if (request.method !== "GET") return;
  if (url.origin !== self.location.origin) return;

  // Stratégie Network-First pour le HTML principal
  if (request.mode === "navigate" || url.pathname.endsWith(".html")) {
    event.respondWith(
      fetch(request)
        .then((networkResponse) => {
          // Mettre à jour le cache avec la réponse réseau fraîche
          const responseClone = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(request, responseClone);
          });
          return networkResponse;
        })
        .catch(() => {
          // Réseau indisponible → servir depuis le cache
          return caches.match(OFFLINE_URL).then((cachedResponse) => {
            return cachedResponse || new Response(
              "<h1>Hors ligne</h1><p>Veuillez vérifier votre connexion.</p>",
              { headers: { "Content-Type": "text/html; charset=utf-8" } }
            );
          });
        })
    );
    return;
  }

  // Stratégie Cache-First pour les autres assets (JSON, images, etc.)
  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      if (cachedResponse) {
        // Revalidation en arrière-plan (stale-while-revalidate)
        fetch(request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(request, networkResponse);
            });
          }
        }).catch(() => {});
        return cachedResponse;
      }

      // Pas en cache → réseau
      return fetch(request).then((networkResponse) => {
        if (!networkResponse || networkResponse.status !== 200) {
          return networkResponse;
        }
        const responseClone = networkResponse.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(request, responseClone);
        });
        return networkResponse;
      });
    })
  );
});

// ── MESSAGE ───────────────────────────────────────────────────────────────────
// Permettre au client de demander une mise à jour du SW
self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});
