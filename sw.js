// MediReport — Service Worker v2 (stratégie RÉSEAU D'ABORD)
// Le cache n'est utilisé QUE si le réseau est indisponible.
// Garantit que chaque déploiement est visible immédiatement.

const CACHE = "medireport-v2";
const OFFLINE_URLS = ["/mobile.html", "/index.html", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(OFFLINE_URLS)));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  // Purger les anciens caches (dont l'éventuel sw v1)
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  // Jamais de cache pour les API (données médicales toujours fraîches, jamais stockées)
  if (req.url.includes("/api/")) return;
  if (req.method !== "GET") return;

  e.respondWith(
    fetch(req)
      .then((res) => {
        // Réseau OK → mettre à jour le cache en arrière-plan pour le mode hors-ligne
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        return res;
      })
      .catch(() => caches.match(req)) // Hors-ligne uniquement → cache
  );
});
