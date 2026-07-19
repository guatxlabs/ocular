// SPDX-FileCopyrightText: 2026 guatx
// SPDX-License-Identifier: AGPL-3.0-or-later
// sw.js — service worker PWA d'Ocular. App shell en NETWORK-FIRST (le frais quand
// en ligne ; le cache sert de secours hors-ligne). L'API (/jobs) n'est JAMAIS mise
// en cache : les résultats et artefacts protégés passent toujours au réseau.
const VER = 'ocular-v1';
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil((async () => {
  for (const k of await caches.keys()) if (k !== VER) await caches.delete(k);
  await self.clients.claim();
})()));
self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  // uniquement GET same-origin hors /jobs : les données live passent toujours au réseau
  if (req.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/jobs')) return;
  e.respondWith((async () => {
    const cache = await caches.open(VER);
    try {
      const res = await fetch(req);
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    } catch {
      return (await cache.match(req)) || new Response('hors-ligne', { status: 503 });
    }
  })());
});
