// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// sw.js — service worker PWA d'Ocular. Met en cache le SEUL app shell statique
// (HTML/CSS/JS/polices/vendor), en NETWORK-FIRST : le frais quand en ligne, le
// cache comme secours hors-ligne.
//
// Le choix est une ALLOWLIST, jamais une denylist : tout ce qui n'est pas un
// fichier du shell part au réseau et n'est jamais écrit sur le poste. C'est ce
// qui ferme le trou PAR CONSTRUCTION — une denylist devrait rester synchronisée
// à la main avec `_PROTECTED` (web/app.py) et laisserait entrer toute route
// ajoutée plus tard. Ce qui ne doit JAMAIS être persisté côté analyste :
// `/saved` (liste et verdicts), `/saved/<id>/result`,
// `/saved/<id>/artifact/<ref>` (captures d'écran ET DOM de pages HOSTILES),
// `/sessions*`, `/auth/whoami`, `/jobs*`. Garde-fou : tests/sw_test.mjs prend la
// liste des préfixes protégés dans `web.app._PROTECTED` (source unique, côté
// serveur) et vérifie qu'aucun n'est cachable.
//
// La déconnexion purge ce cache (`clearToken`, web/ui/state.js).
const VER = 'ocular-v2';
// Fichiers exacts du shell + préfixes de répertoires du shell. Toute autre
// requête (donc toute l'API, présente ou future) va directement au réseau.
const SHELL_FILES = new Set([
  '/', '/index.html', '/style.css', '/favicon.svg', '/manifest.webmanifest', '/sw.js',
]);
const SHELL_DIRS = ['/views/', '/fonts/', '/vendor/'];
const isShell = (p) =>
  SHELL_FILES.has(p)
  || SHELL_DIRS.some((d) => p.startsWith(d))
  // modules ES à la racine (api.js, boot.js, core.js, ...) : un seul segment.
  || (p.endsWith('.js') && p.indexOf('/', 1) === -1);
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil((async () => {
  // Le bump de VER ci-dessus fait tomber ici les caches des versions
  // précédentes — dont celui, pollué de données d'analyse, écrit par la version
  // qui mettait en cache toute réponse GET.
  for (const k of await caches.keys()) if (k !== VER) await caches.delete(k);
  await self.clients.claim();
})()));
self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  // uniquement GET same-origin sur le shell : les données passent au réseau et
  // ne sont jamais écrites dans le Cache Storage.
  if (req.method !== 'GET' || url.origin !== location.origin || !isShell(url.pathname)) return;
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
