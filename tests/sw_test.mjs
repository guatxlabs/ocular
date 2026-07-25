// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// sw_test.mjs — suite comportementale du service worker (web/ui/sw.js) et de la
// purge de cache à la déconnexion (web/ui/state.js), exécutée par
// tests/test_sw_cache_policy.py (qui fournit en argv[2] la liste des préfixes
// protégés lue depuis `web.app._PROTECTED` — SOURCE UNIQUE côté serveur).
//
// sw.js n'est pas un module ES : il s'installe sur `self`. On l'évalue dans un
// bac à sable `node:vm` avec des doublures de Cache Storage / fetch, puis on
// distribue de vrais évènements `fetch`/`activate` et on observe ce qui a été
// ÉCRIT dans le cache — c'est-à-dire ce qui est persisté sur le poste de
// l'analyste.
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const PROTECTED = JSON.parse(process.argv[2] || '[]');
assert.ok(PROTECTED.length > 0, 'préfixes protégés du serveur non fournis');

const ORIGIN = 'https://ocular.test';
const SW_SRC = readFileSync(new URL('../web/ui/sw.js', import.meta.url), 'utf8');

function makeCaches(seed = {}) {
  const store = new Map();
  for (const [name, urls] of Object.entries(seed)) {
    store.set(name, new Map(urls.map((u) => [u, { seeded: true }])));
  }
  return {
    store,
    keys: async () => [...store.keys()],
    delete: async (name) => store.delete(name),
    open: async (name) => {
      if (!store.has(name)) store.set(name, new Map());
      const m = store.get(name);
      return {
        put: async (req, res) => { m.set(req.url, res); },
        match: async (req) => m.get(req.url),
      };
    },
  };
}

// Charge sw.js dans un bac à sable et rend les écouteurs enregistrés.
function loadSw(seed = {}) {
  const listeners = {};
  const caches = makeCaches(seed);
  const sandbox = {
    caches,
    location: { origin: ORIGIN },
    URL,
    console,
    Response: class FakeResponse {
      constructor(body, init = {}) {
        this.body = body;
        this.status = init.status || 200;
        this.ok = this.status >= 200 && this.status < 300;
      }
    },
    fetch: async (req) => ({
      ok: true,
      status: 200,
      url: req.url,
      clone() { return this; },
    }),
  };
  sandbox.self = {
    addEventListener: (type, fn) => { listeners[type] = fn; },
    skipWaiting: () => {},
    clients: { claim: async () => {} },
  };
  vm.createContext(sandbox);
  vm.runInContext(SW_SRC, sandbox, { filename: 'sw.js' });
  return { listeners, caches, sandbox };
}

// Passe une requête dans l'écouteur `fetch` et dit si elle a été mise en cache.
async function cached(listeners, caches, url, method = 'GET') {
  let promise;
  const event = {
    request: { method, url, clone() { return this; } },
    respondWith: (p) => { promise = p; },
  };
  listeners.fetch(event);
  if (promise !== undefined) await promise;
  for (const m of caches.store.values()) if (m.has(url)) return true;
  return false;
}

// --- 1. AUCUNE route protégée par le serveur ne doit être persistée ----------
{
  const { listeners, caches } = loadSw();
  for (const prefix of PROTECTED) {
    for (const path of [prefix, `${prefix}/x`, `${prefix}/x/y?z=1`]) {
      const url = ORIGIN + path;
      assert.equal(
        await cached(listeners, caches, url), false,
        `route protégée mise en cache sur le poste de l'analyste : ${path}`,
      );
    }
  }
  // Les cas les plus sensibles, nommément (captures d'écran + DOM de pages HOSTILES).
  for (const path of [
    '/saved',
    '/saved/42/result',
    `/saved/42/artifact/sha256:${'a'.repeat(64)}`,
    '/sessions',
    '/sessions/abc/live',
    '/auth/whoami',
  ]) {
    assert.equal(
      await cached(listeners, caches, ORIGIN + path), false,
      `donnée d'analyse persistée : ${path}`,
    );
  }
}

// --- 2. Fermé par CONSTRUCTION : une route API FUTURE n'entre pas non plus ---
{
  const { listeners, caches } = loadSw();
  for (const path of ['/api/whatever', '/future-route', '/saved.json', '/reports/1']) {
    assert.equal(
      await cached(listeners, caches, ORIGIN + path), false,
      `route non-shell mise en cache (denylist au lieu d'allowlist ?) : ${path}`,
    );
  }
}

// --- 3. Le shell statique, lui, reste bien mis en cache (mode hors-ligne) ----
{
  const { listeners, caches } = loadSw();
  for (const path of [
    '/', '/index.html', '/style.css', '/favicon.svg', '/manifest.webmanifest',
    '/core.js', '/api.js', '/boot.js', '/state.js', '/i18n.js', '/filter.js', '/triage.js',
    '/views/saved.js', '/views/interactive.js',
    '/fonts/inter-latin.woff2', '/vendor/novnc/core/rfb.js',
  ]) {
    assert.equal(
      await cached(listeners, caches, ORIGIN + path), true,
      `shell statique non mis en cache : ${path}`,
    );
  }
}

// --- 4. Hors périmètre : POST et cross-origin ne sont jamais interceptés -----
{
  const { listeners, caches } = loadSw();
  assert.equal(await cached(listeners, caches, `${ORIGIN}/`, 'POST'), false);
  assert.equal(await cached(listeners, caches, 'https://elsewhere.test/style.css'), false);
}

// --- 5. `activate` doit JETER un cache antérieur (bump de version) -----------
// Un poste déjà utilisé porte un cache écrit par la version précédente, rempli
// de /saved et d'artefacts. Il ne disparaît que si le nom du cache CHANGE :
// sans bump, l'activation le conserve tel quel.
{
  const seeded = { 'ocular-v1': [`${ORIGIN}/saved`, `${ORIGIN}/auth/whoami`] };
  const { listeners, caches } = loadSw(seeded);
  await listeners.activate({ waitUntil: (p) => p });
  assert.equal(
    caches.store.has('ocular-v1'), false,
    "le cache 'ocular-v1' (pollué par la version précédente) survit à l'activation : version de cache non incrémentée",
  );
}

// --- 6. La déconnexion purge le Cache Storage -------------------------------
{
  const bag = new Map();
  globalThis.localStorage = {
    getItem: (k) => (bag.has(k) ? bag.get(k) : null),
    setItem: (k, v) => bag.set(k, String(v)),
    removeItem: (k) => bag.delete(k),
  };
  const caches = makeCaches({ 'ocular-v2': [`${ORIGIN}/index.html`], 'ocular-v1': [`${ORIGIN}/saved`] });
  globalThis.caches = caches;
  const state = await import('../web/ui/state.js');
  state.setToken('secret-token');
  await state.clearToken();
  assert.equal(bag.has('ocular_token'), false, 'jeton non effacé');
  assert.equal(
    caches.store.size, 0,
    'la déconnexion laisse le Cache Storage en place (liste des analyses, verdicts, artefacts)',
  );
}

console.log('sw_test OK');
