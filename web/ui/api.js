// api.js — wrapper fetch qui ajoute Authorization: Bearer <token> à chaque appel
// et redirige vers la vue login sur 401. Le screenshot et le DOM se chargent en
// blob (fetch + header) car un <img src> nu n'envoie PAS l'en-tête Bearer.
import { getToken, clearToken } from './state.js';

// Erreur applicative : on redirige puis on jette pour couper la chaîne d'appel.
class Unauthorized extends Error {}

async function authFetch(path, opts = {}) {
  const token = getToken();
  const headers = Object.assign({}, opts.headers || {});
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if (res.status === 401) {
    clearToken();
    if (location.hash !== '#/login') location.hash = '#/login';
    throw new Unauthorized('401');
  }
  return res;
}

// POST /jobs {profile, html} -> {job_id}. Sert aussi de vérification du token
// à la connexion (401 rejeté par authFetch, 503 = token serveur absent).
export async function submitJob(html) {
  const res = await authFetch('/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ profile: 'analysis', html }),
  });
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// GET /jobs/{id} -> résultat complet OU {status:"pending"}.
export async function getJob(id) {
  const res = await authFetch('/jobs/' + encodeURIComponent(id));
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// Vérifie un token en tapant un endpoint protégé sans effet de bord.
// 401 -> Unauthorized (rejeté). 404/200 -> token accepté. 503 -> serveur non configuré.
export async function checkToken() {
  const res = await authFetch('/jobs/__ping__');
  if (res.status === 503) throw new Error('503');
  return true;
}

// Charge un artefact protégé (PNG ou DOM) en blob -> objectURL utilisable en src/href.
export async function artifactObjectUrl(id, ref) {
  const res = await authFetch('/jobs/' + encodeURIComponent(id) + '/artifact/' + ref);
  if (!res.ok) throw new Error(await errText(res));
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

async function errText(res) {
  const t = await res.text().catch(() => '');
  return res.status + (t ? ' ' + t.slice(0, 160) : '');
}

export { Unauthorized };
