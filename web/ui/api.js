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

// ---- analyses sauvegardées (feature « saved ») ----------------------------

// POST /saved {job_id, label?} -> {id, input_hash}. 409 = artefacts expirés côté
// serveur (le job a été GC) : on remonte un marqueur exploitable par l'UI.
export async function saveAnalysis(jobId, label) {
  const body = { job_id: jobId };
  if (label) body.label = label;
  const res = await authFetch('/saved', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (res.status === 409) { const e = new Error('expired'); e.expired = true; throw e; }
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// GET /saved/{hash} -> méta {id,input_hash,verdict,label,saved_at} ; null si 404
// (pas de sauvegarde pour ce hash) -> sert la dédup avant soumission.
export async function lookupSaved(hash) {
  const res = await authFetch('/saved/' + encodeURIComponent(hash));
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// GET /saved -> liste des métas (id desc).
export async function listSaved() {
  const res = await authFetch('/saved');
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// GET /saved/{id}/result -> OcularResult complet (même forme qu'un job).
export async function getSavedResult(id) {
  const res = await authFetch('/saved/' + encodeURIComponent(id) + '/result');
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// GET /saved/{id}/artifact/{ref} -> blob -> objectURL (fetch + Bearer, comme les jobs).
export async function savedArtifactObjectUrl(id, ref) {
  const res = await authFetch('/saved/' + encodeURIComponent(id) + '/artifact/' + ref);
  if (!res.ok) throw new Error(await errText(res));
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

// DELETE /saved/{id} — exige en plus l'en-tête X-Admin-Token. 403 (token faux) /
// 503 (admin non configuré côté serveur) remontés en messages exploitables.
export async function deleteSaved(id, adminToken) {
  const res = await authFetch('/saved/' + encodeURIComponent(id), {
    method: 'DELETE',
    headers: { 'X-Admin-Token': adminToken || '' },
  });
  if (!res.ok) throw adminError(res);
  return res.json();
}

// DELETE /saved (flush) — idem, X-Admin-Token requis.
export async function flushSaved(adminToken) {
  const res = await authFetch('/saved', {
    method: 'DELETE',
    headers: { 'X-Admin-Token': adminToken || '' },
  });
  if (!res.ok) throw adminError(res);
  return res.json();
}

function adminError(res) {
  const e = new Error(String(res.status));
  e.status = res.status; // 403 / 503 -> message clair côté vue admin
  return e;
}

// Hash d'entrée pour la dédup : "sha256:" + hex du HTML en UTF-8. Doit reproduire
// EXACTEMENT l'input_hash calculé côté moteur (sha256 du html.encode()).
export async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0')).join('');
  return 'sha256:' + hex;
}

async function errText(res) {
  const t = await res.text().catch(() => '');
  return res.status + (t ? ' ' + t.slice(0, 160) : '');
}

export { Unauthorized };
