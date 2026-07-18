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

// POST /jobs -> {job_id}. `body` porte le profil et sa charge utile :
//   { profile: 'analysis', html }  ou  { profile: 'capture', url, steps? }.
// L'erreur applicative garde le status (400 url interdite, 422 payload manquant
// ou script invalide) et, quand la réponse est un JSON {detail}, ce motif exact
// dans `e.detail` — le motif de `StepValidationError` remonté par le serveur,
// exploitable tel quel côté vue (pas de re-parsing dans la vue).
export async function submitJob(body) {
  const res = await authFetch('/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    let detail = '';
    try { detail = JSON.parse(text).detail || ''; } catch { /* réponse non-JSON */ }
    const e = new Error(res.status + (detail ? ' ' + detail : (text ? ' ' + text.slice(0, 160) : '')));
    e.status = res.status;
    e.detail = detail || null;
    throw e;
  }
  return res.json();
}

// GET /jobs/{id} -> résultat complet OU {status:"pending"}.
export async function getJob(id) {
  const res = await authFetch('/jobs/' + encodeURIComponent(id));
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// POST /jobs/{id}/explain -> {explanation, model}. 404 si l'option LLM est
// désarmée (DÉFAUT) OU si le job est introuvable : l'appelant lit `e.status`
// pour afficher une note discrète « option désactivée », jamais une erreur dure.
// La réponse `explanation` est une sortie LLM NON fiable : à poser en textContent.
export async function explainJob(id) {
  const res = await authFetch('/jobs/' + encodeURIComponent(id) + '/explain', { method: 'POST' });
  if (!res.ok) { const e = new Error(await errText(res)); e.status = res.status; throw e; }
  return res.json();
}

// Vérifie un token en tapant un endpoint protégé sans effet de bord.
// 401 -> Unauthorized (rejeté). 404/200 -> token accepté. 503 -> serveur non configuré.
export async function checkToken() {
  const res = await authFetch('/jobs/__ping__');
  if (res.status === 503) throw new Error('503');
  return true;
}

// GET /auth/whoami -> {identity, method}. `identity` porte l'utilisateur résolu côté
// serveur (bearer -> "token", ou identité forward-auth si l'opt-in serveur est actif) ;
// `method` ∈ "bearer"|"forward-auth". Sert le bandeau « connecté : X » (Phase 3e) —
// `identity` est une donnée potentiellement hostile (en-tête forward-auth) : l'appelant
// DOIT la poser en textContent, jamais en innerHTML.
export async function whoami() {
  const res = await authFetch('/auth/whoami');
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// Charge un artefact protégé (PNG ou DOM) en blob -> objectURL utilisable en src/href.
export async function artifactObjectUrl(id, ref) {
  const res = await authFetch('/jobs/' + encodeURIComponent(id) + '/artifact/' + ref);
  if (!res.ok) throw new Error(await errText(res));
  const blob = await res.blob();
  return URL.createObjectURL(blob);
}

// ---- sessions interactives (feature « interactive » T8) --------------------

// POST /sessions {url|html} -> {session_id, token}. Le `token` est un capability
// éphémère à garder EN MÉMOIRE (jamais localStorage) : il authentifie le WebSocket
// via sous-protocole, pas via l'URL. 400 = url interdite (SSRF), 504 = non prête.
export async function createSession(body) {
  const res = await authFetch('/sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    let detail = '';
    try { detail = JSON.parse(text).detail || ''; } catch { /* non-JSON */ }
    const e = new Error(res.status + (detail ? ' ' + detail : ''));
    e.status = res.status;
    e.detail = detail || null;   // permet à openErrMsg de distinguer DNS vs SSRF
    throw e;
  }
  return res.json();
}

// DELETE /sessions/{id} -> {deleted}. Détruit la session côté serveur (arrêt du conteneur).
export async function deleteSession(id) {
  const res = await authFetch('/sessions/' + encodeURIComponent(id), { method: 'DELETE' });
  if (!res.ok) { const e = new Error(await errText(res)); e.status = res.status; throw e; }
  return res.json();
}

// POST /sessions/{id}/capture -> OcularResult (même forme qu'un job, avec job_id).
// Le résultat est aussi stocké côté serveur -> revisible via GET /jobs/{job_id}.
// `opts.turnstilePassed` : déclaration manuelle de l'analyste que le Turnstile a
// été passé à la main (le solve interactif n'est pas introspectable de façon fiable).
export async function captureSession(id, opts) {
  const res = await authFetch('/sessions/' + encodeURIComponent(id) + '/capture', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ turnstile_passed: !!(opts && opts.turnstilePassed) }),
  });
  if (!res.ok) { const e = new Error(await errText(res)); e.status = res.status; throw e; }
  return res.json();
}

// GET /sessions/{id}/live -> {network, findings, counts:{network,findings}, verdict}.
// Canal de DONNÉES séparé du flux pixels VNC (poll ~2s côté vue interactive,
// panneau live C4) : appels réseau capturés jusqu'ici + analyse statique du DOM
// courant. 404 = session inconnue, 502 = conteneur ne répond pas.
export async function liveSession(id) {
  const res = await authFetch('/sessions/' + encodeURIComponent(id) + '/live');
  if (!res.ok) { const e = new Error(await errText(res)); e.status = res.status; throw e; }
  return res.json();
}

// ---- analyses sauvegardées (feature « saved ») ----------------------------

// POST /saved {job_id, label?} -> {id, input_hash}. 409 recouvre DEUX causes
// distinctes côté serveur : artefacts expirés (job GC-é) OU nom (label) déjà
// pris par un input_hash différent (unicité du nom, Task D 3d-1). On lit le
// corps pour distinguer les deux et poser un marqueur exploitable par l'UI —
// le detail JSON vient toujours du serveur (jamais concaténé/affiché brut ici).
export async function saveAnalysis(jobId, label) {
  const body = { job_id: jobId };
  if (label) body.label = label;
  const res = await authFetch('/saved', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (res.status === 409) {
    const data = await res.json().catch(() => ({}));
    const duplicateLabel = data.detail === 'nom déjà utilisé';
    const e = new Error(duplicateLabel ? 'duplicate-label' : 'expired');
    if (duplicateLabel) e.duplicateLabel = true; else e.expired = true;
    throw e;
  }
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

// POST /saved/lookup {url} -> méta {id,input_hash,verdict,label,saved_at} ; null si 404.
// La normalisation + le hash sont calculés côté serveur (normaliseur Python canonique) :
// évite la divergence avec un parseur URL JS (new URL()) qui gère différemment IPv6,
// IDN/punycode et le percent-encoding du path.
export async function lookupSavedByUrl(url) {
  const res = await authFetch('/saved/lookup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// GET /saved -> liste des métas (id desc). Chaque entrée porte, depuis Phase 3e,
// saved_by/turnstile_solved/analyst_verdict/analyst/analyst_at (pas analyst_note :
// non exposé par cette route côté serveur, voir setAnalystVerdict).
export async function listSaved(params) {
  // `params` (ex. {sort:'triage_score'}) -> query-string ; sans param, GET /saved
  // nu (compat des appelants existants : getSavedMeta, renderSaved par défaut).
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  const res = await authFetch('/saved' + qs);
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}

// Pas de route GET /saved/{id} dédiée à la méta (seule /saved/{hash} existe, par
// input_hash) : on réutilise GET /saved et on filtre par id — cohérent avec la
// vue Sauvegardes (déjà consommatrice de listSaved) et suffisant à ce volume de
// données. `null` si l'id est inconnu.
export async function getSavedMeta(sid) {
  const rows = await listSaved();
  return rows.find((r) => String(r.id) === String(sid)) || null;
}

// POST /saved/{sid}/verdict {analyst_verdict, note?} -> méta mise à jour (avec
// analyst_verdict/analyst/analyst_at/analyst_note). 422 si `analyst_verdict` n'est
// pas dans {legitimate,suspicious,malicious}, 404 si sid inconnu — l'appelant lit
// `e.status` pour distinguer les deux.
export async function setAnalystVerdict(sid, verdict, note) {
  const body = { analyst_verdict: verdict };
  if (note) body.note = note;
  const res = await authFetch('/saved/' + encodeURIComponent(sid) + '/verdict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) { const e = new Error(await errText(res)); e.status = res.status; throw e; }
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
