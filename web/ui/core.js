// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// core.js — point d'entrée de l'UI Ocular : helpers DOM partagés, routeur hash,
// et câblage du header (nav / langue / thème / déconnexion). Vanilla ES modules,
// zéro build. Importé une fois par index.html (<script type="module">).
import { getToken, clearToken, LANG, setLang, getTheme, setTheme } from './state.js';
import { i18nWalk } from './i18n.js';
import { whoami, Unauthorized } from './api.js';
import { renderLogin } from './views/login.js';
import { renderSubmit } from './views/submit.js';
import { renderInteractive } from './views/interactive.js';
import { renderJobs } from './views/jobs.js';
import { renderDetail, renderSavedDetail } from './views/detail.js';
import { renderSaved } from './views/saved.js';
import { renderAdmin } from './views/admin.js';

// ---- helpers DOM (repris de l'esprit de core.js/plume, réduits au nécessaire) ----
export const $ = (s, r = document) => r.querySelector(s);
export const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// icônes SVG inline (mêmes chemins que plume ; couleur via currentColor)
const ICONS = {
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
  flask: '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3"/><path d="M7 14h10"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
  moon: '<path d="M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z"/>',
  chevleft: '<path d="M15 6l-6 6 6 6"/>',
  chevright: '<path d="M9 6l6 6-6 6"/>',
  download: '<path d="M12 3v12"/><path d="M7 10l5 5 5-5"/><path d="M5 21h14"/>',
  upload: '<path d="M12 21V9"/><path d="M7 14l5-5 5 5"/><path d="M5 3h14"/>',
  inbox: '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5h13l3.5 7v6a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-6z"/>',
  warn: '<path d="M12 3l10 18H2z"/><path d="M12 10v4M12 18h.01"/>',
  bookmark: '<path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  trash: '<path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/>',
  shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
};
export const ic = (n, cls = '') =>
  `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;

// version NŒUD de ic() : à passer comme enfant dans el(...) (un string enfant
// deviendrait un textNode et afficherait le markup en clair). Contenu 100% statique.
export function iconNode(n, cls = '') {
  const span = document.createElement('span');
  span.style.display = 'contents';
  span.innerHTML = ic(n, cls);
  return span.firstChild;
}

// fabrique d'élément : el('div.card', {onclick}, [child|str])
export function el(tag, attrs = {}, kids = []) {
  const m = tag.match(/^([a-z0-9]+)((?:[.#][\w-]+)*)$/i);
  const node = document.createElement(m ? m[1] : tag);
  if (m && m[2]) m[2].match(/[.#][\w-]+/g).forEach((tok) => {
    if (tok[0] === '.') node.classList.add(tok.slice(1));
    else node.id = tok.slice(1);
  });
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'html') node.innerHTML = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  (Array.isArray(kids) ? kids : [kids]).forEach((c) => {
    if (c == null) return;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  });
  return node;
}

// Ouvre une modale : voile `.modal-ov` + carte `.modal` (déjà stylés). L'appelant
// fournit un nœud `.modal` déjà construit (contenu en textNode -> XSS-safe). Ferme
// sur clic hors carte, sur Échap, et via le `close()` retourné.
export function openModal(modalEl) {
  const ov = el('div.modal-ov', {}, [modalEl]);
  const close = () => {
    document.removeEventListener('keydown', onKey);
    ov.classList.add('out');
    setTimeout(() => ov.remove(), 150);
  };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  ov.addEventListener('mousedown', (e) => { if (e.target === ov) close(); });
  document.addEventListener('keydown', onKey);
  document.body.appendChild(ov);
  return close;
}

export function fmtTs(ms) {
  if (!ms) return '';
  const loc = LANG === 'en' ? 'en-US' : 'fr-FR';
  return new Date(ms).toLocaleString(loc);
}

// ---- helpers de formatage / pastilles partagés (audit qualité : sortis de
// views/saved.js — ce sont des utilitaires génériques, pas spécifiques à la vue
// liste ; réutilisés par jobs/detail/admin/submit). --------------------------
const VERDICT_TONE = { benign: 'ok', suspicious: 'warn', malicious: 'bad' };
export const TONE_STYLE = {
  ok: 'color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent);border-color:color-mix(in srgb,var(--ok) 40%,transparent)',
  warn: 'color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,transparent);border-color:color-mix(in srgb,var(--warn) 40%,transparent)',
  bad: 'color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,transparent);border-color:color-mix(in srgb,var(--bad) 42%,transparent)',
  mut: 'color:var(--mut);background:var(--card2)',
};

// Pastille verdict AUTO (benign/suspicious/malicious) — donnée enum non hostile.
export function verdictPill(v) {
  const tone = VERDICT_TONE[v] || 'mut';
  return el('span.pending-pill', { style: TONE_STYLE[tone] }, v || 'unknown');
}

// ISO 8601 -> horodatage local lisible (fallback : la chaîne brute si non parsable).
// Distinct de fmtTs (qui prend des ms epoch) — ici une chaîne ISO.
export function fmtIso(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

// "sha256:abcd…" -> "abcd…" (12 hex de tête). Jamais rendu en HTML.
export function shortHash(h) {
  const hex = String(h || '').replace(/^sha256:/, '');
  return hex.length > 14 ? hex.slice(0, 12) + '…' : hex;
}

// ---- bandeau whoami « connecté : <identity> » (Phase 3e) --------------------
// Un whoami() réussi authentifie AUSSI le routeur (identityConfirmed) : couvre le
// cas forward-auth pur (opt-in serveur actif, aucun jeton Bearer stocké côté
// navigateur — l'identité vient du proxy sur chaque requête). Si un jeton Bearer
// local existe déjà, le routeur reste authentifié comme avant (comportement
// bearer inchangé, identityConfirmed ne fait qu'AJOUTER un chemin d'accès).
let whoamiEl = null;
let identityConfirmed = false;
let authMethod = null;
let whoamiLoaded = false;
let whoamiPromise = null;
// is_admin/groups (Phase 3h) : reflet UNIQUEMENT ergonomique de whoami() — le
// backend (`_auth`, bloc DELETE /saved) reste la seule vraie garde. Sert à
// masquer les contrôles admin (vue Admin, lien de nav) côté client.
let adminFlag = false;
let groupsList = [];

// Accès en lecture pour les vues (admin.js notamment) — jamais de mutation
// directe depuis l'extérieur, seule refreshWhoami() met ces valeurs à jour.
export function isAdmin() { return adminFlag; }
export function getGroups() { return groupsList.slice(); }

function ensureWhoamiEl() {
  if (whoamiEl) return whoamiEl;
  const tools = $('.hdr-tools');
  if (!tools) return null;
  whoamiEl = el('span.whoami', { id: 'whoami', hidden: 'hidden' });
  tools.insertBefore(whoamiEl, tools.firstChild);
  return whoamiEl;
}

// `who.identity`/`who.groups` viennent du serveur : bearer -> "token", ou identité
// forward-auth (en-tête client relayé par un proxy de confiance) sinon — donnée
// potentiellement hostile -> posée en textNode via el(...)/iconNode, JAMAIS innerHTML.
async function refreshWhoami() {
  const wEl = ensureWhoamiEl();
  try {
    const who = await whoami();
    identityConfirmed = true;
    authMethod = who && who.method;
    whoamiLoaded = true;
    adminFlag = !!(who && who.is_admin);
    groupsList = Array.isArray(who && who.groups) ? who.groups : [];
    if (wEl) {
      const kids = [
        iconNode('shield'),
        el('span.whoami-label', {}, 'connecté'),
        el('b.whoami-id', {}, (who && who.identity) || '?'),
      ];
      // groupes affichés en clair (textContent) si présents -> confort de lecture,
      // jamais de HTML injecté (groupList vient potentiellement d'un en-tête client).
      if (groupsList.length) kids.push(el('span.whoami-groups', { title: 'groupes' }, groupsList.join(', ')));
      wEl.replaceChildren(...kids);
      wEl.hidden = false;
    }
  } catch (ex) {
    if (!(ex instanceof Unauthorized)) { /* réseau/serveur : bandeau reste masqué, pas de routage cassé */ }
    identityConfirmed = false;
    authMethod = null;
    adminFlag = false;
    groupsList = [];
    if (wEl) { wEl.hidden = true; wEl.replaceChildren(); }
  }
}

// Charge le whoami une seule fois par session authentifiée (évite un appel réseau
// à chaque changement de route) ; ré-appelable après logout via whoamiLoaded=false.
function ensureWhoamiLoaded() {
  if (whoamiLoaded || whoamiPromise) return;
  whoamiPromise = refreshWhoami().finally(() => { whoamiPromise = null; });
}

// ---- chrome : nav active + visibilité selon l'état de connexion ----
function updateChrome(view, authed) {
  const nav = $('#topnav');
  const logout = $('#logout');
  if (nav) nav.hidden = !authed;
  // forward-auth : identité gérée par le proxy -> pas de bouton de déconnexion
  // côté client (rien à "oublier" localement).
  if (logout) logout.hidden = !authed || authMethod === 'forward-auth';
  document.querySelectorAll('#topnav a').forEach((a) =>
    a.classList.toggle('on', a.dataset.route === view || (view === 'job' && a.dataset.route === 'jobs')));
  // Lien Admin visible dès qu'on est authentifié : l'admin par X-Admin-Token se
  // saisit DANS la page admin, donc on ne peut pas la masquer sur le seul flag de
  // groupe (sinon un admin par token n'y accéderait jamais). Le backend reste la
  // garde réelle (DELETE /saved -> 403/503).
  const adminLink = document.querySelector('#topnav a[data-route="admin"]');
  if (adminLink) adminLink.hidden = !authed;
}

// ---- routeur hash ----
let cleanup = null;
function route() {
  if (cleanup) { try { cleanup(); } catch { /* noop */ } cleanup = null; }
  const app = $('#app');
  const authed = !!getToken() || identityConfirmed;
  const parts = (location.hash || '').replace(/^#\/?/, '').split('/');
  const view = parts[0] || '';

  if (!authed && view !== 'login') { location.hash = '#/login'; return; }
  if (authed && (view === '' || view === 'login')) { location.hash = '#/jobs'; return; }

  updateChrome(view, authed);
  if (authed) ensureWhoamiLoaded();
  app.replaceChildren();
  if (view === 'login') cleanup = renderLogin(app);
  else if (view === 'submit') cleanup = renderSubmit(app);
  else if (view === 'interactive') cleanup = renderInteractive(app);
  else if (view === 'jobs') cleanup = renderJobs(app);
  else if (view === 'job') cleanup = renderDetail(app, parts[1]);
  else if (view === 'saved' && parts[1]) cleanup = renderSavedDetail(app, parts[1]);
  else if (view === 'saved') cleanup = renderSaved(app);
  else if (view === 'admin') cleanup = renderAdmin(app);
  else { location.hash = '#/jobs'; return; }
  i18nWalk(app);
  window.scrollTo(0, 0);
}

// ---- boot ----
async function boot() {
  // thème appliqué tôt (aussi posé en ligne dans index.html pour éviter le flash)
  document.documentElement.setAttribute('data-theme', getTheme());

  const themeBtn = $('#theme');
  if (themeBtn) {
    const paint = () => { themeBtn.innerHTML = ic(getTheme() === 'dark' ? 'sun' : 'moon'); };
    paint();
    themeBtn.addEventListener('click', () => {
      const next = getTheme() === 'dark' ? 'light' : 'dark';
      setTheme(next);
      document.documentElement.setAttribute('data-theme', next);
      paint();
    });
  }

  const langSel = $('#lang');
  if (langSel) {
    langSel.value = LANG;
    langSel.addEventListener('change', () => { setLang(langSel.value); location.reload(); });
  }

  const logout = $('#logout');
  if (logout) logout.addEventListener('click', () => {
    clearToken();
    identityConfirmed = false; authMethod = null; whoamiLoaded = false;
    adminFlag = false; groupsList = [];
    location.hash = '#/login';
  });

  window.addEventListener('hashchange', route);
  // whoami au chargement (Phase 3e), AVANT le premier routage : c'est ce qui permet
  // au forward-auth pur (aucun jeton local) de ne jamais voir l'écran de connexion —
  // le routeur lit `identityConfirmed` posé ci-dessus dès sa première décision.
  await refreshWhoami();
  route();
  i18nWalk(document.querySelector('header'));

  // PWA : enregistre le service worker (best-effort, ignore les échecs)
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}

boot();
