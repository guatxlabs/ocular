// core.js — point d'entrée de l'UI Ocular : helpers DOM partagés, routeur hash,
// et câblage du header (nav / langue / thème / déconnexion). Vanilla ES modules,
// zéro build. Importé une fois par index.html (<script type="module">).
import { getToken, clearToken, LANG, setLang, getTheme, setTheme } from './state.js';
import { i18nWalk } from './i18n.js';
import { renderLogin } from './views/login.js';
import { renderSubmit } from './views/submit.js';
import { renderJobs } from './views/jobs.js';
import { renderDetail } from './views/detail.js';

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

export function fmtTs(ms) {
  if (!ms) return '';
  const loc = LANG === 'en' ? 'en-US' : 'fr-FR';
  return new Date(ms).toLocaleString(loc);
}

// ---- chrome : nav active + visibilité selon l'état de connexion ----
function updateChrome(view) {
  const authed = !!getToken();
  const nav = $('#topnav');
  const logout = $('#logout');
  if (nav) nav.hidden = !authed;
  if (logout) logout.hidden = !authed;
  document.querySelectorAll('#topnav a').forEach((a) =>
    a.classList.toggle('on', a.dataset.route === view || (view === 'job' && a.dataset.route === 'jobs')));
}

// ---- routeur hash ----
let cleanup = null;
function route() {
  if (cleanup) { try { cleanup(); } catch { /* noop */ } cleanup = null; }
  const app = $('#app');
  const token = getToken();
  const parts = (location.hash || '').replace(/^#\/?/, '').split('/');
  const view = parts[0] || '';

  if (!token && view !== 'login') { location.hash = '#/login'; return; }
  if (token && (view === '' || view === 'login')) { location.hash = '#/jobs'; return; }

  updateChrome(view);
  app.replaceChildren();
  if (view === 'login') cleanup = renderLogin(app);
  else if (view === 'submit') cleanup = renderSubmit(app);
  else if (view === 'jobs') cleanup = renderJobs(app);
  else if (view === 'job') cleanup = renderDetail(app, parts[1]);
  else { location.hash = '#/jobs'; return; }
  i18nWalk(app);
  window.scrollTo(0, 0);
}

// ---- boot ----
function boot() {
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
  if (logout) logout.addEventListener('click', () => { clearToken(); location.hash = '#/login'; });

  window.addEventListener('hashchange', route);
  route();
  i18nWalk(document.querySelector('header'));

  // PWA : enregistre le service worker (best-effort, ignore les échecs)
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
}

boot();
