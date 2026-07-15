// saved.js — liste des analyses sauvegardées (source serveur : GET /saved).
// Chaque ligne ouvre le détail figé (#/saved/{id}). Toutes les données affichées
// (verdict, label, hash, date) posées en textNode/attribut — jamais innerHTML.
import { el, iconNode } from '../core.js';
import { listSaved, Unauthorized } from '../api.js';

const VERDICT_TONE = { benign: 'ok', suspicious: 'warn', malicious: 'bad' };
// verdict ANALYSTE (Phase 3e) : vocabulaire distinct du verdict auto (legitimate,
// pas benign — cf. AnalystVerdictRequest côté serveur) ; même palette de tons.
const ANALYST_TONE = { legitimate: 'ok', suspicious: 'warn', malicious: 'bad' };
const TONE_STYLE = {
  ok: 'color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent);border-color:color-mix(in srgb,var(--ok) 40%,transparent)',
  warn: 'color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,transparent);border-color:color-mix(in srgb,var(--warn) 40%,transparent)',
  bad: 'color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,transparent);border-color:color-mix(in srgb,var(--bad) 42%,transparent)',
  mut: 'color:var(--mut);background:var(--card2)',
};

export function verdictPill(v) {
  const tone = VERDICT_TONE[v] || 'mut';
  return el('span.pending-pill', { style: TONE_STYLE[tone] }, v || 'unknown');
}

// Pastille verdict ANALYSTE — `null` si aucun verdict analyste posé (pas de pastille
// vide affichée). Valeur enum fixe (legitimate/suspicious/malicious, validée côté
// serveur) : jamais de donnée hostile ici, mais on reste sur el()/textNode par
// cohérence avec le reste de la vue.
export function analystPill(v) {
  if (!v) return null;
  const tone = ANALYST_TONE[v] || 'mut';
  return el('span.pending-pill.analyst-pill', { style: TONE_STYLE[tone] }, v);
}

// Provenance compacte pour une ligne de liste : « sauvé par X » + Turnstile ✓/✗
// (omis si `turnstile_solved` est null — non applicable, ex. profil html). `saved_by`
// est une identité potentiellement hostile (forward-auth) -> textNode via el(), jamais
// innerHTML.
export function provenanceLine(m) {
  const kids = [];
  if (m.saved_by) kids.push(el('span.prov-by', {}, ['sauvé par ', el('b', {}, m.saved_by)]));
  if (m.turnstile_solved === 1) kids.push(el('span.prov-ts.ok', { title: 'Turnstile passé' }, 'Turnstile ✓'));
  else if (m.turnstile_solved === 0) kids.push(el('span.prov-ts.bad', { title: 'Turnstile non passé' }, 'Turnstile ✗'));
  if (!kids.length) return null;
  return el('span.provenance-mini', {}, kids);
}

// ISO -> horodatage local lisible (fallback : la chaîne brute si non parsable).
export function fmtIso(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

// "sha256:abcd…" -> "abcd…1234" (12 hex de tête, jamais rendu en HTML).
function shortHash(h) {
  const hex = String(h || '').replace(/^sha256:/, '');
  return hex.length > 14 ? hex.slice(0, 12) + '…' : hex;
}

export function renderSaved(app) {
  app.appendChild(el('div.viewhead', {}, [
    el('h2', {}, 'Sauvegardes'),
    el('span.sub', {}, 'Analyses conservées côté serveur, indépendantes du navigateur.'),
  ]));

  const host = el('div');
  app.appendChild(host);
  host.appendChild(el('div.card', {}, [el('div.emptyview', {}, [el('p', {}, 'chargement…')])]));

  (async () => {
    let rows;
    try { rows = await listSaved(); }
    catch (ex) {
      if (ex instanceof Unauthorized) return;
      host.replaceChildren(el('div.card', {}, [el('div.errbox', {}, String(ex.message || ex))]));
      return;
    }
    if (!rows.length) {
      host.replaceChildren(el('div.card', {}, [
        el('div.emptyview', {}, [
          iconNode('bookmark'),
          el('p', {}, 'Aucune analyse sauvegardée.'),
          el('span.muted', {}, 'Ouvre une analyse terminée puis « Sauvegarder ».'),
        ]),
      ]));
      return;
    }
    const list = el('div.joblist');
    rows.forEach((m) => {
      const go = () => { location.hash = '#/saved/' + m.id; };
      list.appendChild(el('div.jobrow', {
        role: 'button', tabindex: '0', onclick: go,
        onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } },
      }, [
        verdictPill(m.verdict),
        analystPill(m.analyst_verdict),
        el('span.jobtarget', { title: m.label || '' }, m.label || '(sans étiquette)'),
        provenanceLine(m),
        el('span.savedhash', { title: m.input_hash || '' }, shortHash(m.input_hash)),
        el('time', {}, fmtIso(m.saved_at)),
        iconNode('chevright'),
      ]));
    });
    host.replaceChildren(list);
  })();

  return null;
}
