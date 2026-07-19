// SPDX-FileCopyrightText: 2026 guatx
// SPDX-License-Identifier: AGPL-3.0-or-later
// saved.js — liste des analyses sauvegardées (source serveur : GET /saved).
// Chaque ligne ouvre le détail figé (#/saved/{id}). Toutes les données affichées
// (verdict, label, hash, date) posées en textNode/attribut — jamais innerHTML.
import { el, iconNode, TONE_STYLE, verdictPill, fmtIso, shortHash } from '../core.js';
import { listSaved, Unauthorized } from '../api.js';
import { triageBadgeText } from '../triage.js';

// verdict ANALYSTE (Phase 3e) : vocabulaire distinct du verdict auto (legitimate,
// pas benign — cf. AnalystVerdictRequest côté serveur) ; même palette de tons
// (TONE_STYLE partagé depuis core.js). verdictPill/fmtIso/shortHash vivent
// désormais dans core.js (helpers génériques) et sont importés ci-dessus.
const ANALYST_TONE = { legitimate: 'ok', suspicious: 'warn', malicious: 'bad' };

// Pastille TRIAGE compacte pour une ligne de liste — `null` si aucun score de
// triage (analyse antérieure au calcul). La bande (low/medium/high) porte le ton
// via une classe (cf. .triage-pill dans style.css). Valeur issue de NOTRE moteur,
// mais posée en textNode via el() par cohérence (jamais innerHTML).
export function triagePill(m) {
  if (m == null || m.triage_score == null) return null;
  const band = m.triage_band || 'low';
  return el('span.pending-pill.triage-pill.triage-band-' + band, {},
    triageBadgeText({ score: m.triage_score, band }));
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

export function renderSaved(app) {
  app.appendChild(el('div.viewhead', {}, [
    el('h2', {}, 'Sauvegardes'),
    el('span.sub', {}, 'Analyses conservées côté serveur, indépendantes du navigateur.'),
  ]));

  // Contrôle de tri (date | priorité) : au changement, re-fetch listSaved({sort})
  // et re-rend la liste (pas de rechargement de vue). `saved_at` reste le défaut
  // (comportement historique : listSaved() sans param -> GET /saved inchangé).
  const sortSelect = el('select.saved-sort', {}, [
    el('option', { value: 'saved_at' }, 'date'),
    el('option', { value: 'triage_score' }, 'priorité'),
  ]);
  // Filtre de priorité (min_band) : « toutes » n'envoie aucun param (inclut les
  // analyses non triées, band NULL) ; une bande minimale filtre côté serveur
  // (GET /saved?min_band=…) et EXCLUT donc les analyses sans triage.
  const bandSelect = el('select.saved-band', {}, [
    el('option', { value: '' }, 'toutes'),
    el('option', { value: 'low' }, 'triées (≥ basse)'),
    el('option', { value: 'medium' }, '≥ moyenne'),
    el('option', { value: 'high' }, 'haute'),
  ]);
  app.appendChild(el('div.saved-controls', {}, [
    el('label.saved-sort-label', {}, ['trier : ', sortSelect]),
    el('label.saved-band-label', {}, ['priorité : ', bandSelect]),
  ]));

  const host = el('div');
  app.appendChild(host);
  host.appendChild(el('div.card', {}, [el('div.emptyview', {}, [el('p', {}, 'chargement…')])]));

  async function refresh() {
    const sort = sortSelect.value;
    const minBand = bandSelect.value;
    const params = {};
    if (sort && sort !== 'saved_at') params.sort = sort;
    if (minBand) params.min_band = minBand;
    let rows;
    // aucun param (tri=date, filtre=toutes) -> appel nu pour préserver GET /saved.
    try { rows = await (Object.keys(params).length ? listSaved(params) : listSaved()); }
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
        triagePill(m),
        el('span.jobtarget', { title: m.label || '' }, m.label || '(sans étiquette)'),
        provenanceLine(m),
        el('span.savedhash', { title: m.input_hash || '' }, shortHash(m.input_hash)),
        el('time', {}, fmtIso(m.saved_at)),
        iconNode('chevright'),
      ]));
    });
    host.replaceChildren(list);
  }

  sortSelect.addEventListener('change', refresh);
  bandSelect.addEventListener('change', refresh);
  refresh();

  return null;
}
