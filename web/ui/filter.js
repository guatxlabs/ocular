// SPDX-FileCopyrightText: 2026 GuatX
// SPDX-License-Identifier: AGPL-3.0-or-later
// filter.js — filtrage/recherche des entrées réseau d'un résultat, côté client,
// SANS regex utilisateur (anti-ReDoS) : matching uniquement par String.includes
// (insensible à la casse) et égalité insensible à la casse. Logique pure
// (entryHost/entryMime/matchChip/filterEntries) + UI (buildFilterBar), XSS-clean
// via el()/textContent (jamais innerHTML de données non fiables).
//
// NB : AUCUN import (statique OU dynamique) de core.js ici. core.js exécute du
// bootstrap dépendant du navigateur dès son chargement (state.js lit
// `localStorage` au niveau module, core.js appelle `boot()`), ce qui casserait
// le chargement de ce module en environnement non-DOM (ex.
// `node tests/filter_test.mjs`, qui n'exerce que la logique pure). `el` est donc
// INJECTÉ par l'appelant dans `buildFilterBar` — la barre est ainsi construite de
// façon SYNCHRONE (indispensable pour que le `i18nWalk` synchrone de core.js
// couvre les libellés de la barre).

// ---- logique pure ----

export function entryHost(url) {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
}

export function entryMime(entry) {
  const headers = (entry && entry.headers) || {};
  for (const k of Object.keys(headers)) {
    if (String(k).toLowerCase() === 'content-type') {
      const v = headers[k];
      if (v == null) continue;
      return String(v).split(';')[0].trim();
    }
  }
  return (entry && entry.resource_type) || '';
}

function fieldValue(entry, field) {
  if (!entry) return undefined;
  switch (field) {
    case 'url': return entry.url;
    case 'domain': return entryHost(entry.url);
    case 'type': return entry.resource_type;
    case 'status': return entry.status == null ? undefined : String(entry.status);
    case 'mime': return entryMime(entry);
    // champs console (réutilise la même mécanique includes/equals, anti-ReDoS)
    case 'text': return entry.text;
    case 'level': return entry.level;
    default: return undefined;
  }
}

// ---- dédup natif ----
// Regroupe les entrées identiques (selon `keyFn`) en UNE seule, annotée `_count`
// (nombre d'occurrences fusionnées). Ordre stable (première apparition conservée).
// Pur, testable sans DOM. Utilisé pour le réseau (méthode+statut+type+url) et la
// console (niveau+texte) — évite les lignes répétées à l'écran.
export function dedupEntries(entries, keyFn) {
  const list = Array.isArray(entries) ? entries : [];
  const seen = new Map();
  const out = [];
  for (const e of list) {
    const k = keyFn(e);
    const hit = seen.get(k);
    if (hit) { hit._count += 1; continue; }
    const clone = Object.assign({}, e, { _count: 1 });
    seen.set(k, clone);
    out.push(clone);
  }
  return out;
}

export const networkKey = (n) => [n && n.method, n && n.status, n && n.resource_type, n && n.url].join('');
export const consoleKey = (c) => [c && c.level, c && c.text].join('');

// ---- constantes & rendus PARTAGÉS (detail.js + interactive.js) ----
// `el` (et `esc` pour la console) sont INJECTÉS par l'appelant : filter.js reste
// importable hors-DOM (cf. en-tête). Factorise du code jusqu'ici dupliqué à
// l'identique — en particulier le rendu exfil, dont une dérive = risque sécu.

export const CONSOLE_FIELD_DEFS = [
  { value: 'text', label: 'Texte' },
  { value: 'level', label: 'Niveau' },
];
export const SEV_CLASS = { critical: 'sev-4', high: 'sev-3', medium: 'sev-2', low: 'sev-1' };
export const VERDICT_CLASS = { benign: 'v-benign', suspicious: 'v-suspicious', malicious: 'v-malicious', unknown: 'v-unknown' };

// Rangée <tr> réseau (méthode/statut/type/url + badge ×N de dédup).
// Une coupe se DIT à l'endroit où l'analyste regarde. `truncation` en tête de
// vue répond à « ce résultat est-il complet ? » ; il ne désigne AUCUNE ligne.
// Une URL amputée avait donc exactement l'apparence d'une URL entière — et sur
// une balise GET de kit de phishing, ce qui disparaît est la fin de la query
// string, c'est-à-dire la pièce à conviction.
export function truncatedFields(entry) {
  const f = entry && entry.truncated_fields;
  const list = Array.isArray(f) ? f.slice() : [];
  // Alias historique : un payload déjà stocké ne porte que le booléen.
  if (entry && entry.post_data_truncated && !list.includes('post_data')) list.push('post_data');
  return list;
}

const TRUNC_TITLE = 'ce champ a été COUPÉ par un plafond anti-OOM — ce n\'est pas la '
  + 'valeur émise par la page, la fin manque';

// Marqueurs de coupe d'UNE entrée, DÉRIVÉS de `truncated_fields`.
//
// Le rendu ne part plus d'une liste de champs écrite ici : il part des noms que
// l'entrée PORTE. `badge(field)` marque un champ que l'appelant affiche ;
// `rest()` rend le complément — tout nom coupé qu'AUCUN rendu n'a réclamé.
// Un champ que le moteur se met à couper demain atteint donc l'analyste sans
// qu'aucun appelant n'ait à être modifié.
//
// CE QUE ÇA FERME, mesuré sur 651840c : `engine.wrapper._clip_field` peut
// nommer `url`, `post_data`, `headers`, `text`, `title` et `final_url` ;
// `grep -rn truncatedBadge web/ui/` ne rendait que trois appels — `url`,
// `post_data`, `text`. Avec `dom.truncated_fields = ['title', 'final_url']`,
// `detail.js` affichait `addRow('URL finale', dom.final_url)` SANS marqueur :
// une URL d'atterrissage amputée avait exactement l'apparence d'une URL
// entière. `headers`, lui, n'a même pas de ligne où se poser dans l'UI —
// c'est `rest()` qui le porte.
//
// Sens de défaillance : `rest()` calcule le complément des champs RÉCLAMÉS au
// moment où on l'appelle. Appelé trop tôt, il en nomme trop ; il ne peut pas en
// taire. Un marqueur en trop se voit, un marqueur manquant ne se voit pas.
export function truncationMarks(entry) {
  const claimed = new Set();
  const cut = truncatedFields(entry);
  return {
    badge(el, field) {
      claimed.add(field);
      if (!cut.includes(field)) return null;
      return el('span.truncbadge', { title: TRUNC_TITLE }, '✂ coupé');
    },
    rest(el) {
      const left = cut.filter((f) => !claimed.has(f)).sort();
      if (!left.length) return null;
      return el('span.truncbadge', {
        title: TRUNC_TITLE + ' (champ non affiché ailleurs dans cette vue)',
      }, '✂ coupé : ' + left.join(', '));
    },
  };
}

export function networkRow(el, n) {
  const marks = truncationMarks(n);
  return el('tr', {}, [
    el('td', {}, n.method || ''),
    el('td', {}, n.status != null ? String(n.status) : '—'),
    el('td', {}, n.resource_type || ''),
    el('td', { title: n.url || '' }, [
      el('span', {}, n.url || ''),
      marks.badge(el, 'url'),
      marks.badge(el, 'post_data'),
      // `headers` et tout champ coupé qui n'a pas de colonne ici.
      marks.rest(el),
      n._count > 1 ? el('span.dupbadge', { title: n._count + ' occurrences' }, '×' + n._count) : null,
    ]),
  ]);
}

// Ligne console (niveau/texte + badge ×N). `esc` injecté (classe CSS du niveau).
export function consoleLine(el, esc, c) {
  const marks = truncationMarks(c);
  return el('div.consline', {}, [
    el('span', { class: 'lvl ' + esc(c.level || '') }, c.level || ''),
    el('span.ctext', {}, c.text || ''),
    marks.badge(el, 'text'),
    marks.rest(el),
    c._count > 1 ? el('span.dupbadge', { title: c._count + ' occurrences' }, '×' + c._count) : null,
  ]);
}

// Rangée exfil d'un FORMULAIRE (action+méthode). Heuristique de risque
// (POST/externe/mailto) — signal sécu, source unique pour éviter la dérive.
export function exfilFormRow(el, form) {
  const action = String((form && form.action) || '');
  const method = String((form && form.method) || 'GET').toUpperCase();
  const isMailto = /^mailto:/i.test(action);
  const isExternal = /^https?:\/\//i.test(action);
  const risky = isMailto || isExternal || method === 'POST';
  return el('div', { class: 'exfil-row' + (risky ? ' exfil-risk' : '') }, [
    el('span.exfil-method', {}, method),
    el('span.exfil-dest', { title: action }, action || '(page courante)'),
    isMailto ? el('span.exfil-tag', {}, 'mailto') : (isExternal ? el('span.exfil-tag', {}, 'externe') : null),
  ]);
}

// Rangée exfil d'une cible mailto (toujours à risque).
export function exfilMailtoRow(el, mailto) {
  const m = String(mailto || '');
  return el('div.exfil-row.exfil-risk', {}, [
    el('span.exfil-method', {}, 'mailto'),
    el('span.exfil-dest', { title: m }, m.replace(/^mailto:/i, '')),
  ]);
}

// Libellé du marqueur `OcularResult.truncation` — helper PUR (aucun DOM), donc
// testable dans tests/filter_test.mjs.
//
// Sans lui, un résultat amputé s'affichait exactement comme un résultat complet :
// l'analyste croyait voir tout le trafic d'une page qui en avait émis cent fois
// plus. C'est l'angle mort que le champ était censé fermer, et que personne ne
// lisait. Rend `null` quand rien n'a été coupé — l'absence de bandeau signifie
// alors « complet », pas « on ne sait pas ».
//
// Deux familles distinctes, jamais confondues dans le libellé : `*_dropped` =
// des éléments ENTIERS manquent (preuve absente) ; `text_truncated` = les
// éléments sont là mais un champ texte a été coupé.
//
// Cette table est un DICTIONNAIRE DE LIBELLÉS, plus une liste de ce qui est
// rendu : le bandeau parcourt les compteurs REÇUS (cf. `truncationNotice`).
// Un compteur qui n'y figure pas est quand même annoncé, sous un libellé
// dérivé de son nom. `/live` en produit désormais qui ne sont dans aucun
// modèle : `_fit_live_payload` (runner_recon_vnc/session_server.py) délestre
// toutes les listes du payload et nomme son compteur `<champ>_dropped` — donc
// `forms_dropped` et `mailtos_dropped` aujourd'hui, d'autres demain.
const TRUNCATION_LABELS = new Map([
  ['network_dropped', 'appels réseau non conservés'],
  ['console_dropped', 'messages console non conservés'],
  ['findings_dropped', 'détections non conservées'],
  ['forms_dropped', 'formulaires non conservés'],
  ['mailtos_dropped', 'cibles mailto non conservées'],
  ['other_dropped', 'éléments non conservés (fenêtres sans compteur dédié)'],
  ['post_data_truncated', 'corps de requête coupés'],
  ['text_truncated', 'champs texte coupés'],
  ['html_chars_dropped', 'caractères de page non analysés'],
  ['over_cap_bytes', 'octets au-delà du plafond, que le délestage n\'a pas pu retirer'],
]);

// Libellé d'un compteur inconnu, dérivé de son NOM : `<quoi>_dropped` = des
// éléments entiers manquent, `<quoi>_truncated` = des champs ont été coupés,
// `<quoi>_chars_dropped` = une CHAÎNE a été coupée et voici de combien (les
// deux natures de volume variable du payload `/live` : une liste se déleste,
// une chaîne se coupe). Le suffixe le plus long est reconnu d'abord, sans quoi
// `_chars_dropped` se lirait comme un `_dropped`. Le nom brut est conservé dans
// le libellé — c'est le vocabulaire du payload, et il vaut mieux un compteur
// affiché sous son nom technique qu'un compteur tu.
function truncationLabel(key) {
  const known = TRUNCATION_LABELS.get(key);
  if (known) return known;
  if (key.endsWith('_chars_dropped')) return `caractères coupés dans « ${key.slice(0, -14)} »`;
  if (key.endsWith('_dropped')) return `« ${key.slice(0, -8)} » non conservés`;
  if (key.endsWith('_truncated')) return `« ${key.slice(0, -10)} » coupés`;
  return `« ${key} »`;
}

export function truncationNotice(truncation) {
  if (!truncation || typeof truncation !== 'object') return null;
  // Ordre : les compteurs connus d'abord, dans l'ordre du dictionnaire (stable
  // d'un rendu à l'autre), puis les autres, triés. Ce qui est PARCOURU est la
  // liste des clefs REÇUES : aucun compteur ne peut arriver sans être annoncé.
  const received = Object.keys(truncation);
  const known = [...TRUNCATION_LABELS.keys()].filter((k) => received.includes(k));
  const unknown = received.filter((k) => !TRUNCATION_LABELS.has(k)).sort();
  const parts = [];
  for (const key of [...known, ...unknown]) {
    const n = Number(truncation[key]) || 0;
    if (n > 0) parts.push(`${n} ${truncationLabel(key)}`);
  }
  if (!parts.length) return null;
  return `Résultat incomplet : ${parts.join(', ')} — les plafonds anti-OOM ont mordu.`;
}

export function matchChip(entry, chip) {
  if (!chip) return false;
  const val = fieldValue(entry, chip.field);
  if (val == null) return false;
  if (chip.value == null) return false;
  const a = String(val).toLowerCase();
  const b = String(chip.value).toLowerCase();
  if (chip.op === 'equals') return a === b;
  // default / 'contains' : substring uniquement, jamais de regex
  return a.includes(b);
}

export function filterEntries(entries, chips) {
  const list = Array.isArray(entries) ? entries : [];
  const list2 = Array.isArray(chips) ? chips : [];
  const includes = list2.filter((c) => !c.exclude);
  const excludes = list2.filter((c) => c.exclude);
  return list.filter((entry) => {
    for (const c of includes) if (!matchChip(entry, c)) return false;
    for (const c of excludes) if (matchChip(entry, c)) return false;
    return true;
  });
}

// ---- UI ----

const FIELDS = [
  { value: 'url', label: 'URL' },
  { value: 'domain', label: 'Domaine' },
  { value: 'type', label: 'Type' },
  { value: 'status', label: 'Statut' },
  { value: 'mime', label: 'MIME' },
];

const OPS = [
  { value: 'contains', label: 'contient' },
  { value: 'equals', label: 'égal' },
];

function chipLabel(chip) {
  const opSym = chip.op === 'equals' ? '=' : '~';
  const prefix = chip.exclude ? '−' : '+';
  return `${prefix}${chip.field}${opSym}${chip.value}`;
}

export function buildFilterBar(getEntries, onChange, opts = {}) {
  // `el` est injecté par l'appelant (jamais importé ici : voir en-tête). La barre
  // est donc construite de façon SYNCHRONE -> insérée avant i18nWalk().
  const el = opts.el;
  if (typeof el !== 'function') {
    throw new TypeError('buildFilterBar: opts.el (fabrique de nœuds) requis');
  }
  // `opts.fieldDefs` : liste de champs SUR MESURE ({value,label}) — remplace
  // entièrement le menu réseau par défaut (utilisé par la console : text/level).
  // Sinon `opts.fields` restreint les champs réseau intégrés.
  const fields = Array.isArray(opts.fieldDefs) && opts.fieldDefs.length
    ? opts.fieldDefs
    : (Array.isArray(opts.fields) && opts.fields.length
      ? FIELDS.filter((f) => opts.fields.includes(f.value))
      : FIELDS);

  const chips = [];

  const textInput = el('input.filter-value', { type: 'text', placeholder: 'valeur…' });
  const fieldSelect = el('select.filter-field', {}, fields.map((f) =>
    el('option', { value: f.value }, [f.label])));
  const opSelect = el('select.filter-op', {}, OPS.map((o) =>
    el('option', { value: o.value }, [o.label])));
  const excludeToggle = el('input.filter-exclude', { type: 'checkbox' });

  const chipsWrap = el('div.filter-chips');
  const counter = el('span.filter-count');

  function refresh() {
    const all = (typeof getEntries === 'function' ? getEntries() : []) || [];
    const filtered = filterEntries(all, chips);
    counter.textContent = `${filtered.length} / ${all.length}`;
    if (typeof onChange === 'function') onChange(filtered);
  }

  function renderChips() {
    chipsWrap.replaceChildren(...chips.map((chip, idx) => {
      const removeBtn = el('button.chip-remove', {
        type: 'button',
        'aria-label': 'retirer',
        onclick: () => {
          chips.splice(idx, 1);
          renderChips();
          refresh();
        },
      }, ['×']);
      return el(`span.filter-chip${chip.exclude ? '.exclude' : '.include'}`, {}, [
        el('span.chip-label', {}, [chipLabel(chip)]),
        removeBtn,
      ]);
    }));
  }

  function addChip() {
    const value = textInput.value;
    if (!value) return;
    chips.push({
      field: fieldSelect.value,
      op: opSelect.value,
      value,
      exclude: !!excludeToggle.checked,
    });
    textInput.value = '';
    renderChips();
    refresh();
  }

  const addBtn = el('button.filter-add', { type: 'button', onclick: addChip }, ['+']);
  textInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); addChip(); }
  });

  const bar = el('div.filter-bar', {}, [
    el('div.filter-controls', {}, [
      fieldSelect,
      opSelect,
      textInput,
      el('label.filter-exclude-label', {}, [excludeToggle, el('span', {}, ['exclure'])]),
      addBtn,
    ]),
    chipsWrap,
    counter,
  ]);

  renderChips();
  refresh();

  // Expose le refresh interne sur le nœud (rétro-compatible : detail.js ignore
  // `.refresh`). Utile aux appelants dont les données évoluent APRÈS la
  // construction de la barre (ex. panneau live pollé toutes les 2s) : ils
  // gardent une réf mutable, `getEntries` renvoie les données courantes, et
  // `bar.refresh()` ré-applique les chips DÉJÀ posés sur ces nouvelles données
  // + re-rend — sans reconstruire la barre (donc chips préservés).
  bar.refresh = refresh;

  return bar;
}
