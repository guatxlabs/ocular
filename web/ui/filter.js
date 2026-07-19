// SPDX-FileCopyrightText: 2026 guatx
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
export function networkRow(el, n) {
  return el('tr', {}, [
    el('td', {}, n.method || ''),
    el('td', {}, n.status != null ? String(n.status) : '—'),
    el('td', {}, n.resource_type || ''),
    el('td', { title: n.url || '' }, [
      el('span', {}, n.url || ''),
      n._count > 1 ? el('span.dupbadge', { title: n._count + ' occurrences' }, '×' + n._count) : null,
    ]),
  ]);
}

// Ligne console (niveau/texte + badge ×N). `esc` injecté (classe CSS du niveau).
export function consoleLine(el, esc, c) {
  return el('div.consline', {}, [
    el('span', { class: 'lvl ' + esc(c.level || '') }, c.level || ''),
    el('span.ctext', {}, c.text || ''),
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
