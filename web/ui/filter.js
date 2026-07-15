// filter.js — filtrage/recherche des entrées réseau d'un résultat, côté client,
// SANS regex utilisateur (anti-ReDoS) : matching uniquement par String.includes
// (insensible à la casse) et égalité insensible à la casse. Logique pure
// (entryHost/entryMime/matchChip/filterEntries) + UI (buildFilterBar), XSS-clean
// via el()/textContent (jamais innerHTML de données non fiables).
//
// NB : `el()` est importé dynamiquement (lazy) plutôt qu'en import statique.
// core.js exécute du code de bootstrap dépendant du navigateur dès son chargement
// (state.js lit `localStorage` au niveau module, `core.js` appelle `boot()`) — un
// import statique casserait le chargement de ce module en environnement non-DOM
// (ex. `node tests/filter_test.mjs`, qui exerce uniquement la logique pure). Le
// chargement dynamique confine cette dépendance à `buildFilterBar`, seule
// fonction qui construit réellement du DOM.
let elPromise = null;
function loadEl() {
  if (!elPromise) elPromise = import('./core.js').then((m) => m.el);
  return elPromise;
}

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
    default: return undefined;
  }
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

export async function buildFilterBar(getEntries, onChange, opts = {}) {
  const el = await loadEl();
  const fields = Array.isArray(opts.fields) && opts.fields.length
    ? FIELDS.filter((f) => opts.fields.includes(f.value))
    : FIELDS;

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

  return bar;
}
