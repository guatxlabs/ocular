# Phase 3d-2 (I) — Filtrage/recherche des résultats (SOC) — Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Filtrer/chercher efficacement les entrées réseau d'un résultat (centaines d'appels) par domaine / URL / type / statut / MIME, avec inclusions ET exclusions cumulables, **côté client**, **sans ReDoS**. Composant réutilisable (résultat + futur panneau live interactif C).

## Global Constraints
- `ocular/` uniquement ; jamais plume/core/forge. UI vanilla-JS, XSS-clean (textNode/`el()`, jamais innerHTML de données non fiables). i18n FR→EN.
- **Sécurité filtrage** : AUCUNE regex utilisateur (pas de ReDoS). Matching **substring** (`String.includes`, insensible à la casse) et **égalité** structurée uniquement. Filtrage **côté client** sur les données déjà chargées — aucune nouvelle route serveur, aucune ré-injection réseau, aucun log.
- Composant **réutilisable** et **pur** pour la logique (testable).

---

### Task 1 — Module `web/ui/filter.js` (logique pure + UI)

**Files:** Create `web/ui/filter.js` ; Test `tests/filter_test.mjs` (node) + `tests/test_filter_js.py` (subprocess, skip si node absent) + `tests/test_ui_smoke.py` (source assertions).

**Interfaces (produit) :**
- `export function entryHost(url)` : extrait le domaine/host d'une URL (via `new URL`, fallback robuste si URL invalide → `""`), sans crash.
- `export function entryMime(entry)` : renvoie le MIME de l'entrée — d'abord `entry.headers` (clé `content-type`/`Content-Type`, partie avant `;`), sinon `entry.resource_type || ""`. Insensible à la casse pour la clé header.
- `export function matchChip(entry, chip)` : `chip = {field, op, value, exclude}` avec `field ∈ {"url","domain","type","status","mime"}`, `op ∈ {"contains","equals"}`. Renvoie true si l'entrée **matche** (avant application de `exclude`). `field` → valeur testée : url→`entry.url`, domain→`entryHost(entry.url)`, type→`entry.resource_type`, status→`String(entry.status)`, mime→`entryMime(entry)`. `contains` = `String(val).toLowerCase().includes(chip.value.toLowerCase())` ; `equals` = égalité insensible à la casse. **Aucune regex.** Valeur/champ absents → ne matche pas (pas de crash).
- `export function filterEntries(entries, chips)` : une entrée **passe** si (elle matche TOUS les chips include) ET (elle ne matche AUCUN chip exclude). Aucun chip → toutes passent. Retourne le sous-tableau filtré (ordre préservé).
- `export function buildFilterBar(getEntries, onChange, opts)` : construit un nœud DOM (via `el()`) = un champ texte + un select `field` + un select `op` (contains/equals) + un toggle include/exclude + bouton « + » qui ajoute un **chip** ; chips affichés (retirable au clic, label + `×`), **XSS-clean** (`el()`/textContent) ; un compteur « N / total » ; `onChange(filteredEntries)` appelé à chaque modif de chips. `opts` peut fixer les valeurs de `field` disponibles.

- [ ] **Step 1 — Test node comportemental** `tests/filter_test.mjs` (assertions `node:assert`) :

```js
import assert from 'node:assert';
import { entryHost, entryMime, matchChip, filterEntries } from '../web/ui/filter.js';

const E = [
  { url: 'https://a.example.com/x.js', method:'GET', status:200, resource_type:'script', headers:{'content-type':'application/javascript; charset=utf-8'} },
  { url: 'https://cdn.other.net/p.png', method:'GET', status:200, resource_type:'image', headers:{'Content-Type':'image/png'} },
  { url: 'https://a.example.com/api', method:'POST', status:404, resource_type:'xhr', headers:{} },
];
assert.equal(entryHost(E[0].url), 'a.example.com');
assert.equal(entryHost('not a url'), '');
assert.equal(entryMime(E[0]).startsWith('application/javascript'), true);
assert.equal(entryMime(E[2]), 'xhr'); // fallback resource_type
// include: domain contains example -> 2
assert.equal(filterEntries(E, [{field:'domain',op:'contains',value:'example',exclude:false}]).length, 2);
// exclude: type equals image -> 2
assert.equal(filterEntries(E, [{field:'type',op:'equals',value:'image',exclude:true}]).length, 2);
// cumul: domain example AND status 404 -> 1
assert.equal(filterEntries(E, [{field:'domain',op:'contains',value:'example',exclude:false},{field:'status',op:'equals',value:'404',exclude:false}]).length, 1);
// mime contains png -> 1
assert.equal(filterEntries(E, [{field:'mime',op:'contains',value:'png',exclude:false}]).length, 1);
// pas de crash sur entrée sans url/headers
assert.equal(filterEntries([{}], [{field:'url',op:'contains',value:'x',exclude:false}]).length, 0);
console.log('filter_test OK');
```

- [ ] **Step 2 — Test Python** `tests/test_filter_js.py` : lance `node tests/filter_test.mjs` via subprocess ; `pytest.skip` si `node` introuvable ; asserte code retour 0 et « filter_test OK » en sortie.
- [ ] **Step 3 — `node tests/filter_test.mjs`** → FAIL (module absent).
- [ ] **Step 4 — Implémente `web/ui/filter.js`** (logique pure + `buildFilterBar`).
- [ ] **Step 5 — node + pytest verts.**
- [ ] **Step 6 — Commit** `feat(3d): module filter.js (filtrage résultats structuré, sans regex/ReDoS)`.

---

### Task 2 — Intégrer le filtre au tableau réseau du résultat

**Files:** Modify `web/ui/views/detail.js` (`buildNetwork`), `web/ui/i18n.js`, `web/ui/style.css` ; Test `tests/test_ui_smoke.py`.

**Interfaces (consomme) :** `filter.js` (`buildFilterBar`, `filterEntries`).

- `buildNetwork(net)` : si `net.length` dépasse un petit seuil (ex. > 8), afficher la **barre de filtre** au-dessus du tableau ; `onChange(filtered)` re-rend les lignes du tableau (mêmes colonnes method/status/type/url) + met à jour le compteur. Le tableau initial = toutes les entrées. XSS-clean (déjà via `el()`). Aucune requête réseau déclenchée par le filtre.
- i18n FR→EN (labels : filtre, domaine, type, statut, mime, contient, égal, exclure, correspondances).
- CSS : barre de filtre + chips discrets (accent `#8b5cf6`), thème clair+sombre.

- [ ] **Step 1 — Smoke test** : `detail.js` importe `filter.js` et appelle `buildFilterBar`/`filterEntries` dans `buildNetwork` ; le filtre ne fait pas de `fetch`/réseau (grep : pas d'appel API dans le handler de filtre) ; pas d'`innerHTML` sur les lignes.
- [ ] **Step 2 — FAIL.**
- [ ] **Step 3 — Implémente** l'intégration (`node --check` sur detail.js).
- [ ] **Step 4 — pytest vert.**
- [ ] **Step 5 — Commit** `feat(3d): filtre SOC sur le tableau réseau du résultat (réutilise filter.js)`.

---

## Self-review
- Couverture : logique pure testée (node) ; intégration testée (smoke) ; sécurité (pas de regex, pas de réseau, XSS-clean) exigée à chaque tâche.
- Réutilisabilité : `filter.js` autonome → réutilisé par le panneau live interactif (phase C).
