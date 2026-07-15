# Phase 3d-1 — Correctness + UX (batch rapide) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps en cases (`- [ ]`).

**Goal:** 6 correctifs ciblés (verdict, upload, CSS, unicité nom, GC planifié, schéma URL) issus du retour utilisateur, sans régression des invariants existants.

**Tech Stack:** Python 3.11 / FastAPI / Redis / Docker / vanilla-JS UI / pytest.

## Global Constraints
- Ne JAMAIS toucher `plume`/`core`/`forge` ni hors `ocular/`. Séparation de privilèges intacte. DRY, pas de monolithe, pas de hardcode sécu. TDD (test rouge d'abord). Chaque tâche = tests verts + `pytest -m "not integration" -q` sans régression.
- UI XSS-clean (textNode, jamais `innerHTML` de données non fiables). i18n FR→EN maintenu.

---

### Task A — Verdict : un script externe seul ne pilote plus le verdict

**Files:** Modify `engine/static.py` ; Test `tests/test_static.py` (ou existant) + `tests/test_verdict.py`.

**Contexte :** `engine/static.py` `PATTERNS` : `(r"<script...src=https?://...", "External script", "critical")`. `compute_verdict` (engine/verdict.py) : `critical→malicious`, `high→suspicious`, sinon `benign`. Donc un CDN légitime → `malicious`.

**Fix :** abaisser la sévérité de **`External script`** de `critical` à **`medium`** (aligné sur `External image`=medium ; medium ne pilote pas le verdict → `benign`). Ne PAS toucher les autres détecteurs (recalibration plus large = suivi séparé, décision modèle de menace).

- [ ] Test rouge : `analyze_html('<script src="https://cdn.example/x.js"></script>')` → finding `External script` présent ET `compute_verdict(findings) == "benign"`.
- [ ] Fix : changer la sévérité dans `PATTERNS`.
- [ ] Vérifier qu'aucun test existant n'attendait `External script`=critical (ajuster si oui, en cohérence avec la nouvelle intention).
- [ ] `pytest -m "not integration" -q` vert. Commit : `fix(3d): script externe seul ne pilote plus le verdict (External script critical->medium)`.

---

### Task H — Schéma URL : détection auto http/https + fallback

**Files:** Modify `engine/urlnorm.py` (si besoin), `web/app.py` (normalisation à la soumission capture + interactif), `runner_recon/capture.py` (fallback runtime) ; Tests `tests/test_urlnorm.py`, `tests/test_web*.py`, `tests/test_capture_logic.py`.

**Contexte :** `engine/urlnorm.py::normalize_url` préfixe déjà `https://` pour un domaine nu (mirroir `new URL()`). Mais la soumission ne normalise pas forcément avant `validate_capture_url`, et il n'y a pas de fallback si `https` échoue.

**Fix (3 volets) :**
1. **Normalisation à la soumission** : dans `submit_job` (profil capture) ET `POST /sessions` (interactif), normaliser l'URL entrante via `normalize_url` AVANT `validate_capture_url` → `example.com` devient `https://example.com`, `http://x`/`https://x` respectés. Enqueue/lance l'URL normalisée.
2. **Fallback runtime https→http** : dans `runner_recon/capture.py` (`capture_url` ET `capture_scripted`), si le `page.goto(url)` initial échoue (exception réseau / pas de réponse) ET que le schéma est `https`, retenter UNE fois en `http://` (même hôte/chemin). Journaliser le fallback (console `warning`, jamais d'URL secrète). Ne pas retenter si l'échec n'est pas lié au schéma (ex. timeout DNS d'un domaine inexistant → une seule tentative de fallback max, pas de boucle).
3. Le `final_url`/`redirect_chain` du résultat doit refléter l'URL réellement atteinte.

- [ ] Tests urlnorm : `example.com`→`https://example.com` ; `http://example.com` inchangé ; `https://example.com` inchangé.
- [ ] Test web : `POST /jobs {url:"example.com", profile:"capture"}` → le job enqueue porte `https://example.com` (normalisé) ; idem `POST /sessions`.
- [ ] Test logique fallback (sans navigateur si possible, sinon unit ciblé) : un `goto` https qui lève → une seconde tentative http est faite ; un `goto` https qui réussit → pas de seconde tentative.
- [ ] `pytest -m "not integration" -q` vert. Commit : `feat(3d): normalisation schéma URL à la soumission + fallback https->http runtime`.

---

### Task D — Sauvegardes : unicité du nom (label)

**Files:** Modify `saved_store.py`, `web/app.py` (endpoint `POST /saved`), `web/ui/views/saved.js`/`submit.js` (affichage erreur) ; Tests `tests/test_saved_store.py`, `tests/test_web*.py`.

**Contexte :** `saved_store.save(...)` UPSERT par `input_hash` (colonne UNIQUE). Le `label` (nom) n'est pas unique → deux sauvegardes différentes peuvent porter le même nom.

**Fix :** interdire qu'un `label` non vide soit réutilisé par un `input_hash` DIFFÉRENT.
- Dans `saved_store.save`, avant l'INSERT : si `label` non vide ET `SELECT 1 FROM saved_analysis WHERE label=? AND input_hash != ?` existe → lever une exception dédiée `DuplicateLabelError` (nouvelle, sous-classe de `ValueError`). Le re-save du MÊME `input_hash` avec le même label reste autorisé (UPSERT).
- `web/app.py POST /saved` : capturer `DuplicateLabelError` → `HTTPException(409, "nom déjà utilisé")`.
- UI : afficher proprement le 409 (message clair au moment de sauvegarder), XSS-clean.

- [ ] Test store : deux hash différents, même label → 2ᵉ `save` lève `DuplicateLabelError` ; même hash même label → ok (UPSERT) ; label vide/None → pas de contrainte.
- [ ] Test web : `POST /saved` d'un nom déjà pris (hash différent) → 409.
- [ ] `pytest -m "not integration" -q` vert. Commit : `feat(3d): unicité du nom des sauvegardes (409 si nom pris par un autre contenu)`.

---

### Task E — GC des artefacts planifié

**Files:** Modify `broker/main.py`, `ocular_settings.py` ; Test `tests/test_broker*.py`, `tests/test_gc.py`.

**Contexte :** `broker/gc.py::collect(artifacts_dir, client, min_age_seconds=300)` supprime les artefacts non référencés et assez vieux, mais **n'est jamais appelé dans la boucle broker** (seulement `make gc`). Les résultats Redis expirent via `result_ttl()` (24h) mais les artefacts s'accumulent. Le broker a déjà un pattern de thread périodique : `_reaper_loop`/`_start_reaper`.

**Fix :** ajouter `gc_interval()` à `ocular_settings.py` (ex. `OCULAR_GC_INTERVAL`, défaut 600s) et une boucle GC dans `broker/main.py` calquée sur `_reaper_loop` (thread daemon, survit à une erreur transitoire, `stop_event` pour les tests), démarrée dans `run_forever`. Elle appelle `gc.collect(artifacts_dir(), client)` chaque intervalle.

- [ ] Test : la boucle GC appelle bien `collect` à intervalle (avec `stop_event`, mock de `collect`), survit à une exception transitoire.
- [ ] Test : `run_forever`/`_start_*` démarre le thread GC (comme le reaper).
- [ ] `pytest -m "not integration" -q` vert. Commit : `feat(3d): GC des artefacts planifié (thread broker, intervalle configurable)`.

---

### Task F — Upload : accepter .htm/.html (analyse ET interactif)

**Files:** Modify `web/ui/views/submit.js`, `web/ui/views/interactive.js`, `web/ui/i18n.js` ; Test `tests/test_ui_smoke.py`.

**Contexte :** `submit.js:32` `accept: '.eml,message/rfc822,text/html'` ; libellés ne parlent que de `.eml`. L'interactif (mode HTML) n'a pas d'upload fichier.

**Fix :**
- `submit.js` : `accept` inclut `.htm,.html` (+ existants). Libellés/placeholder/i18n : « HTML, .htm, .html ou .eml » (bouton « Charger un fichier » plutôt que « Charger un .eml »). Un `.eml` reste accepté (mail, parfois HTML).
- `interactive.js` (mode HTML) : ajouter le même bouton d'upload fichier `.htm,.html,.eml,text/html` qui remplit la textarea HTML.
- i18n : clés FR→EN mises à jour.

- [ ] Test smoke : `submit.js` accept contient `.html`/`.htm` ; libellé ne dit plus uniquement « .eml » ; `interactive.js` a un input file HTML.
- [ ] `pytest -m "not integration" -q` vert. Commit : `feat(3d): upload accepte .htm/.html (analyse + interactif) + libellés clarifiés`.

---

### Task G — UI : bandeau « IP exposée » ne déborde plus

**Files:** Modify `web/ui/style.css` ; Test `tests/test_ui_smoke.py` (léger).

**Contexte :** `.livewarn` (style.css:1163) a `border:1px ...` + `border-left:3px solid var(--warn)` : le trait gauche de 3px dépasse des coins arrondis (`border-radius`) → « ce qui dépasse à gauche du rectangle ».

**Fix :** retirer le `border-left:3px solid var(--warn)` de `.livewarn` (garder le `border:1px` uniforme + `border-radius`), pas de surplus de CSS. La sémantique d'alerte reste portée par l'icône `.ic` + la couleur du texte `b`.

- [ ] Test smoke : `.livewarn` n'a plus de `border-left` divergent (assertion sur le source CSS).
- [ ] Vérif : la carte reste visuellement propre (bordure uniforme). Commit : `fix(3d): bandeau IP exposée — retire le border-left qui dépasse des coins arrondis`.

---

## Ordre & parallélisme
Backend disjoints en parallèle : **A** (static), **E** (broker/gc), **D** (saved_store+web). Puis UI : **F** (submit/interactive/i18n) + **G** (style.css) — fichiers quasi disjoints, mais séquencer si conflit sur `test_ui_smoke.py`. **H** (urlnorm+web+runner) indépendant. Chaque tâche : implémenteur + relecteur. Puis audit court + e2e (soumission `example.com`→https, save nom dupliqué→409, verdict script externe→benign) + merge.
