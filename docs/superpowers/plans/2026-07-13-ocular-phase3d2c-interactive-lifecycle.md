# Phase 3d-2 (C) — Interactif : cycle de vie + panneau live — Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Rendre la session interactive (3b) « SOC-grade » : panneau **live** (appels réseau + analyse statique en continu), **fermeture auto** (onglet caché >1 min, fermeture brutale du navigateur), **sauvegarde** de la session.

## Global Constraints
- `ocular/` uniquement ; jamais plume/core/forge. Séparation de privilèges intacte (web sans docker.sock ; secret `X-Session-Secret` à la frontière conteneur, jamais loggé). DRY (réutilise `NetworkCapture`/`analyze_html`/`ResultBuilder`, `filter.js`). UI XSS-clean (el()/textNode). i18n FR→EN.
- Décisions figées (validées) : **C4 panneau live temps-réel** via **polling HTTP** (canal données séparé du flux pixels, ~2s) ; **C2 fermeture auto silencieuse** à 60s d'onglet caché.

---

### Task C1 — `/live` (session_server) + proxy web `GET /sessions/{id}/live`

**Files:** Modify `runner_recon_vnc/session_server.py`, `web/app.py` ; Test `tests/test_session_server_logic.py` (ou existant), `tests/test_web_sessions.py`.

**session_server** — nouvel endpoint `GET /live` (auth `require_session_secret`) :
- si pas de page active → `{"network":[],"findings":[],"counts":{"network":0,"findings":0},"verdict":"benign"}`.
- sinon : `dom = await page.content()` (try/except → ""), `findings = analyze_html(dom)`, `network = cap.network` ; renvoyer `{"network": network[-500:], "findings":[f.model_dump(mode="json") for f in findings], "counts":{"network":len(network),"findings":len(findings)}, "verdict": compute_verdict(findings)}`. Bornage `[-500:]` (charge). Réutilise `analyze_html`/`compute_verdict` déjà importés — aucune duplication.

**web** — proxy `GET /sessions/{session_id}/live` (auth Bearer, `_PROTECTED`) :
- helper `_internal_get_json(url, secret, timeout=5.0)` (calqué sur `_internal_capture` : GET urllib + header `X-Session-Secret`, jamais loggé, échec → 502).
- récupère le secret via `registry.get_secret(sid)`, appelle `http://{container}:8090/live`, `registry.touch(sid, now)`, renvoie le JSON. 404 si session inconnue, 502 si le conteneur ne répond pas.

- [ ] Tests session_server : `/live` sans page → structure vide ; avec page mockée (DOM contenant un `<script src=...>` et des entrées `cap.network`) → findings + network + counts + verdict cohérents ; auth requise (403 sans secret).
- [ ] Tests web : `GET /sessions/{id}/live` sans token → 401 ; session inconnue → 404 ; happy path (mock `_internal_get_json`) → 200 + `touch` appelé.
- [ ] `pytest -m "not integration" -q` vert. Commit : `feat(3d): session_server /live (réseau+analyse statique) + proxy web GET /sessions/{id}/live`.

---

### Task C2 — Fermeture brutale : `disconnected_at` + reaper grâce (C1 fonctionnel)

**Files:** Modify `bus/sessions.py`, `web/app.py` (WS proxy), `broker/main.py` (reaper), `ocular_settings.py` ; Test `tests/test_sessions_registry.py`, `tests/test_broker*.py`, `tests/test_ws_proxy.py`.

- `ocular_settings.py` : `session_disconnect_grace() -> int` (`OCULAR_SESSION_DISCONNECT_GRACE`, défaut 45).
- `bus/sessions.py` :
  - `mark_connected(sid)` : efface `disconnected_at` (hdel ou set "" / 0).
  - `mark_disconnected(sid, now_epoch)` : set `disconnected_at`.
  - `expired(now, ttl, idle, disconnect_grace)` : ajouter la règle — reaper si `disconnected_at` **défini et > 0** ET `now - disconnected_at > disconnect_grace`. (Une session jamais connectée a `disconnected_at` absent → PAS reaper par la grâce ; seulement ttl/idle.) Ne pas casser la signature existante : `disconnect_grace` en param avec défaut, ou surcharge — garder les appels existants verts.
  - Le secret/token restent filtrés de `list_active` (ne pas régresser).
- `web/app.py` WS proxy : à l'`accept`/connexion → `registry.mark_connected(sid)` ; dans le `finally` (déconnexion, y compris brutale) → `registry.mark_disconnected(sid, time.time())`.
- `broker/main.py` reaper : passer `session_disconnect_grace()` à `reap`/`expired`.

- [ ] Tests registre : session `disconnected_at` il y a > grâce → dans `expired()` ; connectée (disconnected_at effacé) → pas dans `expired()` ; jamais connectée → pas reaper par la grâce (seulement idle/ttl). Token/secret toujours filtrés.
- [ ] Tests WS proxy : connexion → `mark_connected` ; déconnexion (finally) → `mark_disconnected`.
- [ ] `pytest -m "not integration" -q` vert. Commit : `feat(3d): fermeture brutale — disconnected_at + reaper grâce (session abandonnée nettoyée)`.

---

### Task C3 — UI : panneau live + auto-fermeture onglet + sauvegarde

**Files:** Modify `web/ui/views/interactive.js`, `web/ui/api.js`, `web/ui/i18n.js`, `web/ui/style.css` ; Test `tests/test_ui_smoke.py`. `node --check`.

**C4 panneau live** : pendant la scène live (session ouverte), démarrer un **poll** `GET /sessions/{id}/live` toutes les ~2s (via `api.js`). Rendre un **panneau** à côté/sous le canvas : compteur « N appels réseau · M findings · verdict », un **tableau réseau filtrable** (réutilise `buildFilterBar`/`filterEntries` de `./filter.js`, seuil identique) et la liste des findings (rule/severity, XSS-clean). Arrêter le poll à la fermeture/`disconnect` (clearInterval, pas de fuite). Le poll met à jour `last_activity` côté serveur (via `/live`).

**C2 fermeture auto onglet caché** : `document.addEventListener('visibilitychange', ...)` : quand `document.hidden`, armer un timer 60s (`SESSION_HIDDEN_CLOSE_MS`) ; s'il est toujours caché à 60s → fermer la session (`DELETE /sessions/{id}`) + teardown RFB + arrêt du poll. Redevenu visible avant 60s → annuler le timer. Ajouter aussi `window.addEventListener('beforeunload', ...)` → tentative best-effort de `DELETE` (`navigator.sendBeacon` ou `fetch(..., {keepalive:true})`), sans bloquer la navigation.

**C3 sauvegarde** : sur le résultat produit par « Capturer » (déjà un `OcularResult`), exposer un bouton **Sauvegarder** (réutilise le même flux `POST /saved {job_id?/...}` que la vue résultat — vérifie comment la capture interactive obtient un id/paie la sauvegarde ; si la capture interactive ne passe pas par un job Redis, adapter : soit enregistrer le résultat capturé via un chemin `/saved` acceptant un result inline, soit réutiliser l'endpoint existant). Message clair + i18n. **XSS-clean**.

- [ ] Smoke : `interactive.js` importe `filter.js` et poll `/live` (pas de regex, pas d'innerHTML sur findings/réseau) ; présence du handler `visibilitychange` + timer 60s + `DELETE` ; présence du `beforeunload` ; bouton Sauvegarder ; `clearInterval` au teardown. i18n présentes.
- [ ] `node --check` interactive.js ; `pytest tests/test_ui_smoke.py -q` + `pytest -m "not integration" -q` verts.
- [ ] Commit : `feat(3d): interactif — panneau live filtrable + auto-fermeture onglet 60s + sauvegarde`.

---

### Task C4 — Audit + e2e réel + merge
- [ ] Audit court (sécu : secret jamais exposé au client via /live, pas de fuite ; reaper ne tue pas une session active ; poll borné ; XSS ; DoS /live borné). Remédier Critical/Important.
- [ ] **e2e réel** : `docker compose up`, créer une session URL live, poller `/live` (network+findings non vides), Capturer→Sauvegarder, fermer l'onglet (simuler DELETE), vérifier reaper nettoie une session dont le WS est coupé (grâce), aucun conteneur `ocular-sess-*` orphelin. Rebuild image `ocular-runner-recon-vnc` (contient session_server + engine/).
- [ ] Merge via finishing-a-development-branch (option 1) + MAJ mémoire/roadmap.

## Self-review
- Réutilise NetworkCapture/analyze_html/compute_verdict/ResultBuilder/filter.js (DRY, pas de nouvelle mécanique). Secret à la frontière conteneur inchangé. Poll = canal données séparé borné. Reaper étendu sans casser ttl/idle. UI XSS-clean.
