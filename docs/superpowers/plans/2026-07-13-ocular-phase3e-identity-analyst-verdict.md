# Phase 3e — Identité IdP + verdict analyste + provenance — Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Identité portable (forward-auth opt-in), verdict analyste (override annoté), provenance de sauvegarde (identité + Turnstile), sans régresser l'auth bearer.

## Global Constraints
- `ocular/` uniquement ; jamais plume/core/forge. **Forward-auth = opt-in strict** (`OCULAR_TRUST_FORWARD_AUTH`, défaut OFF → en-tête identité JAMAIS lu, comportement bearer inchangé). Admin (`DELETE /saved`) inchangé (X-Admin-Token, pas d'escalade via IdP). Fail-closed partout. Jamais token/secret loggé. UI XSS-clean, i18n FR→EN. `analyst_verdict ∈ {legitimate,suspicious,malicious}`.

---

### Task 1 — Identité (settings + resolve_identity + _auth + /auth/whoami)

**Files:** Modify `ocular_settings.py`, `web/app.py` ; Create `web/identity.py` ; Test `tests/test_identity.py`, `tests/test_web_auth.py` (ou existant).

- `ocular_settings.py` : `trust_forward_auth()->bool` (`OCULAR_TRUST_FORWARD_AUTH`, défaut False) ; `forward_auth_user_header()->str` (déf. `"X-Forwarded-User"`) ; `forward_auth_email_header()->str` (déf. `"X-Forwarded-Email"`).
- `web/identity.py::resolve_identity(request, *, bearer_ok: bool) -> tuple[bool, str|None, str]` : reçoit si le bearer est déjà validé (`bearer_ok`) et l'objet request.
  - si `bearer_ok` → `(True, forward_id or "token", "bearer")` (forward_id = valeur de l'en-tête user SI `trust_forward_auth()` et présent, sinon None → "token").
  - sinon si `trust_forward_auth()` et en-tête user (`forward_auth_user_header()`) présent+non vide → `(True, valeur, "forward-auth")`.
  - sinon `(False, None, "none")`.
  - **N'accède à l'en-tête que si `trust_forward_auth()` est vrai** (anti-spoofing).
- `web/app.py::_auth` : calcule `bearer_ok` (comme aujourd'hui, compare_digest, mais NE renvoie plus 401 immédiatement) ; `authorized, identity, method = resolve_identity(request, bearer_ok=bearer_ok)` ; si `not authorized` → 401 (même message) ; sinon `request.state.identity = identity` ; `request.state.auth_method = method` ; puis le check admin existant pour `DELETE /saved` (inchangé). Le 503 `OCULAR_TOKEN non configuré` : garder SEULEMENT si ni bearer ni forward-auth possibles — c.-à-d. si `OCULAR_TOKEN` absent ET `trust_forward_auth()` faux → 503 (sinon forward-auth peut autoriser sans OCULAR_TOKEN).
- `GET /auth/whoami` (protégé) : `{"identity": request.state.identity, "method": request.state.auth_method}`.

- [ ] **Tests anti-spoofing (PRIORITAIRES)** `tests/test_identity.py`/`tests/test_web_auth.py` :
  - opt-in OFF (défaut) + `X-Forwarded-User: attacker`, pas de bearer → **401** (en-tête ignoré).
  - opt-in OFF + bearer valide → 200, identity="token".
  - opt-in ON + `X-Forwarded-User: alice`, pas de bearer → 200, identity="alice", method="forward-auth".
  - opt-in ON + bearer valide + `X-Forwarded-User: alice` → 200, identity="alice" (le proxy prime pour la provenance), method="bearer".
  - opt-in ON, pas d'en-tête, pas de bearer → 401.
  - `OCULAR_TOKEN` absent + opt-in OFF → 503 ; `OCULAR_TOKEN` absent + opt-in ON + header → 200.
  - `/auth/whoami` renvoie l'identité de l'appelant.
  - `resolve_identity` n'accède pas à l'en-tête quand opt-in OFF (monkeypatch/mock : vérifier via un header dont la lecture serait tracée, ou tester le résultat).
- [ ] `pytest -m "not integration" -q` vert (aucune régression des tests d'auth existants — le bearer seul marche pareil). Commit : `feat(3e): identité forward-auth opt-in + resolve_identity + /auth/whoami (anti-spoofing)`.

---

### Task 2 — saved_store : migration + provenance + verdict analyste

**Files:** Modify `saved_store.py` ; Test `tests/test_saved_store.py`.

- **Migration idempotente** dans `connect()` : après le `CREATE TABLE IF NOT EXISTS`, pour chaque colonne de `[("saved_by","TEXT"),("turnstile_solved","INTEGER"),("analyst_verdict","TEXT"),("analyst","TEXT"),("analyst_at","TEXT"),("analyst_note","TEXT")]` : si absente de `PRAGMA table_info(saved_analysis)` → `ALTER TABLE saved_analysis ADD COLUMN <nom> <type>`. Idempotent (base neuve : colonnes créées par le CREATE si tu les y ajoutes AUSSI, OU uniquement par l'ALTER — choisis un seul mécanisme cohérent ; le plus simple : garder le CREATE minimal existant + ALTER pour tout le nouveau, s'applique aux deux cas).
- `save(conn, result, blobs, label, now_iso, saved_by=None)` : ajoute `saved_by` et `turnstile_solved = 1 if (result.get("stealth") or {}).get("turnstile_solved") else (0 if "stealth" in result else None)` dans l'INSERT. Rétro-compat (defaut None). Ne casse pas la signature positionnelle existante (saved_by en kwarg à la fin).
- `class DuplicateLabelError` inchangé.
- `set_analyst_verdict(conn, sid, analyst_verdict, analyst, analyst_at, note=None)` : `if analyst_verdict not in {"legitimate","suspicious","malicious"}: raise ValueError` ; `UPDATE saved_analysis SET analyst_verdict=?, analyst=?, analyst_at=?, analyst_note=? WHERE id=?` ; retourne True si une ligne modifiée sinon False.
- `list_all`/`get_by_hash` : ajouter `saved_by, turnstile_solved, analyst_verdict, analyst, analyst_at` aux colonnes SELECT ; nouveau `get_meta(conn, sid)` renvoyant tous les champs meta (dont `analyst_note`).

- [ ] Tests : migration sur base SANS les colonnes (créer une table à l'ancien schéma → connect() ajoute les colonnes, pas d'erreur) ; migration idempotente (2 connect successifs) ; `save` stocke saved_by + turnstile_solved (result avec stealth.turnstile_solved True→1, False→0, sans stealth→None) ; `set_analyst_verdict` valeur valide→ok, invalide→ValueError, sid inconnu→False ; list_all/get_by_hash exposent les nouveaux champs.
- [ ] `pytest -m "not integration" -q` vert. Commit : `feat(3e): saved_store — migration + saved_by/turnstile + verdict analyste`.

---

### Task 3 — Web : endpoints provenance + verdict analyste

**Files:** Modify `web/app.py`, `web/models.py` ; Test `tests/test_saved_api.py`, `tests/test_web*.py`.

- `POST /saved` (`create_saved`) : passe `saved_by=getattr(request.state, "identity", None)` à `saved_store.save`. (Le handler doit accéder à `request` — ajouter `request: Request` en param si absent.)
- `POST /saved/{sid}/verdict` (protégé) : modèle `AnalystVerdictRequest {analyst_verdict: str, note: Optional[str]}` ; valide `analyst_verdict` (via set_analyst_verdict qui lève ValueError → `HTTPException(422)`) ; `analyst = request.state.identity` ; `analyst_at = now iso` ; `note` bornée 2000 ; 404 si sid inconnu ; renvoie le meta mis à jour.
- `GET /saved` + détail (`get_saved`/liste) : inclure `saved_by, turnstile_solved, analyst_verdict, analyst, analyst_at, analyst_note` dans la réponse.
- `GET /auth/whoami` (déjà en T1).

- [ ] Tests : `POST /saved` derrière forward-auth (opt-in ON, header alice) → l'enreg a `saved_by="alice"` ; `POST /saved/{id}/verdict {analyst_verdict:"legitimate"}` → 200, champ posé avec analyst=identité ; valeur invalide → 422 ; sid inconnu → 404 ; la liste/détail expose les champs. Auth : ces routes sont protégées.
- [ ] `pytest -m "not integration" -q` vert. Commit : `feat(3e): web — saved_by, POST /saved/{id}/verdict, exposition provenance+analyste`.

---

### Task 4 — UI : whoami + provenance + contrôles verdict analyste

**Files:** Modify `web/ui/api.js`, `web/ui/views/detail.js` et/ou `web/ui/views/saved.js`, `web/ui/core.js` (bandeau whoami), `web/ui/i18n.js`, `web/ui/style.css` ; Test `tests/test_ui_smoke.py`. `node --check`.

- `api.js` : `whoami()` (GET /auth/whoami), `setAnalystVerdict(sid, verdict, note)` (POST /saved/{sid}/verdict).
- Bandeau « connecté : `<identity>` » (via whoami au chargement) ; si method="forward-auth", pas d'invite de token.
- Vue Sauvegardes/détail : afficher **provenance** (sauvé par X @ T, Turnstile ✓/✗) + **verdict auto** ET **verdict analyste** ; contrôles pour classer (boutons legitimate/suspicious/malicious + champ note) appelant `setAnalystVerdict`, mise à jour à chaud. **XSS-clean** (identité/note en textContent, jamais innerHTML). i18n FR→EN.

- [ ] Smoke : `api.js` a `whoami`/`setAnalystVerdict` ; la vue affiche provenance + contrôles verdict analyste sans innerHTML sur identité/note ; bandeau whoami présent. `node --check` ; `pytest tests/test_ui_smoke.py -q` + `pytest -m "not integration" -q` verts.
- [ ] Commit : `feat(3e): UI — bandeau whoami + provenance + verdict analyste (XSS-clean)`.

---

### Task 5 — Audit + e2e + merge
- [ ] Audit sécu : **anti-spoofing** (opt-in OFF → header ignoré) ; opt-in strict ; admin non escaladable via forward-auth ; identité jamais confondue avec un secret ; migration sûre ; note bornée ; XSS. Remédier Critical/Important.
- [ ] **e2e réel** (rebuild web) : (a) sans opt-in, `X-Forwarded-User: attacker` sans bearer → **401** ; (b) opt-in ON, header alice → whoami=alice, save → saved_by=alice, POST verdict → analyst_verdict posé avec analyst=alice ; (c) `DELETE /saved` sans X-Admin-Token → refusé même en forward-auth ; (d) bearer classique inchangé.
- [ ] Merge via finishing-a-development-branch + MAJ mémoire/roadmap.

## Self-review
- Anti-spoofing = opt-in strict testé en priorité. Admin non escaladable. Bearer inchangé (rétro-compat). Migration idempotente. Verdict auto jamais écrasé (champ analyste séparé). Provenance = identité + Turnstile. UI XSS-clean.
