# Phase 3h — Admin via groupe IdP — Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Accorder le rôle **admin** (`DELETE /saved`) depuis un **groupe IdP** (`X-Forwarded-Groups`), en plus du `X-Admin-Token`. Complète l'intégration IdP portable de 3e (Keycloak/Authentik/LDAP portent des groupes). Opt-in strict anti-spoofing.

## Global Constraints
- `ocular/` uniquement ; jamais plume/core/forge. **Groupes lus UNIQUEMENT si `trust_forward_auth()`** (opt-in strict, même anti-spoofing que l'identité 3e ; sinon `X-Forwarded-Groups` totalement ignoré). `X-Admin-Token` reste le fallback (déploiement hors-IdP inchangé). Fail-closed : aucun mécanisme configuré → 503 ; configuré mais non accordé → 403. Jamais token/secret loggé. UI XSS-clean, i18n FR→EN.

---

### Task H1 — settings + groupes + is_admin + _auth + whoami

**Files:** Modify `ocular_settings.py`, `web/identity.py`, `web/app.py` ; Test `tests/test_identity.py`, `tests/test_web_auth.py`.

- `ocular_settings.py` : `admin_group() -> str` (`OCULAR_ADMIN_GROUP`, défaut `""` = admin-par-groupe désactivé) ; `forward_auth_groups_header() -> str` (`OCULAR_FORWARD_GROUPS_HEADER`, défaut `"X-Forwarded-Groups"`).
- `web/identity.py` :
  - `resolve_groups(request) -> list[str]` : si `trust_forward_auth()`, lit `forward_auth_groups_header()`, split sur `,` (strip, filtre vides) → liste ; sinon `[]`. **N'accède à l'en-tête que si `trust_forward_auth()`** (anti-spoofing).
  - `has_admin_group(request) -> bool` : `g = admin_group()` ; `bool(g) and g in resolve_groups(request)`. (Retourne False si `admin_group` vide OU opt-in off OU groupe absent.)
- `web/app.py::_auth`, bloc admin `DELETE /saved` : remplace le check `X-Admin-Token`-seul par :
  - `adm = os.environ.get("OCULAR_ADMIN_TOKEN")` ; `token_ok = bool(adm) and secrets.compare_digest(provided, adm)` (comme avant) ; `group_ok = has_admin_group(request)`.
  - Si **aucun mécanisme configuré** (`not adm` ET (`not admin_group()` OU pas de forward-auth de confiance)) → `503` (« aucun mécanisme admin configuré »).
  - Sinon si `token_ok or group_ok` → autorisé ; sinon `403`.
  - Jamais logger le token/groupe ; seulement path+status.
- `web/app.py::whoami` : ajoute `groups` (= `resolve_groups(request)`) et `is_admin` (= `token_ok or has_admin_group(request)` — attention : `whoami` est un GET, pas d'`X-Admin-Token` en général ; `is_admin` reflète surtout le groupe pour l'UI ; documente que l'admin-token n'est pas fourni sur un GET whoami donc `is_admin` via token sera rare — l'UI se base sur le groupe). Simplest : `is_admin = has_admin_group(request)` (l'admin-token est un mécanisme par-requête sur DELETE, pas un état de session). Documente ce choix.

- [ ] **Tests anti-spoofing (prioritaires)** :
  - opt-in OFF + `X-Forwarded-Groups: admins` → `resolve_groups` = `[]`, `has_admin_group` False (en-tête ignoré).
  - opt-in ON + `admin_group="admins"` + `X-Forwarded-Groups: "a,admins,b"` → `has_admin_group` True ; groupes = `["a","admins","b"]`.
  - opt-in ON + groupes sans `admins` → False. `admin_group=""` → False même si le groupe est présent.
  - `_auth DELETE /saved` : X-Admin-Token valide → 200 (autorisé) ; opt-in ON + groupe admin → autorisé ; opt-in ON + groupe non-admin → 403 ; **opt-in OFF + `X-Forwarded-Groups: admins` spoofé (sans token) → 403** (anti-spoofing) ; aucun mécanisme (pas de token, pas de admin_group) → 503.
  - `whoami` renvoie `groups` + `is_admin` cohérents ; GET whoami avec groupe admin (opt-in ON) → `is_admin: true`.
- [ ] `pytest -m "not integration" -q` vert (les tests admin/auth existants restent verts : X-Admin-Token seul marche pareil). Commit : `feat(3h): admin via groupe IdP (X-Forwarded-Groups) opt-in + X-Admin-Token fallback + whoami groups/is_admin`.

---

### Task H2 — UI : masquer les contrôles admin aux non-admins

**Files:** Modify `web/ui/views/admin.js` (et/ou saved.js), `web/ui/core.js`, `web/ui/i18n.js` ; Test `tests/test_ui_smoke.py`. `node --check`.

- Au chargement (whoami déjà appelé en 3e), stocker `is_admin`/`groups`. La vue Admin (flush/delete) et les boutons de suppression : **affichés seulement si `is_admin`** ; sinon message « admin requis » (ou masqués). XSS-clean (groupes en textContent si affichés). i18n.
- (Le backend reste la vraie garde — l'UI est juste de l'ergonomie ; ne jamais s'y fier pour la sécu.)

- [ ] Smoke : la vue admin conditionne l'affichage sur `is_admin` ; groupes affichés sans innerHTML. `node --check` ; `pytest tests/test_ui_smoke.py -q` + `pytest -m "not integration" -q` verts.
- [ ] Commit : `feat(3h): UI masque les contrôles admin aux non-admins (is_admin/groups via whoami)`.

---

### Task H3 — Audit + e2e + merge
- [ ] Audit sécu : **anti-spoofing** (opt-in OFF → groupes ignorés → pas d'admin) ; `admin_group` vide → group-admin off ; `X-Admin-Token` toujours valable ; fail-closed (503/403) ; pas d'escalade (un groupe quelconque ne donne pas admin) ; UI n'est pas la garde. Remédier Critical/Important.
- [ ] **e2e réel** : (a) opt-in ON + `admin_group=admins` + `X-Forwarded-Groups: admins` → `DELETE /saved` **autorisé** ; (b) `X-Forwarded-Groups: users` (sans admins) → **403** ; (c) `X-Admin-Token` valide → autorisé ; (d) **opt-in OFF + `X-Forwarded-Groups: admins` spoofé → 403** ; (e) `whoami` reflète `is_admin`.
- [ ] Merge via finishing-a-development-branch + MAJ README (doc `OCULAR_ADMIN_GROUP` + strip proxy) + roadmap/mémoire.

## Self-review
- Groupes = opt-in strict (anti-spoofing prouvé en priorité). X-Admin-Token fallback intact. Fail-closed. UI ergonomique, backend = garde réelle. Pas d'escalade.
