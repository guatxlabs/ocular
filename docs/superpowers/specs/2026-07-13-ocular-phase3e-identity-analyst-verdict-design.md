# Ocular — Phase 3e : Identité IdP + verdict analyste + provenance — Design

- **Date** : 2026-07-13 · **Statut** : Approuvé (design), prêt pour plan.
- **Base** : moteur complet (phases 3a–3d). Ajoute l'**identité portable (forward-auth)**, le **verdict analyste** (override annoté), et la **provenance de sauvegarde** enrichie.

## 1. But
Intégration SOC : savoir **qui** analyse/tranche, sans verrouiller l'outil à un IdP. Compatible Keycloak / Authentik / LDAP / OIDC via **n'importe quel** reverse-proxy forward-auth (oauth2-proxy, Authelia, Authentik proxy, Keycloak+oauth2-proxy…). Un analyste peut **classer** un résultat (legitimate / suspicious / malicious) à côté du verdict automatique, avec traçabilité. Les sauvegardes portent hash + horodatage + **identité** + **statut Turnstile**.

## 2. Décisions figées (validées)
| # | Décision |
|---|----------|
| E1 | **Identité = forward-auth headers** : l'outil fait confiance à l'en-tête d'identité injecté par le reverse-proxy authentifié. Bearer `OCULAR_TOKEN` = fallback hors-proxy. |
| E2 | **Verdict analyste = override annoté** : champ séparé (legitimate/suspicious/malicious) + identité + horodatage + note. Le verdict **auto n'est JAMAIS écrasé**. |
| E3 | **Provenance sauvegarde** : `input_hash` (déjà) + `saved_at` (déjà) + `saved_by` (identité) + `turnstile_solved`. |

## 3. Sécurité (impératif — c'est le cœur du risque)
- **Forward-auth = opt-in strict.** L'en-tête d'identité n'est lu QUE si `OCULAR_TRUST_FORWARD_AUTH=1`. Par défaut **désactivé** → seul le Bearer authentifie (comportement actuel inchangé, aucune régression). Sinon, un client pourrait spoofer `X-Forwarded-User`.
- **Le proxy DOIT stripper** toute copie de l'en-tête venant du client (documenté en gras dans le README : sans ça, spoofing d'identité). Ocular ne peut pas le garantir seul → responsabilité de déploiement clairement documentée.
- **Noms d'en-têtes configurables** (`OCULAR_FORWARD_USER_HEADER` déf. `X-Forwarded-User`, `OCULAR_FORWARD_EMAIL_HEADER` déf. `X-Forwarded-Email`).
- **Admin inchangé** : `DELETE /saved` exige toujours `X-Admin-Token` (le forward-auth donne un utilisateur normal, pas un admin — pas d'escalade). Fail-closed préservé partout.
- Identité **jamais loggée en clair** avec des données sensibles ; l'identité est une donnée de provenance (nom de compte), pas un secret — mais ne jamais logger token/secret. `whoami` ne révèle que l'identité de l'appelant lui-même.
- Pas de nouveau secret cryptographique : l'auto-token = **auto-authentification** via l'identité de confiance du proxy (pas d'émission de JWT maison). « Créer un token automatiquement » = l'analyste derrière l'IdP n'a **rien à coller** ; chaque requête (proxifiée) porte son identité → autorisée.

## 4. Architecture
```
Client ──(IdP: Keycloak/Authentik/LDAP)──▶ reverse-proxy (forward-auth)
   proxy authentifie + injecte X-Forwarded-User: alice  (et strippe les copies client)
        │
        ▼
   [ web/_auth ]  autorisé si (Bearer valide) OU (TRUST_FORWARD_AUTH & en-tête identité présent)
        │  request.state.identity = 'alice' (ou 'token' si bearer seul, ou None)
        ▼
   GET /auth/whoami -> {identity, method}         (UI : « connecté : alice », pas de token à coller)
   POST /saved            -> saved_by = identity, turnstile_solved (depuis result.stealth)
   POST /saved/{id}/verdict {analyst_verdict, note} -> analyst=identity, analyst_at=now
```

### 4.1 Identité (`web/identity.py` + `_auth`, `ocular_settings`)
- `ocular_settings` : `trust_forward_auth()`, `forward_auth_user_header()`, `forward_auth_email_header()`.
- `web/identity.py::resolve_identity(request) -> (authorized: bool, identity: str|None, method: str)` :
  - Bearer valide → `(True, <forward id si présent sinon "token">, "bearer")`.
  - sinon si `trust_forward_auth()` et en-tête identité non vide → `(True, <valeur>, "forward-auth")`.
  - sinon → `(False, None, "none")`.
  - **N'accède JAMAIS à l'en-tête si `trust_forward_auth()` est faux.**
- `_auth` middleware : remplace le check bearer-seul par `resolve_identity` ; 401 si non autorisé ; pose `request.state.identity`. Admin (`DELETE /saved`) : inchangé (X-Admin-Token en plus).
- `GET /auth/whoami` (protégé) : `{identity, method}` de l'appelant.

### 4.2 Provenance + verdict analyste (`saved_store.py`)
- **Migration idempotente** dans `connect()` : après `CREATE TABLE IF NOT EXISTS`, pour chaque nouvelle colonne, `PRAGMA table_info` + `ALTER TABLE saved_analysis ADD COLUMN` si absente (rétro-compatible avec une base existante). Nouvelles colonnes : `saved_by TEXT`, `turnstile_solved INTEGER`, `analyst_verdict TEXT`, `analyst TEXT`, `analyst_at TEXT`, `analyst_note TEXT`.
- `save(..., saved_by=None)` : stocke `saved_by` + `turnstile_solved` (extrait de `result["stealth"]["turnstile_solved"]`, 0/1/None).
- `set_analyst_verdict(conn, sid, analyst_verdict, analyst, analyst_at, note)` : met à jour les 4 champs analyste. `analyst_verdict ∈ {"legitimate","suspicious","malicious"}` (sinon `ValueError`).
- `list_all`/`get_by_hash`/`get_result`/nouveau `get_meta(sid)` exposent les nouveaux champs.

### 4.3 Web (`web/app.py`, `web/models.py`)
- `POST /saved` : `saved_by = getattr(request.state, "identity", None)`.
- `POST /saved/{id}/verdict` (protégé) body `{analyst_verdict, note?}` : valide `analyst_verdict` (422 sinon) ; `set_analyst_verdict(..., analyst=request.state.identity, analyst_at=now, note=note[:2000])`. Note bornée.
- `GET /auth/whoami`.
- `GET /saved` (liste) + détail exposent `saved_by`, `turnstile_solved`, `analyst_verdict`, `analyst`, `analyst_at`, `analyst_note`.

### 4.4 UI
- Bandeau « connecté : `<identity>` » (via `/auth/whoami`) — quand derrière le proxy, aucun token à coller.
- Vue Sauvegardes / détail : **provenance** (sauvé par X @ T, Turnstile ✓/✗) + **verdict auto** ET **verdict analyste** côte à côte ; contrôles pour classer (legitimate/suspicious/malicious + note), XSS-clean. i18n FR→EN.

## 5. Tests
- **Unit** : `resolve_identity` (bearer ok ; forward-auth ok si opt-in ET header ; **header ignoré si opt-in OFF** ; ni l'un ni l'autre → non autorisé) ; `_auth` (401 sans, 200 avec bearer, 200 avec forward-auth opt-in, **401 avec header forward-auth mais opt-in OFF** = anti-spoofing) ; migration saved_store idempotente (base ancienne sans colonnes → ALTER ; base neuve → ok) ; `save` stocke saved_by/turnstile ; `set_analyst_verdict` (valeurs valides/invalides) ; endpoints (`/auth/whoami`, `POST /saved/{id}/verdict` 200/422, `POST /saved` capture l'identité) ; admin toujours protégé.
- **e2e** : (a) sans `OCULAR_TRUST_FORWARD_AUTH` → un `X-Forwarded-User: attacker` NE donne PAS accès (401) [anti-spoofing] ; (b) avec opt-in → `X-Forwarded-User: alice` → autorisé, `whoami=alice`, save → `saved_by=alice`, classer → `analyst_verdict` posé avec `analyst=alice` ; (c) `DELETE /saved` sans X-Admin-Token → refusé même avec forward-auth.

## 6. Différé
- Émission d'un vrai JWT/token signé maison (non nécessaire : auth via identité proxy). Mapping de groupes IdP → rôles (admin via groupe) — futur. Validation OIDC JWT in-app (sans proxy) — futur (le forward-auth couvre le cas proxifié, le plus courant).

## 7. Ordre de livraison (SDD)
1. Identité : settings + `web/identity.py` + `_auth` + `/auth/whoami` + tests (anti-spoofing prioritaire).
2. `saved_store` : migration idempotente + `saved_by`/`turnstile_solved` + `set_analyst_verdict` + getters + tests.
3. Web : `POST /saved` (saved_by), `POST /saved/{id}/verdict`, exposition des champs + tests.
4. UI : whoami + provenance + contrôles verdict analyste + smoke.
5. Audit (sécu : anti-spoofing forward-auth, admin non escaladable, opt-in strict) + e2e + merge.
