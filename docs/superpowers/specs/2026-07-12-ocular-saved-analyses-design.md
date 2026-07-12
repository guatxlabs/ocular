# Ocular — Analyses sauvegardées (persistance opt-in + dédup + admin) — Design

- **Date** : 2026-07-12
- **Statut** : Approuvé (design), prêt pour plan
- **Base** : moteur d'analyse mergé sur `main` (analysis-only). Compatible multi-étapes / « même site » pour la phase 3 sans les construire.

---

## 1. Contexte & but

Les résultats sont aujourd'hui **éphémères** (Redis + TTL 24 h, artefacts sur volume GC-és). L'analyste veut pouvoir **sauvegarder** une analyse terminée de façon **durable**, **retrouver** une analyse déjà faite (dédup), et **contrôler le volume** via une UI admin (supprimer / flush). Le tout self-hosted, léger, sans nouveau service.

## 2. Décisions figées

| # | Décision |
|---|---|
| S1 | Stockage = **SQLite auto-contenu** (`saved.db`) : à la sauvegarde on COPIE le résultat JSON + les **octets** des artefacts dans SQLite. Totalement découplé de Redis/volume/GC. |
| S2 | Tourne dans le **tier web** (déjà Redis + artefacts ro + UI, reste sans Docker). Volume persistant **`ocular-saved:/saved` en rw** (rootfs reste `read_only`). |
| S3 | Clé de dédup = `input_hash` (`sha256(html)` ; URL normalisée en phase 3), **UNIQUE**. Re-sauvegarder le même hash = **remplace** (UPSERT). |
| S4 | Dédup sur les **sauvegardes uniquement** (les éphémères Redis expirent). |
| S5 | Ops destructives (delete/flush) sous **`OCULAR_ADMIN_TOKEN` séparé**, fail-closed (503 si absent), comparaison temps-constant. Sauvegarder/consulter sous le token normal. |
| S6 | **Multi-étapes natif** : à la sauvegarde, boucler sur **tous** les refs du résultat, stocker chaque blob, **transaction atomique**. |

## 3. Modèle de données (`/saved/saved.db`)

```sql
CREATE TABLE saved_analysis (
  id          INTEGER PRIMARY KEY,
  input_hash  TEXT NOT NULL UNIQUE,          -- sha256(html) | url normalisée (phase 3)
  input_kind  TEXT NOT NULL,                 -- 'html' | 'url'
  job_id      TEXT,
  verdict     TEXT,
  label       TEXT,
  result_json TEXT NOT NULL,                 -- OcularResult complet (léger, refs)
  saved_at    TEXT NOT NULL                  -- ISO8601
);
CREATE TABLE saved_artifact (
  saved_id  INTEGER NOT NULL REFERENCES saved_analysis(id) ON DELETE CASCADE,
  ref       TEXT NOT NULL,                   -- sha256:...
  bytes     BLOB NOT NULL,
  PRIMARY KEY (saved_id, ref)
);
```
`PRAGMA foreign_keys = ON` (pour le cascade). Toutes les requêtes **paramétrées**.

Module dédié `saved_store.py` (neutre, comme `bus/`), API interne :
- `save(conn, result: dict, blobs: dict[str,bytes], label: str|None) -> int` — UPSERT par `input_hash`, insère les blobs en transaction.
- `get_by_hash(conn, input_hash) -> dict|None` (métadonnées) · `get_result(conn, id) -> dict|None` · `list_all(conn) -> list[dict]` · `get_artifact(conn, id, ref) -> bytes|None` · `delete(conn, id) -> bool` · `flush(conn) -> int`.
- `input_hash` calculé côté serveur à partir du résultat (`sha256` du HTML original) — voir §5.

## 4. API (tier web)

| Méthode/route | Auth | Rôle |
|---|---|---|
| `POST /saved` `{job_id, label?}` | token | lit le résultat Redis (`job_id`) + les octets des artefacts (volume ro) → `save()` → `{id, input_hash}` |
| `GET /saved/{hash}` | token | métadonnées si une sauvegarde existe pour ce hash (→ modal dédup), sinon 404 |
| `GET /saved` | token | liste `[{id, input_hash, verdict, label, saved_at}]` |
| `GET /saved/{id}/result` | token | `result_json` complet |
| `GET /saved/{id}/artifact/{ref}` | token | blob depuis SQLite ; **nosniff** ; PNG→`image/png`, sinon `text/plain`+`attachment` (DOM jamais inline) ; ref validé `ref_to_filename` |
| `DELETE /saved/{id}` | **admin** | supprime une analyse (cascade artefacts) |
| `DELETE /saved` | **admin** | flush (vide la base) |

**Middleware auth** étendu : `/jobs*` **et** `/saved*` exigent le token normal (fail-closed 503 / 401). En plus, **toute requête `DELETE` sur `/saved*`** exige `OCULAR_ADMIN_TOKEN` (header `Authorization: Bearer <admin>` ou header dédié `X-Admin-Token`) : 503 si admin token non configuré, 403 si absent/faux. Comparaison temps-constant (bytes).

**Comment le POST /saved obtient les octets d'artefacts** : le web a le volume artefacts en `ro` ; pour chaque ref du résultat, il lit `artifacts/<sha256_...>` via `ref_to_filename`. Si un artefact a déjà été GC-é (job trop vieux), la sauvegarde échoue proprement (409 « artefacts expirés, relancer l'analyse ») plutôt que de sauver un enregistrement incomplet.

## 5. Flux dédup (avant de lancer)

1. UI : à la soumission, calcule `sha256(htmlUtf8)` via `crypto.subtle.digest` (doit être **identique** au `input_hash` serveur = `sha256` du HTML brut).
2. `GET /saved/sha256:<hex>` → si 200 (existe) : **modal** « Analyse sauvegardée existante — verdict X, {date}, {label}. [Voir] · [Analyser quand même] · [Annuler] ».
3. « Voir » → vue détail sauvegardé. « Analyser quand même » → `POST /jobs` normal. « Annuler » → rien.
4. Si 404 → soumission directe (pas de modal).

> Le `input_hash` serveur (au moment du save) et le hash client (au submit) doivent coïncider : tous deux = `sha256` de la **chaîne HTML UTF-8 exacte**. Test de cohérence croisée client/serveur documenté.

## 6. UI (vanilla-JS, design plume — accent violet)

- **detail** : bouton **« Sauvegarder »** + champ `label` optionnel → `POST /saved` → état « sauvegardée ✓ » (badge). (Si `409 artefacts expirés` → message clair.)
- **saved** (nouvelle entrée nav) : liste des sauvegardes (verdict badge, date, label, hash tronqué) → clic = détail (réutilise le rendu `detail` sur les endpoints `/saved/{id}/*`).
- **admin** (nouvelle entrée nav) : champ « token admin » (stocké en mémoire de session, pas localStorage) → déverrouille les boutons **Supprimer** (par ligne) et **Flush**. Confirmation avant flush.
- **modal dédup** : au submit (cf. §5). Rendu en textNode/setAttribute (contenu = métadonnées contrôlées, mais on garde la discipline anti-XSS).

## 7. Modèle de menace (delta)

| Risque | Défense |
|---|---|
| Injection SQL | requêtes **paramétrées** partout, `input_kind` contraint |
| Flush par un porteur du token de lecture | ops destructives sous **`OCULAR_ADMIN_TOKEN` séparé** fail-closed |
| HTML hostile sauvegardé servi inline | artefacts `/saved` servis **nosniff + DOM en attachment** `text/plain` (jamais `text/html`) ; ref validé anti-traversal |
| Sauvegarde d'un enregistrement incomplet | 409 si un artefact référencé est déjà GC-é |
| Fuite du token admin dans les logs | jamais loggé (comme le token normal) |
| Croissance non bornée de `saved.db` | contrôle **manuel** via admin (delete/flush) — c'est le but ; log de la taille de base au démarrage/opérations |

> Accepté (ton choix) : un porteur du token admin peut flush ; bénin vu l'usage. Le token séparé limite ça aux détenteurs explicites de l'admin.

## 8. Tests
- `saved_store` : save (UPSERT remplace même hash), get_by_hash, list, get_result, get_artifact, delete (cascade), flush ; multi-étapes (résultat avec 2 screenshots → 2 blobs stockés) ; injection SQL tentée sur `label`/`hash` → paramétré, pas d'exécution.
- API : `POST /saved` (token) persiste ; `GET /saved/{hash}` 200/404 ; artefact sauvegardé **nosniff + DOM attachment** ; `DELETE` sans admin → 403, avec admin → 200 ; admin non configuré → 503 ; ref invalide → 400 (anti-traversal) ; 409 si artefact expiré.
- Cohérence hash **client↔serveur** (même `sha256(htmlUtf8)`).
- UI smoke : vues saved/admin servies ; modal dédup ne rend pas de HTML via innerHTML.

## 9. Ordre de livraison (une branche, SDD)
1. `saved_store.py` + schéma + tests (save/upsert/get/delete/flush/multi-étapes/param SQL).
2. Endpoints `POST /saved`, `GET /saved/{hash}`, `GET /saved`, `GET /saved/{id}/result` + auth normale sur `/saved*`.
3. `GET /saved/{id}/artifact/{ref}` (nosniff, DOM attachment, anti-traversal) — factoriser le service d'artefact avec l'existant.
4. Auth admin (`OCULAR_ADMIN_TOKEN`) + `DELETE /saved/{id}` + `DELETE /saved` (fail-closed 503/403).
5. compose : volume `ocular-saved:/saved` rw sur web + `OCULAR_ADMIN_TOKEN` (`.env`).
6. UI : bouton Sauvegarder (detail) + vue Saved + rendu détail réutilisé.
7. UI : vue Admin (token admin, delete/flush) + modal dédup au submit (hash client `crypto.subtle`).

## 10. Défauts assumés
`ocular_settings` : `saved_db_path()` (défaut `/saved/saved.db`, `OCULAR_SAVED_DB`), `admin_token()` (env `OCULAR_ADMIN_TOKEN`). Dédup exact-hash (pas de fuzzy). `input_kind` = `html` en analysis-only ; `url` réservé phase 3.
