# Ocular — Correctness + Observabilité + Hardening — Design

- **Date** : 2026-07-12
- **Statut** : Approuvé (design), prêt pour plan
- **Origine** : remédiation des findings de l'audit indépendant (3 auditeurs : archi, sécu, qualité/tests) du code mergé après la passe 2.5.

---

## 1. Contexte

Un audit indépendant a **confirmé** l'ossature (pas de monolithe, pas de secret en dur, sécu solide vérifiée en live) mais a relevé de vrais trous de **finition fonctionnelle, d'observabilité et de robustesse**. Cette passe les corrige. Elle est **analysis-only** (la phase 3 recon est séparée).

## 2. Objectifs (issus des findings)

1. **Verdict calculé** (aujourd'hui toujours `"unknown"`) — trou fonctionnel #1.
2. **Chemin d'échec de bout en bout** : état `error` propagé et affiché dans l'UI ; chemins d'erreur du broker testés.
3. **Logging structuré + audit trail** (aujourd'hui : zéro logging).
4. **TTL Redis + limites DoS** (résultats non bornés, GC qui ne collecte jamais, pas de limite de taille HTML ni mémoire).
5. **Hardening web** : `nosniff`+CSP, `compare_digest` en bytes, DOM en `.txt`, `json.loads` gardé, `profile` en `Literal`.
6. **Nettoyage archi/DRY** : config externalisée, defaults centralisés, contrat de file en package neutre, **correction du test creux `test_invalid_ref_400`**.

Non-objectif : profil capture / URL / Turnstile (phase 3).

## 3. Décisions figées

| # | Décision |
|---|---|
| V | **Verdict** dérivé des `static_findings` : `malicious` si ≥1 `critical` ; sinon `suspicious` si ≥1 `high` ; sinon `benign`. (`medium`/`low` n'escaladent pas.) Calculé dans `engine`, appliqué par le runner. Tunable. |
| L | **Logging** : `logging` stdlib, format structuré (`ts level logger job_id=… msg`) vers **stdout**. Audit trail : soumission (`job_id`, `profile`, `html_bytes`), fin (`job_id`, `verdict`, `duration_ms`), erreurs. **Jamais** le token ni le HTML complet dans les logs. Niveau via `OCULAR_LOG_LEVEL` (défaut INFO). |
| C | **Config centralisée** dans `ocular_settings.py` (module neutre) lisant les env : `OCULAR_REDIS_URL`, `OCULAR_ARTIFACTS_DIR`, `OCULAR_RUNNER_IMAGE`, `OCULAR_JOB_MEMORY` (2g), `OCULAR_JOB_PIDS` (256), `OCULAR_JOB_TIMEOUT` (60), `OCULAR_RENDER_TIMEOUT_MS` (15000), `OCULAR_RESULT_TTL` (86400), `OCULAR_MAX_HTML_BYTES` (5_000_000), `OCULAR_LOG_LEVEL` (INFO). Défauts = valeurs actuelles. |
| Q | **Contrat de file** (`Job`, `RedisJobQueue`) déplacé de `broker/queue.py` vers un package neutre `bus/queue.py`. `web` importe `bus.queue` (plus rien de `broker/`) ; `Dockerfile.web` copie `bus/` au lieu de picorer dans `broker/`. |

## 4. Détail par workstream

### 4.1 Verdict (`engine/verdict.py`)
`compute_verdict(findings: list[StaticFinding]) -> Verdict`. Le runner l'appelle et passe le résultat à `OcularResult(verdict=...)`. Test : critical→malicious, high→suspicious, medium/low/vide→benign.

### 4.2 Chemin d'échec
- `broker/main.py` : `error_result` inclut déjà `error` ; ajouter `verdict="unknown"` explicite + un champ `status:"error"` distinct de `pending`.
- **UI** (`jobs.js`, `detail.js`) : lire le champ `error` ; afficher un état « échec » (badge distinct) au lieu de « unknown ».
- **Tests** : `run_forever` (job OK stocke résultat, job qui lève stocke un `error_result` JSON valide) ; `run_analysis_job` sur returncode≠0 → `RuntimeError` ; timeout → `docker kill` + `RuntimeError` (mock subprocess).

### 4.3 Logging (`ocular_logging.py` ou via settings)
Helper `get_logger(name)` configurant le format structuré une fois. `web` logue soumission + réponses d'erreur (401/503 au niveau WARNING sans le token). `broker` logue dépilage, lancement runner, durée, verdict, échecs. `runner` logue début/fin/erreurs de rendu sur stderr (le stdout reste le wrapper JSON pur — **ne pas polluer stdout**).

### 4.4 TTL + DoS
- `RedisJobQueue.set_result(..., ttl=OCULAR_RESULT_TTL)` → `set(k, v, ex=ttl)`.
- GC : période de grâce déjà là ; documenter que le TTL est la vraie purge.
- `web/models.py` : `html: str = Field(max_length=OCULAR_MAX_HTML_BYTES)` (rejet 422 au-delà) — attention : `max_length` compte les caractères, borner aussi via un check taille bytes.
- `deploy/docker-compose.yml` : `mem_limit`/`cpus` sur `web` et `broker` ; note sur le quota du volume artefacts (ou seuil GC).

### 4.5 Hardening web
- `nosniff` sur chaque réponse d'artefact ; CSP `default-src 'self'` sur l'app shell.
- `secrets.compare_digest(provided.encode(), expected.encode())` (évite le 500 sur header non-ASCII).
- DOM servi + bouton download en `.txt` (jamais `.html`).
- `GET /jobs/{id}` : `try: json.loads except: 500→503/500 propre` (ne pas planter sur JSON corrompu).
- `profile` = `Literal["analysis"]` dans `JobRequest` (rejette tout autre profil en 422 tant que capture n'est pas là).

### 4.6 Archi / DRY / test creux
- `bus/queue.py` (déplacement), imports mis à jour (`web/app.py`, `broker/{main,gc,launcher}`, tests, `Dockerfile.web`).
- `ocular_settings.py` : centralise Redis URL, artifacts dir, et tous les `OCULAR_*`. Remplace les defaults dupliqués.
- `engine/artifacts.py` : ajouter `filename_to_ref()` + constante hex, réutilisés par `gc.py`.
- **Corriger `test_invalid_ref_400`** : utiliser un ref invalide qui atteint réellement le handler (ex. `sha256:` + 63 hex, ou majuscules — pas de `/` qui déclenche le 404 de routage) afin de couvrir la vraie branche `400`.
- Client Redis partagé (module-level / `lru_cache`) au lieu d'un neuf par requête.

## 5. Tests (nouveaux/renforcés)
verdict (3 seuils) · `run_forever` OK + échec · `run_analysis_job` returncode≠0 + timeout (mock) · UI état échec (le résultat `{error}` n'affiche pas « unknown ») · TTL passé à `set` (assert `ex`) · `html` trop gros → 422 · `test_invalid_ref_400` **réellement** sur la branche 400 · `json.loads` corrompu géré · `profile` invalide → 422 · logging n'émet jamais le token.

## 6. Ordre de livraison (une branche, SDD)
1. `ocular_settings.py` (config centralisée) — socle des suivants.
2. `bus/queue.py` (déplacement contrat) + imports + Dockerfile.web.
3. Verdict (`engine/verdict.py` + runner).
4. TTL + client Redis partagé.
5. DoS limites (models/app + compose).
6. Chemin d'échec (broker tests + propagation + UI).
7. Logging structuré + audit trail.
8. Hardening web (nosniff/CSP/compare_digest bytes/DOM .txt/json guard/profile Literal).
9. Fixes tests (test creux 400 + `filename_to_ref` DRY).

## 7. Défauts assumés
Seuils verdict tunables (defaults ci-dessus). TTL 24 h. Max HTML 5 Mo. Logs INFO vers stdout.
