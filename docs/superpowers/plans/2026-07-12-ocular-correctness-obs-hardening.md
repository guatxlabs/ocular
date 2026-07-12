# Ocular — Correctness + Observabilité + Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Corriger les findings de l'audit : calculer le verdict, propager/afficher les échecs, ajouter du logging structuré, borner les ressources (TTL + DoS), durcir le web, et nettoyer archi/DRY — le tout analysis-only.

**Architecture:** Config centralisée (`ocular_settings.py`), contrat de file dans un package neutre (`bus/`), verdict dérivé dans `engine/`, logging stdlib vers stdout, limites via env.

**Tech Stack:** Python 3.11, FastAPI, Pydantic v2, redis-py, Playwright, pytest, vanilla-JS.

## Global Constraints
- Le **stdout du runner reste le wrapper JSON pur** — tout log du runner va sur **stderr**.
- Les logs ne contiennent **JAMAIS** `OCULAR_TOKEN` ni le HTML complet soumis.
- Le **web reste sans Docker** (`grep -riE "docker|launcher|subprocess" web/` vide) ; après le déplacement du contrat de file, le web n'importe plus rien de `broker/`.
- Verdict : `malicious` si ≥1 finding `critical` ; sinon `suspicious` si ≥1 `high` ; sinon `benign`.
- Défauts config (env `OCULAR_*`) = valeurs actuelles : image `ocular-runner-analysis:latest`, mem `2g`, pids `256`, job timeout `60`, render `15000`ms, result TTL `86400`s, max HTML `5000000` bytes, log level `INFO`, redis `redis://localhost:6379`, artifacts dir `artifacts`.
- Python 3.11 ; commits fréquents.

---

### Task 1: Module de configuration centralisé

**Files:** Create `ocular_settings.py`, `tests/test_settings.py`

**Interfaces:** Produces `ocular_settings` avec fonctions lisant l'env avec défaut : `redis_url()`, `artifacts_dir()`, `runner_image()`, `job_memory()`, `job_pids()`, `job_timeout()`, `render_timeout_ms()`, `result_ttl()`, `max_html_bytes()`, `log_level()`.

- [ ] **Step 1: Test qui échoue** — `tests/test_settings.py`
```python
import ocular_settings as s


def test_defaults(monkeypatch):
    for v in ["OCULAR_REDIS_URL", "OCULAR_JOB_MEMORY", "OCULAR_RESULT_TTL", "OCULAR_MAX_HTML_BYTES"]:
        monkeypatch.delenv(v, raising=False)
    assert s.redis_url() == "redis://localhost:6379"
    assert s.job_memory() == "2g"
    assert s.result_ttl() == 86400
    assert s.max_html_bytes() == 5_000_000


def test_env_override(monkeypatch):
    monkeypatch.setenv("OCULAR_RESULT_TTL", "120")
    monkeypatch.setenv("OCULAR_JOB_MEMORY", "1g")
    assert s.result_ttl() == 120
    assert s.job_memory() == "1g"
```

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_settings.py -v` → FAIL.

- [ ] **Step 3: Implémenter `ocular_settings.py`**
```python
from __future__ import annotations

import os


def redis_url() -> str:
    return os.environ.get("OCULAR_REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379"))


def artifacts_dir() -> str:
    return os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts")


def runner_image() -> str:
    return os.environ.get("OCULAR_RUNNER_IMAGE", "ocular-runner-analysis:latest")


def job_memory() -> str:
    return os.environ.get("OCULAR_JOB_MEMORY", "2g")


def job_pids() -> int:
    return int(os.environ.get("OCULAR_JOB_PIDS", "256"))


def job_timeout() -> int:
    return int(os.environ.get("OCULAR_JOB_TIMEOUT", "60"))


def render_timeout_ms() -> int:
    return int(os.environ.get("OCULAR_RENDER_TIMEOUT_MS", "15000"))


def result_ttl() -> int:
    return int(os.environ.get("OCULAR_RESULT_TTL", "86400"))


def max_html_bytes() -> int:
    return int(os.environ.get("OCULAR_MAX_HTML_BYTES", "5000000"))


def log_level() -> str:
    return os.environ.get("OCULAR_LOG_LEVEL", "INFO").upper()
```

- [ ] **Step 4: Vérifier le succès** — `pytest tests/test_settings.py -v` → PASS.
- [ ] **Step 5: Commit** — `git add ocular_settings.py tests/test_settings.py && git commit -m "feat: module de configuration centralisé (OCULAR_*)"`

---

### Task 2: Déplacer le contrat de file vers un package neutre `bus/`

**Files:** Create `bus/__init__.py`, `bus/queue.py` ; Modify `web/app.py`, `broker/main.py`, `broker/gc.py`, `broker/launcher.py` (imports), `tests/test_queue.py` (import), `tests/test_web_api.py`, `deploy/Dockerfile.web` ; Delete `broker/queue.py`.

**Interfaces:** `bus.queue.Job`, `bus.queue.RedisJobQueue`, `bus.queue.RESULT_PREFIX` (rendu public).

- [ ] **Step 1: Créer `bus/queue.py`** = copie de `broker/queue.py` avec `_RESULT_PREFIX` renommé public `RESULT_PREFIX` (garder aussi `_QUEUE_KEY`). Créer `bus/__init__.py` vide.
```python
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

_QUEUE_KEY = "ocular:jobs"
RESULT_PREFIX = "ocular:result:"


class Job(BaseModel):
    job_id: str
    profile: str
    html: Optional[str] = None
    url: Optional[str] = None


class RedisJobQueue:
    def __init__(self, client) -> None:
        self._r = client

    def enqueue(self, job: Job) -> None:
        self._r.rpush(_QUEUE_KEY, job.model_dump_json())

    def dequeue(self, timeout: int = 0) -> Optional[Job]:
        item = self._r.blpop([_QUEUE_KEY], timeout=timeout)
        if item is None:
            return None
        _, raw = item
        return Job.model_validate_json(raw)

    def set_result(self, job_id: str, result_json: str, ttl: Optional[int] = None) -> None:
        if ttl:
            self._r.set(RESULT_PREFIX + job_id, result_json, ex=ttl)
        else:
            self._r.set(RESULT_PREFIX + job_id, result_json)

    def get_result(self, job_id: str) -> Optional[str]:
        val = self._r.get(RESULT_PREFIX + job_id)
        return val.decode() if isinstance(val, bytes) else val
```
(Note : `ttl` optionnel ajouté ici — utilisé en Task 4.)

- [ ] **Step 2: Mettre à jour les imports** — remplacer partout `from broker.queue import ...` par `from bus.queue import ...` : `web/app.py`, `broker/main.py`, `broker/launcher.py` (n'importe pas Job? vérifier), `broker/gc.py` (`from bus.queue import RESULT_PREFIX`), `tests/test_queue.py`, `tests/test_web_api.py`, `tests/test_web_artifact.py`, `tests/test_launcher_*`. Dans `broker/gc.py`, remplacer `_RESULT_PREFIX` par `RESULT_PREFIX` et l'usage `match=f"{RESULT_PREFIX}*"`. Puis `git rm broker/queue.py`.

- [ ] **Step 3: Mettre à jour `deploy/Dockerfile.web`** — remplacer les deux lignes `COPY broker/__init__.py` + `COPY broker/queue.py` par `COPY bus/ ./bus/`.

- [ ] **Step 4: Vérifier** — `pytest -m "not integration" -q` vert ; `grep -rn "broker.queue\|broker/queue" web/ tests/ broker/` → vide ; `grep -riE "docker|launcher|subprocess" web/` → vide.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "refactor: contrat de file dans package neutre bus/ (web ne dépend plus de broker/)"`

---

### Task 3: Calcul du verdict

**Files:** Create `engine/verdict.py`, `tests/test_verdict.py` ; Modify `runner_analysis/render.py`.

**Interfaces:** `engine.verdict.compute_verdict(findings: list[StaticFinding]) -> Verdict`.

- [ ] **Step 1: Test qui échoue** — `tests/test_verdict.py`
```python
from engine.result import StaticFinding
from engine.verdict import compute_verdict


def _f(sev):
    return StaticFinding(rule="r", severity=sev, match="m", line=1, context="c")


def test_critical_is_malicious():
    assert compute_verdict([_f("low"), _f("critical")]) == "malicious"


def test_high_is_suspicious():
    assert compute_verdict([_f("medium"), _f("high")]) == "suspicious"


def test_only_low_medium_is_benign():
    assert compute_verdict([_f("low"), _f("medium")]) == "benign"


def test_empty_is_benign():
    assert compute_verdict([]) == "benign"
```

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_verdict.py -v` → FAIL.

- [ ] **Step 3: Implémenter `engine/verdict.py`**
```python
from __future__ import annotations

from engine.result import StaticFinding, Verdict


def compute_verdict(findings: list[StaticFinding]) -> Verdict:
    sev = {f.severity for f in findings}
    if "critical" in sev:
        return "malicious"
    if "high" in sev:
        return "suspicious"
    return "benign"
```

- [ ] **Step 4: Câbler dans `runner_analysis/render.py`** — ajouter `from engine.verdict import compute_verdict` et, à la construction du `OcularResult`, remplacer `verdict` par défaut par `verdict=compute_verdict(static_findings)` (le `static_findings` est calculé en amont). Adapter le test `test_render_populates_static_findings` pour asserter `r.verdict == "malicious"` sur le HTML `eval(atob(...))`.

- [ ] **Step 5: Vérifier** — `pytest tests/test_verdict.py -v` PASS ; `docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .` ; `pytest tests/test_render.py -m integration -v` PASS (verdict désormais `malicious`).
- [ ] **Step 6: Commit** — `git add engine/verdict.py tests/test_verdict.py runner_analysis/render.py tests/test_render.py && git commit -m "feat(engine): calcul du verdict depuis les findings static"`

---

### Task 4: TTL sur les résultats + client Redis partagé

**Files:** Modify `broker/main.py`, `web/app.py` ; Modify/Create tests.

**Interfaces:** le broker passe `ttl=result_ttl()` à `set_result` ; `web` réutilise un client Redis unique.

- [ ] **Step 1: Test qui échoue** — `tests/test_ttl.py`
```python
import fakeredis

from bus.queue import Job, RedisJobQueue, RESULT_PREFIX


def test_set_result_with_ttl_sets_expiry():
    r = fakeredis.FakeStrictRedis()
    q = RedisJobQueue(r)
    q.set_result("j", '{"ok":1}', ttl=120)
    assert 0 < r.ttl(RESULT_PREFIX + "j") <= 120


def test_set_result_without_ttl_persists():
    r = fakeredis.FakeStrictRedis()
    RedisJobQueue(r).set_result("j", "{}")
    assert r.ttl(RESULT_PREFIX + "j") == -1
```

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_ttl.py -v` → FAIL (méthode sans ttl du fichier précédent — mais Task 2 a déjà ajouté le param `ttl`, donc ce test devrait passer si Task 2 est faite ; sinon RED). Si déjà vert, marquer et continuer.

- [ ] **Step 3: `broker/main.py`** — importer `from ocular_settings import redis_url, result_ttl` ; passer `queue.set_result(job.job_id, result_json, ttl=result_ttl())`. Utiliser `redis_url()`.

- [ ] **Step 4: `web/app.py`** — client Redis partagé au niveau module :
```python
import redis
from functools import lru_cache
from ocular_settings import redis_url

@lru_cache(maxsize=1)
def _redis_client():
    return redis.Redis.from_url(redis_url())

def get_queue() -> RedisJobQueue:
    return RedisJobQueue(_redis_client())
```
(garde l'overridabilité via `app.dependency_overrides[get_queue]` pour les tests.)

- [ ] **Step 5: Vérifier + Commit** — `pytest -m "not integration" -q` vert ; `git add -A && git commit -m "feat: TTL sur résultats Redis (OCULAR_RESULT_TTL) + client Redis partagé"`

---

### Task 5: Limite de taille HTML (DoS) + `profile` strict

**Files:** Modify `web/models.py`, `web/app.py` ; Modify `tests/test_web_api.py`.

**Interfaces:** `POST /jobs` rejette `422` si `html` dépasse `max_html_bytes()` ou si `profile != "analysis"`.

- [ ] **Step 1: Test qui échoue** — ajouter à `tests/test_web_api.py`
```python
def test_oversized_html_rejected(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    monkeypatch.setenv("OCULAR_MAX_HTML_BYTES", "100")
    client = _client(monkeypatch)[0]
    r = client.post("/jobs", json={"profile": "analysis", "html": "x" * 200})
    assert r.status_code == 422


def test_invalid_profile_rejected(monkeypatch):
    client = _client(monkeypatch)[0]
    r = client.post("/jobs", json={"profile": "capture", "html": "x"})
    assert r.status_code == 422
```

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_web_api.py -v` → 2 FAIL.

- [ ] **Step 3: `web/models.py`** — `profile` en `Literal["analysis"]` :
```python
from typing import Literal, Optional
from pydantic import BaseModel

class JobRequest(BaseModel):
    profile: Literal["analysis"] = "analysis"
    html: Optional[str] = None
    url: Optional[str] = None
```

- [ ] **Step 4: `web/app.py`** — dans `submit_job`, valider la taille avant enqueue :
```python
from fastapi import HTTPException
from ocular_settings import max_html_bytes
...
    if req.html and len(req.html.encode("utf-8")) > max_html_bytes():
        raise HTTPException(status_code=422, detail="html trop volumineux")
```

- [ ] **Step 5: Vérifier + Commit** — `pytest tests/test_web_api.py -v` PASS ; `git add web/models.py web/app.py tests/test_web_api.py && git commit -m "feat(web): limite taille HTML (DoS) + profile strict analysis"`

---

### Task 6: Chemin d'échec de bout en bout (broker testé + UI)

**Files:** Modify `broker/main.py` (status error) ; Create `tests/test_broker_failure.py` ; Modify `web/ui/views/jobs.js`, `web/ui/views/detail.js`, `web/ui/i18n.js`.

**Interfaces:** `error_result` renvoie `{"job_id", "status":"error", "error"}` ; l'UI affiche un état « échec » distinct de « unknown ».

- [ ] **Step 1: Test qui échoue** — `tests/test_broker_failure.py`
```python
import json

import fakeredis

from bus.queue import Job, RedisJobQueue
from broker import main


def test_error_result_has_status_error():
    d = json.loads(main.error_result("j", RuntimeError('boom "q"\nx')))
    assert d["job_id"] == "j" and d["status"] == "error" and "boom" in d["error"]


def test_run_forever_stores_error_on_job_failure(monkeypatch):
    r = fakeredis.FakeStrictRedis()
    q = RedisJobQueue(r)
    q.enqueue(Job(job_id="jf", profile="analysis", html="x"))
    monkeypatch.setattr(main, "run_analysis_job", lambda job: (_ for _ in ()).throw(RuntimeError("kaboom")))
    # une seule itération : on patche dequeue pour renvoyer le job puis None -> stop
    calls = {"n": 0}
    real_dequeue = q.dequeue
    def one_then_none(timeout=0):
        calls["n"] += 1
        return real_dequeue(timeout) if calls["n"] == 1 else (_ for _ in ()).throw(KeyboardInterrupt)
    monkeypatch.setattr(RedisJobQueue, "dequeue", lambda self, timeout=5: one_then_none())
    monkeypatch.setattr(main, "redis_url", lambda: "redis://x")
    monkeypatch.setattr(main.redis.Redis, "from_url", classmethod(lambda cls, url: r))
    try:
        main.run_forever()
    except KeyboardInterrupt:
        pass
    stored = json.loads(q.get_result("jf"))
    assert stored["status"] == "error" and "kaboom" in stored["error"]
```
(Si le harnais de mock de `run_forever` est trop fragile, garde `test_error_result_has_status_error` comme test principal + un test direct de la boucle extraite ; l'implémenteur peut extraire `process_one(queue, job)` pour tester proprement.)

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_broker_failure.py -v` → FAIL.

- [ ] **Step 3: `broker/main.py`** — `error_result` ajoute `status:"error"` :
```python
def error_result(job_id: str, exc: Exception) -> str:
    return json.dumps({"job_id": job_id, "status": "error", "error": str(exc)[:200]})
```
Pour la testabilité, extraire la logique d'une itération :
```python
def process_one(queue, job) -> None:
    try:
        result_json = run_analysis_job(job)
    except Exception as exc:
        result_json = error_result(job.job_id, exc)
    queue.set_result(job.job_id, result_json, ttl=result_ttl())

def run_forever() -> None:
    queue = RedisJobQueue(redis.Redis.from_url(redis_url()))
    while True:
        job = queue.dequeue(timeout=5)
        if job is not None:
            process_one(queue, job)
```
(Adapter le test pour appeler `process_one` directement — plus simple et robuste que mocker `run_forever`.)

- [ ] **Step 4: UI** — `jobs.js` et `detail.js` : si le résultat a `status === "error"`, afficher un badge « Échec » (classe `.sev` couleur `--bad`) et le message `error` (en **textNode**, jamais innerHTML), au lieu de « unknown ». Ajouter les libellés dans `i18n.js`.

- [ ] **Step 5: Vérifier + Commit** — `pytest tests/test_broker_failure.py -v` PASS ; `pytest -m "not integration" -q` vert ; `grep -n innerHTML web/ui/views/detail.js web/ui/views/jobs.js` → seulement icônes. `git add -A && git commit -m "feat: chemin d'échec bout-en-bout (status error propagé + affiché) + tests broker"`

---

### Task 7: Logging structuré + audit trail

**Files:** Create `ocular_logging.py`, `tests/test_logging.py` ; Modify `web/app.py`, `broker/main.py`, `broker/launcher.py`, `runner_analysis/render.py`.

**Interfaces:** `ocular_logging.get_logger(name) -> Logger` (format structuré, niveau via `log_level()`, sortie stdout — **stderr pour le runner**).

- [ ] **Step 1: Test qui échoue** — `tests/test_logging.py`
```python
import logging

from ocular_logging import get_logger


def test_logger_emits_and_never_contains_token(caplog):
    log = get_logger("test")
    with caplog.at_level(logging.INFO):
        log.info("job submitted", extra={"job_id": "j1", "html_bytes": 42})
    assert any("j1" in r.getMessage() or getattr(r, "job_id", None) == "j1" for r in caplog.records)
    assert all("OCULAR_TOKEN" not in r.getMessage() for r in caplog.records)
```

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_logging.py -v` → FAIL.

- [ ] **Step 3: `ocular_logging.py`**
```python
from __future__ import annotations

import logging
import sys

from ocular_settings import log_level

_CONFIGURED = False


def get_logger(name: str, stream=None) -> logging.Logger:
    global _CONFIGURED
    if not _CONFIGURED:
        handler = logging.StreamHandler(stream or sys.stdout)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"))
        root = logging.getLogger("ocular")
        root.handlers[:] = [handler]
        root.setLevel(log_level())
        root.propagate = False
        _CONFIGURED = True
    return logging.getLogger("ocular." + name)
```

- [ ] **Step 4: Câbler les logs (jamais le token ni le HTML complet)** :
- `web/app.py` : `log.info("job submitted job_id=%s profile=%s html_bytes=%d", job_id, req.profile, len(req.html or ""))` dans `submit_job` ; `log.warning("auth rejected path=%s status=%d", request.url.path, code)` dans le middleware (sans le header).
- `broker/main.py` : dans `process_one`, `log.info("job start job_id=%s", job.job_id)`, puis succès `log.info("job done job_id=%s", job.job_id)` / échec `log.error("job failed job_id=%s err=%s", job.job_id, str(exc)[:200])`.
- `broker/launcher.py` : log du lancement runner + durée (optionnel).
- `runner_analysis/render.py` : `get_logger("runner", stream=sys.stderr)` — logue début/fin/erreurs sur **stderr** (stdout reste le wrapper JSON). Remplacer les `except Exception: pass` (screenshot/DOM) par un `log.warning`.

- [ ] **Step 5: Vérifier stdout du runner non pollué** — `echo '<h1>x</h1>' | python -m runner_analysis.render --job-id t 2>/dev/null | python3 -c "import sys,json;json.load(sys.stdin);print('stdout=JSON pur OK')"` (les logs partent sur stderr). Rebuild image. `pytest -m "not integration" -q` vert.
- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat: logging structuré + audit trail (stdout, runner sur stderr, jamais de token/html)"`

---

### Task 8: Hardening web + fix test creux + DRY artefacts

**Files:** Modify `web/app.py`, `web/ui/views/detail.js`, `engine/artifacts.py`, `broker/gc.py`, `tests/test_web_artifact.py`, `deploy/docker-compose.yml`.

- [ ] **Step 1: Tests d'abord** — dans `tests/test_web_artifact.py` :
```python
def test_artifact_has_nosniff(tmp_path, monkeypatch):
    ref = "sha256:" + "a" * 64
    (tmp_path / ("sha256_" + "a" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nX")
    c = _client(tmp_path, monkeypatch)
    r = c.get(f"/jobs/j/artifact/{ref}")
    assert r.headers["x-content-type-options"] == "nosniff"


def test_invalid_ref_reaches_400_branch(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    # ref SANS slash (donc atteint le handler, pas le 404 de routage) mais invalide -> 400
    r = c.get("/jobs/j/artifact/sha256:" + "A" * 64)  # majuscules -> fullmatch échoue
    assert r.status_code == 400
```
(mettre à jour `_client` de ce fichier pour envoyer le token si l'auth est active — cf. Task 5 de la passe précédente.)

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_web_artifact.py -v` → 2 FAIL.

- [ ] **Step 3: `web/app.py`** — (a) auth bytes-safe : `secrets.compare_digest(provided.encode("utf-8","ignore"), expected.encode())` ; (b) `nosniff` sur chaque `Response` d'artefact (`headers={"X-Content-Type-Options":"nosniff", ...}`) ; (c) DOM `filename="{fname}.txt"` (plus `.html`) ; (d) `get_job` garde `json.loads` :
```python
    try:
        data = json.loads(result)
    except (ValueError, TypeError):
        raise HTTPException(status_code=500, detail="résultat corrompu")
    return data
```
(e) CSP sur l'app shell : ajouter un middleware ou en-tête sur les réponses non-`/jobs` `Content-Security-Policy: default-src 'self'` (via un `@app.middleware` qui ajoute l'en-tête aux réponses statiques).

- [ ] **Step 4: `web/ui/views/detail.js`** — le lien download DOM en `.txt` (`download: id + '-dom.txt'`).

- [ ] **Step 5: DRY artefacts** — `engine/artifacts.py` : ajouter
```python
REF_HEX = "[0-9a-f]{64}"

def filename_to_ref(fname: str) -> str:
    import re
    if not re.fullmatch(r"sha256_" + REF_HEX, fname):
        raise ValueError(f"nom d'artefact invalide: {fname!r}")
    return fname.replace("sha256_", "sha256:", 1)
```
et dans `broker/gc.py`, remplacer le regex/replace locaux par `from engine.artifacts import filename_to_ref` (try/except ValueError pour ignorer les fichiers étrangers).

- [ ] **Step 6: `deploy/docker-compose.yml`** — ajouter `mem_limit: 1g` (et `cpus: "1.0"` si supporté) sur `web` et `broker`.

- [ ] **Step 7: Vérifier + Commit** — `pytest tests/test_web_artifact.py -v` PASS (dont la vraie branche 400) ; `pytest -m "not integration" -q` vert ; `OCULAR_TOKEN=x docker compose -f deploy/docker-compose.yml config` valide ; `grep -riE "docker|launcher|subprocess" web/` vide. `git add -A && git commit -m "harden(web): nosniff+CSP, compare_digest bytes, DOM .txt, json guard + DRY artefacts + mem_limit"`

---

## Self-Review (effectuée)
- **Couverture findings** : verdict (T3), chemin d'échec+tests broker (T6), logging (T7), TTL (T4)+DoS (T5), hardening+test creux+DRY (T8), config centralisée (T1), contrat neutre (T2). Tous les Important/Minor de l'audit adressés sauf M4 authz-par-ref (noté multi-tenant futur, hors scope) et CSP fin (T8 pose une base).
- **Placeholders** : aucun muet ; le mock de `run_forever` (T6) propose une extraction `process_one` testable si le mock est fragile — chemin concret donné.
- **Cohérence types** : `bus.queue` (T2) consommé par T4/T5/T6 ; `ocular_settings` (T1) par T4/T5/T7/T8 ; `compute_verdict` (T3) par le runner ; `filename_to_ref` (T8) par gc.

## Notes de délégation
Ordre = dépendances : T1 (settings) et T2 (bus/) d'abord (socles). T3/T6/T7 rebuild l'image runner (nouveau code/logs). Tâches sans Docker : 1,2,4,5,6(unit),8(unit). Avec Docker : 3,7 (rebuild+integration).
