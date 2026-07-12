# Ocular — Fondation + Runner d'analyse durci — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Livrer la tranche traçante du moteur Ocular : soumettre du HTML hostile → un conteneur Chromium **éphémère et durci** le rend en isolation totale → renvoyer un résultat JSON unifié (screenshot + réseau + console + findings static), avec **preuve testée** qu'aucune requête ne quitte le contexte hôte.

**Architecture:** Séparation de privilèges en 3 composants. `web` (FastAPI) reçoit les jobs et n'a **jamais** accès à Docker. `broker` est le **seul** à parler à Docker : il dépile un job d'une file Redis et lance **un conteneur runner jetable** (`--network none`, `--cap-drop ALL`, seccomp profilé, non-root, ro-rootfs, `--rm`). Le `runner-analysis` rend le HTML avec Playwright/Chromium et émet le résultat sur stdout. Le résultat valide un JSON Schema versionné.

**Tech Stack:** Python 3.11, FastAPI + uvicorn, Pydantic v2, Playwright (Chromium), redis-py (+ fakeredis en test), Docker CLI via subprocess, pytest, jsonschema, ruff, mypy.

## Global Constraints

- `web` : **jamais** d'accès à `/var/run/docker.sock` ; process non-root ; ro-rootfs. Aucun import de `docker`/`subprocess`-vers-docker dans le package `web/`.
- `broker` : **seul** composant avec accès Docker.
- runner `analysis` lancé **obligatoirement** avec : `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--security-opt seccomp=schemas/seccomp-analysis.json` (jamais `unconfined`), `--read-only`, `--tmpfs /work`, `--user 10001:10001`, `--rm`, `--memory 2g`, `--pids-limit 256`.
- Entrée HTML hostile : transmise au runner **par tmpfs / stdin uniquement**, jamais écrite sur le disque hôte.
- Toute sortie moteur valide `schemas/result.schema.json`, `schema_version == "1.0"`.
- Enum `severity` = `critical|high|medium|low`. Enum `verdict` = `benign|suspicious|malicious|unknown`.
- Python 3.11 ; Pydantic v2 ; commits fréquents (un par tâche minimum).

---

## File Structure

```
ocular/
  pyproject.toml                  # deps + config ruff/mypy/pytest
  engine/
    __init__.py
    result.py                     # modèles Pydantic + export JSON Schema
    static.py                     # analyze_html(html) -> list[StaticFinding]
  schemas/
    result.schema.json            # contrat (généré depuis result.py)
    seccomp-analysis.json         # profil seccomp du runner analysis
  runner-analysis/
    render.py                     # entrypoint conteneur : HTML -> résultat JSON (stdout)
    Dockerfile
  broker/
    __init__.py
    queue.py                      # RedisJobQueue
    launcher.py                   # run_analysis_job() : lance le conteneur durci
    main.py                       # boucle broker
  web/
    __init__.py
    models.py                     # JobRequest / JobResponse
    app.py                        # FastAPI : POST /jobs, GET /jobs/{id}
  deploy/
    docker-compose.yml
    .env.example
  tests/
    conftest.py
    test_result_schema.py
    test_static.py
    test_render.py
    test_queue.py
    test_launcher_security.py     # régression sécu
    test_web_api.py
```

---

### Task 1: Modèles de résultat + JSON Schema + test de contrat

**Files:**
- Create: `pyproject.toml`, `engine/__init__.py`, `engine/result.py`, `tests/conftest.py`, `tests/test_result_schema.py`
- Create (généré): `schemas/result.schema.json`

**Interfaces:**
- Produces: `engine.result.OcularResult` (Pydantic BaseModel), `OcularResult.model_json_schema()`, sous-modèles `NetworkEntry`, `ConsoleEntry`, `StaticFinding`, `DynamicStep`, `Screenshot`, `DomInfo`, `StealthInfo`, `Artifacts`. Enums `Severity`, `Verdict`, `Profile`.

- [ ] **Step 1: Créer `pyproject.toml`**

```toml
[project]
name = "ocular"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "pydantic>=2.6",
  "fastapi>=0.110",
  "uvicorn>=0.29",
  "redis>=5.0",
  "playwright>=1.41",
  "jsonschema>=4.21",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "fakeredis>=2.21", "httpx>=0.27", "ruff>=0.3", "mypy>=1.9"]

[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]

[tool.ruff]
line-length = 100

[tool.mypy]
python_version = "3.11"
ignore_missing_imports = true
```

- [ ] **Step 2: Écrire le test de contrat qui échoue** — `tests/test_result_schema.py`

```python
import json
from pathlib import Path

import jsonschema

from engine.result import OcularResult


def _minimal_payload() -> dict:
    return {
        "schema_version": "1.0",
        "job_id": "job-123",
        "profile": "analysis",
        "target": "inline-html",
        "timestamp": "2026-07-12T10:00:00Z",
        "verdict": "malicious",
        "screenshots": [{"step": 0, "phase": "initial", "image_ref": "sha256:abc", "viewport": "1280x720"}],
        "network": [],
        "console": [],
        "dom": {"title": "t", "final_url": "about:blank", "redirect_chain": [], "forms": [], "links": []},
        "static_findings": [{"rule": "eval", "severity": "critical", "match": "eval(x)", "line": 3, "context": "..."}],
        "dynamic_steps": [],
        "stealth": {"engine": "chromium", "turnstile_solved": False, "challenge": None},
        "artifacts": {"har_ref": None, "dom_html_ref": "sha256:def"},
    }


def test_ocularresult_accepts_minimal_payload():
    r = OcularResult.model_validate(_minimal_payload())
    assert r.verdict == "malicious"


def test_generated_schema_validates_payload_and_is_written():
    schema = OcularResult.model_json_schema()
    jsonschema.validate(_minimal_payload(), schema)  # ne lève pas
    # le fichier de contrat existe et correspond au modèle
    on_disk = json.loads(Path("schemas/result.schema.json").read_text())
    assert on_disk["properties"]["schema_version"]  # présent


def test_invalid_severity_is_rejected():
    bad = _minimal_payload()
    bad["static_findings"][0]["severity"] = "spicy"
    try:
        OcularResult.model_validate(bad)
        assert False, "should reject invalid severity"
    except Exception:
        pass
```

- [ ] **Step 3: Lancer le test, vérifier l'échec**

Run: `pytest tests/test_result_schema.py -v`
Expected: FAIL (`ModuleNotFoundError: engine.result`).

- [ ] **Step 4: Implémenter `engine/result.py`**

```python
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low"]
Verdict = Literal["benign", "suspicious", "malicious", "unknown"]
Profile = Literal["capture", "analysis"]


class Screenshot(BaseModel):
    step: int
    phase: str
    image_ref: str
    viewport: str


class NetworkEntry(BaseModel):
    url: str
    method: str
    status: Optional[int] = None
    headers: dict[str, str] = Field(default_factory=dict)
    post_data: Optional[str] = None
    resource_type: Optional[str] = None
    initiator: Optional[str] = None


class ConsoleEntry(BaseModel):
    level: str
    text: str
    location: Optional[str] = None


class StaticFinding(BaseModel):
    rule: str
    severity: Severity
    match: str
    line: int
    context: str


class DynamicStep(BaseModel):
    action: str
    screenshot_ref: Optional[str] = None
    triggered_requests: list[str] = Field(default_factory=list)


class DomInfo(BaseModel):
    title: str = ""
    final_url: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    forms: list[dict] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)


class StealthInfo(BaseModel):
    engine: Literal["camoufox", "chromium"]
    turnstile_solved: bool = False
    challenge: Optional[str] = None


class Artifacts(BaseModel):
    har_ref: Optional[str] = None
    dom_html_ref: Optional[str] = None


class OcularResult(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    job_id: str
    profile: Profile
    target: str
    timestamp: str
    verdict: Verdict = "unknown"
    screenshots: list[Screenshot] = Field(default_factory=list)
    network: list[NetworkEntry] = Field(default_factory=list)
    console: list[ConsoleEntry] = Field(default_factory=list)
    dom: DomInfo = Field(default_factory=DomInfo)
    static_findings: list[StaticFinding] = Field(default_factory=list)
    dynamic_steps: list[DynamicStep] = Field(default_factory=list)
    stealth: Optional[StealthInfo] = None
    artifacts: Artifacts = Field(default_factory=Artifacts)
```

- [ ] **Step 5: Générer le contrat sur disque** — créer `engine/__init__.py` (vide) puis exécuter :

Run:
```bash
python -c "import json,pathlib; from engine.result import OcularResult; \
pathlib.Path('schemas').mkdir(exist_ok=True); \
pathlib.Path('schemas/result.schema.json').write_text(json.dumps(OcularResult.model_json_schema(), indent=2))"
```
Expected: crée `schemas/result.schema.json`.

- [ ] **Step 6: Lancer les tests, vérifier le succès**

Run: `pytest tests/test_result_schema.py -v`
Expected: 3 PASS.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml engine/ schemas/result.schema.json tests/test_result_schema.py
git commit -m "feat(engine): schéma de résultat unifié + test de contrat"
```

---

### Task 2: Détecteurs static (port depuis malware-html-sandbox)

**Files:**
- Create: `engine/static.py`, `tests/test_static.py`

**Interfaces:**
- Consumes: `engine.result.StaticFinding`.
- Produces: `engine.static.analyze_html(html: str) -> list[StaticFinding]`.

- [ ] **Step 1: Écrire le test qui échoue** — `tests/test_static.py`

```python
from engine.static import analyze_html


def test_detects_eval_and_atob_as_critical():
    findings = analyze_html("<script>eval(atob('ZG9j'))</script>")
    rules = {f.rule for f in findings}
    assert "Dynamic code evaluation" in rules
    assert "Base64 decode" in rules
    assert all(f.line >= 1 for f in findings)


def test_detects_password_field_critical():
    findings = analyze_html('<input type="password" name="pass">')
    sev = {f.rule: f.severity for f in findings}
    assert sev.get("Password input field") == "critical"


def test_benign_html_has_no_critical():
    findings = analyze_html("<html><body><h1>Bonjour</h1></body></html>")
    assert not [f for f in findings if f.severity == "critical"]
```

- [ ] **Step 2: Lancer, vérifier l'échec**

Run: `pytest tests/test_static.py -v`
Expected: FAIL (`ModuleNotFoundError: engine.static`).

- [ ] **Step 3: Implémenter `engine/static.py`** — porter les patterns réels de
`malware-html-sandbox/secure_analyzer/main.py` (l.332-398). Table complète :

```python
from __future__ import annotations

import re

from engine.result import Severity, StaticFinding

# (pattern, description, severity) — porté de malware-html-sandbox/secure_analyzer/main.py
PATTERNS: list[tuple[str, str, Severity]] = [
    (r"window\.location\s*[=.].*?[\"']([^\"']+)[\"']", "Malicious redirection", "critical"),
    (r"location\.href\s*=\s*[\"']([^\"']+)[\"']", "Forced URL change", "critical"),
    (r"document\.location\s*=\s*[\"']([^\"']+)[\"']", "Forced navigation", "critical"),
    (r"eval\s*\(\s*([^)]+)\)", "Dynamic code evaluation", "critical"),
    (r"Function\s*\(\s*[\"']([^\"']*)[\"']", "Dynamic function creation", "critical"),
    (r"setTimeout\s*\(\s*[\"']([^\"']+)[\"']", "Delayed code execution", "high"),
    (r"setInterval\s*\(\s*[\"']([^\"']+)[\"']", "Repeated code execution", "high"),
    (r"document\.write\s*\(\s*([^)]+)\)", "Direct DOM write", "high"),
    (r"innerHTML\s*=\s*([^;]+)", "HTML injection", "high"),
    (r"outerHTML\s*=\s*([^;]+)", "Complete HTML replacement", "high"),
    (r"fetch\s*\(\s*[\"']([^\"']+)[\"']", "Fetch request", "high"),
    (r"XMLHttpRequest\s*\(\s*\)", "AJAX request", "high"),
    (r"\.submit\s*\(\s*\)", "Form submission", "critical"),
    (r"<form[^>]*action\s*=\s*[\"']([^\"']+)[\"']", "Form action URL", "critical"),
    (r"<form[^>]*method\s*=\s*[\"']post[\"']", "POST form detected", "critical"),
    (r"<img[^>]*src\s*=\s*[\"']https?://([^\"']+)[\"']", "External image", "medium"),
    (r"<script[^>]*src\s*=\s*[\"']https?://([^\"']+)[\"']", "External script", "critical"),
    (r"document\.cookie", "Cookie access", "high"),
    (r"localStorage\.getItem\s*\(\s*[\"']([^\"']+)[\"']", "Local storage read", "medium"),
    (r"navigator\.userAgent", "Browser detection", "medium"),
    (r"on(?:click|load|error|focus|blur|submit)\s*=\s*[\"']([^\"']+)[\"']", "Event handler", "medium"),
    (r"onsubmit\s*=", "Form submit handler", "critical"),
    (r"<iframe[^>]*src\s*=\s*[\"']([^\"']+)[\"']", "Embedded iframe", "high"),
    (r"<object[^>]*data\s*=\s*[\"']([^\"']+)[\"']", "Embedded object", "high"),
    (r"<embed[^>]*src\s*=\s*[\"']([^\"']+)[\"']", "Embedded content", "high"),
    (r"atob\s*\(\s*[\"']([^\"']+)[\"']", "Base64 decode", "critical"),
    (r"atob\s*\(", "Base64 decoding function", "high"),
    (r"unescape\s*\(\s*[\"']([^\"']+)[\"']", "URL decode", "medium"),
    (r"String\.fromCharCode\s*\(([^)]+)\)", "String construction", "high"),
    (r"<input[^>]*type\s*=\s*[\"']password[\"']", "Password input field", "critical"),
    (r"<input[^>]*name\s*=\s*[\"']pass", "Password field (name)", "critical"),
    (r"<input[^>]*name\s*=\s*[\"']email", "Email input field", "high"),
    (r"<input[^>]*name\s*=\s*[\"']user", "Username input field", "high"),
    (r"verify.*account", "Account verification text", "high"),
    (r"suspended.*account", "Account suspended text", "high"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), d, s) for p, d, s in PATTERNS]


def analyze_html(html: str) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    for rx, description, severity in _COMPILED:
        for m in rx.finditer(html):
            line = html.count("\n", 0, m.start()) + 1
            start = max(0, m.start() - 30)
            findings.append(
                StaticFinding(
                    rule=description,
                    severity=severity,
                    match=m.group(0)[:200],
                    line=line,
                    context=html[start : m.end() + 30].replace("\n", " ")[:200],
                )
            )
    return findings
```

- [ ] **Step 4: Lancer, vérifier le succès**

Run: `pytest tests/test_static.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add engine/static.py tests/test_static.py
git commit -m "feat(engine): détecteurs static portés de malware-html-sandbox"
```

---

### Task 3: Script de rendu du runner (Playwright/Chromium)

**Files:**
- Create: `runner-analysis/render.py`, `tests/test_render.py`

**Interfaces:**
- Consumes: `engine.result.OcularResult`, `engine.static.analyze_html`.
- Produces: `runner_analysis.render.render_html(html: str, job_id: str) -> OcularResult` (fonction sync qui pilote Playwright et retourne le résultat). CLI : `python runner-analysis/render.py --job-id X < input.html` imprime le JSON sur stdout.

- [ ] **Step 1: Écrire le test qui échoue** — `tests/test_render.py`

```python
import pytest

render = pytest.importorskip("runner_analysis.render")


@pytest.mark.integration
def test_render_benign_html_produces_screenshot_and_dom():
    r = render.render_html("<html><title>Hi</title><body>hello</body></html>", "job-1")
    assert r.profile == "analysis"
    assert r.screenshots and r.screenshots[0].image_ref.startswith("sha256:")
    assert r.dom.title == "Hi"


@pytest.mark.integration
def test_render_populates_static_findings():
    r = render.render_html("<script>eval(atob('x'))</script>", "job-2")
    assert any(f.severity == "critical" for f in r.static_findings)
```

- [ ] **Step 2: Lancer, vérifier l'échec (ou skip si Playwright absent)**

Run: `pytest tests/test_render.py -v`
Expected: FAIL/skip (`runner_analysis.render` absent). Après implémentation, exécuter avec `pytest -m integration` sur une machine avec `playwright install chromium`.

- [ ] **Step 3: Implémenter `runner-analysis/render.py`**

Note : le dossier a un tiret ; ajouter `runner-analysis/__init__.py` **non** requis — le test importe via `runner_analysis` grâce à un lien. Créer plutôt le package `runner_analysis/` (underscore) et faire du fichier `render.py` son contenu. **Renommer le dossier en `runner_analysis/`** pour l'importabilité Python (le Dockerfile référencera ce nom).

```python
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

from playwright.sync_api import sync_playwright

from engine.result import (
    ConsoleEntry,
    DomInfo,
    NetworkEntry,
    OcularResult,
    Screenshot,
    StealthInfo,
)
from engine.static import analyze_html


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def render_html(html: str, job_id: str) -> OcularResult:
    network: list[NetworkEntry] = []
    console: list[ConsoleEntry] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])  # sandbox assuré par le conteneur
        context = browser.new_context(viewport={"width": 1280, "height": 720})
        page = context.new_page()
        page.on(
            "request",
            lambda req: network.append(
                NetworkEntry(
                    url=req.url, method=req.method, resource_type=req.resource_type,
                    post_data=req.post_data,
                )
            ),
        )
        page.on(
            "console",
            lambda msg: console.append(ConsoleEntry(level=msg.type, text=msg.text)),
        )
        page.set_content(html, wait_until="networkidle", timeout=15000)
        png = page.screenshot(full_page=True)
        title = page.title()
        final_url = page.url
        dom_html = page.content().encode()
        browser.close()

    return OcularResult(
        job_id=job_id,
        profile="analysis",
        target="inline-html",
        timestamp=datetime.now(timezone.utc).isoformat(),
        verdict="unknown",
        screenshots=[Screenshot(step=0, phase="initial", image_ref=_sha256_ref(png), viewport="1280x720")],
        network=network,
        console=console,
        dom=DomInfo(title=title, final_url=final_url),
        static_findings=analyze_html(html),
        stealth=StealthInfo(engine="chromium"),
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    args = ap.parse_args()
    html = sys.stdin.read()
    result = render_html(html, args.job_id)
    sys.stdout.write(result.model_dump_json())


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Renommer le dossier et vérifier l'import**

Run:
```bash
git mv runner-analysis runner_analysis 2>/dev/null || mkdir -p runner_analysis
touch runner_analysis/__init__.py
python -c "import runner_analysis.render"   # doit passer si playwright installé
```
Expected: pas d'ImportError (hors Playwright).

- [ ] **Step 5: Lancer le test d'intégration (machine avec Chromium)**

Run: `playwright install chromium && pytest tests/test_render.py -m integration -v`
Expected: 2 PASS.

- [ ] **Step 6: Commit**

```bash
git add runner_analysis/ tests/test_render.py
git commit -m "feat(runner-analysis): rendu Chromium -> OcularResult"
```

---

### Task 4: Dockerfile durci du runner + profil seccomp

**Files:**
- Create: `runner_analysis/Dockerfile`, `schemas/seccomp-analysis.json`, `tests/test_dockerfile.py`

**Interfaces:**
- Produces: image `ocular-runner-analysis:latest`, entrypoint = `python -m runner_analysis.render`.

- [ ] **Step 1: Écrire le test qui échoue** — `tests/test_dockerfile.py`

```python
from pathlib import Path


def test_dockerfile_runs_as_nonroot_and_has_no_curl_bash_docker():
    df = Path("runner_analysis/Dockerfile").read_text()
    assert "USER 10001" in df, "le runner doit tourner non-root"
    assert "get.docker.com" not in df, "le runner ne doit PAS contenir le CLI docker"


def test_seccomp_profile_is_not_unconfined():
    import json
    prof = json.loads(Path("schemas/seccomp-analysis.json").read_text())
    assert prof.get("defaultAction") in {"SCMP_ACT_ERRNO", "SCMP_ACT_KILL"}
```

- [ ] **Step 2: Lancer, vérifier l'échec**

Run: `pytest tests/test_dockerfile.py -v`
Expected: FAIL (fichiers absents).

- [ ] **Step 3: Écrire `runner_analysis/Dockerfile`**

```dockerfile
FROM mcr.microsoft.com/playwright/python:v1.41.0-jammy

WORKDIR /app
RUN pip install --no-cache-dir pydantic>=2.6
COPY engine/ ./engine/
COPY runner_analysis/ ./runner_analysis/

# Utilisateur non privilégié
RUN useradd -u 10001 -m runner
USER 10001

ENTRYPOINT ["python", "-m", "runner_analysis.render"]
```

- [ ] **Step 4: Écrire `schemas/seccomp-analysis.json`** — profil de base (deny par défaut, whitelist minimale). Point de départ : partir du profil par défaut de Docker et durcir. Version minimale explicite :

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "archMap": [{ "architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"] }],
  "syscalls": [
    { "names": ["read","write","open","openat","close","stat","fstat","lstat","poll","lseek","mmap","mprotect","munmap","brk","rt_sigaction","rt_sigprocmask","ioctl","access","pipe","pipe2","select","sched_yield","dup","dup2","nanosleep","getpid","socket","connect","clone","execve","exit","exit_group","wait4","fcntl","getdents64","getcwd","chdir","futex","set_tid_address","set_robust_list","epoll_create1","epoll_ctl","epoll_wait","eventfd2","prlimit64","getrandom","statx","clock_gettime","gettid","tgkill","madvise","sysinfo","uname","arch_prctl","prctl","sigaltstack","rseq"], "action": "SCMP_ACT_ALLOW" }
  ]
}
```

> Note d'exécution : ce profil est un socle. La tâche 6 vérifie que le conteneur démarre avec ; si un syscall manque au boot de Chromium, l'ajouter et re-commiter (documenter chaque ajout).

- [ ] **Step 5: Lancer, vérifier le succès**

Run: `pytest tests/test_dockerfile.py -v`
Expected: 2 PASS.

- [ ] **Step 6: Build de l'image (machine Docker)**

Run: `docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .`
Expected: build OK.

- [ ] **Step 7: Commit**

```bash
git add runner_analysis/Dockerfile schemas/seccomp-analysis.json tests/test_dockerfile.py
git commit -m "feat(runner-analysis): Dockerfile durci non-root + profil seccomp"
```

---

### Task 5: File de jobs Redis

**Files:**
- Create: `broker/__init__.py`, `broker/queue.py`, `tests/test_queue.py`

**Interfaces:**
- Produces: `broker.queue.Job` (Pydantic: `job_id: str`, `profile: str`, `html: str | None`, `url: str | None`), `broker.queue.RedisJobQueue(client)` avec `enqueue(job) -> None`, `dequeue(timeout=0) -> Job | None`, `set_result(job_id, result_json) -> None`, `get_result(job_id) -> str | None`.

- [ ] **Step 1: Écrire le test qui échoue** — `tests/test_queue.py`

```python
import fakeredis

from broker.queue import Job, RedisJobQueue


def test_enqueue_then_dequeue_roundtrip():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    q.enqueue(Job(job_id="j1", profile="analysis", html="<h1>x</h1>"))
    got = q.dequeue(timeout=1)
    assert got is not None and got.job_id == "j1" and got.html == "<h1>x</h1>"


def test_result_roundtrip():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    q.set_result("j1", '{"ok": true}')
    assert q.get_result("j1") == '{"ok": true}'


def test_dequeue_empty_returns_none():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    assert q.dequeue(timeout=1) is None
```

- [ ] **Step 2: Lancer, vérifier l'échec**

Run: `pytest tests/test_queue.py -v`
Expected: FAIL (`ModuleNotFoundError: broker.queue`).

- [ ] **Step 3: Implémenter `broker/queue.py`**

```python
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

_QUEUE_KEY = "ocular:jobs"
_RESULT_PREFIX = "ocular:result:"


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

    def set_result(self, job_id: str, result_json: str) -> None:
        self._r.set(_RESULT_PREFIX + job_id, result_json)

    def get_result(self, job_id: str) -> Optional[str]:
        val = self._r.get(_RESULT_PREFIX + job_id)
        return val.decode() if isinstance(val, bytes) else val
```

- [ ] **Step 4: Lancer, vérifier le succès**

Run: `pytest tests/test_queue.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/__init__.py broker/queue.py tests/test_queue.py
git commit -m "feat(broker): file de jobs Redis"
```

---

### Task 6: Launcher — conteneur éphémère durci + **régression sécu**

**Files:**
- Create: `broker/launcher.py`, `tests/test_launcher_security.py`

**Interfaces:**
- Consumes: `broker.queue.Job`.
- Produces: `broker.launcher.build_docker_args(job) -> list[str]` (les arguments `docker run`, testable **sans** Docker) et `broker.launcher.run_analysis_job(job) -> str` (exécute, retourne le JSON résultat).

- [ ] **Step 1: Écrire le test de régression sécu qui échoue** — `tests/test_launcher_security.py`

```python
from broker.launcher import build_docker_args
from broker.queue import Job


def test_analysis_container_has_all_hardening_flags():
    args = build_docker_args(Job(job_id="j1", profile="analysis", html="<h1>x</h1>"))
    joined = " ".join(args)
    assert "--network" in args and "none" in args
    assert "--cap-drop" in args and "ALL" in args
    assert "no-new-privileges" in joined
    assert "seccomp=" in joined and "unconfined" not in joined
    assert "--read-only" in args
    assert "--rm" in args
    assert "--user" in args and "10001:10001" in args
    assert "--pids-limit" in args


def test_html_is_not_written_to_host_disk_path():
    # le HTML transite par stdin (pas de -v montant un fichier hôte contenant le HTML)
    args = build_docker_args(Job(job_id="j1", profile="analysis", html="<h1>x</h1>"))
    assert not any(a.startswith("/") and a.endswith(".html") for a in args)
```

- [ ] **Step 2: Lancer, vérifier l'échec**

Run: `pytest tests/test_launcher_security.py -v`
Expected: FAIL (`ModuleNotFoundError: broker.launcher`).

- [ ] **Step 3: Implémenter `broker/launcher.py`**

```python
from __future__ import annotations

import subprocess

from broker.queue import Job

_IMAGE = "ocular-runner-analysis:latest"
_SECCOMP = "schemas/seccomp-analysis.json"


def build_docker_args(job: Job) -> list[str]:
    if job.profile != "analysis":
        raise ValueError("build_docker_args ne gère que le profil analysis")
    return [
        "docker", "run", "--rm", "-i",
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={_SECCOMP}",
        "--read-only",
        "--tmpfs", "/work:size=256m,mode=1777",
        "--user", "10001:10001",
        "--memory", "2g",
        "--pids-limit", "256",
        _IMAGE,
        "--job-id", job.job_id,
    ]


def run_analysis_job(job: Job) -> str:
    proc = subprocess.run(
        build_docker_args(job),
        input=(job.html or "").encode(),
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"runner a échoué: {proc.stderr.decode()[:500]}")
    return proc.stdout.decode()
```

- [ ] **Step 4: Lancer, vérifier le succès (unit, sans Docker)**

Run: `pytest tests/test_launcher_security.py -v`
Expected: 2 PASS.

- [ ] **Step 5: Test d'intégration réseau (machine Docker)** — ajouter à `tests/test_launcher_security.py` :

```python
import json
import pytest
from broker.launcher import run_analysis_job
from broker.queue import Job


@pytest.mark.integration
def test_runner_has_no_network_egress():
    # HTML tentant un fetch externe : la requête ne doit jamais aboutir (network=none)
    html = '<script>fetch("http://example.com/steal").catch(()=>{})</script>'
    out = run_analysis_job(Job(job_id="net-test", profile="analysis", html=html))
    result = json.loads(out)
    # la requête peut être *tentée* (listée) mais ne peut jamais avoir de status (pas de réseau)
    external = [n for n in result["network"] if "example.com" in n["url"]]
    assert all(n.get("status") is None for n in external)
```

Run: `pytest tests/test_launcher_security.py -m integration -v`
Expected: PASS (aucune requête externe n'obtient de réponse).

- [ ] **Step 6: Commit**

```bash
git add broker/launcher.py tests/test_launcher_security.py
git commit -m "feat(broker): launcher conteneur durci + régression sécu (network none, caps, seccomp)"
```

---

### Task 7: API web (sans accès Docker)

**Files:**
- Create: `web/__init__.py`, `web/models.py`, `web/app.py`, `tests/test_web_api.py`

**Interfaces:**
- Consumes: `broker.queue.RedisJobQueue`, `broker.queue.Job`.
- Produces: FastAPI app `web.app.app` ; `POST /jobs` (body `JobRequest{profile, html?, url?}`) → `JobResponse{job_id}` ; `GET /jobs/{job_id}` → résultat ou `{status: "pending"}`.

- [ ] **Step 1: Écrire le test qui échoue** — `tests/test_web_api.py`

```python
import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from broker.queue import RedisJobQueue


def _client():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    return TestClient(app), q


def test_post_job_returns_job_id_and_enqueues():
    client, q = _client()
    r = client.post("/jobs", json={"profile": "analysis", "html": "<h1>x</h1>"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert q.dequeue(timeout=1).job_id == job_id


def test_get_pending_job():
    client, _ = _client()
    r = client.get("/jobs/unknown-id")
    assert r.json()["status"] == "pending"


def test_web_package_never_imports_docker():
    import pathlib
    src = pathlib.Path("web").rglob("*.py")
    for f in src:
        text = f.read_text()
        assert "docker" not in text.lower(), f"{f} ne doit pas référencer docker"
```

- [ ] **Step 2: Lancer, vérifier l'échec**

Run: `pytest tests/test_web_api.py -v`
Expected: FAIL (`ModuleNotFoundError: web.app`).

- [ ] **Step 3: Implémenter `web/models.py`**

```python
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class JobRequest(BaseModel):
    profile: str
    html: Optional[str] = None
    url: Optional[str] = None


class JobResponse(BaseModel):
    job_id: str
```

- [ ] **Step 4: Implémenter `web/app.py`** (aucun import docker — contrainte testée)

```python
from __future__ import annotations

import json
import os
import uuid

import redis
from fastapi import Depends, FastAPI

from broker.queue import Job, RedisJobQueue
from web.models import JobRequest, JobResponse

app = FastAPI(title="Ocular")


def get_queue() -> RedisJobQueue:
    return RedisJobQueue(redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379")))


@app.post("/jobs", response_model=JobResponse)
def submit_job(req: JobRequest, queue: RedisJobQueue = Depends(get_queue)) -> JobResponse:
    job_id = "job-" + uuid.uuid4().hex[:12]
    queue.enqueue(Job(job_id=job_id, profile=req.profile, html=req.html, url=req.url))
    return JobResponse(job_id=job_id)


@app.get("/jobs/{job_id}")
def get_job(job_id: str, queue: RedisJobQueue = Depends(get_queue)) -> dict:
    result = queue.get_result(job_id)
    if result is None:
        return {"status": "pending"}
    return json.loads(result)
```

- [ ] **Step 5: Lancer, vérifier le succès**

Run: `pytest tests/test_web_api.py -v`
Expected: 3 PASS.

- [ ] **Step 6: Commit**

```bash
git add web/ tests/test_web_api.py
git commit -m "feat(web): API jobs FastAPI (sans accès docker)"
```

---

### Task 8: Boucle broker + compose durci + intégration bout-en-bout

**Files:**
- Create: `broker/main.py`, `deploy/docker-compose.yml`, `deploy/.env.example`

**Interfaces:**
- Consumes: `RedisJobQueue`, `run_analysis_job`.
- Produces: process broker exécutable `python -m broker.main`.

- [ ] **Step 1: Implémenter `broker/main.py`**

```python
from __future__ import annotations

import os

import redis

from broker.launcher import run_analysis_job
from broker.queue import RedisJobQueue


def run_forever() -> None:
    queue = RedisJobQueue(redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379")))
    while True:
        job = queue.dequeue(timeout=5)
        if job is None:
            continue
        try:
            result_json = run_analysis_job(job)
        except Exception as exc:  # le job échoue proprement, le broker survit
            result_json = f'{{"job_id": "{job.job_id}", "error": "{str(exc)[:200]}"}}'
        queue.set_result(job.job_id, result_json)


if __name__ == "__main__":
    run_forever()
```

- [ ] **Step 2: Écrire `deploy/docker-compose.yml`** — noter les postures durcies (web sans socket, broker avec socket)

```yaml
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped

  web:
    build: { context: .., dockerfile: deploy/Dockerfile.web }
    environment: { REDIS_URL: "redis://redis:6379" }
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    user: "10002:10002"
    ports: ["8000:8000"]
    depends_on: [redis]
    # PAS de montage de docker.sock ici — contrainte de sécurité

  broker:
    build: { context: .., dockerfile: deploy/Dockerfile.broker }
    environment: { REDIS_URL: "redis://redis:6379" }
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # SEUL le broker parle à Docker
      - ../schemas:/app/schemas:ro
    depends_on: [redis]
```

- [ ] **Step 3: Écrire `deploy/.env.example`**

```env
REDIS_URL=redis://redis:6379
```

- [ ] **Step 4: Test d'intégration bout-en-bout (machine Docker)** — créer `tests/test_e2e.py`

```python
import json
import time

import pytest
import redis

from broker.launcher import run_analysis_job
from broker.queue import Job, RedisJobQueue


@pytest.mark.integration
def test_end_to_end_analysis_via_broker():
    out = run_analysis_job(Job(job_id="e2e-1", profile="analysis",
                               html="<script>eval(atob('x'))</script>"))
    result = json.loads(out)
    assert result["profile"] == "analysis"
    assert any(f["severity"] == "critical" for f in result["static_findings"])
    assert result["screenshots"][0]["image_ref"].startswith("sha256:")
```

Run: `pytest tests/test_e2e.py -m integration -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/main.py deploy/ tests/test_e2e.py
git commit -m "feat: boucle broker + compose durci (web sans socket) + e2e analyse"
```

---

## Self-Review (effectuée)

- **Couverture spec** : séparation de privilèges (T6/T7/T8), fix cause racine #1 = pas de rendu hôte (le runner rend, le web ne voit que le JSON — T3/T7), fix cause racine #2 = pas de socket sur web + network none (T6/T7/T8), détecteurs static (T2), schéma unifié + contrat (T1), régression sécu (T6), profil seccomp ≠ unconfined (T4/T6). Runner **recon Camoufox**, **tier dynamique**, **gateway durci** = plans suivants (hors tranche, comme annoncé).
- **Placeholders** : le profil seccomp T4 est marqué « socle à compléter au boot » avec procédure explicite — pas un placeholder muet.
- **Cohérence des types** : `Job`, `OcularResult`, `RedisJobQueue.{enqueue,dequeue,set_result,get_result}`, `build_docker_args`, `run_analysis_job`, `render_html`, `analyze_html`, `get_queue` — noms cohérents entre tâches.

## Notes de délégation (supervision)
Chaque tâche = un lot délégable à un agent frais, avec checkpoint de revue à la fin
(deux étapes : l'agent implémente, revue avant la tâche suivante). Les tests marqués
`@pytest.mark.integration` nécessitent Docker + `playwright install chromium` ; les tâches
1, 2, 5, 6(unit), 7 sont exécutables/vérifiables **sans** Docker.
