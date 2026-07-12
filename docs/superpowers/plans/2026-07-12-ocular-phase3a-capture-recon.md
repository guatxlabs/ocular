# Ocular — Phase 3a : Runner capture (Camoufox + vision) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ajouter le profil `capture` : un runner éphémère Camoufox+vision qui navigue une URL live, résout le Turnstile automatiquement, capture screenshots+réseau+DOM et émet le wrapper `OcularResult` — coulant dans le pipeline existant.

**Architecture:** `runner_recon/` (Camoufox headed Xvfb + `vision.py` opencv Turnstile + xdotool OS-click) lancé par le broker via un profil `capture` (réseau ON, durci). `run_job` générique dispatche analysis/capture.

**Tech Stack:** Python 3.11, Camoufox, Playwright, opencv, xdotool/Xvfb, FastAPI, pytest.

## Global Constraints
- Le **stdout du runner recon reste le wrapper JSON pur** — logs sur **stderr**.
- Profil `capture` : **réseau ON** (PAS `--network none`), mais **jamais** de `docker.sock` ni de host-network ; non-root, `--cap-drop ALL`, `no-new-privileges`, seccomp profilé, `--read-only`+tmpfs, `--rm`, limites mem/pids. Passthrough `HTTP_PROXY`/`HTTPS_PROXY` si définis.
- `web` reste sans Docker (`grep -riE "docker|launcher|subprocess" web/` vide).
- `input_hash` capture = `sha256` de l'URL normalisée ; `input_kind="url"` (déjà géré par `saved_store.save` via `profile=="capture"`).
- `--disable-web-security` reste **analysis-only** (le recon = runner séparé, ne partage pas `render.py`).
- Python 3.11 ; commits fréquents.

---

### Task 1: Normalisation URL + input_hash capture

**Files:** Create `engine/urlnorm.py`, `tests/test_urlnorm.py`.

**Interfaces:** `engine.urlnorm.normalize_url(url) -> str` (scheme+host lowercase, host sans port par défaut conservé, garde path/query, retire fragment) ; `engine.urlnorm.url_input_hash(url) -> str` (`"sha256:"+sha256(normalize_url(url))`).

- [ ] **Step 1: Test qui échoue** — `tests/test_urlnorm.py`
```python
import hashlib

from engine.urlnorm import normalize_url, url_input_hash


def test_normalize_lowercases_scheme_host_keeps_path():
    assert normalize_url("HTTPS://Example.COM/Path?q=1#frag") == "https://example.com/Path?q=1"


def test_same_url_diff_case_host_same_hash():
    assert url_input_hash("https://EXAMPLE.com/a") == url_input_hash("https://example.com/a")


def test_hash_format():
    h = url_input_hash("https://example.com")
    assert h == "sha256:" + hashlib.sha256(normalize_url("https://example.com").encode()).hexdigest()
```

- [ ] **Step 2: Échec** — `pytest tests/test_urlnorm.py -v` → FAIL.
- [ ] **Step 3: Implémenter `engine/urlnorm.py`**
```python
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    p = urlsplit(url.strip())
    scheme = p.scheme.lower() or "http"
    netloc = p.netloc.lower()
    # garde path/query, retire le fragment
    return urlunsplit((scheme, netloc, p.path, p.query, ""))


def url_input_hash(url: str) -> str:
    return "sha256:" + hashlib.sha256(normalize_url(url).encode()).hexdigest()
```
- [ ] **Step 4: Succès** — `pytest tests/test_urlnorm.py -v` → PASS.
- [ ] **Step 5: Commit** — `git add engine/urlnorm.py tests/test_urlnorm.py && git commit -m "feat(engine): normalisation URL + input_hash capture"`

---

### Task 2: Module partagé `engine/wrapper.py` (DRY) + script `capture.py`

**Files:** Create `engine/wrapper.py`, `tests/test_wrapper.py`, `runner_recon/__init__.py`, `runner_recon/vision.py` (copie), `runner_recon/turnstile_checkbox.png` (copie), `runner_recon/capture.py`, `tests/test_capture_logic.py`. **Modify** `runner_analysis/render.py` (utiliser le module partagé — retirer la duplication).

**DRY (demande explicite : pas de méthodes répétées)** : `render.py` (analyse) et `capture.py` (recon) partagent la même mécanique (hash de ref, collecte de blobs, listeners réseau, émission du wrapper). On factorise dans `engine/wrapper.py` :
- `sha256_ref(data: bytes) -> str`.
- classe `NetworkCapture` : `attach(page)` (arme `page.on("request"/"response"/"console")`), expose `.network` / `.console` (listes de dicts).
- classe `ResultBuilder` : `.add_screenshot(step, phase, png)`, `.set_dom(dom_html_bytes)`, `.build(job_id, profile, target, input_hash, verdict, dom_info, stealth) -> (OcularResult, blobs)`.
- `emit_wrapper(result, blobs)` → écrit `{result, blobs(base64)}` sur stdout.
`render.py` ET `capture.py` consomment `engine/wrapper.py` — **une seule** implémentation de la mécanique. Le test `test_wrapper.py` couvre `ResultBuilder`/`sha256_ref`/`emit_wrapper` ; `test_render.py` reste vert (comportement identique).

**Interfaces:** `runner_recon.capture.capture_url(url, timeout_ms) -> tuple[OcularResult, dict]` (pilote Camoufox via `NetworkCapture`) ; `runner_recon.capture.build_result(...)` s'appuie sur `ResultBuilder` ; `main()` = `emit_wrapper(*capture_url(...))`.

- [ ] **Step 1: Copier vision + template**
```bash
cd /home/guat/wslRecover/guat/ocular && mkdir -p runner_recon && touch runner_recon/__init__.py
cp ../YesWeHack/toolkit/browser-automation/vision.py runner_recon/vision.py
cp ../YesWeHack/toolkit/browser-automation/turnstile_checkbox.png runner_recon/turnstile_checkbox.png
```

- [ ] **Step 2: Test qui échoue (logique pure, sans navigateur)** — `tests/test_capture_logic.py`
```python
from runner_recon.capture import build_result


def test_build_result_capture_profile_and_hash():
    r, blobs = build_result(
        url="https://example.com/x",
        screenshots=[(0, "initial", b"\x89PNG\r\n\x1a\nAAA")],
        network=[{"url": "https://example.com/x", "method": "GET", "status": 200}],
        console=[], dom_html=b"<script>eval(atob('x'))</script>",
        title="t", final_url="https://example.com/x", turnstile_solved=True,
    )
    assert r.profile == "capture"
    assert r.stealth.engine == "camoufox" and r.stealth.turnstile_solved is True
    assert r.input_hash.startswith("sha256:")
    assert r.verdict == "malicious"          # static détecte eval/atob dans le DOM capturé
    assert r.screenshots[0].image_ref in blobs
    # le DOM est aussi un blob
    assert r.artifacts.dom_html_ref in blobs
```

- [ ] **Step 3: Échec** — `pytest tests/test_capture_logic.py -v` → FAIL.

- [ ] **Step 4: Implémenter `runner_recon/capture.py`** (réutilise engine.result/static/verdict/urlnorm ; `capture_url` pilote Camoufox comme `browser-automation/api.py` + `vision`)
```python
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import sys

from engine.result import (Artifacts, ConsoleEntry, DomInfo, NetworkEntry,
                           OcularResult, Screenshot, StealthInfo)
from engine.static import analyze_html
from engine.urlnorm import url_input_hash
from engine.verdict import compute_verdict


def _ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_result(url, screenshots, network, console, dom_html, title,
                 final_url, turnstile_solved):
    blobs: dict[str, bytes] = {}
    shots = []
    for step, phase, png in screenshots:
        ref = _ref(png)
        blobs[ref] = png
        shots.append(Screenshot(step=step, phase=phase, image_ref=ref, viewport="1280x720"))
    artifacts = Artifacts()
    if dom_html:
        dref = _ref(dom_html)
        blobs[dref] = dom_html
        artifacts = Artifacts(dom_html_ref=dref)
    findings = analyze_html(dom_html.decode("utf-8", "replace")) if dom_html else []
    from datetime import datetime, timezone
    result = OcularResult(
        job_id="", profile="capture", target=url, input_hash=url_input_hash(url),
        timestamp=datetime.now(timezone.utc).isoformat(),
        verdict=compute_verdict(findings),
        screenshots=shots,
        network=[NetworkEntry(**n) for n in network],
        console=[ConsoleEntry(**c) for c in console],
        dom=DomInfo(title=title, final_url=final_url),
        static_findings=findings,
        stealth=StealthInfo(engine="camoufox", turnstile_solved=turnstile_solved),
        artifacts=artifacts,
    )
    return result, blobs


async def capture_url(url: str, timeout_ms: int = 45000):
    import vision  # copié dans runner_recon/, sur le PYTHONPATH du conteneur
    from camoufox.async_api import AsyncCamoufox

    network, console = [], []
    screenshots, turnstile_solved = [], False
    dom_html, title, final_url = b"", "", url
    async with AsyncCamoufox(headless=False, os="linux", humanize=0.3,
                             i_know_what_im_doing=True) as ctx:
        page = await ctx.new_page()
        req_index = {}

        def on_req(r):
            e = {"url": r.url, "method": r.method, "resource_type": r.resource_type,
                 "post_data": r.post_data}
            network.append(e); req_index[r] = e

        def on_resp(r):
            e = req_index.get(r.request)
            if e is not None:
                e["status"] = r.status

        page.on("request", on_req); page.on("response", on_resp)
        page.on("console", lambda m: console.append({"level": m.type, "text": m.text}))
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:
            console.append({"level": "error", "text": f"goto: {type(exc).__name__}"})
        png0 = await page.screenshot(full_page=False)
        screenshots.append((0, "initial", png0))
        # Turnstile : détection vision + clic OS xdotool
        try:
            det = vision.detect(vision.png_to_bgr(png0), strategy="turnstile")
            if det is not None:
                x, y = det[0], det[1]
                await vision.human_click_xdotool(x, y)
                await asyncio.sleep(4)
                png1 = await page.screenshot(full_page=False)
                screenshots.append((1, "post-turnstile", png1))
                turnstile_solved = True
        except Exception as exc:
            console.append({"level": "warning", "text": f"turnstile: {type(exc).__name__}"})
        try:
            dom_html = (await page.content()).encode()
            title = await page.title()
            final_url = page.url
        except Exception:
            pass
    return build_result(url, screenshots, network, console, dom_html, title,
                        final_url, turnstile_solved)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    args = ap.parse_args()
    result, blobs = asyncio.run(capture_url(args.url))
    payload = {"result": result.model_dump(mode="json"),
               "blobs": {r: base64.b64encode(b).decode() for r, b in blobs.items()}}
    sys.stdout.write(json.dumps(payload) + "\n")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Succès (logique pure)** — `pytest tests/test_capture_logic.py -v` → PASS (`build_result` n'importe pas Camoufox).
- [ ] **Step 6: Commit** — `git add runner_recon/ tests/test_capture_logic.py && git commit -m "feat(runner-recon): port vision + script capture one-shot (build_result testé)"`

---

### Task 3: Image `runner_recon` + seccomp + build réel

**Files:** Create `runner_recon/Dockerfile`, `runner_recon/entrypoint_recon.sh`, `schemas/seccomp-recon.json`, `tests/test_recon_dockerfile.py`.

- [ ] **Step 1: Test contenu** — `tests/test_recon_dockerfile.py`
```python
from pathlib import Path


def test_recon_dockerfile_nonroot_no_novnc():
    df = Path("runner_recon/Dockerfile").read_text()
    assert "USER" in df and "camoufox" in df
    assert "novnc" not in df.lower()  # noVNC = 3b, pas 3a
```

- [ ] **Step 2: Échec** — `pytest tests/test_recon_dockerfile.py -v` → FAIL.

- [ ] **Step 3: `runner_recon/Dockerfile`** (dérivé de browser-automation, sans x11vnc/novnc)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates xvfb xdotool scrot \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libgtk-3-0 libdbus-glib-1-2 libxt6 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir camoufox[geoip] opencv-python-headless numpy playwright pydantic
# Patch Playwright coreBundle (survie erreurs JS CF/Auth0)
RUN CB=$(python3 -c "import playwright,os;print(os.path.join(os.path.dirname(playwright.__file__),'driver/package/lib/coreBundle.js'))") \
    && sed -i 's/const pageError = { error, location: location2 };/const pageError = { error, location: location2 || { url: "", lineNumber: 0, columnNumber: 0 } };/' "$CB" || true
RUN python3 -m camoufox fetch
COPY engine/ ./engine/
COPY runner_recon/ ./runner_recon/
COPY runner_recon/vision.py ./vision.py
COPY runner_recon/entrypoint_recon.sh /entrypoint_recon.sh
RUN chmod +x /entrypoint_recon.sh && useradd -u 10001 -m runner \
    && mkdir -p /work && chown 10001:10001 /work
ENV HOME=/work TMPDIR=/work DISPLAY=:99
USER 10001
ENTRYPOINT ["/entrypoint_recon.sh"]
```
> Note : `camoufox fetch` télécharge Camoufox dans `$HOME` — comme `USER 10001` + `HOME=/work` sont réglés APRÈS le fetch (fait en root, HOME=/root), le fetch runtime peut re-télécharger dans /work. Si le smoke échoue à trouver le binaire, faire le `camoufox fetch` en tant que user 10001 avec HOME=/work AVANT le USER, ou pointer `CAMOUFOX_...` cache. L'implémenteur ajuste jusqu'à ce que le smoke navigue.

- [ ] **Step 4: `runner_recon/entrypoint_recon.sh`**
```bash
#!/bin/bash
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true
Xvfb :99 -screen 0 1280x720x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99
exec python -m runner_recon.capture "$@"
```
(stdout de `capture` = wrapper JSON pur ; Xvfb logue sur /dev/null.)

- [ ] **Step 5: `schemas/seccomp-recon.json`** — partir du profil analysis (`schemas/seccomp-analysis.json`) copié, `defaultAction: SCMP_ACT_ERRNO`. Note : Firefox/Xvfb peuvent exiger des syscalls en plus — l'implémenteur dérive au boot (voir Step 6). Fallback documenté : si Firefox ne démarre pas malgré itérations, un profil plus permissif (mais **jamais `unconfined`** sans justification écrite) est acceptable, documenté dans le rapport.

- [ ] **Step 6: Build réel + smoke** —
```bash
cd /home/guat/wslRecover/guat/ocular
docker build -f runner_recon/Dockerfile -t ocular-runner-recon:latest .
# smoke : naviguer une URL bénigne (réseau ON) et vérifier le wrapper
docker run --rm --cap-drop ALL --security-opt no-new-privileges:true \
  --read-only --tmpfs /work:size=512m --tmpfs /tmp:size=64m --user 10001:10001 \
  --memory 4g --pids-limit 512 ocular-runner-recon:latest --url https://example.com \
  2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print('profile',d['result']['profile'],'shots',len(d['result']['screenshots']),'net',len(d['result']['network']))"
```
Attendu : `profile capture shots>=1 net>=1`. Si seccomp bloque Firefox, ajuster `schemas/seccomp-recon.json` (documenter les syscalls ajoutés) et re-tester.

- [ ] **Step 7: Commit** — `git add runner_recon/Dockerfile runner_recon/entrypoint_recon.sh schemas/seccomp-recon.json tests/test_recon_dockerfile.py && git commit -m "feat(runner-recon): Dockerfile Camoufox+Xvfb durci + seccomp recon + build vérifié"`

---

### Task 4: Launcher — profil `capture` + `run_job` générique

**Files:** Modify `broker/launcher.py`, `broker/main.py` ; Create `tests/test_launcher_capture.py`.

**Interfaces:** `build_docker_args(job)` gère `analysis` ET `capture` ; `run_job(job) -> str` dispatche (remplace/englobe `run_analysis_job`).

- [ ] **Step 1: Test qui échoue** — `tests/test_launcher_capture.py`
```python
from broker.launcher import build_docker_args
from bus.queue import Job


def test_capture_args_network_on_hardened_no_socket():
    a = build_docker_args(Job(job_id="j", profile="capture", url="https://example.com"))
    j = " ".join(a)
    assert "--network" not in a or "none" not in a          # réseau ON (pas de --network none)
    assert "--cap-drop" in a and "ALL" in a
    assert "--rm" in a and "no-new-privileges" in j
    assert "docker.sock" not in j and "--privileged" not in a
    assert "ocular-runner-recon:latest" in a and "--url" in a and "https://example.com" in a


def test_analysis_still_network_none():
    a = build_docker_args(Job(job_id="j", profile="analysis", html="x"))
    assert "--network" in a and "none" in a
```

- [ ] **Step 2: Échec** — `pytest tests/test_launcher_capture.py -v` → FAIL.

- [ ] **Step 3: `broker/launcher.py`** — ajouter constantes recon + branche capture + `run_job` :
```python
_RECON_IMAGE = "ocular-runner-recon:latest"
_RECON_SECCOMP = "schemas/seccomp-recon.json"


def _proxy_env() -> list[str]:
    out = []
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        if os.environ.get(k):
            out += ["-e", f"{k}={os.environ[k]}"]
    return out


def build_docker_args(job: Job) -> list[str]:
    if job.profile == "analysis":
        return [ ... inchangé ... ]
    if job.profile == "capture":
        return [
            "docker", "run", "--rm",
            "--name", f"ocular-job-{job.job_id}",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--security-opt", f"seccomp={_RECON_SECCOMP}",
            "--read-only",
            "--tmpfs", "/work:size=512m,mode=1777",
            "--tmpfs", "/tmp:size=64m,mode=1777",
            "--user", "10001:10001",
            "--memory", "4g",
            "--pids-limit", "512",
            *_proxy_env(),
            _RECON_IMAGE,
            "--url", job.url or "",
        ]
    raise ValueError(f"profil non géré: {job.profile}")


def run_job(job: Job) -> str:
    log.info("runner launch job_id=%s profile=%s", job.job_id, job.profile)
    if job.profile == "capture":
        log.warning("capture job job_id=%s : IP exposée (proxy=%s)",
                    job.job_id, bool(_proxy_env()))
    started = time.monotonic()
    stdin = (job.html or "").encode() if job.profile == "analysis" else None
    timeout = 60 if job.profile == "analysis" else 90
    try:
        proc = subprocess.run(build_docker_args(job), input=stdin,
                              capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", f"ocular-job-{job.job_id}"],
                       capture_output=True, check=False)
        raise RuntimeError(f"runner timeout (job {job.job_id})")
    if proc.returncode != 0:
        raise RuntimeError(f"runner a échoué: {proc.stderr.decode()[:500]}")
    return _parse_and_store(proc.stdout.decode(), _ARTIFACTS_DIR)


run_analysis_job = run_job  # rétro-compat pour les tests/imports existants
```
(Garder `run_analysis_job` comme alias évite de casser `broker/main.py` et les tests existants ; mettre aussi à jour `broker/main.py` pour appeler `run_job`.)

- [ ] **Step 4: `broker/main.py`** — remplacer `from broker.launcher import run_analysis_job` par `run_job` et l'appel dans `process_one`.

- [ ] **Step 5: Succès** — `pytest tests/test_launcher_capture.py tests/test_launcher_security.py tests/test_e2e.py -v` (analysis intact, capture ok) ; `pytest -m "not integration" -q` vert.
- [ ] **Step 6: Commit** — `git add broker/ tests/test_launcher_capture.py && git commit -m "feat(broker): profil capture (réseau ON durci) + run_job générique + warning IP"`

---

### Task 5: web/models + submit + broker route capture

**Files:** Modify `web/models.py`, `web/app.py` ; Modify `tests/test_web_api.py`.

- [ ] **Step 1: Test qui échoue** — ajouter à `tests/test_web_api.py`
```python
def test_capture_requires_url(monkeypatch):
    c = _client(monkeypatch)[0]
    assert c.post("/jobs", json={"profile": "capture"}).status_code == 422
    r = c.post("/jobs", json={"profile": "capture", "url": "https://example.com"})
    assert r.status_code == 200


def test_analysis_requires_html(monkeypatch):
    c = _client(monkeypatch)[0]
    assert c.post("/jobs", json={"profile": "analysis"}).status_code == 422
```

- [ ] **Step 2: Échec** — FAIL.
- [ ] **Step 3: `web/models.py`** — `profile: Literal["analysis", "capture"] = "analysis"`.
- [ ] **Step 4: `web/app.py` `submit_job`** — validation par profil avant enqueue :
```python
    if req.profile == "capture" and not req.url:
        raise HTTPException(status_code=422, detail="url requis pour capture")
    if req.profile == "analysis" and not req.html:
        raise HTTPException(status_code=422, detail="html requis pour analysis")
```
- [ ] **Step 5: Succès + Commit** — `pytest tests/test_web_api.py -v` PASS ; `grep -riE "docker|launcher|subprocess" web/*.py` vide ; `git add web/ tests/test_web_api.py && git commit -m "feat(web): profil capture (url requis) + validation par profil"`

---

### Task 6: UI — champ URL activé + toggle profil + dédup URL

**Files:** Modify `web/ui/views/submit.js`, `web/ui/api.js`, `web/ui/views/detail.js`, `web/ui/i18n.js` ; Modify `tests/test_ui_smoke.py`.

**SOUS-COMPÉTENCE** : `frontend-design`. Anti-XSS : données via textNode/setAttribute.

- [ ] **Step 1** — `submit.js` : retirer `disabled` du champ URL + le badge « phase 3 » ; ajouter un **toggle profil** (radio « HTML » / « URL »). Selon le profil : envoyer `{profile:"analysis",html}` ou `{profile:"capture",url}`. La **dédup** : pour URL, `sha256Hex(normalizeUrlClient(url))` (normalisation JS miroir de `engine/urlnorm` : scheme+host lowercase, retire fragment) → `lookupSaved(hash)` → modal.
- [ ] **Step 2** — `api.js` : `normalizeUrlClient(url)` (miroir de `normalize_url`) + `sha256Hex` déjà là.
- [ ] **Step 3** — `detail.js` : afficher `stealth.engine` (camoufox/chromium) + `turnstile_solved` (badge « Turnstile passé ✓ ») quand présent ; les 2 screenshots (initial/post-turnstile) si multi-étapes.
- [ ] **Step 4** — `i18n.js` : libellés FR/EN (Analyser HTML / Analyser URL / IP exposée / Turnstile passé).
- [ ] **Step 5: smoke + vérif** — `tests/test_ui_smoke.py` inchangé (vues déjà servies) ; vérif : `grep -nE "innerHTML" web/ui/views/submit.js` → seulement icônes ; le toggle switch bien entre html/url. `pytest tests/test_ui_smoke.py -q` vert.
- [ ] **Step 6: Commit** — `git add web/ui tests/test_ui_smoke.py && git commit -m "feat(ui): profil capture (URL activée + toggle + dédup URL + stealth/turnstile)"`

---

### Task 7: Ops — make analyze URL= + guard 4e image + doc

**Files:** Modify `Makefile`, `tests/test_deploy_images.py`, `README.md`, `deploy/docker-compose.yml` (le broker doit builder l'image recon ? non — pré-buildée sur l'hôte comme runner-analysis).

- [ ] **Step 1** — `Makefile` : `build-runner` build AUSSI l'image recon (`ocular-runner-recon:latest`). `analyze` : supporte `URL=` (mode direct via `run_job` avec un `Job(profile=capture,url=...)`).
```makefile
build-runner:
	docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .
	docker build -f runner_recon/Dockerfile -t ocular-runner-recon:latest .
analyze: build-runner
	@if [ -n "$(URL)" ]; then . .venv/bin/activate && python -c "from broker.launcher import run_job; from bus.queue import Job; print(run_job(Job(job_id='cli', profile='capture', url='$(URL)')))"; \
	elif [ -n "$(FILE)" ]; then . .venv/bin/activate && python -c "from broker.launcher import run_job; from bus.queue import Job; print(run_job(Job(job_id='cli', profile='analysis', html=open('$(FILE)').read())))"; \
	else echo "usage: make analyze FILE=x.html | URL=https://…"; exit 1; fi
```
- [ ] **Step 2** — `tests/test_deploy_images.py` : ajouter le build+smoke de `ocular-runner-recon` (build + `docker run … --url https://example.com` → wrapper `profile:capture`). Marqué `@pytest.mark.integration`.
- [ ] **Step 3** — `README.md` : section « Analyser une URL » (`make analyze URL=…` ; profil capture ; **avertissement exposition IP** + `HTTP_PROXY` pour VPN/Tor).
- [ ] **Step 4: Vérifier + Commit** — `pytest -m "not integration" -q` vert ; `git add Makefile tests/test_deploy_images.py README.md && git commit -m "feat(ops): make analyze URL= + guard image recon + doc exposition IP"`

---

## Self-Review (effectuée)
- **Couverture spec** : urlnorm+input_hash (T1), capture.py+vision (T2), image+seccomp+build (T3), launcher profil capture réseau-ON+run_job (T4), models/submit (T5), UI (T6), ops (T7). Verdict=static sur DOM capturé (T2). Réseau ON sans docker.sock (T4 testé). analysis intact (T4 test).
- **Placeholders** : aucun muet ; T3 note explicitement l'ajustement camoufox-fetch/seccomp au boot (dérivation, comme l'analyse).
- **Cohérence types** : `url_input_hash` (T1) ↔ `build_result` (T2) ; `run_job` (T4) ↔ `process_one` (T4) ↔ `make`/`test_deploy_images` (T7) ; `profile capture` (T5) ↔ launcher (T4).

## Notes de délégation
Sans Docker : T1, T2 (logique pure), T4 (unit), T5. Avec Docker : T3 (build Camoufox — long, réseau requis pour `camoufox fetch`), T7 (guard). T3 est le plus risqué (Camoufox/Xvfb/seccomp) — itérer le smoke jusqu'à navigation réelle. T6 = vérif navigateur.
