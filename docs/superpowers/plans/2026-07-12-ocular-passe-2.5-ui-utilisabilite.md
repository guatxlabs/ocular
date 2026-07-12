# Ocular — Passe 2.5 : Utilisabilité + UI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rendre le moteur d'analyse Ocular réellement exploitable : screenshots/DOM récupérables (stockage d'artefacts), auth token Bearer, UI web vanilla-JS PWA façon plume/forge, et déploiement propre (Makefile + compose + quickstart).

**Architecture:** Le runner émet ses artefacts (base64) dans un wrapper stdout ; le broker les extrait vers un **volume disque** (indexé par sha256) et ne stocke en Redis que le résultat léger ; le web sert `GET /jobs/{id}/artifact/{ref}` (validation anti-traversal + DOM jamais inline) derrière un middleware **Bearer**, et sert l'**UI statique**. L'UI réutilise le `style.css` réel de plume, accent surchargé en violet.

**Tech Stack:** Python 3.11, FastAPI, Playwright, redis-py, Docker CLI, pytest/httpx, + vanilla-JS PWA (aucun framework, aucun build).

## Global Constraints

- **`web` reste sans Docker** : le stockage d'artefacts n'ajoute AUCUN accès Docker au web (lecture d'un volume seulement). `grep -riE "docker|launcher|subprocess" web/` doit rester vide (test maintenu).
- **Auth fail-closed** : si `OCULAR_TOKEN` non défini, le web renvoie `503` sur `/jobs*` (jamais ouvert par défaut). Sinon `Authorization: Bearer <OCULAR_TOKEN>` requis → `401` si absent/faux. Le middleware couvre AUSSI `GET .../artifact/...`.
- **Artefacts anti-traversal** : tout `ref` est validé `^sha256:[0-9a-f]{64}$` avant résolution sur disque ; jamais de `../`.
- **DOM hostile jamais servi en `text/html` inline** : `Content-Type: text/plain; charset=utf-8` + `Content-Disposition: attachment` (préserve le fix cause racine #1).
- **Contrat `result.schema.json` inchangé** : les champs `*_b64` sont un canal de transport runner→broker, retirés avant stockage (jamais dans le résultat Redis).
- UI = **vanilla JS, zéro build**, design repris de `../../GUATX/plume/web/` (dark navy, Inter+JetBrains Mono, PWA, i18n FR/EN, toggle thème), accent Ocular `#8b5cf6`.
- Python 3.11 ; commits fréquents.

---

## File Structure

```
ocular/
  engine/artifacts.py          # REF_RE + ref_to_filename() partagé (launcher store / web serve)  [NEW]
  runner_analysis/render.py     # render_html -> (result, blobs) ; main() émet le wrapper           [MODIF]
  broker/launcher.py            # run_analysis_job: stocke blobs sur volume, renvoie résultat léger  [MODIF]
  broker/gc.py                  # nettoyage des artefacts orphelins/expirés                          [NEW]
  web/app.py                    # + GET artifact + middleware auth Bearer + service statique UI      [MODIF]
  web/ui/                       # PWA vanilla-JS façon plume (index.html, style.css, views/…, sw.js) [NEW]
  deploy/docker-compose.yml     # + tmpfs /tmp web, volume artefacts, OCULAR_TOKEN, static UI        [MODIF]
  deploy/Dockerfile.web         # + copie web/ui                                                     [MODIF]
  Makefile                      # build-runner/up/down/analyze/test/test-int/gc                       [NEW]
  README.md                     # sections Utiliser / Déployer                                        [MODIF]
  pyproject.toml                # addopts = -m 'not integration'                                      [MODIF]
  tests/                        # test_artifacts, test_launcher_store, test_web_artifact, test_web_auth [NEW]
```

---

### Task 1: Helper d'artefacts partagé (validation + mapping ref→fichier)

**Files:**
- Create: `engine/artifacts.py`, `tests/test_artifacts.py`

**Interfaces:**
- Produces: `engine.artifacts.REF_RE`, `engine.artifacts.ref_to_filename(ref: str) -> str` (lève `ValueError` si ref non conforme).

- [ ] **Step 1: Test qui échoue** — `tests/test_artifacts.py`

```python
import pytest

from engine.artifacts import ref_to_filename


def test_valid_ref_maps_to_safe_filename():
    ref = "sha256:" + "a" * 64
    assert ref_to_filename(ref) == "sha256_" + "a" * 64


@pytest.mark.parametrize("bad", [
    "sha256:xyz", "../../etc/passwd", "sha256:" + "a" * 63,
    "sha256:" + "A" * 64, "md5:" + "a" * 32, "sha256:" + "a" * 64 + "/..",
])
def test_invalid_ref_rejected(bad):
    with pytest.raises(ValueError):
        ref_to_filename(bad)
```

- [ ] **Step 2: Lancer, vérifier l'échec** — `pytest tests/test_artifacts.py -v` → FAIL (module absent).

- [ ] **Step 3: Implémenter `engine/artifacts.py`**

```python
from __future__ import annotations

import re

REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def ref_to_filename(ref: str) -> str:
    """Valide un ref d'artefact (anti-traversal) et le mappe vers un nom de fichier sûr."""
    if not REF_RE.match(ref):
        raise ValueError(f"ref d'artefact invalide: {ref!r}")
    return ref.replace("sha256:", "sha256_")
```

- [ ] **Step 4: Lancer, vérifier le succès** — `pytest tests/test_artifacts.py -v` → PASS.
- [ ] **Step 5: Commit** — `git add engine/artifacts.py tests/test_artifacts.py && git commit -m "feat(engine): helper artefacts ref->filename (anti-traversal)"`

---

### Task 2: Le runner émet ses artefacts (wrapper stdout)

**Files:**
- Modify: `runner_analysis/render.py`
- Modify: `tests/test_render.py` (les 3 tests existants dépaquettent désormais un tuple)

**Interfaces:**
- Consumes: `engine.artifacts` (non requis ici) ; les modèles de `engine.result`.
- Produces: `render_html(html, job_id, render_timeout_ms=15000) -> tuple[OcularResult, dict[str, bytes]]` (2ᵉ valeur = `{ref: octets}`). `main()` émet sur stdout `{"result": <OcularResult json>, "blobs": {ref: base64}}`.

- [ ] **Step 1: Adapter les tests existants** — dans `tests/test_render.py`, remplacer les appels `r = render.render_html(...)` par `r, blobs = render.render_html(...)` et ajouter une assertion au 1er test :

```python
@pytest.mark.integration
def test_render_benign_html_produces_screenshot_and_dom():
    r, blobs = render.render_html("<html><title>Hi</title><body>hello</body></html>", "job-1")
    assert r.screenshots and r.screenshots[0].image_ref.startswith("sha256:")
    assert r.dom.title == "Hi"
    # le blob du screenshot est présent et correspond au ref
    assert r.screenshots[0].image_ref in blobs and blobs[r.screenshots[0].image_ref][:8] == b"\x89PNG\r\n\x1a\n"
```

(mettre à jour de la même façon `test_render_populates_static_findings` et le test hostile : `r, _ = render.render_html(...)`.)

- [ ] **Step 2: Lancer, vérifier l'échec** — `pytest tests/test_render.py -m integration -v` → FAIL (render_html renvoie encore un seul objet).

- [ ] **Step 3: Modifier `render_html`** — collecter les octets dans `blobs` et retourner le tuple. Remplacer les 2 blocs de capture et le `return` :

```python
def render_html(html: str, job_id: str, render_timeout_ms: int = 15000) -> tuple[OcularResult, dict[str, bytes]]:
    network: list[NetworkEntry] = []
    console: list[ConsoleEntry] = []
    static_findings = analyze_html(html)
    screenshots: list[Screenshot] = []
    dom = DomInfo()
    artifacts = Artifacts()
    blobs: dict[str, bytes] = {}
    render_error: str | None = None
    # ... (bloc playwright inchangé jusqu'aux captures) ...
            try:
                png = page.screenshot(full_page=True)
                ref = _sha256_ref(png)
                blobs[ref] = png
                screenshots.append(
                    Screenshot(step=0, phase="initial", image_ref=ref, viewport="1280x720")
                )
            except Exception:
                pass
            try:
                dom_html = page.content().encode()
                ref = _sha256_ref(dom_html)
                blobs[ref] = dom_html
                dom = DomInfo(title=page.title(), final_url=page.url)
                artifacts = Artifacts(dom_html_ref=ref)
            except Exception:
                pass
            browser.close()
    except Exception as exc:
        render_error = f"browser failure: {type(exc).__name__}"

    if render_error:
        console.append(ConsoleEntry(level="error", text=render_error, location="ocular-runner"))

    result = OcularResult(
        job_id=job_id, profile="analysis", target="inline-html",
        timestamp=datetime.now(timezone.utc).isoformat(),
        screenshots=screenshots, network=network, console=console, dom=dom,
        static_findings=static_findings, stealth=StealthInfo(engine="chromium"), artifacts=artifacts,
    )
    return result, blobs
```

- [ ] **Step 4: Modifier `main()`** — émettre le wrapper (ajouter `import base64` et `import json` en tête) :

```python
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    args = ap.parse_args()
    html = sys.stdin.read()
    result, blobs = render_html(html, args.job_id)
    payload = {
        "result": result.model_dump(mode="json"),
        "blobs": {ref: base64.b64encode(data).decode() for ref, data in blobs.items()},
    }
    sys.stdout.write(json.dumps(payload) + "\n")
```

- [ ] **Step 5: Rebuild image + vérifier** — `docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .` puis `pytest tests/test_render.py -m integration -v` → PASS. Vérifier le wrapper : `echo '<h1>x</h1>' | docker run --rm -i ... ocular-runner-analysis:latest --job-id w | python3 -c "import sys,json;d=json.load(sys.stdin);print('keys',list(d),'nblobs',len(d['blobs']))"` → `keys ['result','blobs']`.

- [ ] **Step 6: Commit** — `git add runner_analysis/render.py tests/test_render.py && git commit -m "feat(runner): émet les artefacts (wrapper stdout result+blobs base64)"`

---

### Task 3: Le broker stocke les artefacts sur volume + renvoie le résultat léger

**Files:**
- Modify: `broker/launcher.py`
- Create: `tests/test_launcher_store.py`

**Interfaces:**
- Consumes: `engine.artifacts.ref_to_filename`.
- Produces: `run_analysis_job(job) -> str` renvoie désormais le **résultat léger** (JSON, sans blobs) après avoir écrit les octets dans `OCULAR_ARTIFACTS_DIR` (défaut `artifacts`). `broker.launcher._store_blobs(blobs: dict, artifacts_dir: str) -> None`.

- [ ] **Step 1: Test qui échoue** — `tests/test_launcher_store.py`

```python
import base64
import json
from pathlib import Path

from broker.launcher import _store_blobs, _parse_and_store


def test_store_blobs_writes_valid_refs_only(tmp_path):
    ref = "sha256:" + "b" * 64
    _store_blobs({ref: base64.b64encode(b"PNGDATA").decode(),
                  "../evil": base64.b64encode(b"x").decode()}, str(tmp_path))
    assert (tmp_path / ("sha256_" + "b" * 64)).read_bytes() == b"PNGDATA"
    assert not (tmp_path / "../evil").exists()
    assert list(tmp_path.iterdir()) == [tmp_path / ("sha256_" + "b" * 64)]


def test_parse_and_store_returns_lean_result_without_blobs(tmp_path):
    ref = "sha256:" + "c" * 64
    wrapper = json.dumps({"result": {"job_id": "j", "profile": "analysis", "target": "t",
                                     "timestamp": "now", "schema_version": "1.0"},
                          "blobs": {ref: base64.b64encode(b"DATA").decode()}})
    lean = _parse_and_store(wrapper, str(tmp_path))
    assert "blobs" not in lean
    assert json.loads(lean)["job_id"] == "j"
    assert (tmp_path / ("sha256_" + "c" * 64)).read_bytes() == b"DATA"
```

- [ ] **Step 2: Lancer, vérifier l'échec** — `pytest tests/test_launcher_store.py -v` → FAIL (symbols absents).

- [ ] **Step 3: Modifier `broker/launcher.py`** — ajouter en tête `import base64, json, os` et `from engine.artifacts import ref_to_filename`, une constante, et les 2 helpers ; adapter `run_analysis_job` :

```python
_ARTIFACTS_DIR = os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts")


def _store_blobs(blobs: dict, artifacts_dir: str) -> None:
    os.makedirs(artifacts_dir, exist_ok=True)
    for ref, b64 in blobs.items():
        try:
            fname = ref_to_filename(ref)          # lève ValueError si ref non conforme (anti-traversal)
        except ValueError:
            continue
        with open(os.path.join(artifacts_dir, fname), "wb") as fh:
            fh.write(base64.b64decode(b64))


def _parse_and_store(stdout: str, artifacts_dir: str) -> str:
    wrapper = json.loads(stdout)
    _store_blobs(wrapper.get("blobs", {}), artifacts_dir)
    return json.dumps(wrapper["result"])          # résultat léger, sans blobs
```

Dans `run_analysis_job`, remplacer `return proc.stdout.decode()` par :

```python
    return _parse_and_store(proc.stdout.decode(), _ARTIFACTS_DIR)
```

- [ ] **Step 4: Lancer, vérifier le succès** — `pytest tests/test_launcher_store.py -v` → PASS.

- [ ] **Step 5: e2e intégration** — `pytest tests/test_e2e.py -m integration -v` doit toujours passer (le résultat reste lisible ; les blobs sont maintenant sur disque dans `./artifacts/`). Vérifier qu'un fichier `sha256_*` est bien créé.

- [ ] **Step 6: Commit** — `git add broker/launcher.py tests/test_launcher_store.py && git commit -m "feat(broker): stocke les artefacts sur volume, renvoie le résultat léger"`

---

### Task 4: Endpoint artefact du web (validation + DOM non-inline)

**Files:**
- Modify: `web/app.py`
- Create: `tests/test_web_artifact.py`

**Interfaces:**
- Consumes: `engine.artifacts.ref_to_filename`.
- Produces: `GET /jobs/{job_id}/artifact/{ref}` → sert l'octet depuis `OCULAR_ARTIFACTS_DIR` ; PNG → `image/png` ; sinon (DOM) → `text/plain` + `Content-Disposition: attachment`. `400` ref invalide, `404` absent.

- [ ] **Step 1: Test qui échoue** — `tests/test_web_artifact.py`

```python
import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from broker.queue import RedisJobQueue


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setenv("OCULAR_TOKEN", "")  # auth désactivée pour ce test (task 6 l'ajoute)
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(fakeredis.FakeStrictRedis())
    return TestClient(app)


def test_serves_png_as_image(tmp_path, monkeypatch):
    ref = "sha256:" + "a" * 64
    (tmp_path / ("sha256_" + "a" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nDATA")
    c = _client(tmp_path, monkeypatch)
    r = c.get(f"/jobs/j/artifact/{ref}")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"


def test_serves_dom_as_attachment_never_html(tmp_path, monkeypatch):
    ref = "sha256:" + "d" * 64
    (tmp_path / ("sha256_" + "d" * 64)).write_bytes(b"<script>alert(1)</script>")
    c = _client(tmp_path, monkeypatch)
    r = c.get(f"/jobs/j/artifact/{ref}")
    assert r.status_code == 200
    assert "text/html" not in r.headers["content-type"]
    assert "attachment" in r.headers.get("content-disposition", "")


def test_invalid_ref_400(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.get("/jobs/j/artifact/..%2f..%2fetc%2fpasswd").status_code in (400, 404)


def test_missing_artifact_404(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.get(f"/jobs/j/artifact/sha256:{'e'*64}").status_code == 404
```

- [ ] **Step 2: Lancer, vérifier l'échec** — `pytest tests/test_web_artifact.py -v` → FAIL (route absente).

- [ ] **Step 3: Modifier `web/app.py`** — ajouter en tête `import os` (déjà présent) et `from fastapi import HTTPException, Response`, `from engine.artifacts import ref_to_filename`. Ajouter :

```python
_ARTIFACTS_DIR = os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts")
_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@app.get("/jobs/{job_id}/artifact/{ref}")
def get_artifact(job_id: str, ref: str) -> Response:
    try:
        fname = ref_to_filename(ref)              # valide ^sha256:[0-9a-f]{64}$ (anti-traversal)
    except ValueError:
        raise HTTPException(status_code=400, detail="ref invalide")
    path = os.path.join(_ARTIFACTS_DIR, fname)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="artefact absent")
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:8] == _PNG_MAGIC:
        return Response(content=data, media_type="image/png")
    # DOM hostile : JAMAIS servi en text/html inline
    return Response(
        content=data, media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}.html"'},
    )
```

- [ ] **Step 4: Lancer, vérifier le succès** — `pytest tests/test_web_artifact.py -v` → PASS. Vérifier `grep -riE "docker|launcher|subprocess" web/` reste vide.
- [ ] **Step 5: Commit** — `git add web/app.py tests/test_web_artifact.py && git commit -m "feat(web): GET artefact (anti-traversal, PNG inline / DOM attachment)"`

---

### Task 5: Middleware d'auth Bearer (fail-closed)

**Files:**
- Modify: `web/app.py`
- Modify: `tests/test_web_api.py`, `tests/test_web_artifact.py` (envoient désormais le token)
- Create: `tests/test_web_auth.py`

**Interfaces:**
- Produces: middleware HTTP sur `/jobs*` : `503` si `OCULAR_TOKEN` non défini, `401` si `Authorization` ≠ `Bearer <OCULAR_TOKEN>`, sinon passe.

- [ ] **Step 1: Test qui échoue** — `tests/test_web_auth.py`

```python
import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from broker.queue import RedisJobQueue


def _client(monkeypatch, token):
    if token is None:
        monkeypatch.delenv("OCULAR_TOKEN", raising=False)
    else:
        monkeypatch.setenv("OCULAR_TOKEN", token)
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(fakeredis.FakeStrictRedis())
    return TestClient(app, raise_server_exceptions=False)


def test_503_when_token_unset(monkeypatch):
    c = _client(monkeypatch, None)
    assert c.get("/jobs/x").status_code == 503


def test_401_without_or_wrong_header(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    assert c.get("/jobs/x").status_code == 401
    assert c.get("/jobs/x", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_200_with_correct_bearer(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    r = c.get("/jobs/x", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200  # {"status":"pending"}
```

- [ ] **Step 2: Lancer, vérifier l'échec** — `pytest tests/test_web_auth.py -v` → FAIL (pas de middleware).

- [ ] **Step 3: Ajouter le middleware dans `web/app.py`** — après la création de `app`, ajouter `from starlette.responses import JSONResponse` en tête et :

```python
@app.middleware("http")
async def _auth(request, call_next):
    if request.url.path.startswith("/jobs"):
        token = os.environ.get("OCULAR_TOKEN")
        if not token:                              # fail-closed : jamais ouvert par défaut
            return JSONResponse({"detail": "OCULAR_TOKEN non configuré"}, status_code=503)
        if request.headers.get("authorization", "") != f"Bearer {token}":
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)
```

- [ ] **Step 4: Mettre à jour les tests existants** — dans `tests/test_web_api.py`, régler `OCULAR_TOKEN` et envoyer le header. Modifier `_client()` :

```python
def _client(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer t"})
    return client, q
```

(adapter les signatures d'appel `_client(monkeypatch)` dans les 4 tests ; ajouter `monkeypatch` en paramètre.) De même dans `tests/test_web_artifact.py`, remplacer `monkeypatch.setenv("OCULAR_TOKEN", "")` par un vrai token + header `Authorization` sur les requêtes (sinon 503).

- [ ] **Step 5: Lancer, vérifier le succès** — `pytest tests/test_web_auth.py tests/test_web_api.py tests/test_web_artifact.py -v` → tous PASS. `pytest -m "not integration" -q` vert.
- [ ] **Step 6: Commit** — `git add web/app.py tests/ && git commit -m "feat(web): middleware auth Bearer (fail-closed 503 / 401)"`

---

### Task 6: UI web — PWA vanilla-JS façon plume/forge

**Files:**
- Create: `web/ui/{index.html, style.css, api.js, core.js, state.js, i18n.js, sw.js, manifest.webmanifest, favicon.svg, views/login.js, views/submit.js, views/jobs.js, views/detail.js, fonts/*}`
- Modify: `web/app.py` (monter `web/ui` en statique sur `/`)
- Create: `tests/test_ui_smoke.py`

**SOUS-COMPÉTENCE REQUISE** : utiliser `frontend-design` (skill). **SOURCE DE STYLE** : copier/adapter le système réel de `../../GUATX/plume/web/` (NE PAS inventer un design). Lire `GUATX/plume/web/style.css` (tokens `--bg #070b13`, `--card`, `--acc`, `.card`, `.card h2`, `.alert .sev`, `.qtable`, `.kvdetail`), `GUATX/plume/web/index.html`, `manifest.webmanifest`, `sw.js`, et réutiliser les mêmes classes/patterns. Copier les woff2 Inter + JetBrains Mono depuis `GUATX/plume/web/fonts/`.

**Contraintes UI (verbatim)** :
- Vanilla JS, **zéro build**, PWA (sw + manifest), i18n FR/EN, toggle thème clair/sombre, `html[data-theme]`.
- **Accent Ocular = `#8b5cf6`** : surcharger uniquement `--acc` / `--acc-bg` / `--acc-soft` par rapport au style plume, garder tout le reste.
- `api.js` : wrapper `fetch` qui ajoute `Authorization: Bearer <token du localStorage>` à chaque appel et redirige vers la vue **login** sur `401`.
- **Vues** : `login` (saisir token → localStorage) · `submit` (textarea HTML + upload `.eml` + champ URL **désactivé/grisé** avec `.soon-badge` "phase 3" → POST /jobs) · `jobs` (liste, polling GET /jobs/{id} des `pending`) · `detail` (image via `/jobs/{id}/artifact/{image_ref}` avec le header Bearer chargé en blob ; badge verdict ; findings groupés par sévérité avec couleurs `--bad/--warn/--hi`; table réseau `.qtable` url/method/status/type ; console ; `.kvdetail` DOM title/final_url/redirect_chain ; lien téléchargement DOM).
- Le screenshot et le DOM se chargent en `fetch(..., {headers:{Authorization}})` → `blob()` → `URL.createObjectURL` (car l'`<img src>` nu n'envoie pas le header Bearer).

- [ ] **Step 1: Invoquer `frontend-design` et lire les références** — lire `GUATX/plume/web/{style.css,index.html,manifest.webmanifest,sw.js,core.js,i18n.js}` pour t'imprégner du système avant d'écrire.

- [ ] **Step 2: Écrire le test smoke d'abord** — `tests/test_ui_smoke.py`

```python
import os

from fastapi.testclient import TestClient

from web.app import app


def test_index_served_at_root():
    os.environ["OCULAR_TOKEN"] = "t"
    c = TestClient(app)
    r = c.get("/")
    assert r.status_code == 200
    assert "Ocular" in r.text  # l'index se charge (route publique, pas /jobs)


def test_static_assets_served():
    c = TestClient(app)
    assert c.get("/style.css").status_code == 200
    assert c.get("/api.js").status_code == 200
```

- [ ] **Step 3: Vérifier l'échec** — `pytest tests/test_ui_smoke.py -v` → FAIL (statique non monté).

- [ ] **Step 4: Construire `web/ui/`** — copier `style.css` + fonts depuis plume, surcharger `--acc:#8b5cf6` (+ `--acc-bg`/`--acc-soft` dérivés), écrire `index.html` (SPA shell : header avec titre "Ocular", toggle thème/langue, `<main id="app">`), `state.js` (token localStorage, thème, langue), `api.js` (fetch+Bearer+redirection login sur 401), `i18n.js` (FR/EN), `core.js` (routeur de vues hash-based), les 4 vues, `sw.js` + `manifest.webmanifest` (theme-color `#0b0e14`), `favicon.svg`. Réutiliser les classes plume (`.card`, `.alert .sev`, `.qtable`, `.kvdetail`, `.soon-badge`).

- [ ] **Step 5: Monter le statique dans `web/app.py`** — ajouter en tête `from fastapi.staticfiles import StaticFiles` et, **après** la déclaration des routes `/jobs`, monter la racine :

```python
app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "ui"), html=True), name="ui")
```

(Le `mount("/")` doit être déclaré APRÈS les routes `/jobs*` pour ne pas les masquer ; le middleware auth ne touche que `/jobs*`, l'UI statique reste publique.)

- [ ] **Step 6: Vérifier** — `pytest tests/test_ui_smoke.py -v` → PASS. Lancer `uvicorn web.app:app` avec `OCULAR_TOKEN=t`, ouvrir `http://localhost:8000`, vérifier manuellement : login accepte le token, submit d'un `<script>eval(atob('x'))</script>` crée un job, la vue détail affiche le screenshot + findings. Documenter le check manuel dans le rapport.

- [ ] **Step 7: Commit** — `git add web/ui web/app.py tests/test_ui_smoke.py && git commit -m "feat(web): UI PWA vanilla-JS façon plume (login/submit/jobs/detail)"`

---

### Task 7: Ops / DX — Makefile, compose, README, gc, pyproject

**Files:**
- Create: `Makefile`, `broker/gc.py`
- Modify: `deploy/docker-compose.yml`, `deploy/Dockerfile.web`, `pyproject.toml`, `README.md`

**Interfaces:**
- Produces: cibles make ; `broker/gc.py` (supprime les fichiers de `artifacts/` dont aucun job Redis ne référence le ref).

- [ ] **Step 1: `pyproject.toml`** — sous `[tool.pytest.ini_options]`, ajouter `addopts = "-m 'not integration'"`. Vérifier `pytest -q` ne lance plus les tests `integration` par défaut (`... deselected`).

- [ ] **Step 2: `deploy/docker-compose.yml`** — ajouter le volume artefacts + tmpfs web + token. Remplacer par :

```yaml
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped

  web:
    build: { context: .., dockerfile: deploy/Dockerfile.web }
    environment:
      REDIS_URL: "redis://redis:6379"
      OCULAR_TOKEN: "${OCULAR_TOKEN:?OCULAR_TOKEN requis}"
      OCULAR_ARTIFACTS_DIR: "/artifacts"
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
    user: "10002:10002"
    ports: ["8000:8000"]
    volumes:
      - ocular-artifacts:/artifacts:ro   # web LIT les artefacts
    depends_on: [redis]
    # PAS de docker.sock — contrainte de sécurité

  broker:
    build: { context: .., dockerfile: deploy/Dockerfile.broker }
    environment:
      REDIS_URL: "redis://redis:6379"
      OCULAR_ARTIFACTS_DIR: "/artifacts"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # SEUL le broker parle à Docker
      - ../schemas:/app/schemas:ro
      - ocular-artifacts:/artifacts                # broker ÉCRIT les artefacts
    depends_on: [redis]

volumes:
  ocular-artifacts:
```

- [ ] **Step 3: `deploy/Dockerfile.web`** — après `COPY web/ ./web/`, s'assurer que `web/ui/` est inclus (il l'est via `COPY web/`). Aucun changement si `COPY web/` copie déjà tout. Vérifier.

- [ ] **Step 4: `broker/gc.py`** — nettoyage des artefacts orphelins :

```python
from __future__ import annotations

import os

import redis

from broker.queue import _RESULT_PREFIX  # noqa: F401  (documentaire)


def collect(artifacts_dir: str, client) -> int:
    """Supprime les fichiers d'artefacts dont plus aucun résultat Redis ne référence le ref.
    Retourne le nombre de fichiers supprimés."""
    referenced: set[str] = set()
    for key in client.scan_iter(match="ocular:result:*"):
        raw = client.get(key)
        if raw:
            referenced.update(_refs_in(raw.decode() if isinstance(raw, bytes) else raw))
    removed = 0
    if not os.path.isdir(artifacts_dir):
        return 0
    for fname in os.listdir(artifacts_dir):
        ref = fname.replace("sha256_", "sha256:", 1)
        if ref not in referenced:
            os.remove(os.path.join(artifacts_dir, fname))
            removed += 1
    return removed


def _refs_in(result_json: str) -> set[str]:
    import re
    return set(re.findall(r"sha256:[0-9a-f]{64}", result_json))


if __name__ == "__main__":
    c = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379"))
    n = collect(os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts"), c)
    print(f"gc: {n} artefacts supprimés")
```

Ajouter `tests/test_gc.py` (fakeredis) : un artefact référencé est gardé, un orphelin est supprimé.

```python
import fakeredis

from broker.gc import collect


def test_gc_removes_orphans_keeps_referenced(tmp_path):
    r = fakeredis.FakeStrictRedis()
    kept = "sha256_" + "a" * 64
    orphan = "sha256_" + "b" * 64
    (tmp_path / kept).write_bytes(b"x")
    (tmp_path / orphan).write_bytes(b"y")
    r.set("ocular:result:j", '{"screenshots":[{"image_ref":"sha256:' + "a" * 64 + '"}]}')
    removed = collect(str(tmp_path), r)
    assert removed == 1
    assert (tmp_path / kept).exists() and not (tmp_path / orphan).exists()
```

- [ ] **Step 5: `Makefile`**

```makefile
.PHONY: build-runner up down analyze test test-int gc
build-runner:
	docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .
up: build-runner
	docker compose -f deploy/docker-compose.yml up -d --build
down:
	docker compose -f deploy/docker-compose.yml down
analyze: build-runner
	@test -n "$(FILE)" || (echo "usage: make analyze FILE=suspect.html"; exit 1)
	. .venv/bin/activate && python -c "from broker.launcher import run_analysis_job; from broker.queue import Job; import sys; print(run_analysis_job(Job(job_id='cli', profile='analysis', html=open('$(FILE)').read())))"
test:
	. .venv/bin/activate && pytest -q
test-int:
	. .venv/bin/activate && pytest -m integration -q
gc:
	. .venv/bin/activate && python -m broker.gc
```

- [ ] **Step 6: `README.md`** — ajouter sections **Utiliser** (`make analyze FILE=…` ; API : `curl` POST/GET avec `Authorization: Bearer $OCULAR_TOKEN` ; UI : `make up` puis `http://localhost:8000`) et **Déployer** (VPS : `.env` avec `OCULAR_TOKEN`, `make up`, pré-build runner automatique via `build-runner`, Caddy+TLS + auth devant recommandé).

- [ ] **Step 7: Vérifier + Commit** — `pytest -q` (unit vert, integration deselected), `pytest tests/test_gc.py -v` PASS, `docker compose -f deploy/docker-compose.yml config` valide (avec `OCULAR_TOKEN=x` dans l'env). `git add -A && git commit -m "feat(ops): Makefile, compose volume artefacts+auth, gc, README quickstart, integration off par défaut"`

---

## Self-Review (effectuée)

- **Couverture spec** : artefacts (T1-T4), auth fail-closed (T5), UI plume/forge (T6), ops/DX (T7). Anti-traversal (T1 `ref_to_filename` + T4), DOM non-inline (T4), web-sans-docker préservé (T4 vérif grep), b64 hors schéma stocké (T3 `_parse_and_store` retire les blobs), tmpfs web + volume artefacts (T7).
- **Placeholders** : aucun muet ; T6 (UI) délègue explicitement à `frontend-design` + fichiers de référence réels (le CSS dérive du vrai plume, pas d'invention) avec critères d'acceptation concrets.
- **Cohérence des types** : `ref_to_filename` (T1) consommé par T3/T4 ; `render_html -> (result, blobs)` (T2) consommé par le wrapper→`_parse_and_store` (T3) ; middleware auth (T5) couvre les routes de T4 ; les tests de T5 mettent à jour ceux de T4/existants.

## Notes de délégation
Tâches sans Docker : 1, 5 (unit), et parties de 4/7. Avec Docker : 2 (rebuild+e2e), 3 (e2e), 7 (compose config). T6 (UI) = vérif manuelle navigateur documentée dans le rapport. Rebuild de l'image runner requis après T2 (nouveau format stdout) — T3 et suivantes en dépendent.
