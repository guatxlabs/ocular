# Phase 3c — Tier dynamique scripté — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Rejouer une séquence d'actions déclarative (fill/click/wait…) dans le runner recon 3a pendant qu'on enregistre le réseau, pour révéler les appels post-interaction. One-shot éphémère.

**Architecture:** `engine/steps.py` (DSL + validateur, partagé web+runner) → web valide `steps` à la soumission → broker `docker run --rm -i runner_recon`, steps sur **stdin** → runner rejoue via l'API locator Playwright, journalise + screenshots `capture`, `engine.wrapper` → `OcularResult`.

**Tech Stack:** Python 3.11, FastAPI, Playwright (Camoufox), Redis, Docker, pytest.

## Global Constraints
- **Aucun JS arbitraire, aucun `eval`.** Verbes en allowlist stricte : `goto`, `fill`, `click`, `wait`, `press`, `capture`, `scroll`.
- Sélecteurs/valeurs passés à l'**API locator** Playwright (`page.locator`, `page.fill(sel, value)`), jamais interpolés dans du code.
- Steps transmis au runner via **stdin** (JSON), jamais via env var / argument CLI (pas de fuite dans `docker inspect`).
- Valeurs `fill` **redigées** (`"***"`) dans tout log et dans le journal d'actions du résultat.
- Bornes : `len(steps) ≤ 50` ; `sel ≤ 500` ; `fill.value ≤ 2000` ; `wait ≤ 30000` ms ; `label ≤ 64` (`[\w .:-]`) ; `press` ∈ allowlist ; `scroll` px ≤ 100000 ; timeout d'exécution total 120 s.
- SSRF : `engine.ssrf.validate_capture_url` sur l'URL initiale **et** chaque `goto`.
- DRY : `validate_steps` défini **une fois** dans `engine/steps.py`, importé par web ET runner. Réutiliser `engine/wrapper.py` (NetworkCapture/ResultBuilder/emit_wrapper) et le durcissement broker 3a existant — ne pas dupliquer.
- Sans `steps`, le chemin capture 3a reste **strictement inchangé**.

---

### Task 1: DSL + validateur `engine/steps.py`

**Files:**
- Create: `engine/steps.py`
- Test: `tests/test_steps.py`

**Interfaces:**
- Consumes: `engine.ssrf.validate_capture_url(url: str) -> None` (lève `ValueError` si SSRF/scheme).
- Produces:
  - `class StepValidationError(ValueError)` — motif lisible en message.
  - `ALLOWED_PRESS_KEYS: frozenset[str]` = `{"Enter","Tab","Escape","Backspace","Delete","ArrowUp","ArrowDown","ArrowLeft","ArrowRight","Home","End","PageUp","PageDown","Space"}`.
  - `MAX_STEPS = 50`, `MAX_SEL = 500`, `MAX_VALUE = 2000`, `MAX_WAIT_MS = 30000`, `MAX_SCROLL_PX = 100000`, `MAX_LABEL = 64`.
  - `validate_steps(raw) -> list[dict]` : `raw` doit être une `list` ; chaque élément un dict **mono-clé** dont la clé ∈ allowlist ; valide la forme/bornes de chaque verbe ; `goto` → `validate_capture_url`. Retourne la liste **normalisée** (verbes canoniques ; ajoute toujours un `{"capture": "final"}` en dernier s'il n'y en a pas déjà un en position finale). Lève `StepValidationError` sinon.
  - `redact_step(step: dict) -> dict` : copie où la `value` d'un `fill` devient `"***"` (pour logs/journal).

- [ ] **Step 1: Write the failing test**

```python
import pytest
from engine.steps import validate_steps, StepValidationError, redact_step, MAX_STEPS

def test_valid_sequence_normalized_with_final_capture():
    raw = [{"click": "#a"}, {"fill": {"sel": "input", "value": "x"}}, {"wait": 1000}]
    out = validate_steps(raw)
    assert out[:3] == raw
    assert out[-1] == {"capture": "final"}  # capture final implicite ajouté

def test_explicit_final_capture_not_duplicated():
    raw = [{"click": "#a"}, {"capture": "fin"}]
    out = validate_steps(raw)
    assert out.count({"capture": "fin"}) == 1 and out[-1] == {"capture": "fin"}

def test_unknown_verb_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"evil": "alert(1)"}])

def test_multikey_step_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"click": "#a", "fill": {"sel": "i", "value": "v"}}])

def test_not_a_list_rejected():
    with pytest.raises(StepValidationError):
        validate_steps({"click": "#a"})

def test_too_many_steps_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"click": "#a"}] * (MAX_STEPS + 1))

def test_selector_too_long_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"click": "a" * 501}])

def test_wait_too_long_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"wait": 30001}])

def test_wait_selector_form_ok():
    assert validate_steps([{"wait": {"selector": ".x"}}])[0] == {"wait": {"selector": ".x"}}

def test_press_not_in_allowlist_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"press": "F1"}])

def test_goto_ssrf_rejected():
    with pytest.raises(StepValidationError):
        validate_steps([{"goto": "http://169.254.169.254/"}])

def test_goto_public_ok():
    assert validate_steps([{"goto": "https://example.com/"}])[0]["goto"] == "https://example.com/"

def test_fill_value_redacted():
    assert redact_step({"fill": {"sel": "i", "value": "secret"}}) == {"fill": {"sel": "i", "value": "***"}}
    assert redact_step({"click": "#a"}) == {"click": "#a"}

def test_label_charset_enforced():
    with pytest.raises(StepValidationError):
        validate_steps([{"capture": "bad<label>"}])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `. .venv/bin/activate && pytest tests/test_steps.py -q`
Expected: FAIL (module `engine.steps` inexistant).

- [ ] **Step 3: Write minimal implementation**

```python
"""DSL d'actions déclaratif borné pour le tier dynamique scripté (3c).
Partagé par le web (validation à la soumission) et le runner (re-validation
défensive avant exécution) — source unique, jamais deux implémentations.
Aucun JS arbitraire, aucun eval : verbes en allowlist stricte."""
import re
from engine.ssrf import validate_capture_url

MAX_STEPS = 50
MAX_SEL = 500
MAX_VALUE = 2000
MAX_WAIT_MS = 30000
MAX_SCROLL_PX = 100000
MAX_LABEL = 64
ALLOWED_PRESS_KEYS = frozenset({
    "Enter", "Tab", "Escape", "Backspace", "Delete",
    "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight",
    "Home", "End", "PageUp", "PageDown", "Space",
})
_LABEL_RE = re.compile(r"[\w .:-]{1,%d}$" % MAX_LABEL)


class StepValidationError(ValueError):
    """Motif de rejet lisible (renvoyé tel quel au client / loggé)."""


def _sel(v):
    if not isinstance(v, str) or not (1 <= len(v) <= MAX_SEL):
        raise StepValidationError(f"sélecteur invalide (str, 1..{MAX_SEL})")
    return v


def _one(step):
    if not isinstance(step, dict) or len(step) != 1:
        raise StepValidationError("chaque step doit être un objet mono-clé")
    (verb, arg), = step.items()
    if verb == "goto":
        if not isinstance(arg, str):
            raise StepValidationError("goto: url str attendue")
        try:
            validate_capture_url(arg)
        except ValueError as e:
            raise StepValidationError(f"goto SSRF/scheme: {e}")
        return {"goto": arg}
    if verb == "fill":
        if not isinstance(arg, dict) or set(arg) != {"sel", "value"}:
            raise StepValidationError("fill: {sel, value} attendu")
        val = arg["value"]
        if not isinstance(val, str) or len(val) > MAX_VALUE:
            raise StepValidationError(f"fill.value invalide (str ≤ {MAX_VALUE})")
        return {"fill": {"sel": _sel(arg["sel"]), "value": val}}
    if verb == "click":
        return {"click": _sel(arg)}
    if verb == "wait":
        if isinstance(arg, bool):
            raise StepValidationError("wait invalide")
        if isinstance(arg, int):
            if not (0 <= arg <= MAX_WAIT_MS):
                raise StepValidationError(f"wait ms 0..{MAX_WAIT_MS}")
            return {"wait": arg}
        if isinstance(arg, dict) and set(arg) == {"selector"}:
            return {"wait": {"selector": _sel(arg["selector"])}}
        raise StepValidationError("wait: ms int ou {selector}")
    if verb == "press":
        if arg not in ALLOWED_PRESS_KEYS:
            raise StepValidationError(f"press hors allowlist: {arg!r}")
        return {"press": arg}
    if verb == "capture":
        if not isinstance(arg, str) or not _LABEL_RE.fullmatch(arg):
            raise StepValidationError("capture: label [\\w .:-] ≤ 64")
        return {"capture": arg}
    if verb == "scroll":
        if arg in ("top", "bottom"):
            return {"scroll": arg}
        if isinstance(arg, int) and not isinstance(arg, bool) and 0 <= arg <= MAX_SCROLL_PX:
            return {"scroll": arg}
        raise StepValidationError("scroll: 'top'|'bottom'|px")
    raise StepValidationError(f"verbe non autorisé: {verb!r}")


def validate_steps(raw):
    if not isinstance(raw, list):
        raise StepValidationError("steps doit être une liste")
    if len(raw) > MAX_STEPS:
        raise StepValidationError(f"trop de steps (max {MAX_STEPS})")
    out = [_one(s) for s in raw]
    # capture final implicite : garantit un screenshot d'état de fin,
    # sauf si le dernier step est déjà un `capture`.
    if not (out and set(out[-1]) == {"capture"}):
        out.append({"capture": "final"})
    return out


def redact_step(step):
    if set(step) == {"fill"}:
        return {"fill": {"sel": step["fill"]["sel"], "value": "***"}}
    return dict(step)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `. .venv/bin/activate && pytest tests/test_steps.py -q`
Expected: PASS (14 tests). Corrige la logique du `capture` final si un cas échoue (l'intention : n'ajouter `{"capture":"final"}` que si le dernier step normalisé n'est pas déjà un `capture`).

- [ ] **Step 5: Commit**

```bash
git add engine/steps.py tests/test_steps.py
git commit -m "feat(3c): DSL d'actions borné + validate_steps (allowlist, bornes, SSRF goto)"
```

---

### Task 2: Exécuteur de steps (runner)

**Files:**
- Create: `runner_recon/steps_exec.py`
- Test: `tests/test_steps_exec.py`

**Interfaces:**
- Consumes: `engine.steps.validate_steps`, `engine.steps.redact_step` ; un objet `page` type Playwright (méthodes async `goto`, `fill`, `click`, `wait_for_timeout`, `wait_for_selector`, `keyboard.press`, `evaluate`, `screenshot`) ; `engine.wrapper` (NetworkCapture déjà armé par l'appelant).
- Produces:
  - `async def run_steps(page, steps, *, screenshot_cb) -> list[dict]` : exécute les steps **déjà validés**, retourne le **journal** `[{index, verb, ok, ms, error?}]` (via `redact_step` pour l'étiquette du verbe — jamais la valeur en clair). À chaque `capture`, appelle `await screenshot_cb(label)` (l'appelant range le PNG dans le résultat). Une erreur sur un step est journalisée (`ok:false, error`) et **arrête** la séquence (les phishings enchaînent ; un step raté invalide la suite) — le journal reflète les steps tentés.
  - `SCROLL_JS = "window.scrollTo(0, {y})"` (constante ; `top`→0, `bottom`→`document.body.scrollHeight`).

- [ ] **Step 1: Write the failing test** (page mockée, pas de vrai navigateur)

```python
import pytest
from runner_recon.steps_exec import run_steps

class FakePage:
    def __init__(self): self.calls = []; self.keyboard = self
    async def goto(self, url, **k): self.calls.append(("goto", url))
    async def fill(self, sel, val, **k): self.calls.append(("fill", sel, val))
    async def click(self, sel, **k): self.calls.append(("click", sel))
    async def wait_for_timeout(self, ms): self.calls.append(("wait_ms", ms))
    async def wait_for_selector(self, sel, **k): self.calls.append(("wait_sel", sel))
    async def press(self, key): self.calls.append(("press", key))
    async def evaluate(self, js): self.calls.append(("eval", js))
    async def screenshot(self, **k): return b"PNG"

@pytest.mark.asyncio
async def test_run_steps_dispatches_each_verb():
    page = FakePage(); shots = []
    async def cb(label): shots.append(label)
    steps = [{"fill": {"sel": "i", "value": "secret"}}, {"click": "#b"},
             {"wait": 500}, {"press": "Enter"}, {"capture": "fin"}]
    journal = await run_steps(page, steps, screenshot_cb=cb)
    assert ("fill", "i", "secret") in page.calls
    assert ("click", "#b") in page.calls
    assert shots == ["fin"]
    # valeur redigée dans le journal
    fill_entry = next(e for e in journal if e["verb"] == "fill")
    assert "secret" not in str(fill_entry)
    assert all(e["ok"] for e in journal)

@pytest.mark.asyncio
async def test_run_steps_stops_on_error():
    class Boom(FakePage):
        async def click(self, sel, **k): raise RuntimeError("no element")
    page = Boom()
    async def cb(label): pass
    journal = await run_steps(page, [{"click": "#x"}, {"fill": {"sel": "i", "value": "v"}}],
                              screenshot_cb=cb)
    assert journal[0]["ok"] is False and "no element" in journal[0]["error"]
    assert len(journal) == 1  # arrêt après l'échec
```

- [ ] **Step 2: Run test to verify it fails**

Run: `. .venv/bin/activate && pytest tests/test_steps_exec.py -q`
Expected: FAIL (module inexistant).

- [ ] **Step 3: Write minimal implementation**

```python
"""Exécuteur de steps 3c côté runner : rejoue une séquence VALIDÉE via l'API
locator Playwright (aucun eval de contenu utilisateur), journalise, déclenche
les screenshots `capture`. La validation vit dans engine.steps (source unique)."""
import time
from engine.steps import redact_step

SCROLL_JS_TOP = "window.scrollTo(0, 0)"
SCROLL_JS_BOTTOM = "window.scrollTo(0, document.body.scrollHeight)"


async def _apply(page, step, screenshot_cb):
    (verb, arg), = step.items()
    if verb == "goto":
        await page.goto(arg, wait_until="networkidle")
    elif verb == "fill":
        await page.fill(arg["sel"], arg["value"])
    elif verb == "click":
        await page.click(arg["sel"])
    elif verb == "wait":
        if isinstance(arg, int):
            await page.wait_for_timeout(arg)
        else:
            await page.wait_for_selector(arg["selector"], timeout=30000)
    elif verb == "press":
        await page.keyboard.press(arg)
    elif verb == "capture":
        await screenshot_cb(arg)
    elif verb == "scroll":
        if arg == "top":
            await page.evaluate(SCROLL_JS_TOP)
        elif arg == "bottom":
            await page.evaluate(SCROLL_JS_BOTTOM)
        else:
            await page.evaluate(f"window.scrollTo(0, {int(arg)})")


async def run_steps(page, steps, *, screenshot_cb):
    journal = []
    for i, step in enumerate(steps):
        verb = next(iter(step))
        t0 = time.monotonic()
        try:
            await _apply(page, step, screenshot_cb)
            journal.append({"index": i, "verb": verb, "ok": True,
                            "ms": int((time.monotonic() - t0) * 1000),
                            "step": redact_step(step)})
        except Exception as e:  # noqa: BLE001 — journalise et arrête
            journal.append({"index": i, "verb": verb, "ok": False,
                            "ms": int((time.monotonic() - t0) * 1000),
                            "error": str(e)[:200], "step": redact_step(step)})
            break
    return journal
```

Note : `time.monotonic` est autorisé dans le runner (process réel) — pas dans un workflow. Ajoute `pytest-asyncio` si absent (`pyproject.toml`, section test) et le marqueur `asyncio_mode = "auto"` ou décore avec `@pytest.mark.asyncio`.

- [ ] **Step 4: Run test to verify it passes**

Run: `. .venv/bin/activate && pytest tests/test_steps_exec.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add runner_recon/steps_exec.py tests/test_steps_exec.py pyproject.toml
git commit -m "feat(3c): exécuteur de steps runner (locator API, journal redigé, screenshots capture)"
```

---

### Task 3: Mode scripté du runner (stdin) + intégration réelle

**Files:**
- Modify: `runner_recon/__main__.py` (ou l'entrypoint Python du runner recon — repérer comment 3a lit `url`/émet le wrapper ; y ajouter le mode scripté)
- Test: `tests/test_runner_scripted_integration.py` (marqueur `integration`)

**Interfaces:**
- Consumes: stdin = JSON `{"url": str, "steps": [...]}` quand présent ; `engine.steps.validate_steps`, `runner_recon.steps_exec.run_steps`, `engine.wrapper` (NetworkCapture/ResultBuilder/emit_wrapper), le lancement Camoufox de 3a.
- Produces: sur stdin `{url, steps}` → le runner : `validate_steps` (défense en profondeur), `goto(url)`, arme NetworkCapture, `run_steps` (screenshots `capture` rangés comme blobs référencés dans le résultat), `emit_wrapper` d'un `OcularResult` dont le champ **existant `dynamic_steps: list[DynamicStep]`** porte le journal, avec les screenshots labellisés. Sans steps sur stdin → comportement 3a **inchangé**.

**Réutilisation schéma (IMPORTANT)** : `engine/result.py` possède DÉJÀ `DynamicStep {action, screenshot_ref, triggered_requests}` et `OcularResult.dynamic_steps` — conçus pour ce tier. **NE PAS** créer un champ `actions`. À la place :
- Étendre `DynamicStep` avec 3 champs optionnels rétro-compatibles : `ok: bool = True`, `duration_ms: Optional[int] = None`, `error: Optional[str] = None` (portent l'issue d'exécution du journal `run_steps`).
- Ajouter à `ResultBuilder.build(...)` un paramètre `dynamic_steps: Optional[list] = None` qui alimente `OcularResult.dynamic_steps` (comme les autres champs optionnels).
- Mapper chaque entrée du journal `run_steps` → un `DynamicStep` : `action` = description redigée du step (`str(redact_step(step))` ou un libellé lisible), `ok`/`duration_ms`/`error` depuis le journal, `screenshot_ref` = le ref du PNG pour un step `capture`.

**Détail d'implémentation** : dans `runner_recon/capture.py`, `main()` lit `--url` via argparse. Ajouter : lire stdin ; si non vide et JSON `{url, steps}` valide → mode scripté (`capture_scripted(url, steps)`), sinon 3a (`capture_url`) inchangé. Écrire une fonction `capture_scripted` calquée sur `capture_url` (Camoufox headed, `capture.attach(page)`, `goto(url)`) mais qui appelle `run_steps(page, validate_steps(steps), screenshot_cb=...)`. Le `screenshot_cb(label)` fait `png = await page.screenshot()`, l'ajoute via `builder.add_screenshot(idx, label, png)` (réutilise l'API existante, qui retourne le `screenshot_ref`), et le cb mémorise le ref pour l'attacher au `DynamicStep` du step `capture`. Réutiliser `build_result`/`ResultBuilder` (ne pas refaire la structure du résultat à la main).

- [ ] **Step 1: Write the failing integration test**

```python
import json, subprocess, pytest

pytestmark = pytest.mark.integration

def test_scripted_run_captures_post_click_call(tmp_path):
    # page fixture servie localement qui ne fait un fetch qu'APRÈS un clic
    # (le test monte un petit serveur http fixture, passe {url, steps} sur stdin
    #  du conteneur runner_recon, et vérifie que le résultat contient :
    #   - un screenshot labellisé 'apres'
    #   - une entrée réseau vers /beacon (déclenchée par le clic)
    #   - un journal d'actions cohérent)
    ...  # implémenter avec le harnais docker des autres tests d'intégration
```

Écris ce test en suivant EXACTEMENT le pattern des tests d'intégration existants (`tests/test_deploy_images.py` / tout test qui `docker run` un runner). Sers une page fixture (ex. `http.server` sur un réseau que le conteneur atteint, ou via `set_content` d'un HTML inline qui `fetch('/beacon')` au clic). Steps : `[{"click":"#go"},{"wait":500},{"capture":"apres"}]`.

- [ ] **Step 2: Run test to verify it fails**

Run: `. .venv/bin/activate && pytest tests/test_runner_scripted_integration.py -q -m integration`
Expected: FAIL (mode scripté pas encore câblé).

- [ ] **Step 3: Implémenter le mode scripté dans l'entrypoint runner**

Câbler la lecture stdin + bascule, en réutilisant `validate_steps`/`run_steps`/`ResultBuilder`/`emit_wrapper`. Garder le chemin 3a intact (aucun step → identique).

- [ ] **Step 4: Build + run integration**

```bash
docker build -f runner_recon/Dockerfile -t ocular-runner-recon:latest .
. .venv/bin/activate && pytest tests/test_runner_scripted_integration.py -q -m integration
```
Expected: PASS — screenshot `apres` présent, appel `/beacon` capté, journal cohérent.

- [ ] **Step 5: Commit**

```bash
git add runner_recon/ tests/test_runner_scripted_integration.py
git commit -m "feat(3c): mode scripté runner (stdin {url,steps}) — post-interaction capté, 3a inchangé"
```

---

### Task 4: Broker — chemin job scripté

**Files:**
- Modify: `broker/launcher.py` (là où `build_docker_args`/`run_job` gèrent le profil capture)
- Modify: `broker/main.py` (si le passage du payload steps au launcher le nécessite)
- Test: `tests/test_launcher_scripted.py`

**Interfaces:**
- Consumes: le job Redis capture peut porter `steps` (liste déjà validée par le web) ; `build_docker_args` (profil capture) existant.
- Produces:
  - `build_docker_args` inchangé pour la commande, mais le lancement scripté utilise `docker run --rm -i` et **écrit `{url, steps}` (JSON) sur le stdin** du conteneur (pas d'env/arg). Le durcissement 3a (non-root, cap-drop, seccomp-recon, réseau ON, mem/pids, timeout) est **réutilisé tel quel**. Sans `steps` → chemin 3a inchangé (pas de `-i`, pas de stdin).
  - Une fonction testable qui, pour un job avec `steps`, produit (a) les args docker incluant `-i` et (b) le payload stdin `{url, steps}` — pour pouvoir asserter **sans** Docker.

- [ ] **Step 1: Write the failing test**

```python
from broker.launcher import build_docker_args  # + helper scripté à créer

def test_scripted_job_uses_stdin_not_env():
    args, stdin_payload = build_scripted_run("https://example.com", [{"click": "#a"}, {"capture": "final"}])
    assert "-i" in args
    joined = " ".join(args)
    # la valeur/les steps ne fuitent PAS dans les args (donc absents de docker inspect)
    assert "#a" not in joined and "click" not in joined
    import json
    assert json.loads(stdin_payload) == {"url": "https://example.com",
                                         "steps": [{"click": "#a"}, {"capture": "final"}]}
    # durcissement 3a préservé
    assert "--rm" in args and "--network" in args and "--cap-drop" in args

def test_capture_without_steps_unchanged():
    # le chemin 3a ne prend pas -i ni stdin
    args = build_docker_args_capture("https://example.com")  # nom réel de l'API 3a
    assert "-i" not in args
```

Adapter les noms aux fonctions réelles de `broker/launcher.py`. L'important : (1) `-i` + stdin pour scripté, (2) steps **absents** des args, (3) durcissement 3a réutilisé, (4) chemin sans-steps intact.

- [ ] **Step 2: Run test to verify it fails**

Run: `. .venv/bin/activate && pytest tests/test_launcher_scripted.py -q`
Expected: FAIL.

- [ ] **Step 3: Implémenter le helper scripté** (réutilise `base_hardening`/`build_docker_args`, ajoute `-i` + renvoie le payload stdin ; `run_job` passe le payload via `subprocess ... input=stdin_payload`).

- [ ] **Step 4: Run test to verify it passes**

Run: `. .venv/bin/activate && pytest tests/test_launcher_scripted.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add broker/ tests/test_launcher_scripted.py
git commit -m "feat(3c): broker chemin scripté (docker run --rm -i, steps sur stdin, durci 3a réutilisé)"
```

---

### Task 5: Web — `POST /jobs` accepte `steps`

**Files:**
- Modify: `web/app.py` (handler de soumission de job capture), `web/models.py` (modèle de requête)
- Test: `tests/test_web_scripted.py`

**Interfaces:**
- Consumes: `engine.steps.validate_steps` ; le flux d'enqueue capture existant.
- Produces:
  - Le modèle de requête capture accepte `steps: list | None`. Si `steps` présent : `validate_steps` **côté serveur** (SSRF sur url + chaque `goto` couverts par `validate_steps`) ; invalide → **422** (motif = message de `StepValidationError`). La liste normalisée (avec `capture` final) est enqueue dans le job. Sans `steps` → 3a inchangé.
  - Le résultat renvoyé au client expose `dynamic_steps` (journal) + screenshots labellisés (via le mécanisme d'artefacts existant, DOM jamais inline).

- [ ] **Step 1: Write the failing test**

```python
from fastapi.testclient import TestClient
from web.app import app
client = TestClient(app)
H = {"Authorization": "Bearer test-token"}  # aligner sur le fixture d'auth existant

def test_submit_with_valid_steps_enqueues(monkeypatch):
    captured = {}
    monkeypatch.setattr("web.app.enqueue_job", lambda job: captured.update(job) or "job-1")  # nom réel
    r = client.post("/jobs", json={"url": "https://example.com", "profile": "capture",
                                   "steps": [{"click": "#a"}]}, headers=H)
    assert r.status_code == 200
    assert captured["steps"][-1] == {"capture": "final"}  # normalisé

def test_submit_with_ssrf_goto_rejected():
    r = client.post("/jobs", json={"url": "https://example.com", "profile": "capture",
                                   "steps": [{"goto": "http://127.0.0.1/"}]}, headers=H)
    assert r.status_code == 422

def test_submit_with_oversize_steps_rejected():
    r = client.post("/jobs", json={"url": "https://example.com", "profile": "capture",
                                   "steps": [{"click": "#a"}] * 51}, headers=H)
    assert r.status_code == 422

def test_submit_without_steps_unchanged(monkeypatch):
    captured = {}
    monkeypatch.setattr("web.app.enqueue_job", lambda job: captured.update(job) or "job-2")
    r = client.post("/jobs", json={"url": "https://example.com", "profile": "capture"}, headers=H)
    assert r.status_code == 200 and "steps" not in captured
```

Aligner les noms (`enqueue_job`, route `/jobs`, fixture token) sur le code réel de `web/app.py`.

- [ ] **Step 2: Run test to verify it fails**

Run: `. .venv/bin/activate && pytest tests/test_web_scripted.py -q`
Expected: FAIL.

- [ ] **Step 3: Implémenter** (modèle `steps` optionnel ; `validate_steps` dans le handler ; `StepValidationError` → `HTTPException(422, detail=str(e))` ; enqueue la liste normalisée).

- [ ] **Step 4: Run test to verify it passes**

Run: `. .venv/bin/activate && pytest tests/test_web_scripted.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/ tests/test_web_scripted.py
git commit -m "feat(3c): web POST /jobs accepte steps (validate_steps serveur, 422 borné, 3a inchangé)"
```

---

### Task 6: UI — formulaire scripté + rendu du journal

**Files:**
- Modify: `web/ui/index.html`, `web/ui/style.css`, `web/ui/i18n.js`, `web/ui/api.js`, une vue (`web/ui/views/…`) et/ou `web/ui/core.js`
- Test: `tests/test_ui_smoke.py` (étendre le smoke existant)

**Interfaces:**
- Consumes: `POST /jobs` avec `steps` ; le rendu de résultat existant.
- Produces: un champ « script » (textarea JSON) sur le formulaire capture, avec 1–2 **exemples** insérables et un **retour de validation** (parse JSON client + message d'erreur serveur 422 affiché proprement) ; le rendu du résultat affiche le **journal d'actions** (depuis `dynamic_steps` : action/ok/duration_ms/error, valeurs déjà redigées côté serveur) et la **galerie de screenshots labellisés**. **XSS-clean** : tout texte via `textContent`/équivalent, jamais `innerHTML` de contenu non fiable (labels, erreurs, journal).

- [ ] **Step 1: Write the failing smoke test** (étend le smoke : la page contient le champ script + les i18n keys ; le JS ne fait pas d'`innerHTML` sur le journal).

```python
def test_scripted_form_present():
    html = open("web/ui/index.html").read()
    assert "steps" in html.lower() or "script" in html.lower()

def test_no_innerhtml_on_untrusted_journal():
    js = open("web/ui/views/... .js").read()  # la vue du résultat
    # le journal/labels passent par textContent (pas d'innerHTML brut)
    assert ".innerHTML" not in js or "actions" not in js.split(".innerHTML")[0][-200:]
```

Adapter au smoke réel. Idée : vérifier la présence du champ + l'absence d'injection.

- [ ] **Step 2: Run to verify it fails**

Run: `. .venv/bin/activate && pytest tests/test_ui_smoke.py -q`
Expected: FAIL.

- [ ] **Step 3: Implémenter** la vue/le formulaire (design plume, accent `#8b5cf6`), i18n FR, rendu XSS-clean du journal + galerie.

- [ ] **Step 4: Run to verify it passes**

Run: `. .venv/bin/activate && pytest tests/test_ui_smoke.py -q`
Expected: PASS. Vérif navigateur manuelle notée dans le rapport.

- [ ] **Step 5: Commit**

```bash
git add web/ui/ tests/test_ui_smoke.py
git commit -m "feat(3c): UI formulaire scripté + journal d'actions/galerie XSS-clean"
```

---

### Task 7: Ops — Makefile, README, garde images

**Files:**
- Modify: `Makefile`, `README.md`, `tests/test_deploy_images.py` (confirmer : aucune image nouvelle, réutilise `runner_recon`)
- Test: `tests/test_deploy_images.py`

**Interfaces:**
- Produces: cible `make script URL=… STEPS=…` (STEPS = chemin d'un fichier JSON de steps) qui soumet un job scripté ; section README « Tier dynamique scripté (3c) » (usage, DSL, sécu, exemple) ; le guard `test_deploy_images` reste vert (5 images inchangées ; 3c n'ajoute pas d'image).

- [ ] **Step 1: Failing test** (assert la cible `script:` dans le Makefile et la section README).

```python
def test_makefile_has_script_target():
    assert "\nscript:" in open("Makefile").read()

def test_readme_documents_3c():
    r = open("README.md").read().lower()
    assert "scripté" in r or "dynamic" in r or "steps" in r
```

- [ ] **Step 2: Run to verify it fails.** `pytest tests/test_deploy_images.py -q` (+ les 2 asserts ci-dessus où tu les places).

- [ ] **Step 3: Implémenter** la cible Makefile + la doc README + confirmer le guard images.

- [ ] **Step 4: Run to verify it passes.**

- [ ] **Step 5: Commit**

```bash
git add Makefile README.md tests/
git commit -m "docs(3c): make script + README tier dynamique scripté + guard images"
```

---

### Task 8: Audit indépendant + e2e réel + merge

- [ ] Dispatch **3 auditeurs** (archi/sécu/qualité) sur le diff de branche (`scripts/review-package $(git merge-base main HEAD) HEAD`) : chercher DSL contournable (verbe/`eval` caché, injection sélecteur, borne manquante), fuite des valeurs `fill` (env/inspect/logs/journal), SSRF `goto` manquée, divergence des deux `validate_steps`, monolithe/répétition, chemin 3a régressé.
- [ ] Remédier Critical/Important (un fix-agent, liste complète).
- [ ] **e2e réel** : `docker compose up`, `make script` (page fixture qui beacone au clic) → résultat montre journal + screenshots + **appel post-clic** ; `goto` SSRF bloqué (422) ; steps > 50 rejetés (422) ; `docker inspect` du conteneur runner **ne montre pas** les valeurs `fill` ; conteneur bien `--rm` (aucun orphelin) ; suite complète verte.
- [ ] Revue finale de branche (agent le plus capable) → si findings, UN fix-agent.
- [ ] Merge via **finishing-a-development-branch** (option 1, merge local no-ff sur main), supprimer la branche, mettre à jour la mémoire projet.

---

## Self-review (plan vs spec)
- **Couverture** : DSL+validateur (T1) ✓ ; exécuteur (T2) ✓ ; runner mode scripté+intégration (T3) ✓ ; broker stdin (T4) ✓ ; web validation serveur (T5) ✓ ; UI (T6) ✓ ; ops+doc (T7) ✓ ; audit+e2e+merge (T8) ✓. Toutes les décisions C1–C6 mappées.
- **Placeholders** : les seuls « … » sont dans le test d'intégration T3 (harnais docker à copier du pattern existant) et les noms d'API à aligner (`enqueue_job`, entrypoint runner) — signalés explicitement à l'implémenteur, pas des trous de logique.
- **Cohérence des types** : `validate_steps(raw)->list[dict]`, `run_steps(page, steps, *, screenshot_cb)->list[dict]`, `redact_step(step)->dict` cohérents T1↔T2↔T3↔T5. Bornes identiques partout (Global Constraints). `{"capture":"final"}` implicite défini en T1, consommé en T3/T5.
