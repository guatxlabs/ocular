# Couche IA/ML de triage — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ajouter à Ocular un score de triage 0-100 décomposable + un 2e avis qui complète (jamais n'écrase) le verdict règles, avec tri/filtre des Sauvegardes, une calibration ML hors-ligne, et une option LLM d'explication off par défaut.

**Architecture:** Un scoreur linéaire transparent pur-Python (`engine/triage.py`) lit les features déjà présentes dans `OcularResult` et produit un bloc `triage`. Il est calculé **une seule fois**, dans `ResultBuilder.build()` (qui reçoit déjà findings/verdict/network/console/dom) — donc aucun des 4 sites appelant `compute_verdict` n'est modifié individuellement. La persistance dénormalise `triage_score/band` en colonnes SQLite indexées ; un CLI hors-ligne calibre les poids par régression logistique numpy.

**Tech Stack:** Python 3 / pydantic (moteur), FastAPI (web), SQLite (`saved_store`), JS ES-modules vanilla (`web/ui`), numpy (calibration hors-ligne uniquement), pytest + node (tests), Docker (`make test`).

## Global Constraints

- **Pur-Python, 0 dépendance runtime ajoutée** au scoring (numpy autorisé UNIQUEMENT dans le CLI de calibration hors-ligne).
- **`engine/verdict.py::compute_verdict` n'est JAMAIS modifié ni écrasé.** Le triage est un calcul parallèle.
- **Aucun egress au scoring ni à la calibration.** Seul egress possible = option LLM, opt-in strict via garde egress existante.
- **Fail-safe** : poids illisibles/malformés → fallback `BUILTIN` + signal `weights_load_error` (jamais de crash).
- **Rétro-compatibilité** : `triage` est `Optional` (comme `stealth`) ; un `OcularResult` sans triage reste valide ; une sauvegarde pré-triage reste listable.
- **UI** : tout rendu en `el()`/`textContent`, jamais `innerHTML`.
- **Tests Dockerisés** : cycle rapide `. .venv/bin/activate && pytest tests/<f>.py -q` ; validation finale `make test`.
- **Commits** : conventional-commits FR sur `main` (pas de remote → pas de push), trailer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Ne jamais committer `deploy/.env` ni de cache.

---

## Structure des fichiers

**Tranche 1 — socle moteur**
- Créer `engine/triage_weights.py` — dict `BUILTIN` (poids/seuils), seul point de réglage.
- Créer `engine/triage.py` — extracteurs de signaux + `load_weights()` + `compute_triage()`.
- Modifier `engine/result.py` — modèles `TriageSignal`, `Triage`, champ `OcularResult.triage`.
- Modifier `engine/wrapper.py:98` — `ResultBuilder.build()` calcule `triage` depuis ses params.
- Tests : `tests/test_triage.py`.

**Tranche 2 — persistance + API + UI**
- Modifier `saved_store.py` — colonnes `triage_score/triage_band`, `save()`, `_META_COLUMNS`.
- Modifier `web/app.py:709` — `GET /saved` params `sort/order/min_band` validés + SQL.
- Modifier `saved_store.py::list_all` — signature avec tri/filtre.
- Créer `web/ui/triage.js` — `triagePanel()` partagé.
- Modifier `web/ui/views/saved.js` + la vue résultat (job/saved) pour intégrer le panneau + le contrôle de tri.
- Tests : ajouts dans `tests/test_saved_store.py`, `tests/test_saved_api.py`, `tests/triage_test.mjs` + `tests/test_triage_js.py`.

**Tranche 3 — calibration hors-ligne**
- Créer `tools/calibrate_triage.py` — replay features + régression logistique numpy + garde-fous + rapport.
- Modifier `Makefile` — cible `calibrate` (conteneur jetable).
- Tests : `tests/test_calibrate.py`.

**Tranche 4 — option LLM (isolée, dernière)**
- Modifier `ocular_settings.py` — accès aux env LLM.
- Modifier `web/app.py` — `POST /jobs/{id}/explain` (garde egress).
- Modifier la vue résultat — bouton « Expliquer avec LLM ».
- Tests : ajouts `tests/test_web_api.py`.

---

# TRANCHE 1 — Socle moteur

### Task 1 : Modèles `Triage` (rétro-compatibles)

**Files:**
- Modify: `engine/result.py` (après `class StealthInfo`, avant `class Artifacts`)
- Test: `tests/test_triage.py` (créé ici)

**Interfaces:**
- Produces: `TriageSignal(key:str, label:str, weight:float, detail:str="")` ; `Triage(score:int, band:Literal["low","medium","high"], second_opinion:Verdict, agrees_with_rules:bool, signals:list[TriageSignal], weights_version:str)` ; `OcularResult.triage: Optional[Triage] = None`.

- [ ] **Step 1: Écrire le test rétro-compat + construction**

Créer `tests/test_triage.py` :
```python
from engine.result import OcularResult, Triage, TriageSignal


def _minimal_result(**kw):
    base = dict(job_id="j", profile="analysis", target="t", timestamp="2026-01-01T00:00:00Z")
    base.update(kw)
    return OcularResult(**base)


def test_result_without_triage_is_valid():
    r = _minimal_result()
    assert r.triage is None


def test_result_with_triage_roundtrips():
    tri = Triage(
        score=72, band="high", second_opinion="suspicious", agrees_with_rules=False,
        signals=[TriageSignal(key="k", label="L", weight=35.0, detail="d")],
        weights_version="builtin-1",
    )
    r = _minimal_result(triage=tri)
    dumped = r.model_dump(mode="json")
    again = OcularResult(**dumped)
    assert again.triage.score == 72
    assert again.triage.signals[0].weight == 35.0
```

- [ ] **Step 2: Lancer le test — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_triage.py -q`
Expected: FAIL — `ImportError: cannot import name 'Triage'`

- [ ] **Step 3: Ajouter les modèles**

Dans `engine/result.py`, insérer après `class StealthInfo` (ligne ~73) :
```python
class TriageSignal(BaseModel):
    key: str
    label: str
    weight: float
    detail: str = ""


class Triage(BaseModel):
    """2e avis natif, parallèle au verdict règles (jamais un écrasement).
    `score` 0-100 = priorité « à regarder » ; sa décomposition intégrale est
    dans `signals` (Σ des weight affichés == score). `weights_version` trace le
    jeu de poids (BUILTIN ou calibré) ayant produit ce score."""
    score: int
    band: Literal["low", "medium", "high"]
    second_opinion: Verdict
    agrees_with_rules: bool
    signals: list[TriageSignal] = Field(default_factory=list)
    weights_version: str
```
Puis, dans `class OcularResult`, ajouter après `stealth: Optional[StealthInfo] = None` :
```python
    triage: Optional[Triage] = None
```

- [ ] **Step 4: Lancer le test — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_triage.py -q`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**
```bash
git add engine/result.py tests/test_triage.py
git commit -m "feat(triage): modèles Triage/TriageSignal + champ OcularResult.triage (rétro-compat)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2 : Poids par défaut `BUILTIN`

**Files:**
- Create: `engine/triage_weights.py`
- Test: `tests/test_triage.py` (ajout)

**Interfaces:**
- Produces: `BUILTIN: dict` avec clés `version:str`, `base:int`, `bands:{"medium":int,"high":int}`, `signals:{key:(poids:float, label:str)}`.

- [ ] **Step 1: Écrire le test de forme**

Ajouter à `tests/test_triage.py` :
```python
from engine.triage_weights import BUILTIN


def test_builtin_shape():
    assert BUILTIN["version"] == "builtin-1"
    assert 0 <= BUILTIN["bands"]["medium"] < BUILTIN["bands"]["high"] <= 100
    for key, (weight, label) in BUILTIN["signals"].items():
        assert isinstance(key, str) and isinstance(weight, (int, float))
        assert isinstance(label, str) and label
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_triage.py::test_builtin_shape -q`
Expected: FAIL — `ModuleNotFoundError: engine.triage_weights`

- [ ] **Step 3: Créer le fichier de poids**

Créer `engine/triage_weights.py` :
```python
"""Poids par défaut du scoreur de triage (engine/triage.py). SEUL point de
réglage des poids/seuils : éditable à la main, versionné en Git. Un jeu calibré
(tools/calibrate_triage.py) a la même forme et remplace celui-ci via
OCULAR_TRIAGE_WEIGHTS. Poids calés sur la logique de engine/verdict.py."""

BUILTIN = {
    "version": "builtin-1",
    "base": 5,
    "bands": {"medium": 40, "high": 70},  # score < medium -> low ; >= high -> high
    "signals": {
        # clé -> (poids, libellé FR)
        "obfuscation_cluster":   (35.0, "Cluster d'obfuscation/exécution"),
        "obfuscation_single":    (18.0, "Obfuscation isolée"),
        "cred_and_urgency":      (25.0, "Identifiants + langage d'urgence"),
        "cred_external_form":    (22.0, "Identifiants postés vers un domaine externe"),
        "external_form":         (10.0, "Formulaire vers action externe"),
        "mailto_exfil":          (12.0, "Exfiltration par mailto:"),
        "high_severity_finding": (15.0, "Finding de sévérité haute"),
        "many_third_parties":    (8.0,  "Nombreux tiers réseau"),
        "console_errors":        (4.0,  "Erreurs console"),
        "redirect_chain":        (6.0,  "Chaîne de redirections"),
    },
}

# Seuil (nombre d'hôtes réseau distincts) au-delà duquel `many_third_parties`
# se déclenche. Ici (pas dans BUILTIN) car c'est un paramètre d'extraction, pas
# un poids calibrable.
MANY_THIRD_PARTIES_THRESHOLD = 10
```

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_triage.py::test_builtin_shape -q`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add engine/triage_weights.py tests/test_triage.py
git commit -m "feat(triage): poids/seuils par défaut BUILTIN (point de réglage unique)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3 : Extracteurs + `load_weights` + `compute_triage`

**Files:**
- Create: `engine/triage.py`
- Test: `tests/test_triage.py` (ajout)

**Interfaces:**
- Consumes: `engine.verdict._OBF/_CRED/_URGENCY` (clusters existants) ; `engine.triage_weights.BUILTIN`, `MANY_THIRD_PARTIES_THRESHOLD` ; `engine.result.StaticFinding/DomInfo/Triage/TriageSignal`.
- Produces: `extract_signals(findings, network, console, dom) -> dict[str,(bool,str)]` ; `load_weights() -> tuple[dict, str|None]` (poids, message d'erreur ou None) ; `compute_triage(findings, *, verdict, network=None, console=None, dom=None, weights=None) -> Triage`.

- [ ] **Step 1: Écrire les tests de comportement**

Ajouter à `tests/test_triage.py` :
```python
import json
from engine.result import DomInfo, StaticFinding
from engine.triage import compute_triage, extract_signals, load_weights


def _rf(rule, sev="low"):
    return StaticFinding(rule=rule, severity=sev, match="m", line=1, context="c")


def test_benign_low_score():
    tri = compute_triage([], verdict="benign")
    assert tri.band == "low"
    assert tri.second_opinion == "benign"
    assert tri.agrees_with_rules is True


def test_score_decomposition_equals_sum():
    # Σ des contributions affichées == score (invariant « explicite »).
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium"),
                _rf("Password input field"), _rf("Account verification text", "medium")]
    tri = compute_triage(findings, verdict="malicious")
    assert sum(round(s.weight) for s in tri.signals) == tri.score


def test_signals_sorted_by_abs_weight_desc():
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium"),
                _rf("External form action", "medium")]
    tri = compute_triage(findings, verdict="suspicious")
    weights = [abs(s.weight) for s in tri.signals if s.key != "base"]
    assert weights == sorted(weights, reverse=True)


def test_obfuscation_cluster_high_band():
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium")]
    tri = compute_triage(findings, verdict="malicious")
    assert tri.band == "high"
    assert tri.second_opinion == "malicious"


def test_diverges_when_rules_benign_but_score_high():
    # Règles=benign mais faisceau fort -> 2e avis diverge (badge « à revoir »).
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium")]
    tri = compute_triage(findings, verdict="benign")
    assert tri.second_opinion == "malicious"
    assert tri.agrees_with_rules is False


def test_mailto_and_redirect_signals():
    dom = DomInfo(mailtos=["a@evil.tld"], redirect_chain=["u1", "u2", "u3"])
    sig = extract_signals([], network=[], console=[], dom=dom)
    assert sig["mailto_exfil"][0] is True
    assert sig["redirect_chain"][0] is True


def test_many_third_parties_signal():
    net = [{"url": f"https://h{i}.tld/x"} for i in range(12)]
    sig = extract_signals([], network=net, console=[], dom=DomInfo())
    assert sig["many_third_parties"][0] is True
    assert "12" in sig["many_third_parties"][1]


def test_console_errors_signal():
    sig = extract_signals([], network=[], console=[{"level": "error", "text": "x"}], dom=DomInfo())
    assert sig["console_errors"][0] is True


def test_load_weights_default_is_builtin():
    weights, err = load_weights()
    assert weights["version"] == "builtin-1" and err is None


def test_load_weights_malformed_falls_back(tmp_path, monkeypatch):
    bad = tmp_path / "w.json"
    bad.write_text("{ not json")
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(bad))
    weights, err = load_weights()
    assert weights["version"] == "builtin-1"
    assert err is not None


def test_malformed_weights_surface_error_signal(tmp_path, monkeypatch):
    bad = tmp_path / "w.json"
    bad.write_text("{ not json")
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(bad))
    tri = compute_triage([], verdict="benign")
    assert any(s.key == "weights_load_error" for s in tri.signals)


def test_calibrated_weights_override(tmp_path, monkeypatch):
    good = tmp_path / "w.json"
    good.write_text(json.dumps({
        "version": "calibrated-2026-07-18", "base": 0,
        "bands": {"medium": 40, "high": 70},
        "signals": {"external_form": [50.0, "Formulaire externe"]},
    }))
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(good))
    tri = compute_triage([_rf("External form action", "medium")], verdict="suspicious")
    assert tri.weights_version == "calibrated-2026-07-18"
    assert tri.score == 50
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_triage.py -q`
Expected: FAIL — `ModuleNotFoundError: engine.triage`

- [ ] **Step 3: Implémenter `engine/triage.py`**

Créer `engine/triage.py` :
```python
from __future__ import annotations

import json
import os
from typing import Any, Optional
from urllib.parse import urlparse

from engine.result import DomInfo, StaticFinding, Triage, TriageSignal, Verdict
from engine.triage_weights import BUILTIN, MANY_THIRD_PARTIES_THRESHOLD
from engine.verdict import _CRED, _OBF, _URGENCY


def _network_hosts(network: list[dict[str, Any]]) -> set[str]:
    hosts = set()
    for n in network or []:
        try:
            h = urlparse(n.get("url", "")).hostname
        except ValueError:
            h = None
        if h:
            hosts.add(h)
    return hosts


def extract_signals(
    findings: list[StaticFinding],
    network: list[dict[str, Any]],
    console: list[dict[str, Any]],
    dom: DomInfo,
) -> dict[str, tuple[bool, str]]:
    """Un signal par clé -> (présent, detail). Source unique des features,
    rejouée à l'identique par la calibration (pas de dérive train/serve)."""
    rules = {f.rule for f in findings}
    severities = {f.severity for f in findings}
    obf = _OBF & rules
    cred = bool(_CRED & rules)
    urgency = bool(_URGENCY & rules)
    ext_form = "External form action" in rules
    hosts = _network_hosts(network)
    n_err = sum(1 for c in (console or []) if str(c.get("level")) == "error")
    n_redir = len(dom.redirect_chain) if dom else 0

    return {
        "obfuscation_cluster":   (len(obf) >= 2, f"{len(obf)} patterns d'obfuscation" if obf else ""),
        "obfuscation_single":    (len(obf) == 1, "1 pattern d'obfuscation" if len(obf) == 1 else ""),
        "cred_and_urgency":      (cred and urgency, "identifiants + urgence" if cred and urgency else ""),
        "cred_external_form":    (cred and ext_form, "identifiants + form externe" if cred and ext_form else ""),
        "external_form":         (ext_form, "action de formulaire externe" if ext_form else ""),
        "mailto_exfil":          (bool(dom and dom.mailtos), f"{len(dom.mailtos)} mailto:" if dom and dom.mailtos else ""),
        "high_severity_finding": ("high" in severities, "finding sévérité haute" if "high" in severities else ""),
        "many_third_parties":    (len(hosts) > MANY_THIRD_PARTIES_THRESHOLD, f"{len(hosts)} hôtes distincts" if hosts else ""),
        "console_errors":        (n_err > 0, f"{n_err} erreurs console" if n_err else ""),
        "redirect_chain":        (n_redir > 1, f"{n_redir} sauts" if n_redir > 1 else ""),
    }


def load_weights() -> tuple[dict, Optional[str]]:
    """Poids depuis OCULAR_TRIAGE_WEIGHTS (JSON) sinon BUILTIN. Fichier
    absent-mais-configuré / illisible / malformé -> BUILTIN + message d'erreur
    (jamais d'exception : fail-safe)."""
    path = os.environ.get("OCULAR_TRIAGE_WEIGHTS", "").strip()
    if not path:
        return BUILTIN, None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        # validation minimale de forme
        assert isinstance(data["version"], str)
        assert isinstance(data["base"], (int, float))
        assert {"medium", "high"} <= set(data["bands"])
        assert isinstance(data["signals"], dict)
        return data, None
    except Exception as exc:  # noqa: BLE001 — fail-safe volontaire
        return BUILTIN, f"{type(exc).__name__}: {exc}"


def _band(score: int, bands: dict) -> str:
    if score >= bands["high"]:
        return "high"
    if score >= bands["medium"]:
        return "medium"
    return "low"


def _second_opinion(band: str) -> Verdict:
    return {"high": "malicious", "medium": "suspicious", "low": "benign"}[band]


def compute_triage(
    findings: list[StaticFinding],
    *,
    verdict: str,
    network: Optional[list[dict[str, Any]]] = None,
    console: Optional[list[dict[str, Any]]] = None,
    dom: Optional[DomInfo] = None,
    weights: Optional[dict] = None,
) -> Triage:
    load_err = None
    if weights is None:
        weights, load_err = load_weights()
    dom = dom or DomInfo()
    signals_present = extract_signals(findings, network or [], console or [], dom)

    sig_weights = weights["signals"]
    base = float(weights["base"])
    contributions: list[TriageSignal] = [
        TriageSignal(key="base", label="base", weight=base, detail="")
    ]
    for key, (present, detail) in signals_present.items():
        if present and key in sig_weights:
            w, label = sig_weights[key][0], sig_weights[key][1]
            contributions.append(TriageSignal(key=key, label=label, weight=float(w), detail=detail))

    if load_err:
        contributions.append(TriageSignal(
            key="weights_load_error", label="poids par défaut (fichier illisible)",
            weight=0.0, detail=load_err[:200]))

    raw = sum(round(c.weight) for c in contributions)
    score = max(0, min(100, raw))
    # garde l'invariant Σ==score après clamp : ajuste la contribution base.
    if raw != score:
        contributions[0].weight += (score - raw)

    band = _band(score, weights["bands"])
    second = _second_opinion(band)
    # tri : base en tête reste informatif ; les signaux par |poids| desc.
    signals_sorted = [contributions[0]] + sorted(
        contributions[1:], key=lambda s: abs(s.weight), reverse=True)
    return Triage(
        score=score, band=band, second_opinion=second,
        agrees_with_rules=(second == verdict),
        signals=signals_sorted, weights_version=str(weights["version"]),
    )
```

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_triage.py -q`
Expected: PASS (tous les tests de triage)

- [ ] **Step 5: Commit**
```bash
git add engine/triage.py tests/test_triage.py
git commit -m "feat(triage): extracteurs de signaux + load_weights fail-safe + compute_triage

Score linéaire décomposable (Σ contributions == score), 2e avis dérivé
des seuils, agrees_with_rules vs verdict règles. Poids surchargeables
via OCULAR_TRIAGE_WEIGHTS, fallback BUILTIN si illisible.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4 : Brancher le triage dans `ResultBuilder.build()`

**Files:**
- Modify: `engine/wrapper.py:98-135` (`ResultBuilder.build`)
- Test: `tests/test_wrapper.py` (ajout)

**Interfaces:**
- Consumes: `engine.triage.compute_triage`.
- Produces: tout `OcularResult` construit via `build()` porte `triage` non-nul. Les 4 sites appelants (`runner_analysis/render.py:67`, `runner_recon/capture.py:152` & `:585`, `runner_recon_vnc/session_server.py:143`) sont **inchangés** — le calcul est centralisé ici.

- [ ] **Step 1: Écrire le test**

Ajouter à `tests/test_wrapper.py` :
```python
from engine.wrapper import ResultBuilder
from engine.result import StaticFinding, DomInfo


def test_build_populates_triage():
    b = ResultBuilder()
    findings = [StaticFinding(rule="Dynamic code evaluation", severity="high",
                              match="m", line=1, context="c"),
                StaticFinding(rule="Base64 decode", severity="medium",
                              match="m", line=1, context="c")]
    result, _ = b.build(
        job_id="j", profile="analysis", target="t", input_hash=None,
        verdict="malicious", dom_info=DomInfo(), static_findings=findings,
        network=[], console=[],
    )
    assert result.triage is not None
    assert result.triage.band == "high"
    assert result.triage.weights_version == "builtin-1"
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_wrapper.py::test_build_populates_triage -q`
Expected: FAIL — `AssertionError: result.triage is None`

- [ ] **Step 3: Calculer le triage dans `build()`**

Dans `engine/wrapper.py`, ajouter l'import en tête (près des autres imports moteur) :
```python
from engine.triage import compute_triage
```
Puis, dans `build()`, juste avant `result = OcularResult(`, insérer :
```python
        _findings = static_findings or []
        _dom = dom_info or DomInfo()
        triage = compute_triage(
            _findings, verdict=verdict,
            network=network or [], console=console or [], dom=_dom,
        )
```
et ajouter `triage=triage,` dans les kwargs de `OcularResult(...)` (après `stealth=stealth,`). Remplacer aussi `static_findings=static_findings or [],` par `static_findings=_findings,` et `dom=dom_info or DomInfo(),` par `dom=_dom,` pour réutiliser les variables (pas de double évaluation).

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_wrapper.py -q`
Expected: PASS

- [ ] **Step 5: Vérifier la non-régression du schéma et des runners**

Run: `. .venv/bin/activate && pytest tests/test_wrapper.py tests/test_result_schema.py tests/test_render.py tests/test_capture_logic.py -q`
Expected: PASS (aucune régression ; `triage` optionnel n'invalide rien)

- [ ] **Step 6: Commit**
```bash
git add engine/wrapper.py tests/test_wrapper.py
git commit -m "feat(triage): calcul du triage centralisé dans ResultBuilder.build

Un seul site de calcul (build reçoit déjà findings/verdict/network/
console/dom) plutôt que 4 sites compute_verdict. compute_verdict reste
intact.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

# TRANCHE 2 — Persistance + API + UI

### Task 5 : Persistance `triage_score/triage_band` (migration idempotente)

**Files:**
- Modify: `saved_store.py` (`_NEW_COLUMNS`, `save()`, `_META_COLUMNS`)
- Test: `tests/test_saved_store.py` (ajout)

**Interfaces:**
- Consumes: `result.get("triage")` (dict avec `score`, `band`).
- Produces: colonnes `triage_score INTEGER`, `triage_band TEXT` ; remontées par `list_all`/`get_by_hash`/`get_meta`.

- [ ] **Step 1: Écrire le test**

Ajouter à `tests/test_saved_store.py` :
```python
def test_save_persists_triage(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    result = {
        "input_hash": "sha256:aa", "profile": "analysis", "job_id": "j",
        "verdict": "benign",
        "triage": {"score": 63, "band": "medium"},
    }
    sid = saved_store.save(conn, result, {}, "lbl", "2026-01-01T00:00:00Z")
    meta = saved_store.get_meta(conn, sid)
    assert meta["triage_score"] == 63
    assert meta["triage_band"] == "medium"


def test_save_without_triage_is_null(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    result = {"input_hash": "sha256:bb", "profile": "analysis", "verdict": "benign"}
    sid = saved_store.save(conn, result, {}, None, "2026-01-01T00:00:00Z")
    meta = saved_store.get_meta(conn, sid)
    assert meta["triage_score"] is None
    assert meta["triage_band"] is None
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_saved_store.py -k triage -q`
Expected: FAIL — `KeyError: 'triage_score'` (colonne absente de `_META_COLUMNS`)

- [ ] **Step 3: Ajouter colonnes + écriture + lecture**

Dans `saved_store.py` :

3a. Étendre `_NEW_COLUMNS` (après `("analyst_note", "TEXT")`) :
```python
    ("triage_score", "INTEGER"),
    ("triage_band", "TEXT"),
```

3b. Dans `save()`, avant `with conn:`, extraire :
```python
    triage = result.get("triage") or {}
    triage_score = triage.get("score")
    triage_band = triage.get("band")
```

3c. Modifier l'`INSERT` (liste de colonnes + valeurs) pour inclure les deux nouvelles colonnes :
```python
            cur = conn.execute(
                "INSERT INTO saved_analysis"
                " (input_hash, input_kind, job_id, verdict, label, result_json, saved_at,"
                "  saved_by, turnstile_solved, triage_score, triage_band)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (input_hash, kind, result.get("job_id"), result.get("verdict"),
                 label, json.dumps(result), now_iso, saved_by, turnstile_solved,
                 triage_score, triage_band),
            )
```

3d. Étendre `_META_COLUMNS` :
```python
_META_COLUMNS = (
    "id, input_hash, verdict, label, saved_at, saved_by, turnstile_solved,"
    " analyst_verdict, analyst, analyst_at, triage_score, triage_band"
)
```

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_saved_store.py -q`
Expected: PASS (tous les tests saved_store, dont rétro-compat existante)

- [ ] **Step 5: Commit**
```bash
git add saved_store.py tests/test_saved_store.py
git commit -m "feat(triage): dénormalise triage_score/triage_band en colonnes indexées

Migration idempotente (mécanisme _NEW_COLUMNS). NULL si résultat pré-
triage -> sauvegardes anciennes listables.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6 : `GET /saved` — tri & filtre validés (SQL)

**Files:**
- Modify: `saved_store.py::list_all` (signature tri/filtre)
- Modify: `web/app.py:709-715` (`list_saved` — query params)
- Test: `tests/test_saved_store.py` + `tests/test_saved_api.py` (ajouts)

**Interfaces:**
- Consumes: colonnes `triage_score/triage_band`.
- Produces: `list_all(conn, *, sort="saved_at", order="desc", min_band=None) -> list[dict]` ; `GET /saved?sort=&order=&min_band=` (422 hors-enum).

- [ ] **Step 1: Écrire les tests (store + API)**

Ajouter à `tests/test_saved_store.py` :
```python
def _seed(conn, hash_, score, band):
    saved_store.save(conn, {"input_hash": hash_, "profile": "analysis", "verdict": "benign",
                            "triage": {"score": score, "band": band}}, {}, None,
                     "2026-01-01T00:00:00Z")


def test_list_all_sort_by_triage_desc(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    _seed(conn, "sha256:a", 10, "low")
    _seed(conn, "sha256:b", 80, "high")
    rows = saved_store.list_all(conn, sort="triage_score", order="desc")
    assert [r["triage_score"] for r in rows] == [80, 10]


def test_list_all_filter_min_band(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    _seed(conn, "sha256:a", 10, "low")
    _seed(conn, "sha256:b", 80, "high")
    rows = saved_store.list_all(conn, min_band="high")
    assert [r["input_hash"] for r in rows] == ["sha256:b"]
```

Ajouter à `tests/test_saved_api.py` (suivre le style d'appel client existant du fichier — client de test FastAPI déjà en place) :
```python
def test_saved_rejects_bad_sort(client):
    r = client.get("/saved?sort=DROP", headers=AUTH)
    assert r.status_code == 422


def test_saved_accepts_triage_sort(client):
    r = client.get("/saved?sort=triage_score&order=asc", headers=AUTH)
    assert r.status_code == 200
```
> Note : réutiliser la fixture `client` et la constante d'en-tête d'auth déjà définies en tête de `tests/test_saved_api.py` (ne pas en recréer).

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_saved_store.py -k "sort or band" tests/test_saved_api.py -k "sort" -q`
Expected: FAIL — `TypeError: list_all() got an unexpected keyword argument 'sort'`

- [ ] **Step 3: Implémenter le tri/filtre SQL puis le param serveur**

3a. Dans `saved_store.py`, remplacer `list_all` :
```python
_SORTABLE = {"saved_at", "triage_score"}
_ORDERS = {"asc", "desc"}
_BANDS = {"low", "medium", "high"}
_BAND_RANK = {"low": 0, "medium": 1, "high": 2}


def list_all(conn, *, sort: str = "saved_at", order: str = "desc",
             min_band: Optional[str] = None) -> list[dict]:
    if sort not in _SORTABLE or order not in _ORDERS:
        raise ValueError("tri invalide")
    if min_band is not None and min_band not in _BANDS:
        raise ValueError("bande invalide")
    where, params = "", []
    if min_band is not None:
        allowed = [b for b, rank in _BAND_RANK.items() if rank >= _BAND_RANK[min_band]]
        where = " WHERE triage_band IN (%s)" % ",".join("?" * len(allowed))
        params = allowed
    # tri secondaire par id desc pour un ordre stable ; NULLs de triage en fin.
    direction = "DESC" if order == "desc" else "ASC"
    order_sql = f"{sort} {direction}, id DESC"
    rows = conn.execute(
        f"SELECT {_META_COLUMNS} FROM saved_analysis{where} ORDER BY {order_sql}",
        params,
    ).fetchall()
    return [dict(r) for r in rows]
```
> `sort`/`order`/`min_band` sont validés contre des whitelists AVANT interpolation → pas d'injection (seuls des littéraux connus atteignent la f-string).

3b. Dans `web/app.py`, remplacer `list_saved` :
```python
@app.get("/saved")
def list_saved(sort: str = "saved_at", order: str = "desc",
               min_band: str | None = None) -> list:
    conn = _saved_conn()
    try:
        return saved_store.list_all(conn, sort=sort, order=order, min_band=min_band)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    finally:
        conn.close()
```

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_saved_store.py tests/test_saved_api.py -q`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add saved_store.py web/app.py tests/test_saved_store.py tests/test_saved_api.py
git commit -m "feat(triage): GET /saved tri/filtre par score (SQL, whitelist, 422 hors-enum)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7 : UI — panneau Triage partagé + intégration vues

**Files:**
- Create: `web/ui/triage.js`
- Create: `tests/triage_test.mjs`, `tests/test_triage_js.py`
- Modify: la vue résultat (job + saved) et `web/ui/views/saved.js` pour appeler `triagePanel()` et le contrôle de tri
- Test: `tests/triage_test.mjs` (node)

**Interfaces:**
- Consumes: `triage` dans l'objet résultat (`{score,band,second_opinion,agrees_with_rules,signals[],weights_version}`) ; `verdict` règles.
- Produces: `export function triagePanel(triage, rulesVerdict)` (renvoie un nœud `el()` ou `null` si `triage` absent) ; `export function triageBadge(triage)` (pastille compacte pour la liste).

- [ ] **Step 1: Écrire le test node**

Créer `tests/triage_test.mjs` (mirroir de `filter_test.mjs` : stub minimal de `el`/`iconNode` puis assertions) :
```js
// Test comportemental de web/ui/triage.js (rendu DOM-less via stub el()).
import assert from 'node:assert';

// --- stub du module core.js (el/iconNode) : construit un arbre inspectable ---
function el(tag, attrs, kids) {
  const node = { tag, attrs: attrs || {}, kids: [], text: '' };
  const arr = Array.isArray(kids) ? kids : (kids != null ? [kids] : []);
  for (const k of arr) {
    if (typeof k === 'string') node.text += k;
    else if (k) node.kids.push(k);
  }
  return node;
}
function flat(node, acc = []) {
  if (!node) return acc;
  acc.push(node);
  (node.kids || []).forEach((k) => flat(k, acc));
  return acc;
}
function allText(node) {
  return flat(node).map((n) => n.text || '').join(' ');
}

// injection du stub avant import du module testé
const core = await import('../web/ui/core.js').catch(() => null);
globalThis.__OCULAR_TEST_EL__ = el;  // triage.js lit ce hook si présent (voir Step 3)

const { triagePanel, triageBadge } = await import('../web/ui/triage.js');

// 1. triage absent -> null
assert.strictEqual(triagePanel(null, 'benign'), null, 'triage null -> null');

// 2. panneau contient score, bande, version, signaux
const tri = {
  score: 72, band: 'high', second_opinion: 'malicious', agrees_with_rules: false,
  weights_version: 'builtin-1',
  signals: [
    { key: 'base', label: 'base', weight: 5, detail: '' },
    { key: 'obfuscation_cluster', label: "Cluster d'obfuscation/exécution", weight: 35, detail: '2 patterns' },
  ],
};
const panel = triagePanel(tri, 'benign');
const txt = allText(panel);
assert.ok(txt.includes('72'), 'score affiché');
assert.ok(txt.includes('builtin-1'), 'version affichée');
assert.ok(txt.includes("obfuscation"), 'signal affiché');
assert.ok(/diverge/i.test(txt), 'badge divergence quand !agrees_with_rules');

// 3. accord -> pas de badge divergence
const tri2 = { ...tri, agrees_with_rules: true, second_opinion: 'malicious' };
assert.ok(!/diverge/i.test(allText(triagePanel(tri2, 'malicious'))), 'pas de divergence si accord');

// 4. badge compact
assert.ok(allText(triageBadge(tri)).includes('72'), 'badge score');

console.log('triage_test OK');
```

Créer `tests/test_triage_js.py` (mirroir exact de `test_filter_js.py`) :
```python
"""Test comportemental (node) du module UI web/ui/triage.js."""
import shutil
import subprocess
from pathlib import Path

import pytest

NODE = shutil.which("node")
REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(NODE is None, reason="node introuvable — test JS ignoré")
def test_triage_js_node_suite():
    result = subprocess.run(
        [NODE, "tests/triage_test.mjs"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, (
        f"triage_test.mjs a échoué (rc={result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "triage_test OK" in result.stdout
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_triage_js.py -q`
Expected: FAIL — `triage_test.mjs a échoué` (module `web/ui/triage.js` inexistant)

- [ ] **Step 3: Implémenter `web/ui/triage.js`**

Créer `web/ui/triage.js` :
```js
// triage.js — panneau « Triage » partagé (vue job + vue saved). Rendu 100%
// el()/textNode (jamais innerHTML). Aucune donnée hostile ici (score/signaux
// viennent de notre moteur), mais on suit la discipline du reste de l'UI.
import { el as coreEl } from './core.js';

// hook de test : les tests node injectent un stub el() via globalThis.
const el = (globalThis.__OCULAR_TEST_EL__) || coreEl;

const BAND_STYLE = {
  low:    'color:var(--mut);background:var(--card2)',
  medium: 'color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,transparent)',
  high:   'color:var(--bad);background:color-mix(in srgb,var(--bad) 14%,transparent)',
};
const BAND_LABEL = { low: 'BASSE', medium: 'MOYENNE', high: 'HAUTE' };

// Pastille compacte pour la liste des Sauvegardes.
export function triageBadge(triage) {
  if (!triage) return null;
  return el('span.pending-pill.triage-pill', { style: BAND_STYLE[triage.band] || BAND_STYLE.low },
    'triage ' + String(triage.score));
}

// Panneau complet. `rulesVerdict` sert seulement à libeller la divergence.
export function triagePanel(triage, rulesVerdict) {
  if (!triage) return null;
  const kids = [];
  kids.push(el('div.triage-head', {}, [
    el('span.triage-score', {}, 'Priorité ' + String(triage.score) + ' / 100'),
    el('span.pending-pill', { style: BAND_STYLE[triage.band] || BAND_STYLE.low },
       BAND_LABEL[triage.band] || triage.band),
  ]));

  const opinion = [el('span', {}, '2e avis : '), el('b', {}, String(triage.second_opinion))];
  if (!triage.agrees_with_rules) {
    opinion.push(el('span.triage-diverge', { title: 'verdict règles : ' + String(rulesVerdict || '') },
      ' — diverge du verdict règles'));
  }
  kids.push(el('div.triage-opinion', {}, opinion));

  const sigList = el('ul.triage-signals', {}, (triage.signals || []).map((s) => {
    const line = [el('span.sig-label', {}, s.label),
                  el('span.sig-weight', {}, (s.weight >= 0 ? '+' : '') + String(Math.round(s.weight)))];
    if (s.detail) line.push(el('span.sig-detail', {}, ' — ' + s.detail));
    return el('li', {}, line);
  }));
  kids.push(sigList);

  kids.push(el('div.triage-foot', {}, 'Poids : ' + String(triage.weights_version)));
  return el('div.card.triage-panel', {}, kids);
}
```
> Le hook `__OCULAR_TEST_EL__` permet au test node de rendre l'arbre sans le vrai DOM ; en prod il est `undefined` → le vrai `el` de `core.js` est utilisé.

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_triage_js.py -q`
Expected: PASS (ou SKIP si `node` absent)

- [ ] **Step 5: Intégrer le panneau dans la vue résultat + la liste Sauvegardes**

5a. Repérer la vue qui rend un `OcularResult` (job détaillé et sauvegarde figée). Rechercher l'endroit où le verdict est affiché :
Run: `grep -rn "verdictPill\|verdict" web/ui/views/*.js | grep -i "result\|detail" | head`
5b. Dans cette vue, importer `triagePanel` (`import { triagePanel } from '../triage.js';`) et insérer `const tp = triagePanel(result.triage, result.verdict); if (tp) host.appendChild(tp);` juste après le bloc verdict.
5c. Dans `web/ui/views/saved.js`, importer `triageBadge` et l'ajouter dans la `jobrow` après `verdictPill(m.verdict)` :
```js
        verdictPill(m.verdict),
        triageBadge(m.triage_score != null ? { score: m.triage_score, band: m.triage_band } : null),
```
et importer en tête : `import { triageBadge } from '../triage.js';`.
5d. Ajouter un contrôle de tri au-dessus de la liste (dans `renderSaved`, avant la construction de `list`) :
```js
  const controls = el('div.saved-controls', {}, [
    el('label', {}, ['trier : ',
      el('select', { onchange: (e) => { location.hash = '#/saved?sort=' + e.target.value; } }, [
        el('option', { value: 'saved_at' }, 'date'),
        el('option', { value: 'triage_score' }, 'priorité'),
      ])]),
  ]);
  host.appendChild(controls);
```
et faire lire à `listSaved()` les query params du hash (passer `sort`/`order`/`min_band` à `GET /saved`). Si le routeur hash n'expose pas de query, se limiter à re-appeler `listSaved(sort)` en modifiant `api.js::listSaved` pour accepter un paramètre optionnel construisant la query-string — étape 5e.
5e. Dans `web/ui/api.js`, remplacer `listSaved` :
```js
export async function listSaved(params) {
  const qs = params ? ('?' + new URLSearchParams(params).toString()) : '';
  const res = await authFetch('/saved' + qs);
  if (!res.ok) throw new Error(await errText(res));
  return res.json();
}
```

- [ ] **Step 6: Vérifier l'UI (smoke) + non-régression filtre**

Run: `. .venv/bin/activate && pytest tests/test_ui_smoke.py tests/test_filter_js.py tests/test_triage_js.py -q`
Expected: PASS (ou SKIP node)

- [ ] **Step 7: Commit**
```bash
git add web/ui/triage.js web/ui/views/saved.js web/ui/api.js tests/triage_test.mjs tests/test_triage_js.py
# + la vue résultat modifiée en 5b
git commit -m "feat(triage): panneau Triage explicite (UI) + pastille + tri des Sauvegardes

Score/100 + bande + 2e avis + badge « diverge du verdict règles » +
décomposition des signaux + weights_version. Rendu el()/textNode.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

# TRANCHE 3 — Calibration hors-ligne

### Task 8 : CLI de calibration + cible `make calibrate`

**Files:**
- Create: `tools/calibrate_triage.py`
- Modify: `Makefile` (cible `calibrate`)
- Test: `tests/test_calibrate.py`

**Interfaces:**
- Consumes: `saved_store.connect` + `result_json` ; `engine.triage.extract_signals` (rejeu features — source unique) ; `engine.triage_weights.BUILTIN`.
- Produces: `collect_dataset(conn) -> tuple[list[dict], list[str]]` (features par signal, labels benign/suspicious/malicious) ; `fit_weights(X, y, feature_keys) -> dict` (même forme que BUILTIN) ; `calibrate(conn, *, min_total=30, min_per_class=5) -> tuple[dict|None, str]` (poids ou None + rapport).

- [ ] **Step 1: Écrire les tests**

Créer `tests/test_calibrate.py` :
```python
import numpy as np
import pytest

import saved_store
from tools.calibrate_triage import calibrate, collect_dataset, fit_weights


def _save_labeled(conn, hash_, findings_rules, analyst_verdict):
    findings = [{"rule": r, "severity": "medium", "match": "m", "line": 1, "context": "c"}
                for r in findings_rules]
    result = {"input_hash": hash_, "profile": "analysis", "verdict": "benign",
              "static_findings": findings, "network": [], "console": [],
              "dom": {"mailtos": [], "redirect_chain": []}}
    sid = saved_store.save(conn, result, {}, None, "2026-01-01T00:00:00Z")
    saved_store.set_analyst_verdict(conn, sid, analyst_verdict, "a", "2026-01-01T00:00:00Z")


def test_calibrate_refuses_below_threshold(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    _save_labeled(conn, "sha256:a", ["External form action"], "malicious")
    weights, report = calibrate(conn, min_total=30, min_per_class=5)
    assert weights is None
    assert "requis" in report


def test_calibrate_deterministic_and_shaped(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    # jeu jouet clivant : form externe -> malicious ; rien -> legitimate.
    for i in range(20):
        _save_labeled(conn, f"sha256:m{i}", ["External form action"], "malicious")
        _save_labeled(conn, f"sha256:l{i}", [], "legitimate")
    w1, _ = calibrate(conn, min_total=10, min_per_class=3)
    w2, _ = calibrate(conn, min_total=10, min_per_class=3)
    assert w1 is not None
    assert w1 == w2  # déterminisme (graine fixe)
    assert set(w1["bands"]) == {"medium", "high"}
    assert w1["version"].startswith("calibrated-")
    # le signal clivant a un poids strictement positif
    assert w1["signals"]["external_form"][0] > 0
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_calibrate.py -q`
Expected: FAIL — `ModuleNotFoundError: tools.calibrate_triage`

- [ ] **Step 3: Implémenter le CLI**

Créer `tools/__init__.py` (vide s'il n'existe pas) puis `tools/calibrate_triage.py` :
```python
"""Calibration HORS-LIGNE des poids de triage par régression logistique.
Lecture seule de la base saved, aucun accès réseau. Sortie = fichier de poids
proposé (même forme que BUILTIN) + rapport ; l'opérateur relit puis pointe
OCULAR_TRIAGE_WEIGHTS dessus. Déterministe (graine fixe).

Usage : python -m tools.calibrate_triage --db <path> --out <weights.json>
"""
from __future__ import annotations

import argparse
import json
from typing import Optional

import numpy as np

import saved_store
from engine.result import DomInfo, StaticFinding
from engine.triage import extract_signals
from engine.triage_weights import BUILTIN

_LABEL_MAP = {"legitimate": "benign", "suspicious": "suspicious", "malicious": "malicious"}
_CLASSES = ["benign", "suspicious", "malicious"]
_FEATURE_KEYS = [k for k in BUILTIN["signals"]]  # ordre stable


def _signal_vector(result: dict) -> list[int]:
    findings = [StaticFinding(**f) for f in result.get("static_findings", [])]
    dom = DomInfo(**(result.get("dom") or {}))
    sig = extract_signals(findings, result.get("network", []), result.get("console", []), dom)
    return [1 if sig[k][0] else 0 for k in _FEATURE_KEYS]


def collect_dataset(conn) -> tuple[list[list[int]], list[str]]:
    rows = conn.execute(
        "SELECT id, analyst_verdict FROM saved_analysis WHERE analyst_verdict IS NOT NULL"
    ).fetchall()
    X, y = [], []
    for row in rows:
        result = saved_store.get_result(conn, row["id"])
        if not result:
            continue
        X.append(_signal_vector(result))
        y.append(_LABEL_MAP[row["analyst_verdict"]])
    return X, y


def _softmax_fit(X: np.ndarray, y_idx: np.ndarray, n_classes: int,
                 iters: int = 4000, lr: float = 0.1, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    n, d = X.shape
    W = rng.normal(0, 0.01, size=(d, n_classes))
    Y = np.eye(n_classes)[y_idx]
    for _ in range(iters):
        logits = X @ W
        logits -= logits.max(axis=1, keepdims=True)
        p = np.exp(logits)
        p /= p.sum(axis=1, keepdims=True)
        grad = X.T @ (p - Y) / n
        W -= lr * grad
    return W


def fit_weights(X: list[list[int]], y: list[str], feature_keys: list[str]) -> dict:
    Xa = np.asarray(X, dtype=float)
    y_idx = np.asarray([_CLASSES.index(v) for v in y])
    W = _softmax_fit(Xa, y_idx, len(_CLASSES))
    # coefficient « malicious » - « benign » = tendance d'un signal à aggraver.
    delta = W[:, _CLASSES.index("malicious")] - W[:, _CLASSES.index("benign")]
    scale = 35.0 / (np.abs(delta).max() or 1.0)  # borne le plus fort à ~35
    signals = {}
    for i, key in enumerate(feature_keys):
        signals[key] = [round(float(delta[i] * scale), 1), BUILTIN["signals"][key][1]]
    return {
        "version": "calibrated",  # suffixe date ajouté par le caller (Date interdit ici)
        "base": 5,
        "bands": {"medium": 40, "high": 70},
        "signals": signals,
    }


def _report(X, y, weights) -> str:
    from collections import Counter
    counts = Counter(y)
    lines = [f"labels: {dict(counts)} (total {len(y)})", "poids (calibré vs builtin):"]
    for key in _FEATURE_KEYS:
        old = BUILTIN["signals"][key][0]
        new = weights["signals"][key][0]
        lines.append(f"  {key:24s} {old:6.1f} -> {new:6.1f}")
    return "\n".join(lines)


def calibrate(conn, *, min_total: int = 30, min_per_class: int = 5
              ) -> tuple[Optional[dict], str]:
    from collections import Counter
    X, y = collect_dataset(conn)
    counts = Counter(y)
    if len(y) < min_total:
        return None, f"{len(y)} labels, {min_total} requis"
    missing = [c for c in _CLASSES if counts.get(c, 0) < min_per_class]
    if missing:
        return None, f"classes sous {min_per_class}: {missing} (compte {dict(counts)})"
    weights = fit_weights(X, y, _FEATURE_KEYS)
    return weights, _report(X, y, weights)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--date", required=True, help="suffixe version, ex. 2026-07-18")
    ap.add_argument("--min-total", type=int, default=30)
    ap.add_argument("--min-per-class", type=int, default=5)
    args = ap.parse_args()
    conn = saved_store.connect(args.db)
    try:
        weights, report = calibrate(conn, min_total=args.min_total,
                                    min_per_class=args.min_per_class)
    finally:
        conn.close()
    print(report)
    if weights is None:
        raise SystemExit("calibration refusée : données insuffisantes")
    weights["version"] = f"calibrated-{args.date}"
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(weights, fh, ensure_ascii=False, indent=2)
    print(f"\nÉcrit {args.out} (version {weights['version']}). "
          f"Relire, puis pointer OCULAR_TRIAGE_WEIGHTS dessus pour activer.")


if __name__ == "__main__":
    main()
```
> `Date.now()`/`datetime.now()` sont volontairement évités dans le corps calculatoire (déterminisme + contrainte harness) : la date est passée en `--date` par la cible Make.

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_calibrate.py -q`
Expected: PASS (dont déterminisme `w1 == w2`)

- [ ] **Step 5: Ajouter la cible Make (conteneur jetable, zéro résidu host)**

Dans `Makefile`, ajouter (numpy n'est nécessaire QUE là → image de test qui l'embarque déjà, ou installation à la volée dans le conteneur jetable) :
```makefile
# Calibration HORS-LIGNE des poids de triage (lecture seule de la base saved,
# aucun réseau). Tourne dans un conteneur jetable -> aucun résidu host.
# DB= chemin de la base saved ; OUT= fichier de poids proposé ; DATE= suffixe version.
calibrate:
	docker build -f deploy/Dockerfile.test -t ocular-test:latest .
	docker run --rm -v "$(CURDIR):/app" -w /app ocular-test:latest \
		sh -c "pip install --quiet numpy && python -m tools.calibrate_triage \
		--db $(DB) --out $(OUT) --date $(DATE)"
```
> Si `deploy/Dockerfile.test` embarque déjà numpy (le vérifier : `grep -i numpy deploy/Dockerfile.test requirements*.txt`), retirer le `pip install`. Sinon l'ajouter aux deps de test uniquement — jamais au runtime.

- [ ] **Step 6: Commit**
```bash
git add tools/__init__.py tools/calibrate_triage.py tests/test_calibrate.py Makefile
git commit -m "feat(triage): CLI calibration hors-ligne (régression logistique numpy) + make calibrate

Rejoue extract_signals (source unique features), refuse sous seuil de
données, sortie relue puis activée à la main. Déterministe, lecture
seule, aucun réseau, conteneur jetable.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

# TRANCHE 4 — Option LLM (isolée, dernière)

### Task 9 : Réglages env LLM + endpoint `POST /jobs/{id}/explain`

**Files:**
- Modify: `ocular_settings.py` (accès env)
- Modify: `web/app.py` (endpoint)
- Test: `tests/test_web_api.py` (ajout)

**Interfaces:**
- Consumes: `engine.egress_policy` (garde egress existante) ; réglage `OCULAR_LLM_ENABLED/BASE_URL/MODEL/ALLOW_INTERNAL`.
- Produces: `POST /jobs/{id}/explain` → `{explanation, model}` si armé ; `404` si LLM désarmé.

- [ ] **Step 1: Écrire le test (désactivé par défaut = 404, aucun réseau)**

Ajouter à `tests/test_web_api.py` (réutiliser la fixture client/auth du fichier) :
```python
def test_explain_disabled_by_default_is_404(client, monkeypatch):
    monkeypatch.delenv("OCULAR_LLM_ENABLED", raising=False)
    r = client.post("/jobs/whatever/explain", headers=AUTH)
    assert r.status_code == 404
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_web_api.py -k explain -q`
Expected: FAIL — 404 attendu mais route inexistante renvoie 405/404 selon routeur (préciser le message si 405)

- [ ] **Step 3: Implémenter réglages + endpoint**

3a. Dans `ocular_settings.py`, ajouter :
```python
def llm_enabled() -> bool:
    return os.environ.get("OCULAR_LLM_ENABLED", "0") == "1"


def llm_base_url() -> str:
    return os.environ.get("OCULAR_LLM_BASE_URL", "").strip()


def llm_model() -> str:
    return os.environ.get("OCULAR_LLM_MODEL", "").strip()


def llm_allow_internal() -> bool:
    return os.environ.get("OCULAR_LLM_ALLOW_INTERNAL", "0") == "1"
```

3b. Dans `web/app.py`, ajouter l'endpoint (près des routes `/jobs`) :
```python
@app.post("/jobs/{job_id}/explain")
def explain_job(job_id: str, queue: RedisJobQueue = Depends(get_queue)) -> dict:
    if not ocular_settings.llm_enabled() or not ocular_settings.llm_base_url():
        raise HTTPException(status_code=404, detail="option LLM désactivée")
    result = queue.get_result(job_id)
    if result is None:
        raise HTTPException(status_code=404, detail="job introuvable")
    summary = _llm_summary_payload(result)  # verdict/triage/signaux/findings — JAMAIS le HTML brut
    try:
        text, model = _llm_explain(summary)
    except CaptureError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"explanation": text, "model": model}
```
et une fonction interne `_llm_explain` qui construit la requête OpenAI-compatible et l'envoie **via la garde egress** (`engine.egress_policy` : l'hôte du `llm_base_url()` doit être autorisé ; RFC1918 seulement si `llm_allow_internal()`), timeout court, réponse tronquée à N caractères. `_llm_summary_payload` sérialise UNIQUEMENT `verdict`, `triage`, `static_findings` (rule/severity), `dom.forms/mailtos` — jamais d'artefact ni de HTML.
> L'implémentation exacte de l'appel HTTP suit le pattern de `deephat-search/deepsearch.py::ollama` (urllib vers `/v1/chat/completions`), mais **encapsulé derrière la garde egress** d'Ocular, pas un `urllib` nu.

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_web_api.py -k explain -q`
Expected: PASS (404 par défaut, aucun appel réseau émis)

- [ ] **Step 5: Commit**
```bash
git add ocular_settings.py web/app.py tests/test_web_api.py
git commit -m "feat(triage): option LLM d'explication POST /jobs/{id}/explain (off par défaut, garde egress)

Désarmé sauf OCULAR_LLM_ENABLED=1 + BASE_URL. Résumé structuré (jamais
le HTML brut), appel via garde egress, note d'aide jamais un verdict.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 10 : UI — bouton « Expliquer avec LLM »

**Files:**
- Modify: la vue résultat (job/saved) + `web/ui/api.js`
- Test: manuel (feature optionnelle, désarmée par défaut) — pas de test node dédié

**Interfaces:**
- Consumes: `POST /jobs/{id}/explain`.
- Produces: bouton conditionnel + affichage de la note en `textContent` avec badge modèle.

- [ ] **Step 1: Ajouter l'appel API**

Dans `web/ui/api.js`, ajouter :
```js
// POST /jobs/{id}/explain -> {explanation, model}. 404 si option LLM désarmée
// (le bouton doit alors rester masqué / afficher « option désactivée »).
export async function explainJob(id) {
  const res = await authFetch('/jobs/' + encodeURIComponent(id) + '/explain', { method: 'POST' });
  if (!res.ok) { const e = new Error(await errText(res)); e.status = res.status; throw e; }
  return res.json();
}
```

- [ ] **Step 2: Ajouter le bouton dans la vue résultat**

Sous le panneau Triage (Task 7, étape 5b), ajouter un bouton « Expliquer avec LLM ». Au clic : appeler `explainJob(id)` ; en cas de 404, remplacer le bouton par « note LLM : option désactivée » ; sinon afficher `el('div.llm-note', {}, [el('span.badge', {}, 'note générée par LLM (' + res.model + ')'), el('p', {}, res.explanation)])` — la réponse en `textContent` via `el()`, jamais `innerHTML`.

- [ ] **Step 3: Vérifier le smoke UI**

Run: `. .venv/bin/activate && pytest tests/test_ui_smoke.py -q`
Expected: PASS

- [ ] **Step 4: Commit**
```bash
git add web/ui/api.js
# + la vue résultat modifiée
git commit -m "feat(triage): bouton « Expliquer avec LLM » (masqué/désactivé si option off)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Validation finale (après la dernière tranche livrée)

- [ ] **Suite complète Dockerisée**

Run: `make test`
Expected: PASS (aucune régression ; nouveaux tests triage/saved/calibrate/web verts).

- [ ] **Mettre à jour la roadmap**

Documenter la phase (ex. « Phase 3o — triage IA/ML ») comme LIVRÉE dans `docs/ROADMAP.md`, avec le backlog explicite (ré-scoring de masse, bouton admin de calibration). Commit `docs(roadmap): ...`.

---

## Self-review (fait à l'écriture du plan)

- **Couverture spec** : T1 (rôle) → Tasks 3/7/9 ; T2 (hybride) → Tasks 2/3 + 8 ; T3 (verdict intact) → Task 4 (compute_verdict non touché) ; T4 (natif 0-dep) → Tasks 2/3 ; T5 (consommateurs) → Tasks 6/7/8 ; T6 (calibration hors-ligne relue) → Task 8 ; T7 (pas de ML day-1) → BUILTIN heuristique (Task 2) ; T8 (LLM opt-in egress) → Task 9. Persistance/UI/tri → Tasks 5/6/7. Tests §6 du spec → répartis par task + `make test` final.
- **Placeholders** : aucun « TBD/TODO » ; chaque step de code porte le code réel. Les deux points d'intégration UI (vue résultat) exigent un `grep` de localisation (Task 7 step 5a, Task 10 step 2) car le nom exact du fichier de vue résultat n'est pas figé — c'est une localisation, pas un placeholder de logique.
- **Cohérence des types** : `compute_triage(findings, *, verdict, network, console, dom, weights)` cohérent entre Tasks 3/4/8 ; `list_all(conn, *, sort, order, min_band)` cohérent Tasks 6 ; `triagePanel(triage, rulesVerdict)`/`triageBadge(triage)` cohérents Tasks 7/10 ; forme de poids `{version,base,bands,signals:{k:[w,label]}}` identique BUILTIN (Task 2) / calibré (Task 8) / load_weights (Task 3).
