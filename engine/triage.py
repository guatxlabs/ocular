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
