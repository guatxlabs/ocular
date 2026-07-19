# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mécanique commune aux runners `runner_analysis/render.py` (profil analysis,
Chromium/Playwright) et `runner_recon/capture.py` (profil capture, Camoufox) :
hash de référence des blobs, listeners réseau/console, construction de
l'`OcularResult`, émission du wrapper JSON sur stdout.

Chaque runner reste responsable de sa propre logique métier (moteur navigateur,
détection Turnstile, calcul des `static_findings`/verdict) — ce module ne
factorise QUE la mécanique répétée entre les deux profils, pour qu'il n'y ait
qu'une seule implémentation à maintenir (cf. task-2-brief.md, exigence DRY)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional

from engine.result import (
    Artifacts,
    ConsoleEntry,
    DomInfo,
    DynamicStep,
    NetworkEntry,
    OcularResult,
    Screenshot,
    StealthInfo,
)
from engine.triage import compute_triage
from ocular_logging import get_logger

_log = get_logger("wrapper")
_DEFAULT_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024  # 32 MiB


def _max_artifact_bytes() -> int:
    """Cap de taille d'UN artefact (DOM ou screenshot) stocké dans le wrapper.
    Anti-OOM : une page HOSTILE peut gonfler son DOM (`body.innerHTML =
    'x'.repeat(5e8)`) et produire un blob de centaines de Mo que le broker
    (mem_limit 1g) lirait en entier depuis stdout du runner. `0` = illimité.
    Réglable via `OCULAR_MAX_ARTIFACT_BYTES`."""
    try:
        return max(0, int(os.environ.get("OCULAR_MAX_ARTIFACT_BYTES", str(_DEFAULT_MAX_ARTIFACT_BYTES))))
    except ValueError:
        return _DEFAULT_MAX_ARTIFACT_BYTES


def sha256_ref(data: bytes) -> str:
    """Référence de contenu-adressage d'un blob (screenshot, DOM, ...)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


class NetworkCapture:
    """Arme les listeners `page.on("request"/"response"/"console")` communs aux
    deux moteurs (Playwright sync pour Chromium, Playwright async pour Camoufox
    partagent la même API d'événements). Collecte dans des listes de DICTS
    neutres — pas de dépendance au moteur, pas de conversion Pydantic ici (elle
    se fait dans `ResultBuilder.build`, au moment de composer l'`OcularResult`).
    """

    def __init__(self) -> None:
        self.network: list[dict[str, Any]] = []
        self.console: list[dict[str, Any]] = []
        self._req_index: dict[Any, dict[str, Any]] = {}

    def attach(self, page: Any) -> None:
        def _on_request(req: Any) -> None:
            entry = {
                "url": req.url,
                "method": req.method,
                "resource_type": getattr(req, "resource_type", None),
                "post_data": getattr(req, "post_data", None),
            }
            self.network.append(entry)
            self._req_index[req] = entry

        def _on_response(resp: Any) -> None:
            entry = self._req_index.get(resp.request)
            if entry is not None:
                entry["status"] = resp.status

        def _on_console(msg: Any) -> None:
            self.console.append({"level": msg.type, "text": msg.text})

        page.on("request", _on_request)
        page.on("response", _on_response)
        page.on("console", _on_console)


class ResultBuilder:
    """Construit progressivement les blobs (screenshots, DOM) référencés par
    `sha256_ref`, puis assemble l'`OcularResult` final. Ne connaît rien du
    moteur de rendu ni des findings — c'est de la pure mécanique de wrapper."""

    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.screenshots: list[Screenshot] = []
        self.artifacts = Artifacts()

    def add_screenshot(self, step: int, phase: str, png: bytes, viewport: str = "1280x720") -> Optional[str]:
        # Un PNG tronqué serait invalide -> on IGNORE un screenshot hors-cap
        # (le résultat n'aura pas cette capture) plutôt que de corrompre l'image.
        cap = _max_artifact_bytes()
        if cap and len(png) > cap:
            _log.warning("screenshot ignoré step=%d phase=%s bytes=%d > cap=%d (page hostile bloatée ?)",
                         step, phase, len(png), cap)
            return None
        ref = sha256_ref(png)
        self.blobs[ref] = png
        self.screenshots.append(Screenshot(step=step, phase=phase, image_ref=ref, viewport=viewport))
        return ref

    def set_dom(self, dom_html: bytes) -> Optional[str]:
        if not dom_html:
            return None
        # Le DOM est un artefact de CONSULTATION : on le tronque au cap (reste
        # affichable) plutôt que d'OOM. Le hash porte sur les octets réellement
        # stockés (contenu-adressage cohérent).
        cap = _max_artifact_bytes()
        if cap and len(dom_html) > cap:
            _log.warning("DOM tronqué bytes=%d > cap=%d (page hostile bloatée ?)", len(dom_html), cap)
            dom_html = dom_html[:cap]
        ref = sha256_ref(dom_html)
        self.blobs[ref] = dom_html
        self.artifacts = Artifacts(dom_html_ref=ref, har_ref=self.artifacts.har_ref)
        return ref

    def build(
        self,
        *,
        job_id: str,
        profile: str,
        target: str,
        input_hash: Optional[str],
        verdict: str,
        dom_info: Optional[DomInfo] = None,
        stealth: Optional[StealthInfo] = None,
        static_findings: Optional[list] = None,
        network: Optional[list[dict[str, Any]]] = None,
        console: Optional[list[dict[str, Any]]] = None,
        dynamic_steps: Optional[list] = None,
    ) -> tuple[OcularResult, dict[str, bytes]]:
        _findings = static_findings or []
        _dom = dom_info or DomInfo()
        triage = compute_triage(
            _findings, verdict=verdict,
            network=network or [], console=console or [], dom=_dom,
        )
        result = OcularResult(
            job_id=job_id,
            profile=profile,
            target=target,
            input_hash=input_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            verdict=verdict,
            screenshots=self.screenshots,
            network=[NetworkEntry(**n) for n in (network or [])],
            console=[ConsoleEntry(**c) for c in (console or [])],
            dom=_dom,
            static_findings=_findings,
            # 3c : journal du mode scripté (déjà des `DynamicStep`, construits
            # par runner_recon/capture.py::journal_to_dynamic_steps). Absent
            # (None) -> liste vide, comme tout autre champ optionnel ici.
            dynamic_steps=[
                d if isinstance(d, DynamicStep) else DynamicStep(**d)
                for d in (dynamic_steps or [])
            ],
            stealth=stealth,
            triage=triage,
            artifacts=self.artifacts,
        )
        return result, self.blobs


def wrapper_payload(result: OcularResult, blobs: dict[str, bytes]) -> dict:
    """Forme `{result, blobs(base64)}` du wrapper d'échange runner<->web. Source
    unique : le tier batch l'émet sur stdout (`emit_wrapper`), le tier interactif
    la renvoie telle quelle en réponse HTTP (session_server /capture)."""
    return {
        "result": result.model_dump(mode="json"),
        "blobs": {ref: base64.b64encode(data).decode() for ref, data in blobs.items()},
    }


def emit_wrapper(result: OcularResult, blobs: dict[str, bytes]) -> None:
    """Écrit `{result, blobs(base64)}` sur stdout — LE seul flux stdout du
    runner, consommé par broker/launcher.py. Les logs partent ailleurs (stderr)."""
    sys.stdout.write(json.dumps(wrapper_payload(result, blobs)) + "\n")
