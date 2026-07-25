# SPDX-FileCopyrightText: 2026 GuatX
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
    POST_DATA_MAX_CHARS,
    Artifacts,
    ConsoleEntry,
    DomInfo,
    DynamicStep,
    NetworkEntry,
    OcularResult,
    Screenshot,
    StealthInfo,
    Truncation,
)
from engine.triage import compute_triage
from ocular_logging import get_logger

_log = get_logger("wrapper")
_DEFAULT_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024  # 32 MiB
_DEFAULT_MAX_POST_DATA_BYTES = 8 * 1024         # 8 KiB
_DEFAULT_MAX_NETWORK_ENTRIES = 5000
_DEFAULT_MAX_CONSOLE_ENTRIES = 5000


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


def _env_cap(name: str, default: int, hard_max: Optional[int] = None) -> int:
    """Plafond entier de configuration. Ne lève JAMAIS (une valeur illisible
    retombe sur le défaut — même règle qu'`ocular_settings`). Plancher 1 :
    contrairement aux artefacts, ces plafonds n'ont PAS de « 0 = illimité », car
    ce qu'ils bornent est dicté par la page hostile — l'exploitation peut les
    baisser, jamais les retirer."""
    try:
        val = int(os.environ.get(name, str(default)))
    except ValueError:
        val = default
    val = max(1, val)
    return min(val, hard_max) if hard_max is not None else val


def _max_post_data_chars() -> int:
    """Taille max CONSERVÉE du corps d'une requête capturée.
    `OCULAR_MAX_POST_DATA_BYTES`, défaut 8192, borné par `POST_DATA_MAX_CHARS`
    (65536, le plafond du modèle). Au dépassement le corps est TRONQUÉ, l'entrée
    marquée `post_data_truncated` et comptée dans `OcularResult.truncation`."""
    return _env_cap("OCULAR_MAX_POST_DATA_BYTES", _DEFAULT_MAX_POST_DATA_BYTES, POST_DATA_MAX_CHARS)


def _max_network_entries() -> int:
    """Nombre max d'entrées réseau conservées. `OCULAR_MAX_NETWORK_ENTRIES`,
    défaut 5000. Au dépassement, les entrées SUIVANTES sont rejetées — on garde
    les PREMIÈRES (la chaîne de chargement initiale est ce qui documente la
    page ; c'est aussi ce qui garde `_req_index` borné) — et comptées dans
    `OcularResult.truncation.network_dropped`."""
    return _env_cap("OCULAR_MAX_NETWORK_ENTRIES", _DEFAULT_MAX_NETWORK_ENTRIES)


def _max_console_entries() -> int:
    """Idem pour le journal console : `OCULAR_MAX_CONSOLE_ENTRIES`, défaut 5000,
    surplus compté dans `OcularResult.truncation.console_dropped`."""
    return _env_cap("OCULAR_MAX_CONSOLE_ENTRIES", _DEFAULT_MAX_CONSOLE_ENTRIES)


def _truncate_post_data(entry: dict[str, Any], cap: int) -> bool:
    """Tronque `entry["post_data"]` au cap EN PLACE ; renvoie True s'il l'a été.
    Le marqueur n'est posé QUE dans ce cas (une entrée intacte garde la forme
    historique du dict ; `NetworkEntry.post_data_truncated` vaut False)."""
    body = entry.get("post_data")
    if isinstance(body, str) and len(body) > cap:
        entry["post_data"] = body[:cap]
        entry["post_data_truncated"] = True
        return True
    return False


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
        # Ce qui a été REJETÉ ou coupé, reporté dans `OcularResult.truncation`
        # via `truncation()` : le résultat dit ce qu'il ne contient pas.
        self.dropped_network = 0
        self.dropped_console = 0
        self.truncated_post_data = 0

    def truncation(self) -> Truncation:
        """État de troncature de CETTE capture, à passer à `ResultBuilder.build`."""
        return Truncation(
            network_dropped=self.dropped_network,
            console_dropped=self.dropped_console,
            post_data_truncated=self.truncated_post_data,
        )

    def attach(self, page: Any) -> None:
        def _on_request(req: Any) -> None:
            # Plafond de CARDINALITÉ (anti-OOM, même justification que les
            # artefacts) : une page hostile peut émettre des requêtes sans fin.
            # Au-delà on rejette et on compte — et on n'indexe pas la requête,
            # ce qui borne `_req_index` avec la liste.
            if len(self.network) >= _max_network_entries():
                self.dropped_network += 1
                return
            entry = {
                "url": req.url,
                "method": req.method,
                "resource_type": getattr(req, "resource_type", None),
                "post_data": getattr(req, "post_data", None),
            }
            if _truncate_post_data(entry, _max_post_data_chars()):
                self.truncated_post_data += 1
            self.network.append(entry)
            self._req_index[req] = entry

        def _on_response(resp: Any) -> None:
            entry = self._req_index.get(resp.request)
            if entry is not None:
                entry["status"] = resp.status

        def _on_console(msg: Any) -> None:
            if len(self.console) >= _max_console_entries():
                self.dropped_console += 1
                return
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
        truncation: Optional[Truncation] = None,
    ) -> tuple[OcularResult, dict[str, bytes]]:
        _findings = static_findings or []
        _dom = dom_info or DomInfo()
        # Choke-point des plafonds réseau/console, symétrique de celui des
        # artefacts (`add_screenshot`/`set_dom`) : la garantie tient pour TOUT
        # `OcularResult`, quelle que soit l'origine des listes. `truncation`
        # reporte ce qu'un `NetworkCapture` a déjà rejeté en amont ; ce qui est
        # déjà borné ne l'est pas deux fois (les compteurs ne doublent pas).
        _raw_network = list(network or [])
        _raw_console = list(console or [])
        _body_cap = _max_post_data_chars()
        _kept_network: list[dict[str, Any]] = []
        _body_truncated = 0
        for _n in _raw_network[: _max_network_entries()]:
            _entry = dict(_n)
            if _truncate_post_data(_entry, _body_cap):
                _body_truncated += 1
            _kept_network.append(_entry)
        _kept_console = _raw_console[: _max_console_entries()]
        _upstream = truncation or Truncation()
        _truncation = Truncation(
            network_dropped=_upstream.network_dropped + len(_raw_network) - len(_kept_network),
            console_dropped=_upstream.console_dropped + len(_raw_console) - len(_kept_console),
            post_data_truncated=_upstream.post_data_truncated + _body_truncated,
        )
        if _truncation != Truncation():
            _log.warning("résultat tronqué network_dropped=%d console_dropped=%d post_data_truncated=%d",
                         _truncation.network_dropped, _truncation.console_dropped,
                         _truncation.post_data_truncated)
        triage = compute_triage(
            _findings, verdict=verdict,
            network=_kept_network, console=_kept_console, dom=_dom,
        )
        result = OcularResult(
            job_id=job_id,
            profile=profile,
            target=target,
            input_hash=input_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            verdict=verdict,
            screenshots=self.screenshots,
            network=[NetworkEntry(**n) for n in _kept_network],
            console=[ConsoleEntry(**c) for c in _kept_console],
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
            truncation=_truncation,
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
