# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Appels HTTP INTERNES du web vers le `session_server` d'un conteneur de
session (réseau applicatif interne uniquement). Bibliothèque standard seule —
le web n'a AUCUN accès au moteur de conteneurs (seul le broker en dispose) et
n'ajoute aucune dépendance. Extrait de `web/app.py`, qui était le seul vrai
monolithe du dépôt ; `web/app.py` réimporte ces symboles sous leurs
noms `_préfixés` historiques (compat monkeypatch des tests)."""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

# Plafonds de LECTURE des réponses internes. Le corps traverse le web (mem_limit
# 1g) puis Redis, monté sur tmpfs — donc la RAM de l'hôte : un `read()` non borné
# fait dicter cette consommation par la page analysée. Même motif que
# `web/llm.py` (`_LLM_MAX_RESPONSE_BYTES`).
#
# `/capture` transporte les blobs en base64 : un DOM et un screenshot au plafond
# d'artefact par défaut (32 Mio chacun) font déjà ~85 Mio encodés, d'où 128 Mio.
# `/live` ne transporte que du JSON (fenêtres de 500 entrées), d'où 16 Mio.
# Réglables par `OCULAR_MAX_INTERNAL_CAPTURE_BYTES` / `OCULAR_MAX_INTERNAL_JSON_BYTES`.
# Au dépassement : `CaptureError` -> 502 côté route, JAMAIS un corps tronqué
# re-parsé comme s'il était complet.
_DEFAULT_MAX_CAPTURE_BYTES = 128 * 1024 * 1024
_DEFAULT_MAX_JSON_BYTES = 16 * 1024 * 1024
_HARD_MAX_INTERNAL_BYTES = 512 * 1024 * 1024

# Plancher OPÉRATIONNEL, pas de sécurité : ces plafonds de lecture ne protègent
# que si la SOURCE est déjà bornée sous eux (`engine.wrapper._max_result_json_bytes`
# = 32 Mio pour `/capture`, `session_server._max_live_json_bytes` = 8 Mio pour
# `/live`). Descendre le plafond de lecture SOUS le budget de la source rend le
# refus structurel : la réponse dépasse à chaque appel, et la fonction devient
# inaccessible pour le restant de la session. On le journalise plutôt que de
# l'interdire — un exploitant peut avoir une raison de serrer, il doit serrer les
# DEUX côtés. Cf. docs/DEPLOY-SECURITY.md §2.10.
_SOURCE_BUDGET = {
    "OCULAR_MAX_INTERNAL_CAPTURE_BYTES": 32 * 1024 * 1024 + 90 * 1024 * 1024,
    "OCULAR_MAX_INTERNAL_JSON_BYTES": 8 * 1024 * 1024,
}

_log = logging.getLogger("ocular.internal_http")


def _max_bytes(name: str, default: int) -> int:
    """Ne lève jamais sur une valeur malformée (même règle qu'`ocular_settings`)
    mais ne substitue jamais EN SILENCE. Plancher 1 Kio, borne haute
    `_HARD_MAX_INTERNAL_BYTES` : un plafond de lecture qu'on peut porter à
    999999999999 n'est plus un plafond."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        val = int(raw)
    except ValueError:
        _log.warning("%s=%r illisible — plafond laissé au défaut %d", name, raw, default)
        return default
    clamped = min(max(1024, val), _HARD_MAX_INTERNAL_BYTES)
    if clamped != val:
        _log.warning("%s=%d hors bornes [1024, %d] — plafond ramené à %d",
                     name, val, _HARD_MAX_INTERNAL_BYTES, clamped)
    budget = _SOURCE_BUDGET.get(name)
    if budget is not None and clamped < budget:
        _log.warning(
            "%s=%d est SOUS le budget de la source (%d) : la réponse dépassera à "
            "chaque appel et la fonction restera inaccessible — baisser aussi le "
            "budget côté runner/session (cf. DEPLOY-SECURITY §2.10)",
            name, clamped, budget,
        )
    return clamped


def session_host(session_id: str) -> str:
    """Nom réseau interne du conteneur de session — jamais de port hôte, le
    web parle au conteneur uniquement via le réseau applicatif interne."""
    return f"ocular-sess-{session_id}"


def internal_get_ok(url: str, timeout: float = 2.0) -> bool:
    """GET interne (health) via la bibliothèque standard uniquement."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - réseau interne uniquement
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def internal_post_json(url: str, payload: dict, secret: str, timeout: float = 5.0) -> bool:
    data = json.dumps(payload).encode("utf-8")
    # X-Session-Secret : auth à la frontière conteneur (le session_server exige
    # ce secret sur /goto,/load). Jamais loggé.
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-Session-Secret": secret},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - réseau interne uniquement
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


class CaptureError(Exception):
    """Échec (réseau, HTTP non-2xx, JSON invalide, ou corps hors plafond) de
    l'appel interne au `session_server` — traduit systématiquement en 502 côté
    route."""


def _read_capped(resp, cap: int, what: str) -> bytes:
    """Lecture BORNÉE : `read(cap + 1)` détecte le dépassement sans jamais
    charger davantage. Fail-closed — au-delà du plafond on refuse, on ne rend pas
    un corps amputé qui serait re-parsé comme s'il était complet."""
    raw = resp.read(cap + 1)
    if len(raw) > cap:
        raise CaptureError(f"réponse {what} trop volumineuse")
    return raw


def internal_capture(url: str, secret: str, timeout: float = 30.0, payload: dict | None = None) -> dict:
    """POST interne vers `/capture` du `session_server`. Signe l'appel avec
    `X-Session-Secret` (jamais loggé). `payload` (JSON, défaut `{}`) transporte
    les options de capture (ex. `{"turnstile_passed": true}`). Renvoie le wrapper
    `{result, blobs}` désérialisé ; lève `CaptureError` sur tout échec — y compris
    un corps au-delà de `OCULAR_MAX_INTERNAL_CAPTURE_BYTES`."""
    data = json.dumps(payload or {}).encode()
    cap = _max_bytes("OCULAR_MAX_INTERNAL_CAPTURE_BYTES", _DEFAULT_MAX_CAPTURE_BYTES)
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-Session-Secret": secret},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - réseau interne uniquement
            body = _read_capped(resp, cap, "capture")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CaptureError(str(exc)) from exc
    try:
        return json.loads(body)
    except (ValueError, TypeError) as exc:
        raise CaptureError("réponse capture invalide") from exc


def internal_get_json(url: str, secret: str, timeout: float = 5.0) -> dict:
    """GET interne (données, pas health) vers le `session_server` (`/live`),
    calqué sur `internal_capture` : signé `X-Session-Secret`, échec traduit en
    `CaptureError` (-> 502 côté route), corps borné par
    `OCULAR_MAX_INTERNAL_JSON_BYTES`."""
    cap = _max_bytes("OCULAR_MAX_INTERNAL_JSON_BYTES", _DEFAULT_MAX_JSON_BYTES)
    req = urllib.request.Request(
        url,
        headers={"X-Session-Secret": secret},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - réseau interne uniquement
            body = _read_capped(resp, cap, "live")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CaptureError(str(exc)) from exc
    try:
        return json.loads(body)
    except (ValueError, TypeError) as exc:
        raise CaptureError("réponse live invalide") from exc
