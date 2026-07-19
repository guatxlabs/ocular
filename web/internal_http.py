# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Appels HTTP INTERNES du web vers le `session_server` d'un conteneur de
session (réseau applicatif interne uniquement). Bibliothèque standard seule —
le web n'a AUCUN accès au moteur de conteneurs (seul le broker en dispose) et
n'ajoute aucune dépendance. Extrait de `web/app.py` (audit qualité 3m : app.py
était le seul vrai monolithe) ; `web/app.py` réimporte ces symboles sous leurs
noms `_préfixés` historiques (compat monkeypatch des tests)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request


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
    """Échec (réseau, HTTP non-2xx, ou JSON invalide) de l'appel interne au
    `session_server` — traduit systématiquement en 502 côté route."""


def internal_capture(url: str, secret: str, timeout: float = 30.0, payload: dict | None = None) -> dict:
    """POST interne vers `/capture` du `session_server`. Signe l'appel avec
    `X-Session-Secret` (jamais loggé). `payload` (JSON, défaut `{}`) transporte
    les options de capture (ex. `{"turnstile_passed": true}`). Renvoie le wrapper
    `{result, blobs}` désérialisé ; lève `CaptureError` sur tout échec."""
    data = json.dumps(payload or {}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-Session-Secret": secret},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - réseau interne uniquement
            body = resp.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CaptureError(str(exc)) from exc
    try:
        return json.loads(body)
    except (ValueError, TypeError) as exc:
        raise CaptureError("réponse capture invalide") from exc


def internal_get_json(url: str, secret: str, timeout: float = 5.0) -> dict:
    """GET interne (données, pas health) vers le `session_server` (`/live`),
    calqué sur `internal_capture` : signé `X-Session-Secret`, échec traduit en
    `CaptureError` (-> 502 côté route)."""
    req = urllib.request.Request(
        url,
        headers={"X-Session-Secret": secret},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - réseau interne uniquement
            body = resp.read()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CaptureError(str(exc)) from exc
    try:
        return json.loads(body)
    except (ValueError, TypeError) as exc:
        raise CaptureError("réponse live invalide") from exc
