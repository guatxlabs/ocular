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
import urllib.error
import urllib.request

from engine.limits import PAIRS, env_cap, resolve

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
_DEFAULT_MAX_CAPTURE_BYTES = PAIRS["capture"].read_default
_DEFAULT_MAX_JSON_BYTES = PAIRS["live"].read_default
_HARD_MAX_INTERNAL_BYTES = PAIRS["live"].read_hard_max
# Quelle PAIRE porte chaque plafond de lecture — c'est ce qui interdit de lire
# l'un des deux côtés sans confronter l'autre.
_PAIR_OF = {spec.read_var: name for name, spec in PAIRS.items()}

_log = logging.getLogger("ocular.internal_http")


def _max_bytes(name: str, default: int) -> int:
    """Plafond de LECTURE d'une réponse interne. Résolu par `engine.limits`, qui
    possède la PAIRE « budget de la source / plafond de lecture » et la confronte
    DANS LES DEUX SENS.

    Avant, l'invariant n'était gardé que d'un côté : baisser ce plafond sous le
    budget de la source émettait un WARNING, mais RELEVER le budget de la source
    ne déclenchait rien — et le code sanctionnait des valeurs qui brisent son
    propre invariant (la borne haute autorisée pour `OCULAR_MAX_LIVE_JSON_BYTES`
    valait 2× ce plafond-ci par défaut). Mesuré avec cette valeur pourtant
    acceptée : corps `/live` de 23,45 Mio annoncé COMPLET, `502` à chaque poll,
    zéro WARNING. La confrontation vit désormais dans `engine.limits.resolve`."""
    pair = _PAIR_OF.get(name)
    if pair is None:  # pragma: no cover - toutes les variables lues sont appariées
        return env_cap(name, default, _HARD_MAX_INTERNAL_BYTES, floor=1024)
    return resolve(pair).read_cap


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
