from __future__ import annotations

import logging
import sys

from ocular_settings import log_level

_CONFIGURED = False


def get_logger(name: str, stream=None) -> logging.Logger:
    """Logger applicatif. Le flux par défaut est **stderr**, JAMAIS stdout.

    C'est une contrainte de CORRECTION, pas de style : les runners écrivent leur
    wrapper `{result, blobs}` en JSON sur **stdout**, que `broker/launcher.py`
    parse. Une seule ligne de log sur stdout casse ce parsing
    (`JSONDecodeError: Extra data`) et fait échouer le job.

    Le piège est aggravé par `_CONFIGURED` : le PREMIER appel fixe le flux pour
    tout le monde. Un module importé tôt (`engine/wrapper.py`, `engine/
    egress_guard.py`) appelant `get_logger()` sans `stream` gagnait donc la
    course contre le `stream=sys.stderr` explicite des runners — c'est
    exactement la régression qu'a produite l'ajout d'un logger dans
    `engine/wrapper.py` (attrapée par les tests d'intégration, 2026-07-18).
    Avec stderr par défaut, l'ordre d'import n'a plus d'importance."""
    global _CONFIGURED
    if not _CONFIGURED:
        handler = logging.StreamHandler(stream or sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"))
        root = logging.getLogger("ocular")
        root.handlers[:] = [handler]
        root.setLevel(log_level())
        _CONFIGURED = True
    return logging.getLogger("ocular." + name)
