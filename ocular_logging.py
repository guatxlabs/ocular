from __future__ import annotations

import logging
import sys

from ocular_settings import log_level

_CONFIGURED = False

# Repli quand le niveau demandé est inconnu. JAMAIS d'exception ici : `get_logger`
# est appelé au NIVEAU MODULE dans le broker, le web et l'engine — un
# `setLevel("VERBOSE")` levait `ValueError: Unknown level` et faisait donc échouer
# l'import du système ENTIER, soit un crashloop sans le moindre indice sur la cause.
_DEFAULT_LEVEL = logging.INFO

# Allowlist de repli pour les runtimes sans `logging.getLevelNamesMapping()`
# (ajouté en 3.11) — la source de vérité reste le mapping du module `logging`.
_FALLBACK_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "FATAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARN": logging.WARNING,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
    "NOTSET": logging.NOTSET,
}


def resolve_level(name: str) -> int:
    """Traduit un nom de niveau en entier `logging`, avec repli sur INFO si le
    nom est inconnu, vide, ou non textuel. Ne lève jamais : une variable
    d'environnement mal saisie doit dégrader la VERBOSITÉ, jamais empêcher le
    service de démarrer."""
    try:
        known = logging.getLevelNamesMapping()  # type: ignore[attr-defined]
    except AttributeError:  # < 3.11
        known = _FALLBACK_LEVELS
    if not isinstance(name, str):
        return _DEFAULT_LEVEL
    level = known.get(name.strip().upper())
    return level if isinstance(level, int) else _DEFAULT_LEVEL


def get_logger(name: str) -> logging.Logger:
    """Logger applicatif. Le flux est **stderr**, JAMAIS stdout.

    C'est une contrainte de CORRECTION, pas de style : les runners écrivent leur
    wrapper `{result, blobs}` en JSON sur **stdout**, que `broker/launcher.py`
    parse. Une seule ligne de log sur stdout casse ce parsing
    (`JSONDecodeError: Extra data`) et fait échouer le job.

    Il n'y a DÉLIBÉRÉMENT aucun paramètre `stream` : le flux n'est pas un choix
    d'appelant. Historiquement, `get_logger(name, stream=None)` laissait les
    runners passer `stream=sys.stderr` explicitement — mais `_CONFIGURED` fait
    que le PREMIER appel fixe le flux pour tout le monde, donc un module importé
    tôt (`engine/wrapper.py`, `engine/egress_guard.py`) appelant `get_logger()`
    sans `stream` gagnait la course contre le `stream=sys.stderr` des runners.
    C'est exactement la régression qu'a produite l'ajout d'un logger dans
    `engine/wrapper.py` (attrapée par les tests d'intégration, 2026-07-18).

    Depuis que le défaut est stderr, ces `stream=sys.stderr` ne servaient plus
    à rien — et le paramètre RESTAIT une façon de recréer la panne
    (`get_logger("x", stream=sys.stdout)`). Le supprimer rend l'ordre d'import
    ET l'appelant incapables de casser le contrat des runners."""
    global _CONFIGURED
    if not _CONFIGURED:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"))
        root = logging.getLogger("ocular")
        root.handlers[:] = [handler]
        root.setLevel(resolve_level(log_level()))
        _CONFIGURED = True
    return logging.getLogger("ocular." + name)
