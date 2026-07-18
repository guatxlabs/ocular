import logging

from ocular_logging import get_logger


def test_logger_emits_and_never_contains_token(caplog):
    log = get_logger("test")
    with caplog.at_level(logging.INFO):
        log.info("job submitted", extra={"job_id": "j1", "html_bytes": 42})
    assert any("j1" in r.getMessage() or getattr(r, "job_id", None) == "j1" for r in caplog.records)
    assert all("OCULAR_TOKEN" not in r.getMessage() for r in caplog.records)


# --- Régression 2026-07-18 : logs sur stdout cassaient le contrat des runners ---

def test_get_logger_defaults_to_stderr_never_stdout():
    """Le wrapper JSON {result, blobs} des runners part sur STDOUT et est parsé
    par broker/launcher.py. Une seule ligne de log sur stdout le casse
    (JSONDecodeError: Extra data) et fait échouer le job.

    Ce test verrouille le défaut. Il a été ajouté après une vraie régression :
    un `get_logger()` sans `stream` ajouté dans engine/wrapper.py (importé tôt
    par les runners) gagnait la course contre le `stream=sys.stderr` explicite
    des runners, à cause du garde `_CONFIGURED` qui fige le flux au 1er appel.
    """
    import importlib
    import sys as _sys
    import ocular_logging

    # module rechargé pour repartir de _CONFIGURED = False (l'état est global)
    mod = importlib.reload(ocular_logging)
    logger = mod.get_logger("regression-stream-check")

    handlers = logging.getLogger("ocular").handlers
    assert handlers, "le logger 'ocular' doit porter un handler"
    streams = [getattr(h, "stream", None) for h in handlers]
    assert _sys.stdout not in streams, (
        "RÉGRESSION : un handler de log écrit sur STDOUT — cela corrompt le "
        "wrapper JSON des runners et fait échouer les jobs (JSONDecodeError)."
    )
    assert _sys.stderr in streams, "le flux de log par défaut doit être stderr"
    assert logger.name == "ocular.regression-stream-check"


# --- Défaut D : un OCULAR_LOG_LEVEL invalide crashait TOUT à l'import --------
# `root.setLevel(log_level())` sans validation : `OCULAR_LOG_LEVEL=verbose`
# -> `ValueError: Unknown level: 'VERBOSE'`. Comme `get_logger` est appelé au
# NIVEAU MODULE partout (broker, web, engine), l'import du système entier
# échouait -> crashloop sans le moindre indice sur la cause.

import importlib

import pytest

import ocular_settings


def _reload_logging(monkeypatch, raw):
    """Recharge `ocular_logging` (l'état `_CONFIGURED` est global) avec la
    valeur d'env donnée, et retourne le logger racine 'ocular'."""
    monkeypatch.setenv("OCULAR_LOG_LEVEL", raw)
    import ocular_logging
    mod = importlib.reload(ocular_logging)
    mod.get_logger("niveau-check")
    return logging.getLogger("ocular")


@pytest.mark.parametrize("raw", ["verbose", "trace", "", "  ", "42x", "DEBUGG"])
def test_invalid_log_level_falls_back_to_info_instead_of_crashing(monkeypatch, raw):
    root = _reload_logging(monkeypatch, raw)  # ne doit PAS lever
    assert root.level == logging.INFO, (
        f"RÉGRESSION défaut D : OCULAR_LOG_LEVEL={raw!r} doit retomber sur INFO"
    )


@pytest.mark.parametrize("raw,expected", [
    ("DEBUG", logging.DEBUG),
    ("debug", logging.DEBUG),
    ("  WARNING  ", logging.WARNING),
    ("error", logging.ERROR),
    ("critical", logging.CRITICAL),
])
def test_valid_log_levels_are_still_honoured(monkeypatch, raw, expected):
    assert _reload_logging(monkeypatch, raw).level == expected


def test_log_level_accessor_strips_and_never_raises(monkeypatch):
    monkeypatch.setenv("OCULAR_LOG_LEVEL", "  debug \n")
    assert ocular_settings.log_level() == "DEBUG"
