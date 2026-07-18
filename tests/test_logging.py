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
