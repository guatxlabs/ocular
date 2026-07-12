import logging

from ocular_logging import get_logger


def test_logger_emits_and_never_contains_token(caplog):
    log = get_logger("test")
    with caplog.at_level(logging.INFO):
        log.info("job submitted", extra={"job_id": "j1", "html_bytes": 42})
    assert any("j1" in r.getMessage() or getattr(r, "job_id", None) == "j1" for r in caplog.records)
    assert all("OCULAR_TOKEN" not in r.getMessage() for r in caplog.records)
