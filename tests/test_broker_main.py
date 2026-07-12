import json

from broker.main import error_result


def test_error_result_is_valid_json_even_with_special_chars():
    s = error_result("job-x", RuntimeError('runner a échoué: err "quote"\nline\\back'))
    d = json.loads(s)  # ne doit PAS lever
    assert d["job_id"] == "job-x"
    assert "runner a échoué" in d["error"]


def test_error_result_truncates_long_messages():
    s = error_result("job-y", RuntimeError("x" * 500))
    d = json.loads(s)
    assert len(d["error"]) <= 200
