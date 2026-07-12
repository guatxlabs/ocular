from engine.result import StaticFinding
from engine.verdict import compute_verdict


def _f(sev):
    return StaticFinding(rule="r", severity=sev, match="m", line=1, context="c")


def test_critical_is_malicious():
    assert compute_verdict([_f("low"), _f("critical")]) == "malicious"


def test_high_is_suspicious():
    assert compute_verdict([_f("medium"), _f("high")]) == "suspicious"


def test_only_low_medium_is_benign():
    assert compute_verdict([_f("low"), _f("medium")]) == "benign"


def test_empty_is_benign():
    assert compute_verdict([]) == "benign"
