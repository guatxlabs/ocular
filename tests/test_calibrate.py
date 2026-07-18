import numpy as np
import pytest

import saved_store
from tools.calibrate_triage import calibrate, collect_dataset, fit_weights


def _save_labeled(conn, hash_, findings_rules, analyst_verdict):
    findings = [{"rule": r, "severity": "medium", "match": "m", "line": 1, "context": "c"}
                for r in findings_rules]
    result = {"input_hash": hash_, "profile": "analysis", "verdict": "benign",
              "static_findings": findings, "network": [], "console": [],
              "dom": {"mailtos": [], "redirect_chain": []}}
    sid = saved_store.save(conn, result, {}, None, "2026-01-01T00:00:00Z")
    saved_store.set_analyst_verdict(conn, sid, analyst_verdict, "a", "2026-01-01T00:00:00Z")


def test_calibrate_refuses_below_threshold(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    _save_labeled(conn, "sha256:a", ["External form action"], "malicious")
    weights, report = calibrate(conn, min_total=30, min_per_class=5)
    assert weights is None
    assert "requis" in report


def test_calibrate_deterministic_and_shaped(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    # jeu jouet clivant : form externe -> malicious ; rien -> legitimate.
    for i in range(20):
        _save_labeled(conn, f"sha256:m{i}", ["External form action"], "malicious")
        _save_labeled(conn, f"sha256:l{i}", [], "legitimate")
    w1, _ = calibrate(conn, min_total=10, min_per_class=3)
    w2, _ = calibrate(conn, min_total=10, min_per_class=3)
    assert w1 is not None
    assert w1 == w2  # déterminisme (graine fixe)
    assert set(w1["bands"]) == {"medium", "high"}
    assert w1["version"].startswith("calibrated-")
    # le signal clivant a un poids strictement positif
    assert w1["signals"]["external_form"][0] > 0
