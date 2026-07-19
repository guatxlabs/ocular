# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
import sqlite3

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


def test_connect_readonly_rejects_writes(tmp_path):
    # La calibration ouvre la base en lecture seule : toute écriture est rejetée.
    p = str(tmp_path / "s.db")
    saved_store.connect(p).close()  # crée le schéma
    ro = saved_store.connect_readonly(p)
    try:
        with pytest.raises(sqlite3.OperationalError):
            ro.execute(
                "INSERT INTO saved_analysis (input_hash, input_kind, result_json, saved_at)"
                " VALUES ('sha256:z','html','{}','t')"
            )
    finally:
        ro.close()


def test_calibrate_over_readonly_connection(tmp_path):
    # Calibration au-dessus d'une connexion LECTURE SEULE : fonctionne et ne
    # mute pas la base (le connect_readonly ne lance pas _migrate).
    p = str(tmp_path / "s.db")
    conn = saved_store.connect(p)
    for i in range(20):
        _save_labeled(conn, f"sha256:m{i}", ["External form action"], "malicious")
        _save_labeled(conn, f"sha256:l{i}", [], "legitimate")
    conn.close()

    ro = saved_store.connect_readonly(p)
    try:
        weights, report = calibrate(ro, min_total=10, min_per_class=3)
    finally:
        ro.close()
    assert weights is not None
    assert weights["signals"]["external_form"][0] > 0


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


def test_collect_dataset_skips_malformed_row(tmp_path):
    # Une sauvegarde avec un finding malformé (champ manquant) ne doit pas
    # avorter la calibration : la ligne est sautée, les bonnes sont gardées.
    conn = saved_store.connect(str(tmp_path / "s.db"))
    _save_labeled(conn, "sha256:ok", ["External form action"], "malicious")
    # injecte une sauvegarde au result_json malformé (finding sans champs requis)
    sid = saved_store.save(conn, {"input_hash": "sha256:bad", "profile": "analysis",
                                  "verdict": "benign",
                                  "static_findings": [{"rule": "x"}]},  # manque severity/match/line/context
                           {}, None, "2026-01-01T00:00:00Z")
    saved_store.set_analyst_verdict(conn, sid, "legitimate", "a", "2026-01-01T00:00:00Z")
    X, y = collect_dataset(conn)
    assert len(X) == len(y) == 1  # seule la ligne valide est retenue
    assert y == ["malicious"]
