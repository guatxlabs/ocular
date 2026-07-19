# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
from engine.result import OcularResult, Triage, TriageSignal


def _minimal_result(**kw):
    base = dict(job_id="j", profile="analysis", target="t", timestamp="2026-01-01T00:00:00Z")
    base.update(kw)
    return OcularResult(**base)


def test_result_without_triage_is_valid():
    r = _minimal_result()
    assert r.triage is None


def test_result_with_triage_roundtrips():
    tri = Triage(
        score=72, band="high", second_opinion="suspicious", agrees_with_rules=False,
        signals=[TriageSignal(key="k", label="L", weight=35.0, detail="d")],
        weights_version="builtin-1",
    )
    r = _minimal_result(triage=tri)
    dumped = r.model_dump(mode="json")
    again = OcularResult(**dumped)
    assert again.triage.score == 72
    assert again.triage.signals[0].weight == 35.0


from engine.triage_weights import BUILTIN


def test_builtin_shape():
    assert BUILTIN["version"] == "builtin-1"
    assert 0 <= BUILTIN["bands"]["medium"] < BUILTIN["bands"]["high"] <= 100
    for key, (weight, label) in BUILTIN["signals"].items():
        assert isinstance(key, str) and isinstance(weight, (int, float))
        assert isinstance(label, str) and label


import json
from engine.result import DomInfo, StaticFinding
from engine.triage import compute_triage, extract_signals, load_weights


def _rf(rule, sev="low"):
    return StaticFinding(rule=rule, severity=sev, match="m", line=1, context="c")


def test_benign_low_score():
    tri = compute_triage([], verdict="benign")
    assert tri.band == "low"
    assert tri.second_opinion == "benign"
    assert tri.agrees_with_rules is True


def test_score_decomposition_equals_sum():
    # Σ des contributions affichées == score (invariant « explicite »).
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium"),
                _rf("Password input field"), _rf("Account verification text", "medium")]
    tri = compute_triage(findings, verdict="malicious")
    assert sum(round(s.weight) for s in tri.signals) == tri.score


def test_signals_sorted_by_abs_weight_desc():
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium"),
                _rf("External form action", "medium")]
    tri = compute_triage(findings, verdict="suspicious")
    weights = [abs(s.weight) for s in tri.signals if s.key != "base"]
    assert weights == sorted(weights, reverse=True)


def test_obfuscation_cluster_high_band():
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium")]
    tri = compute_triage(findings, verdict="malicious")
    assert tri.band == "high"
    assert tri.second_opinion == "malicious"


def test_medium_only_obfuscation_cluster_aligns_with_rules():
    # 2 règles _OBF MEDIUM (aucun high-severity) : compute_verdict renvoie
    # malicious (len(obf)>=2). Le 2e avis doit atteindre malicious lui aussi
    # (band high via obfuscation_cluster=65) -> PAS de fausse divergence sur le
    # signal malveillant le plus fort.
    findings = [_rf("Base64 decode", "medium"), _rf("URL decode", "medium")]
    tri = compute_triage(findings, verdict="malicious")
    assert tri.band == "high"
    assert tri.second_opinion == "malicious"
    assert tri.agrees_with_rules is True


def test_diverges_when_rules_benign_but_score_high():
    # Règles=benign mais faisceau fort -> 2e avis diverge (badge « à revoir »).
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium")]
    tri = compute_triage(findings, verdict="benign")
    assert tri.second_opinion == "malicious"
    assert tri.agrees_with_rules is False


def test_mailto_and_redirect_signals():
    dom = DomInfo(mailtos=["a@evil.tld"], redirect_chain=["u1", "u2", "u3"])
    sig = extract_signals([], network=[], console=[], dom=dom)
    assert sig["mailto_exfil"][0] is True
    assert sig["redirect_chain"][0] is True


def test_many_third_parties_signal():
    net = [{"url": f"https://h{i}.tld/x"} for i in range(12)]
    sig = extract_signals([], network=net, console=[], dom=DomInfo())
    assert sig["many_third_parties"][0] is True
    assert "12" in sig["many_third_parties"][1]


def test_console_errors_signal():
    sig = extract_signals([], network=[], console=[{"level": "error", "text": "x"}], dom=DomInfo())
    assert sig["console_errors"][0] is True


def test_load_weights_default_is_builtin():
    weights, err = load_weights()
    assert weights["version"] == "builtin-1" and err is None


def test_load_weights_malformed_falls_back(tmp_path, monkeypatch):
    bad = tmp_path / "w.json"
    bad.write_text("{ not json")
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(bad))
    weights, err = load_weights()
    assert weights["version"] == "builtin-1"
    assert err is not None


def test_malformed_weights_surface_error_signal(tmp_path, monkeypatch):
    bad = tmp_path / "w.json"
    bad.write_text("{ not json")
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(bad))
    tri = compute_triage([], verdict="benign")
    assert any(s.key == "weights_load_error" for s in tri.signals)


def test_calibrated_weights_override(tmp_path, monkeypatch):
    good = tmp_path / "w.json"
    good.write_text(json.dumps({
        "version": "calibrated-2026-07-18", "base": 0,
        "bands": {"medium": 40, "high": 70},
        "signals": {"external_form": [50.0, "Formulaire externe"]},
    }))
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(good))
    tri = compute_triage([_rf("External form action", "medium")], verdict="suspicious")
    assert tri.weights_version == "calibrated-2026-07-18"
    assert tri.score == 50


def _write_weights(tmp_path, monkeypatch, **over):
    data = {
        "version": "cal-test", "base": 0,
        "bands": {"medium": 40, "high": 70},
        "signals": {"external_form": [50.0, "Formulaire externe"]},
    }
    data.update(over)
    p = tmp_path / "w.json"
    p.write_text(json.dumps(data))
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(p))
    return p


# --- F1 : la branche de clamp (raw hors [0,100]) doit préserver Σ==score ---

def test_clamp_high_preserves_invariant(tmp_path, monkeypatch):
    # signaux qui somment > 100 -> score plafonné à 100, invariant maintenu.
    _write_weights(tmp_path, monkeypatch, base=30,
                   signals={"external_form": [200.0, "Formulaire externe"]})
    tri = compute_triage([_rf("External form action", "medium")], verdict="malicious")
    assert tri.score == 100
    assert sum(round(s.weight) for s in tri.signals) == tri.score


def test_clamp_low_preserves_invariant(tmp_path, monkeypatch):
    # base négative -> raw < 0 -> score plancher à 0, invariant maintenu.
    _write_weights(tmp_path, monkeypatch, base=-50,
                   signals={"external_form": [10.0, "Formulaire externe"]})
    tri = compute_triage([_rf("External form action", "medium")], verdict="benign")
    assert tri.score == 0
    assert sum(round(s.weight) for s in tri.signals) == tri.score


# --- F2 : base demi-entière + clamp ne doit pas casser Σ==score (banker's rounding) ---

def test_half_integer_base_under_clamp_preserves_invariant(tmp_path, monkeypatch):
    # base=0.5 + poids forçant un delta impair : round(base+delta) != round(base)+delta.
    _write_weights(tmp_path, monkeypatch, base=0.5,
                   signals={"external_form": [103.0, "Formulaire externe"]})
    tri = compute_triage([_rf("External form action", "medium")], verdict="malicious")
    assert tri.score == 100
    assert sum(round(s.weight) for s in tri.signals) == tri.score


# --- F3 : validation explicite / fail-safe (jamais d'exception) ---

def test_empty_weights_file_falls_back(tmp_path, monkeypatch):
    p = tmp_path / "w.json"
    p.write_text("{}")
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(p))
    weights, err = load_weights()
    assert weights["version"] == "builtin-1"
    assert err is not None
    tri = compute_triage([], verdict="benign")
    assert any(s.key == "weights_load_error" for s in tri.signals)


def test_malformed_signal_entry_falls_back(tmp_path, monkeypatch):
    # forme globale valide mais une entrée de signal n'est pas [poids, libellé].
    _write_weights(tmp_path, monkeypatch, signals={"external_form": "oops"})
    weights, err = load_weights()
    assert weights["version"] == "builtin-1"
    assert err is not None
    # compute_triage ne doit pas lever et doit surfacer l'erreur de chargement.
    tri = compute_triage([_rf("External form action", "medium")], verdict="benign")
    assert any(s.key == "weights_load_error" for s in tri.signals)


def test_agrees_with_rules_none_when_verdict_unknown():
    # verdict règles non comparable ("unknown", ex. capture en échec) -> pas
    # d'avis à (dés)accorder -> agrees_with_rules None (pas de badge « diverge »).
    findings = [_rf("Dynamic code evaluation", "high"), _rf("Base64 decode", "medium")]
    tri = compute_triage(findings, verdict="unknown")
    assert tri.agrees_with_rules is None
    assert tri.second_opinion == "malicious"


def test_validate_weights_rejects_bad_band_order(tmp_path, monkeypatch):
    import json as _json
    bad = tmp_path / "w.json"
    bad.write_text(_json.dumps({
        "version": "x", "base": 5,
        "bands": {"medium": 70, "high": 40},  # medium >= high : incohérent
        "signals": {"external_form": [10.0, "x"]},
    }))
    monkeypatch.setenv("OCULAR_TRIAGE_WEIGHTS", str(bad))
    weights, err = load_weights()
    assert weights["version"] == "builtin-1"  # fallback
    assert err is not None
