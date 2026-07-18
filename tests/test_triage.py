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
