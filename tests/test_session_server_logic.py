import pytest
from fastapi.testclient import TestClient

import runner_recon_vnc.session_server as ss
from runner_recon_vnc.session_server import build_capture_result


def test_build_capture_result_url_profile_and_hash():
    # `eval(atob(...))` below is an inert byte-string fixture (fake captured
    # DOM), never executed — it only exercises engine.static's pattern match.
    r, blobs = build_capture_result(
        target="https://example.com/x",
        kind="url",
        png=b"\x89PNG\r\n\x1a\nAAA",
        dom=b"<script>eval(atob('x'))</script>",
        title="t",
        final="https://example.com/x",
        network=[{"url": "https://example.com/x", "method": "GET", "status": 200}],
    )
    assert r.profile == "capture"
    assert r.stealth.engine == "camoufox"
    assert r.input_hash.startswith("sha256:")
    assert r.verdict == "malicious"          # static détecte eval/atob dans le DOM capturé
    assert r.screenshots[0].image_ref in blobs
    assert r.artifacts.dom_html_ref in blobs
    assert r.network[0].url == "https://example.com/x"


def test_build_capture_result_includes_console_parity_with_static_analysis():
    # BUG 2 — l'interactif doit être un SUR-ENSEMBLE du résultat statique
    # (runner_analysis/render.py remplit `console` via NetworkCapture.console) :
    # `build_capture_result` doit relayer le même journal console, jamais le
    # laisser vide par construction.
    r, _ = build_capture_result(
        target="https://example.com/x",
        kind="url",
        png=b"",
        dom=b"<html></html>",
        title="t",
        final="https://example.com/x",
        network=[],
        console=[{"level": "error", "text": "boom"}, {"level": "log", "text": "hi"}],
    )
    assert [c.level for c in r.console] == ["error", "log"]
    assert [c.text for c in r.console] == ["boom", "hi"]


def test_build_capture_result_console_defaults_to_empty_list():
    r, _ = build_capture_result(
        target="https://example.com/x", kind="url", png=b"", dom=b"", title="", final="", network=[],
    )
    assert r.console == []


def test_build_capture_result_html_profile_and_hash():
    html_input = "<html><body>hello</body></html>"
    r, blobs = build_capture_result(
        target="inline-html",
        kind="html",
        png=b"\x89PNG\r\n\x1a\nBBB",
        dom=html_input.encode(),
        title="",
        final="",
        network=[],
        html_input=html_input,
    )
    assert r.profile == "analysis"
    assert r.input_hash.startswith("sha256:")
    assert r.verdict == "benign"


def test_build_capture_result_no_screenshot_no_dom():
    r, blobs = build_capture_result(
        target="https://example.com/",
        kind="url",
        png=b"",
        dom=b"",
        title="",
        final="",
        network=[],
    )
    assert r.screenshots == []
    assert r.artifacts.dom_html_ref is None
    assert r.static_findings == []
    assert r.verdict == "benign"


_LIVE_SECRET = "the-live-secret"


@pytest.fixture
def live_client(monkeypatch):
    monkeypatch.setenv("OCULAR_SESSION_SECRET", _LIVE_SECRET)
    ss._state.update(cm=None, page=None, cap=None, target=None, kind=None, html_input="")
    return TestClient(ss.app)


def test_live_no_active_session_returns_empty_structure(live_client):
    r = live_client.get("/live", headers={"X-Session-Secret": _LIVE_SECRET})
    assert r.status_code == 200
    assert r.json() == {
        "network": [],
        "console": [],
        "findings": [],
        "counts": {"network": 0, "findings": 0, "console": 0},
        "verdict": "benign",
    }


def test_live_with_page_returns_network_findings_counts_verdict(live_client):
    dom_html = '<html><body><script src="https://evil.example/a.js"></script></body></html>'
    network_entries = [{"url": "https://evil.example/a.js", "method": "GET", "status": 200}]
    console_entries = [{"level": "error", "text": "boom"}]

    class _FakePage:
        async def content(self):
            return dom_html

    class _FakeCap:
        network = network_entries
        console = console_entries

    ss._state.update(page=_FakePage(), cap=_FakeCap())

    r = live_client.get("/live", headers={"X-Session-Secret": _LIVE_SECRET})
    assert r.status_code == 200
    body = r.json()

    # reflète le réseau/console capturés et l'analyse statique du DOM courant —
    # mêmes fonctions que /capture (aucune duplication de la mécanique).
    expected_findings = ss.analyze_html(dom_html)
    assert body["network"] == network_entries
    assert body["console"] == console_entries
    assert len(body["findings"]) == len(expected_findings) > 0
    assert body["counts"] == {
        "network": len(network_entries), "findings": len(expected_findings), "console": len(console_entries),
    }
    assert body["verdict"] == ss.compute_verdict(expected_findings)


def test_live_dom_content_failure_falls_back_to_empty_dom(live_client):
    class _FakePage:
        async def content(self):
            raise RuntimeError("page closed")

    class _FakeCap:
        network = []
        console = []

    ss._state.update(page=_FakePage(), cap=_FakeCap())

    r = live_client.get("/live", headers={"X-Session-Secret": _LIVE_SECRET})
    assert r.status_code == 200
    body = r.json()
    assert body["findings"] == []
    assert body["counts"] == {"network": 0, "findings": 0, "console": 0}
    assert body["verdict"] == "benign"


def test_live_network_bounded_to_last_500(live_client):
    network_entries = [{"url": f"https://x/{i}", "method": "GET", "status": 200} for i in range(600)]

    class _FakePage:
        async def content(self):
            return "<html></html>"

    class _FakeCap:
        network = network_entries
        console = []

    ss._state.update(page=_FakePage(), cap=_FakeCap())

    r = live_client.get("/live", headers={"X-Session-Secret": _LIVE_SECRET})
    body = r.json()
    assert len(body["network"]) == 500
    assert body["network"] == network_entries[-500:]
    assert body["counts"]["network"] == 600


def test_live_console_bounded_to_last_500(live_client):
    console_entries = [{"level": "log", "text": f"line {i}"} for i in range(600)]

    class _FakePage:
        async def content(self):
            return "<html></html>"

    class _FakeCap:
        network = []
        console = console_entries

    ss._state.update(page=_FakePage(), cap=_FakeCap())

    r = live_client.get("/live", headers={"X-Session-Secret": _LIVE_SECRET})
    body = r.json()
    assert len(body["console"]) == 500
    assert body["console"] == console_entries[-500:]
    assert body["counts"]["console"] == 600
