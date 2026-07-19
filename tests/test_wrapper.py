# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import io
import json

from engine.result import ConsoleEntry, DomInfo, NetworkEntry, StealthInfo
from engine.wrapper import NetworkCapture, ResultBuilder, emit_wrapper, sha256_ref


def test_sha256_ref_format():
    data = b"hello"
    assert sha256_ref(data) == "sha256:" + hashlib.sha256(data).hexdigest()


def test_result_builder_add_screenshot_registers_blob_and_ref():
    b = ResultBuilder()
    ref = b.add_screenshot(0, "initial", b"\x89PNG\r\n\x1a\nAAA", viewport="1280x720")
    assert ref.startswith("sha256:")
    assert b.blobs[ref] == b"\x89PNG\r\n\x1a\nAAA"
    assert b.screenshots[0].step == 0
    assert b.screenshots[0].phase == "initial"
    assert b.screenshots[0].image_ref == ref
    assert b.screenshots[0].viewport == "1280x720"


def test_result_builder_set_dom_registers_blob_and_artifacts():
    b = ResultBuilder()
    ref = b.set_dom(b"<html></html>")
    assert ref in b.blobs
    assert b.artifacts.dom_html_ref == ref


def test_result_builder_set_dom_empty_is_noop():
    b = ResultBuilder()
    assert b.set_dom(b"") is None
    assert b.blobs == {}
    assert b.artifacts.dom_html_ref is None


def test_result_builder_build_assembles_ocular_result():
    b = ResultBuilder()
    b.add_screenshot(0, "initial", b"\x89PNG\r\n\x1a\nAAA")
    b.set_dom(b"<html></html>")
    result, blobs = b.build(
        job_id="job-1",
        profile="analysis",
        target="inline-html",
        input_hash="sha256:" + hashlib.sha256(b"x").hexdigest(),
        verdict="benign",
        dom_info=DomInfo(title="Hi", final_url="https://x"),
        stealth=StealthInfo(engine="chromium"),
        static_findings=[],
        network=[{"url": "https://x", "method": "GET", "status": 200}],
        console=[{"level": "log", "text": "hi"}],
    )
    assert result.job_id == "job-1"
    assert result.profile == "analysis"
    assert result.dom.title == "Hi"
    assert result.stealth.engine == "chromium"
    assert isinstance(result.network[0], NetworkEntry) and result.network[0].status == 200
    assert isinstance(result.console[0], ConsoleEntry) and result.console[0].text == "hi"
    assert blobs is b.blobs
    assert result.screenshots[0].image_ref in blobs
    assert result.artifacts.dom_html_ref in blobs


def test_result_builder_build_defaults_network_console_to_empty():
    b = ResultBuilder()
    result, _ = b.build(
        job_id="", profile="capture", target="https://x",
        input_hash="sha256:" + hashlib.sha256(b"x").hexdigest(), verdict="unknown",
    )
    assert result.network == []
    assert result.console == []
    assert result.dom == DomInfo()


class _FakePage:
    """Simule l'API Playwright/Camoufox page.on() pour tester NetworkCapture sans
    navigateur réel — request/response/console sont de simples callbacks Python."""

    def __init__(self):
        self._handlers: dict[str, list] = {}

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)

    def fire(self, event, *args):
        for h in self._handlers.get(event, []):
            h(*args)


class _FakeRequest:
    def __init__(self, url, method="GET", resource_type="document", post_data=None):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data = post_data


class _FakeResponse:
    def __init__(self, request, status):
        self.request = request
        self.status = status


class _FakeConsoleMsg:
    def __init__(self, type_, text):
        self.type = type_
        self.text = text


def test_network_capture_attach_collects_request_response_console():
    page = _FakePage()
    cap = NetworkCapture()
    cap.attach(page)

    req = _FakeRequest("https://x/a", method="GET")
    page.fire("request", req)
    page.fire("response", _FakeResponse(req, 200))
    page.fire("console", _FakeConsoleMsg("log", "hi"))

    assert cap.network == [{"url": "https://x/a", "method": "GET",
                            "resource_type": "document", "post_data": None, "status": 200}]
    assert cap.console == [{"level": "log", "text": "hi"}]


def test_network_capture_response_without_matching_request_is_ignored():
    page = _FakePage()
    cap = NetworkCapture()
    cap.attach(page)
    unrelated_req = _FakeRequest("https://x/never-seen")
    page.fire("response", _FakeResponse(unrelated_req, 404))
    assert cap.network == []


def test_emit_wrapper_writes_json_with_base64_blobs(monkeypatch):
    b = ResultBuilder()
    b.add_screenshot(0, "initial", b"\x89PNG\r\n\x1a\nAAA")
    result, blobs = b.build(
        job_id="job-1", profile="analysis", target="inline-html",
        input_hash="sha256:" + hashlib.sha256(b"x").hexdigest(), verdict="benign",
    )
    buf = io.StringIO()
    monkeypatch.setattr("sys.stdout", buf)
    emit_wrapper(result, blobs)
    payload = json.loads(buf.getvalue())
    assert payload["result"]["job_id"] == "job-1"
    ref = result.screenshots[0].image_ref
    assert payload["blobs"][ref] == "iVBORw0KGgpBQUE="


from engine.wrapper import ResultBuilder
from engine.result import StaticFinding, DomInfo


def test_build_populates_triage():
    b = ResultBuilder()
    findings = [StaticFinding(rule="Dynamic code evaluation", severity="high",
                              match="m", line=1, context="c"),
                StaticFinding(rule="Base64 decode", severity="medium",
                              match="m", line=1, context="c")]
    result, _ = b.build(
        job_id="j", profile="analysis", target="t", input_hash=None,
        verdict="malicious", dom_info=DomInfo(), static_findings=findings,
        network=[], console=[],
    )
    assert result.triage is not None
    assert result.triage.band == "high"
    assert result.triage.weights_version == "builtin-1"


def test_add_screenshot_skips_oversized(monkeypatch):
    from engine.wrapper import ResultBuilder
    monkeypatch.setenv("OCULAR_MAX_ARTIFACT_BYTES", "100")
    b = ResultBuilder()
    ref = b.add_screenshot(0, "initial", b"\x89PNG" + b"x" * 200)
    assert ref is None            # hors-cap -> ignoré
    assert b.screenshots == []
    assert b.blobs == {}
    # sous le cap : stocké normalement
    ref2 = b.add_screenshot(0, "initial", b"tiny")
    assert ref2 is not None and ref2 in b.blobs


def test_set_dom_truncates_oversized(monkeypatch):
    from engine.wrapper import ResultBuilder
    monkeypatch.setenv("OCULAR_MAX_ARTIFACT_BYTES", "50")
    b = ResultBuilder()
    ref = b.set_dom(b"<html>" + b"x" * 500 + b"</html>")
    assert ref is not None
    stored = b.blobs[ref]
    assert len(stored) == 50                       # tronqué au cap
    from engine.wrapper import sha256_ref
    assert ref == sha256_ref(stored)               # hash cohérent avec les octets stockés
