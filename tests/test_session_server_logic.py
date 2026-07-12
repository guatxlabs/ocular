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
