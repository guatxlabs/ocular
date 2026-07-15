import hashlib

import pytest

render = pytest.importorskip("runner_analysis.render")


@pytest.mark.integration
def test_render_benign_html_produces_screenshot_and_dom():
    html = "<html><title>Hi</title><body>hello</body></html>"
    r, blobs = render.render_html(html, "job-1")
    assert r.profile == "analysis"
    assert r.screenshots and r.screenshots[0].image_ref.startswith("sha256:")
    assert r.dom.title == "Hi"
    # le blob du screenshot est présent et correspond au ref
    assert r.screenshots[0].image_ref in blobs and blobs[r.screenshots[0].image_ref][:8] == b"\x89PNG\r\n\x1a\n"
    assert r.input_hash == "sha256:" + hashlib.sha256(html.encode()).hexdigest()


@pytest.mark.integration
def test_render_populates_static_findings():
    # eval(...) + atob("...") = cluster obfuscation/exécution (>=2 rules dans
    # _OBF) -> corroboré, donc malicious même sans severity "critical" (le
    # re-tier 3d-2j a supprimé "critical" des patterns statiques).
    r, _ = render.render_html("<script>eval(atob('x'))</script>", "job-2")
    rules = {f.rule for f in r.static_findings}
    assert {"Dynamic code evaluation", "Base64 decode"} <= rules
    assert any(f.severity == "high" for f in r.static_findings)
    assert r.verdict == "malicious"


@pytest.mark.integration
def test_render_hostile_hanging_html_still_returns_result_with_static_findings():
    r, _ = render.render_html("<script>eval(atob('x')); while(true){}</script>", "job-hang",
                           render_timeout_ms=2000)
    assert r.job_id == "job-hang"
    rules = {f.rule for f in r.static_findings}
    assert {"Dynamic code evaluation", "Base64 decode"} <= rules  # static toujours calculé
