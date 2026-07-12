import pytest

render = pytest.importorskip("runner_analysis.render")


@pytest.mark.integration
def test_render_benign_html_produces_screenshot_and_dom():
    r = render.render_html("<html><title>Hi</title><body>hello</body></html>", "job-1")
    assert r.profile == "analysis"
    assert r.screenshots and r.screenshots[0].image_ref.startswith("sha256:")
    assert r.dom.title == "Hi"


@pytest.mark.integration
def test_render_populates_static_findings():
    r = render.render_html("<script>eval(atob('x'))</script>", "job-2")
    assert any(f.severity == "critical" for f in r.static_findings)
