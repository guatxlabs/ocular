from runner_recon.capture import build_result


def test_build_result_capture_profile_and_hash():
    r, blobs = build_result(
        url="https://example.com/x",
        screenshots=[(0, "initial", b"\x89PNG\r\n\x1a\nAAA")],
        network=[{"url": "https://example.com/x", "method": "GET", "status": 200}],
        console=[], dom_html=b"<script>eval(atob('x'))</script>",
        title="t", final_url="https://example.com/x", turnstile_solved=True,
    )
    assert r.profile == "capture"
    assert r.stealth.engine == "camoufox" and r.stealth.turnstile_solved is True
    assert r.input_hash.startswith("sha256:")
    assert r.verdict == "malicious"          # static détecte eval/atob dans le DOM capturé
    assert r.screenshots[0].image_ref in blobs
    # le DOM est aussi un blob
    assert r.artifacts.dom_html_ref in blobs
