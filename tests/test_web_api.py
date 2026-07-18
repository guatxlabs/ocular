import json

import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from bus.queue import RedisJobQueue


def _client(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer t"})
    return client, q


def test_post_job_returns_job_id_and_enqueues(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post("/jobs", json={"profile": "analysis", "html": "<h1>x</h1>"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert q.dequeue(timeout=1).job_id == job_id


def test_get_unknown_job_is_terminal_not_pending(monkeypatch):
    # Phase 3k : un id jamais soumis (ou dont le marqueur d'acceptation a expiré /
    # Redis vidé par un down/up) est TERMINAL "unknown" — plus jamais "pending"
    # à l'infini (anti job fantôme qui poll sans fin).
    client, _ = _client(monkeypatch)
    r = client.get("/jobs/unknown-id")
    assert r.json()["status"] == "unknown"


def test_get_accepted_job_is_pending(monkeypatch):
    # Un job réellement soumis (marqueur d'acceptation présent) et pas encore
    # terminé reste "pending".
    client, _ = _client(monkeypatch)
    job_id = client.post("/jobs", json={"profile": "analysis", "html": "<h1>x</h1>"}).json()["job_id"]
    r = client.get("/jobs/" + job_id)
    assert r.json()["status"] == "pending"


def test_get_completed_job_returns_stored_result(monkeypatch):
    client, q = _client(monkeypatch)
    q.set_result("job-done", '{"job_id": "job-done", "verdict": "malicious"}')
    r = client.get("/jobs/job-done")
    assert r.status_code == 200
    assert r.json()["verdict"] == "malicious"


def test_oversized_html_rejected(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    monkeypatch.setenv("OCULAR_MAX_HTML_BYTES", "100")
    client = _client(monkeypatch)[0]
    r = client.post("/jobs", json={"profile": "analysis", "html": "x" * 200})
    assert r.status_code == 422


def test_invalid_profile_rejected(monkeypatch):
    client = _client(monkeypatch)[0]
    r = client.post("/jobs", json={"profile": "capture", "html": "x"})
    assert r.status_code == 422


def test_oversized_url_rejected(monkeypatch):
    client = _client(monkeypatch)[0]
    r = client.post("/jobs", json={"profile": "analysis", "url": "x" * 5000})
    assert r.status_code == 422


def test_capture_requires_url(monkeypatch):
    c = _client(monkeypatch)[0]
    assert c.post("/jobs", json={"profile": "capture"}).status_code == 422
    r = c.post("/jobs", json={"profile": "capture", "url": "https://example.com"})
    assert r.status_code == 200


def test_analysis_requires_html(monkeypatch):
    c = _client(monkeypatch)[0]
    assert c.post("/jobs", json={"profile": "analysis"}).status_code == 422


def test_capture_ssrf_url_rejected(monkeypatch):
    c = _client(monkeypatch)[0]
    r = c.post("/jobs", json={"profile": "capture", "url": "http://127.0.0.1"})
    assert r.status_code == 400


# --- Task H : normalisation schéma URL à la soumission (avant SSRF, avant enqueue) ---


def test_capture_bare_domain_normalized_to_https_before_enqueue(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post("/jobs", json={"profile": "capture", "url": "example.com"})
    assert r.status_code == 200
    job = q.dequeue(timeout=1)
    assert job.url == "https://example.com/"


def test_capture_explicit_http_scheme_respected_at_submission(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post("/jobs", json={"profile": "capture", "url": "http://example.com"})
    assert r.status_code == 200
    job = q.dequeue(timeout=1)
    assert job.url == "http://example.com/"


def test_capture_bare_private_ip_still_ssrf_rejected_after_normalization(monkeypatch):
    # La normalisation ne doit PAS contourner la garde SSRF : un domaine nu
    # désignant une IP privée reste rejeté une fois "https://" préfixé.
    c = _client(monkeypatch)[0]
    r = c.post("/jobs", json={"profile": "capture", "url": "127.0.0.1"})
    assert r.status_code == 400


def test_web_package_never_imports_docker():
    import pathlib
    for f in pathlib.Path("web").rglob("*.py"):
        text = f.read_text()
        assert "docker" not in text.lower(), f"{f} ne doit pas référencer docker"
        assert "broker.launcher" not in text, f"{f} ne doit pas importer broker.launcher"
        assert "subprocess" not in text, f"{f} ne doit pas utiliser subprocess"


# --- Task 9 : option LLM d'explication (POST /jobs/{id}/explain) -------------

def test_explain_disabled_by_default_is_404(monkeypatch):
    # OFF par défaut : sans OCULAR_LLM_ENABLED, l'endpoint renvoie 404 et
    # n'émet AUCUN appel réseau (on n'atteint même pas get_result).
    monkeypatch.delenv("OCULAR_LLM_ENABLED", raising=False)
    monkeypatch.delenv("OCULAR_LLM_BASE_URL", raising=False)
    client = _client(monkeypatch)[0]
    r = client.post("/jobs/whatever/explain")
    assert r.status_code == 404


def test_llm_summary_excludes_raw_html_and_artifacts(monkeypatch):
    # Garde anti-exfil : le résumé envoyé au LLM ne doit JAMAIS contenir le HTML
    # brut, les artefacts (dom_html_ref/har_ref), les screenshots, ni les
    # post-bodies réseau — seulement verdict/triage + findings réduits (rule/
    # severity) et dom réduit (forms/mailtos).
    from web.app import _llm_summary_payload

    RAW_HTML = "<html><body>SECRET PASSWORD leak</body></html>"
    result = {
        "verdict": "malicious",
        "triage": {
            "score": 88,
            "band": "high",
            "second_opinion": "suspicious",
            "agrees_with_rules": True,
            "weights_version": "BUILTIN",
            "signals": [{"key": "mailto_exfil", "label": "mailto", "weight": 20.0, "detail": "1 mailto:"}],
        },
        "static_findings": [
            {"rule": "phish_kw", "severity": "high", "match": "SECRET PASSWORD leak", "line": 1, "context": RAW_HTML},
        ],
        "dom": {
            "title": "x",
            "forms": [{"action": "https://evil.example/steal", "method": "POST"}],
            "mailtos": ["drop@evil.example"],
            "links": ["https://evil.example"],
        },
        "html": RAW_HTML,
        "dom_html": RAW_HTML,
        "screenshots": [{"step": 0, "phase": "final", "image_ref": "sha256:abc", "viewport": "1920x1080"}],
        "network": [{"url": "https://evil.example/steal", "method": "POST", "post_data": "user=a&pw=SECRET"}],
        "artifacts": {"dom_html_ref": "sha256:deadbeef", "har_ref": "sha256:cafe"},
    }

    summary = _llm_summary_payload(result)

    # Contient bien ce qui doit être présent
    assert summary["verdict"] == "malicious"
    assert summary["triage"]["score"] == 88
    assert summary["triage"]["band"] == "high"
    assert summary["triage"]["second_opinion"] == "suspicious"
    assert summary["static_findings"] == [{"rule": "phish_kw", "severity": "high"}]
    assert summary["dom"] == {
        "forms": [{"action": "https://evil.example/steal", "method": "POST"}],
        "mailtos": ["drop@evil.example"],
    }

    # NE contient AUCUN champ sensible, à aucune profondeur
    blob = json.dumps(summary)
    assert "artifacts" not in summary
    assert "screenshots" not in summary
    assert "html" not in summary
    assert "dom_html" not in summary
    assert "network" not in summary
    assert RAW_HTML not in blob            # le HTML brut ne fuit nulle part
    assert "SECRET PASSWORD" not in blob   # ni via match/context d'un finding
    assert "sha256:deadbeef" not in blob   # ni les refs d'artefact
    assert "user=a&pw=SECRET" not in blob  # ni les post-bodies réseau


def test_explain_internal_host_refused_without_optin(monkeypatch):
    # Garde egress : base_url loopback SANS OCULAR_LLM_ALLOW_INTERNAL doit être
    # refusée (502) AVANT tout appel sortant. On piège urlopen pour prouver
    # qu'aucune connexion n'est ouverte.
    import urllib.request

    monkeypatch.setenv("OCULAR_LLM_ENABLED", "1")
    monkeypatch.setenv("OCULAR_LLM_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("OCULAR_LLM_MODEL", "whatever")
    monkeypatch.delenv("OCULAR_LLM_ALLOW_INTERNAL", raising=False)

    def _boom(*a, **k):  # pragma: no cover - ne doit jamais être appelé
        raise AssertionError("aucun appel urlopen ne doit être émis pour un hôte interne")

    monkeypatch.setattr(urllib.request, "urlopen", _boom)

    client, q = _client(monkeypatch)
    q.set_result("job-x", json.dumps({"verdict": "suspicious", "triage": None,
                                       "static_findings": [], "dom": {"forms": [], "mailtos": []}}))
    r = client.post("/jobs/job-x/explain")
    assert r.status_code == 502
