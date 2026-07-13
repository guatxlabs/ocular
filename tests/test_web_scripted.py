import fakeredis
from fastapi.testclient import TestClient

from bus.queue import RedisJobQueue
from web.app import _MAX_BODY_BYTES, app, get_queue


def _client(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer t"})
    return client, q


def test_submit_with_valid_steps_enqueues_normalized(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"url": "https://example.com", "profile": "capture",
              "steps": [{"click": "#a"}]},
    )
    assert r.status_code == 200
    job = q.dequeue(timeout=1)
    assert job.steps[-1] == {"capture": "final"}
    assert job.steps[0] == {"click": "#a"}


def test_submit_with_ssrf_goto_rejected(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"url": "https://example.com", "profile": "capture",
              "steps": [{"goto": "http://127.0.0.1/"}]},
    )
    assert r.status_code == 422
    assert q.dequeue(timeout=1) is None  # aucun step non validé n'atteint la file


def test_submit_with_oversize_steps_rejected(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"url": "https://example.com", "profile": "capture",
              "steps": [{"click": "#a"}] * 51},
    )
    assert r.status_code == 422
    assert q.dequeue(timeout=1) is None


def test_submit_with_forbidden_verb_rejected(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"url": "https://example.com", "profile": "capture",
              "steps": [{"evil": "x"}]},
    )
    assert r.status_code == 422
    assert q.dequeue(timeout=1) is None


def test_submit_steps_with_analysis_profile_rejected(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"html": "<h1>x</h1>", "profile": "analysis",
              "steps": [{"click": "#a"}]},
    )
    assert r.status_code == 422
    assert q.dequeue(timeout=1) is None


def test_submit_capture_without_steps_unchanged(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"url": "https://example.com", "profile": "capture"},
    )
    assert r.status_code == 200
    job = q.dequeue(timeout=1)
    assert job.steps is None


def test_submit_analysis_without_steps_unchanged(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"html": "<h1>x</h1>", "profile": "analysis"},
    )
    assert r.status_code == 200
    job = q.dequeue(timeout=1)
    assert job.steps is None


# --- FIX2 (audit 3c) : garde de taille de corps (413), anti-OOM avant Pydantic ---

def test_oversized_content_length_rejected_413(monkeypatch):
    client, q = _client(monkeypatch)
    # Content-Length forgé au-delà du plafond ; le corps réel reste petit —
    # la garde rejette sur le seul header, sans jamais lire/désérialiser le
    # corps (donc pas besoin d'envoyer réellement des dizaines de Mo ici).
    r = client.post(
        "/jobs",
        json={"url": "https://example.com", "profile": "capture", "steps": [{"click": "#a"}]},
        headers={"content-length": str(_MAX_BODY_BYTES + 1)},
    )
    assert r.status_code == 413
    assert q.dequeue(timeout=1) is None  # jamais désérialisé, jamais enqueue


def test_normal_body_unaffected_by_size_guard(monkeypatch):
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"url": "https://example.com", "profile": "capture",
              "steps": [{"click": "#a"}]},
    )
    assert r.status_code == 200  # corps légitime, sous le plafond : non affecté
    job = q.dequeue(timeout=1)
    assert job.steps[0] == {"click": "#a"}
