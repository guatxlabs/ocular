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


def test_get_pending_job(monkeypatch):
    client, _ = _client(monkeypatch)
    r = client.get("/jobs/unknown-id")
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


def test_web_package_never_imports_docker():
    import pathlib
    for f in pathlib.Path("web").rglob("*.py"):
        text = f.read_text()
        assert "docker" not in text.lower(), f"{f} ne doit pas référencer docker"
        assert "broker.launcher" not in text, f"{f} ne doit pas importer broker.launcher"
        assert "subprocess" not in text, f"{f} ne doit pas utiliser subprocess"
