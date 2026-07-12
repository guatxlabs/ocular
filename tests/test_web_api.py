import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from broker.queue import RedisJobQueue


def _client():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    return TestClient(app), q


def test_post_job_returns_job_id_and_enqueues():
    client, q = _client()
    r = client.post("/jobs", json={"profile": "analysis", "html": "<h1>x</h1>"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert q.dequeue(timeout=1).job_id == job_id


def test_get_pending_job():
    client, _ = _client()
    r = client.get("/jobs/unknown-id")
    assert r.json()["status"] == "pending"


def test_get_completed_job_returns_stored_result():
    client, q = _client()
    q.set_result("job-done", '{"job_id": "job-done", "verdict": "malicious"}')
    r = client.get("/jobs/job-done")
    assert r.status_code == 200
    assert r.json()["verdict"] == "malicious"


def test_web_package_never_imports_docker():
    import pathlib
    for f in pathlib.Path("web").rglob("*.py"):
        text = f.read_text()
        assert "docker" not in text.lower(), f"{f} ne doit pas référencer docker"
        assert "broker.launcher" not in text, f"{f} ne doit pas importer broker.launcher"
        assert "subprocess" not in text, f"{f} ne doit pas utiliser subprocess"
