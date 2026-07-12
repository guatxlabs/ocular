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


def test_web_package_never_imports_docker():
    import pathlib
    src = pathlib.Path("web").rglob("*.py")
    for f in src:
        text = f.read_text()
        assert "docker" not in text.lower(), f"{f} ne doit pas référencer docker"
