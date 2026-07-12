import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from broker.queue import RedisJobQueue


def _client(monkeypatch, token):
    if token is None:
        monkeypatch.delenv("OCULAR_TOKEN", raising=False)
    else:
        monkeypatch.setenv("OCULAR_TOKEN", token)
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(fakeredis.FakeStrictRedis())
    return TestClient(app, raise_server_exceptions=False)


def test_503_when_token_unset(monkeypatch):
    c = _client(monkeypatch, None)
    assert c.get("/jobs/x").status_code == 503


def test_503_when_token_empty_string(monkeypatch):
    c = _client(monkeypatch, "")
    assert c.get("/jobs/x").status_code == 503


def test_401_without_or_wrong_header(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    assert c.get("/jobs/x").status_code == 401
    assert c.get("/jobs/x", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_200_with_correct_bearer(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    r = c.get("/jobs/x", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200  # {"status":"pending"}
