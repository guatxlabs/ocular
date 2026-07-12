import fakeredis
from fastapi.testclient import TestClient

import web.app as app_mod
from web.app import app, get_cmd_queue, get_queue, get_session_registry
from bus.queue import RedisJobQueue
from bus.sessions import SessionCmdQueue, SessionRegistry


def _client(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    redis_client = fakeredis.FakeStrictRedis()
    registry = SessionRegistry(redis_client)
    cmd_queue = SessionCmdQueue(redis_client)
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_session_registry] = lambda: registry
    app.dependency_overrides[get_cmd_queue] = lambda: cmd_queue
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer t"})
    return client, registry, cmd_queue


def test_create_session_requires_auth(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    redis_client = fakeredis.FakeStrictRedis()
    app.dependency_overrides[get_session_registry] = lambda: SessionRegistry(redis_client)
    app.dependency_overrides[get_cmd_queue] = lambda: SessionCmdQueue(redis_client)
    client = TestClient(app)
    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 401


def test_create_session_ssrf_url_rejected(monkeypatch):
    client, _, cmd_queue = _client(monkeypatch)
    r = client.post("/sessions", json={"url": "http://127.0.0.1"})
    assert r.status_code == 400
    assert cmd_queue.dequeue_cmd(timeout=1) is None  # rien enqueue avant validation


def test_create_session_requires_url_or_html(monkeypatch):
    client, *_ = _client(monkeypatch)
    r = client.post("/sessions", json={})
    assert r.status_code == 422


def test_create_session_oversized_html_rejected(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_HTML_BYTES", "10")
    client, *_ = _client(monkeypatch)
    r = client.post("/sessions", json={"html": "x" * 100})
    assert r.status_code == 422


def test_create_session_success_url_returns_token_and_enqueues_launch(monkeypatch):
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda registry, sid, deadline: True)
    monkeypatch.setattr(app_mod, "_internal_post_json", lambda url, payload, timeout=5.0: True)

    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"].startswith("sess-")
    assert isinstance(body["token"], str) and len(body["token"]) > 20

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["action"] == "launch"
    assert cmd["session_id"] == body["session_id"]
    assert cmd["token"] == body["token"]
    assert cmd["target"] == "https://example.com"


def test_create_session_html_uses_load_endpoint(monkeypatch):
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: True)
    calls = []

    def fake_post(url, payload, timeout=5.0):
        calls.append((url, payload))
        return True

    monkeypatch.setattr(app_mod, "_internal_post_json", fake_post)

    r = client.post("/sessions", json={"html": "<h1>x</h1>"})
    assert r.status_code == 200
    assert len(calls) == 1
    assert calls[0][0].endswith("/load")
    assert calls[0][1] == {"html": "<h1>x</h1>"}

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["target"] == "inline-html"


def test_create_session_timeout_returns_504_and_enqueues_stop(monkeypatch):
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: False)

    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 504

    launch_cmd = cmd_queue.dequeue_cmd(timeout=1)
    stop_cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert launch_cmd["action"] == "launch"
    assert stop_cmd == {"action": "stop", "session_id": launch_cmd["session_id"]}


def test_list_sessions_excludes_token(monkeypatch):
    client, registry, _ = _client(monkeypatch)
    registry.create(
        "s1", container="ocular-sess-s1", kind="recon-vnc", target="https://example.com",
        token="super-secret-token", now_iso="2026-07-13T10:00:00+00:00",
    )
    r = client.get("/sessions")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert "token" not in body[0]
    assert "super-secret-token" not in r.text
    assert body[0]["session_id"] == "s1"
    assert body[0]["container"] == "ocular-sess-s1"


def test_delete_session_enqueues_stop_and_removes_registry_entry(monkeypatch):
    client, registry, cmd_queue = _client(monkeypatch)
    registry.create(
        "s1", container="ocular-sess-s1", kind="recon-vnc", target="t",
        token="tok", now_iso="2026-07-13T10:00:00+00:00",
    )

    r = client.delete("/sessions/s1")
    assert r.status_code == 200
    assert r.json() == {"deleted": "s1"}
    assert registry.get("s1") is None

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd == {"action": "stop", "session_id": "s1"}


def test_web_sessions_module_never_imports_docker():
    import pathlib
    for f in pathlib.Path("web").rglob("*.py"):
        text = f.read_text()
        assert "docker" not in text.lower(), f"{f} ne doit pas référencer docker"
        assert "broker.launcher" not in text, f"{f} ne doit pas importer broker.launcher"
        assert "subprocess" not in text, f"{f} ne doit pas utiliser subprocess"
