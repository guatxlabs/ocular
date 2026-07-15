import base64
import hashlib
import json

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
    # même instance redis pour queue/registry/cmd_queue (comme en prod : un seul
    # Redis, des préfixes de clé différents) — nécessaire pour que le résultat
    # posé par /capture reste lisible par un GET /jobs/{id} ultérieur.
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(redis_client)
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
    seen = {}

    def fake_post(url, payload, secret, timeout=5.0):
        seen["secret"] = secret
        return True

    monkeypatch.setattr(app_mod, "_internal_post_json", fake_post)

    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["session_id"].startswith("sess-")
    assert isinstance(body["token"], str) and len(body["token"]) > 20
    # le secret de session n'est JAMAIS renvoyé (comme le token WS l'est mais
    # pas le secret conteneur) — anti-fuite frontière conteneur
    assert "secret" not in body
    assert "session_secret" not in r.text

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["action"] == "launch"
    assert cmd["session_id"] == body["session_id"]
    assert cmd["token"] == body["token"]
    # Task H : la cible enqueue est l'URL NORMALISÉE (path vide -> "/").
    assert cmd["target"] == "https://example.com/"
    # un secret conteneur, distinct du token WS, est enqueue vers le broker
    assert cmd["secret"] and cmd["secret"] != body["token"]
    # et le web signe son appel /goto interne avec CE secret
    assert seen["secret"] == cmd["secret"]


def test_create_session_bare_domain_normalized_to_https(monkeypatch):
    # Task H : même normalisation qu'à la soumission d'un job capture — un
    # domaine nu devient "https://..." AVANT la garde SSRF et le launch.
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda registry, sid, deadline: True)
    monkeypatch.setattr(app_mod, "_internal_post_json", lambda *a, **k: True)

    r = client.post("/sessions", json={"url": "example.com"})
    assert r.status_code == 200

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["target"] == "https://example.com/"


def test_create_session_explicit_http_scheme_respected(monkeypatch):
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda registry, sid, deadline: True)
    monkeypatch.setattr(app_mod, "_internal_post_json", lambda *a, **k: True)

    r = client.post("/sessions", json={"url": "http://example.com"})
    assert r.status_code == 200

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["target"] == "http://example.com/"


def test_create_session_html_uses_load_endpoint(monkeypatch):
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: True)
    calls = []

    def fake_post(url, payload, secret, timeout=5.0):
        calls.append((url, payload, secret))
        return True

    monkeypatch.setattr(app_mod, "_internal_post_json", fake_post)

    r = client.post("/sessions", json={"html": "<h1>x</h1>"})
    assert r.status_code == 200
    assert len(calls) == 1
    assert calls[0][0].endswith("/load")
    assert calls[0][1] == {"html": "<h1>x</h1>"}

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["target"] == "inline-html"
    # le secret enqueue est bien celui utilisé pour signer /load
    assert calls[0][2] == cmd["secret"]


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
        token="super-secret-token", secret="super-secret-container",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    r = client.get("/sessions")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert "token" not in body[0]
    assert "secret" not in body[0]
    assert "super-secret-token" not in r.text
    assert "super-secret-container" not in r.text
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


def test_capture_unknown_session_returns_404(monkeypatch):
    client, *_ = _client(monkeypatch)
    r = client.post("/sessions/does-not-exist/capture")
    assert r.status_code == 404


def test_capture_requires_auth(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    redis_client = fakeredis.FakeStrictRedis()
    app.dependency_overrides[get_session_registry] = lambda: SessionRegistry(redis_client)
    app.dependency_overrides[get_cmd_queue] = lambda: SessionCmdQueue(redis_client)
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(redis_client)
    client = TestClient(app)
    r = client.post("/sessions/s1/capture")
    assert r.status_code == 401


def test_capture_stores_blobs_and_returns_lean_result(monkeypatch, tmp_path):
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path))
    client, registry, _ = _client(monkeypatch)
    registry.create(
        "s1", container="ocular-sess-s1", kind="recon-vnc", target="https://example.com",
        token="tok", secret="cap-secret", now_iso="2026-07-13T10:00:00+00:00",
    )
    data = b"PNGDATA"
    ref = "sha256:" + hashlib.sha256(data).hexdigest()  # ref cohérent : store_blobs vérifie l'intégrité
    wrapper = {
        "result": {"job_id": "", "profile": "capture", "target": "https://example.com",
                   "timestamp": "now", "schema_version": "1.0"},
        "blobs": {ref: base64.b64encode(data).decode(),
                  "../evil": base64.b64encode(b"x").decode()},
    }
    calls = []

    def fake_capture(url, secret, timeout=30.0):
        calls.append((url, secret))
        return wrapper

    monkeypatch.setattr(app_mod, "_internal_capture", fake_capture)

    r = client.post("/sessions/s1/capture")
    assert r.status_code == 200
    # le web signe /capture avec le secret conteneur lu dans le registre
    assert calls == [("http://ocular-sess-s1:8090/capture", "cap-secret")]

    body = r.json()
    assert "blobs" not in body
    assert body["target"] == "https://example.com"

    # artefact stocké de façon sûre (anti-traversal : "../evil" ignoré)
    fname = "sha256_" + hashlib.sha256(data).hexdigest()
    assert (tmp_path / fname).read_bytes() == data
    assert list(tmp_path.iterdir()) == [tmp_path / fname]

    # résultat léger retrouvable via GET /jobs/{id} comme un job normal
    assert body["job_id"]
    r2 = client.get(f"/jobs/{body['job_id']}")
    assert r2.status_code == 200
    assert r2.json() == body

    # touch : last_activity rafraîchi vers l'heure réelle de la requête,
    # donc différent de l'horodatage figé posé à la création de la session
    sess = registry.get("s1")
    assert sess["last_activity"] != sess["created_at"]


def test_capture_session_server_error_returns_502(monkeypatch):
    client, registry, _ = _client(monkeypatch)
    registry.create(
        "s1", container="ocular-sess-s1", kind="recon-vnc", target="https://example.com",
        token="tok", now_iso="2026-07-13T10:00:00+00:00",
    )

    def boom(url, secret, timeout=30.0):
        raise app_mod._CaptureError("boom")

    monkeypatch.setattr(app_mod, "_internal_capture", boom)

    r = client.post("/sessions/s1/capture")
    assert r.status_code == 502


def test_web_sessions_module_never_imports_docker():
    import pathlib
    for f in pathlib.Path("web").rglob("*.py"):
        text = f.read_text()
        assert "docker" not in text.lower(), f"{f} ne doit pas référencer docker"
        assert "broker.launcher" not in text, f"{f} ne doit pas importer broker.launcher"
        assert "subprocess" not in text, f"{f} ne doit pas utiliser subprocess"
