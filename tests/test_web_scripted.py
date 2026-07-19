# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
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


# --- F2 (3f) : garde ASGI qui compte les octets réels (couvre chunked, sans Content-Length) ---
#
# NB : le vrai juge est l'e2e (POST `Transfer-Encoding: chunked` > plafond
# contre uvicorn -> 413 ; cf. commit). `TestClient`/httpx envoie TOUJOURS un
# `Content-Length` (jamais chunked), donc les tests via `_client` ne peuvent
# PAS exercer le chemin chunked ; on teste ici l'unité ASGI directement.
# Contrat vérifié : le middleware compte les octets `http.request`, émet
# LUI-MÊME un 413 via `send` au dépassement, coupe l'app via `http.disconnect`,
# et avale la réponse tardive de l'app (pas de double réponse).

def test_max_body_size_middleware_emits_413_and_cuts_on_streamed_overflow():
    from web.app import _MAX_BODY_BYTES, _BODY_TOO_LARGE_PAYLOAD
    from web.middleware import MaxBodySizeMiddleware

    chunk = b"x" * (_MAX_BODY_BYTES // 2 + 1)  # 2 chunks -> total > plafond
    messages = [
        {"type": "http.request", "body": chunk, "more_body": True},
        {"type": "http.request", "body": chunk, "more_body": False},
    ]

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    sent = []

    async def send(message):
        sent.append(message)

    received_types = []

    async def inner_app(scope, rcv, snd):
        # Imite un lecteur de corps (parsing route) : tire `receive` jusqu'à
        # fin de corps OU déconnexion. Sur déconnexion (le middleware a coupé),
        # tente une réponse d'erreur tardive — qui DOIT être avalée.
        while True:
            m = await rcv()
            received_types.append(m["type"])
            if m["type"] == "http.disconnect":
                await snd({"type": "http.response.start", "status": 400, "headers": []})
                await snd({"type": "http.response.body", "body": b"late"})
                return
            if not m.get("more_body", False):  # corps complet -> route atteinte
                await snd({"type": "http.response.start", "status": 200, "headers": []})
                await snd({"type": "http.response.body", "body": b"ok"})
                return

    scope = {"type": "http", "path": "/jobs", "method": "POST", "headers": []}
    import asyncio
    asyncio.run(MaxBodySizeMiddleware(inner_app, max_bytes=_MAX_BODY_BYTES, payload=_BODY_TOO_LARGE_PAYLOAD)(scope, receive, send))

    # le middleware a émis un 413...
    starts = [m for m in sent if m["type"] == "http.response.start"]
    assert len(starts) == 1  # exactement une réponse (pas de double)
    assert starts[0]["status"] == 413
    # ...et l'app a été coupée (elle a reçu un http.disconnect, jamais le corps complet)
    assert "http.disconnect" in received_types


def test_max_body_size_middleware_lets_small_streamed_body_through():
    # Unité : total sous le plafond -> l'app enveloppée est appelée, lit son
    # corps complet, et SA réponse 200 passe (le middleware ne coupe pas).
    from web.app import _MAX_BODY_BYTES, _BODY_TOO_LARGE_PAYLOAD
    from web.middleware import MaxBodySizeMiddleware

    messages = [{"type": "http.request", "body": b"small", "more_body": False}]

    async def receive():
        if messages:
            return messages.pop(0)
        return {"type": "http.disconnect"}

    sent = []

    async def send(message):
        sent.append(message)

    async def inner_app(scope, rcv, snd):
        m = await rcv()
        assert m["type"] == "http.request" and m.get("more_body", False) is False
        await snd({"type": "http.response.start", "status": 200, "headers": []})
        await snd({"type": "http.response.body", "body": b"ok"})

    scope = {"type": "http", "path": "/jobs", "method": "POST", "headers": []}
    import asyncio
    asyncio.run(MaxBodySizeMiddleware(inner_app, max_bytes=_MAX_BODY_BYTES, payload=_BODY_TOO_LARGE_PAYLOAD)(scope, receive, send))

    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 200  # réponse de l'app, non altérée


def test_small_post_reaches_route_normally(monkeypatch):
    # Bout-en-bout via TestClient : un POST légitime (petit corps, en dessous
    # du plafond) traverse la nouvelle garde ASGI sans être affecté.
    client, q = _client(monkeypatch)
    r = client.post(
        "/jobs",
        json={"url": "https://example.com", "profile": "capture",
              "steps": [{"click": "#a"}]},
    )
    assert r.status_code == 200
    job = q.dequeue(timeout=1)
    assert job.steps[0] == {"click": "#a"}


def test_get_request_unaffected_by_new_guard(monkeypatch):
    client, _ = _client(monkeypatch)
    r = client.get("/jobs/unknown-id")
    assert r.status_code == 200
    # id inconnu -> terminal "unknown" (anti job fantôme, Phase 3k), pas "pending"
    assert r.json()["status"] == "unknown"
