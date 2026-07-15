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

def test_max_body_size_middleware_cuts_streamed_body_over_limit():
    # Unité : le middleware ASGI pur reçoit des chunks `http.request` dont le
    # total dépasse _MAX_BODY_BYTES SANS jamais déclarer de Content-Length
    # (simule un corps chunked). Il doit répondre 413 et la garde doit couper
    # AVANT que le handler de route enveloppé ne soit atteint.
    from web.app import _MAX_BODY_BYTES, _MaxBodySizeMiddleware

    chunk = b"x" * (_MAX_BODY_BYTES // 2 + 1)
    messages = [
        {"type": "http.request", "body": chunk, "more_body": True},
        {"type": "http.request", "body": chunk, "more_body": False},
    ]

    async def receive():
        return messages.pop(0)

    sent = []

    async def send(message):
        sent.append(message)

    endpoint_reached = False

    async def inner_app(scope, receive, send):
        # Comme le vrai empilement Starlette/FastAPI : le corps est tiré via
        # `receive` (parsing Pydantic) AVANT que le handler de route ne soit
        # atteint. Le dépassement doit couper pendant ce tirage, donc le
        # handler de route (`endpoint_reached`) ne doit jamais s'exécuter.
        nonlocal endpoint_reached
        more = True
        while more:
            message = await receive()
            more = message.get("more_body", False)
        endpoint_reached = True  # jamais atteint si la garde a coupé avant

    middleware = _MaxBodySizeMiddleware(inner_app)
    scope = {"type": "http", "path": "/jobs", "method": "POST", "headers": []}

    import asyncio
    asyncio.run(middleware(scope, receive, send))

    assert endpoint_reached is False  # coupé avant d'atteindre la route
    start = next(m for m in sent if m["type"] == "http.response.start")
    assert start["status"] == 413


def test_max_body_size_middleware_lets_small_streamed_body_through():
    # Unité : total sous le plafond -> l'app enveloppée est bien appelée,
    # aucun 413 n'est émis par le middleware lui-même.
    from web.app import _MaxBodySizeMiddleware

    messages = [{"type": "http.request", "body": b"small", "more_body": False}]

    async def receive():
        return messages.pop(0)

    async def send(message):
        pass

    inner_app_called = False

    async def inner_app(scope, receive, send):
        nonlocal inner_app_called
        inner_app_called = True
        await receive()  # consomme le seul message, comme le ferait une vraie route

    middleware = _MaxBodySizeMiddleware(inner_app)
    scope = {"type": "http", "path": "/jobs", "method": "POST", "headers": []}

    import asyncio
    asyncio.run(middleware(scope, receive, send))

    assert inner_app_called is True


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
    assert r.json()["status"] == "pending"
