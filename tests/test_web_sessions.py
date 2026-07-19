# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import hashlib
import json

import fakeredis
import pytest
from fastapi.testclient import TestClient

import web.app as app_mod
from web.app import app, get_cmd_queue, get_queue, get_session_registry
from bus.queue import RedisJobQueue
from bus.sessions import SessionCmdQueue, SessionRegistry

# Format RÉEL des identifiants de session (cf. create_session : "sess-" +
# uuid4().hex[:12]) — les routes de session ne valident QUE celui-ci.
_SID = "sess-0123456789ab"

# Propriétaire inscrit par `create_session` en mode bearer (défaut) : TOUS les
# porteurs du jeton partagé ont l'identité "token" (cf. `resolve_identity`), donc
# une session semée pour ces tests doit porter ce propriétaire — sans quoi elle
# est « sans propriétaire » et refusée aux non-admins (fail-closed).
_BEARER_OWNER = "token"


def _inline_bootstrap(monkeypatch):
    """Exécute l'amorçage de session (attente + navigation initiale) EN LIGNE
    au lieu du thread démon de production. `POST /sessions` ne l'attend plus
    (202 immédiat) : sans cette bascule, un test qui vérifie l'appel `/goto`
    courserait un thread. Elle ne remet PAS l'attente sur le chemin de requête
    — c'est le test dédié `test_create_session_does_not_wait_on_request_path`
    qui verrouille ce point, sans cette bascule."""
    monkeypatch.setattr(
        app_mod, "_spawn_session_bootstrap", lambda *a: app_mod._session_bootstrap(*a)
    )


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
    _inline_bootstrap(monkeypatch)
    seen = {}

    def fake_post(url, payload, secret, timeout=5.0):
        seen["secret"] = secret
        return True

    monkeypatch.setattr(app_mod, "_internal_post_json", fake_post)

    r = client.post("/sessions", json={"url": "https://example.com"})
    # 202 Accepted : la session est acceptée, PAS encore prête (le client sonde
    # ensuite `GET /sessions/{id}`).
    assert r.status_code == 202
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
    _inline_bootstrap(monkeypatch)

    r = client.post("/sessions", json={"url": "example.com"})
    assert r.status_code == 202

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["target"] == "https://example.com/"


def test_create_session_explicit_http_scheme_respected(monkeypatch):
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda registry, sid, deadline: True)
    monkeypatch.setattr(app_mod, "_internal_post_json", lambda *a, **k: True)
    _inline_bootstrap(monkeypatch)

    r = client.post("/sessions", json={"url": "http://example.com"})
    assert r.status_code == 202

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["target"] == "http://example.com/"


def test_create_session_html_uses_load_endpoint(monkeypatch):
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: True)
    _inline_bootstrap(monkeypatch)
    calls = []

    def fake_post(url, payload, secret, timeout=5.0):
        calls.append((url, payload, secret))
        return True

    monkeypatch.setattr(app_mod, "_internal_post_json", fake_post)

    r = client.post("/sessions", json={"html": "<h1>x</h1>"})
    assert r.status_code == 202
    assert len(calls) == 1
    assert calls[0][0].endswith("/load")
    assert calls[0][1] == {"html": "<h1>x</h1>"}

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["target"] == "inline-html"
    # le secret enqueue est bien celui utilisé pour signer /load
    assert calls[0][2] == cmd["secret"]


def test_create_session_timeout_still_answers_202_and_enqueues_stop(monkeypatch):
    """Un démarrage qui n'aboutit pas ne rend PLUS 504 : le client a déjà reçu
    son 202 et son `session_id` — c'est la sonde qui lui apprendra l'échec. Le
    filet de sécurité serveur (stop du conteneur) est conservé, simplement
    déplacé dans l'amorçage."""
    client, _, cmd_queue = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: False)
    _inline_bootstrap(monkeypatch)

    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 202
    assert r.json()["session_id"].startswith("sess-")

    launch_cmd = cmd_queue.dequeue_cmd(timeout=1)
    stop_cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert launch_cmd["action"] == "launch"
    assert stop_cmd == {"action": "stop", "session_id": launch_cmd["session_id"]}


def test_list_sessions_excludes_token(monkeypatch):
    client, registry, _ = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="https://example.com",
        token="super-secret-token", secret="super-secret-container",
        owner=_BEARER_OWNER, now_iso="2026-07-13T10:00:00+00:00",
    )
    r = client.get("/sessions")
    assert r.status_code == 200
    body = r.json()
    assert len(body) == 1
    assert "token" not in body[0]
    assert "secret" not in body[0]
    assert "super-secret-token" not in r.text
    assert "super-secret-container" not in r.text
    assert body[0]["session_id"] == _SID
    assert body[0]["container"] == "ocular-sess-" + _SID


def test_delete_session_enqueues_stop_and_removes_registry_entry(monkeypatch):
    client, registry, cmd_queue = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="t",
        token="tok", owner=_BEARER_OWNER, now_iso="2026-07-13T10:00:00+00:00",
    )

    r = client.delete(f"/sessions/{_SID}")
    assert r.status_code == 200
    assert r.json() == {"deleted": _SID}
    assert registry.get(_SID) is None

    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd == {"action": "stop", "session_id": _SID}


# --- Défaut E : un session_id hors format ne doit atteindre NI le broker,
# --- NI le registre. `DELETE /sessions/*` était enqueue tel quel vers le
# --- broker, dont `purge_session_results` l'interpole dans un GLOB Redis :
# --- une seule requête purgeait les captures éphémères de TOUTES les sessions.

# Métacaractères de glob Redis + formats simplement hors-contrat. `?` est
# passé PERCENT-ENCODÉ : envoyé brut il ouvrirait une query string côté client
# HTTP et n'atteindrait jamais la route (il arrive bien décodé côté serveur).
_HOSTILE_SESSION_IDS = ["*", "%3F", "s*", "[a-z]1", "sess-XYZ", "sess-0123456789abc", "sess-0123456789ab "]


@pytest.mark.parametrize("hostile", _HOSTILE_SESSION_IDS)
def test_delete_session_rejects_malformed_session_id(monkeypatch, hostile):
    client, registry, cmd_queue = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="t",
        token="tok", owner=_BEARER_OWNER, now_iso="2026-07-13T10:00:00+00:00",
    )

    r = client.delete("/sessions/" + hostile)

    assert r.status_code == 404, hostile
    # AUCUNE commande n'atteint le broker (donc aucune purge Redis élargie)...
    assert cmd_queue.dequeue_cmd(timeout=1) is None, hostile
    # ...et la session légitime est intacte.
    assert registry.get(_SID) is not None, hostile


@pytest.mark.parametrize("hostile", _HOSTILE_SESSION_IDS)
def test_capture_and_live_reject_malformed_session_id(monkeypatch, hostile):
    client, *_ = _client(monkeypatch)
    assert client.post(f"/sessions/{hostile}/capture").status_code == 404, hostile
    assert client.get(f"/sessions/{hostile}/live").status_code == 404, hostile


def test_ws_proxy_rejects_malformed_session_id_before_any_registry_lookup(monkeypatch):
    """Le proxy WS applique la MÊME grille : fermeture 1008 sur un id hors
    format, et ce AVANT toute interrogation du registre (le gabarit est un
    filtre d'entrée, pas un effet de bord de l'échec d'authentification)."""
    from starlette.websockets import WebSocketDisconnect

    client, registry, _ = _client(monkeypatch)
    looked_up = []
    monkeypatch.setattr(
        type(registry), "valid_token",
        lambda self, sid, token: looked_up.append(sid) or True,
    )

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            "/sessions/*/ws", subprotocols=["binary", "ocular.session.tok"]
        ):
            pass

    assert exc.value.code == 1008
    assert looked_up == []


def test_delete_session_still_works_for_a_wellformed_id(monkeypatch):
    """Contre-épreuve : la validation ne casse pas le chemin nominal, au format
    RÉELLEMENT produit par create_session (`sess-` + 12 hexs)."""
    client, registry, cmd_queue = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="t",
        token="tok", owner=_BEARER_OWNER, now_iso="2026-07-13T10:00:00+00:00",
    )

    r = client.delete("/sessions/" + _SID)

    assert r.status_code == 200
    assert r.json() == {"deleted": _SID}
    assert registry.get(_SID) is None
    assert cmd_queue.dequeue_cmd(timeout=1) == {"action": "stop", "session_id": _SID}


def test_created_session_id_matches_the_validated_format(monkeypatch):
    """Verrou anti-dérive : le format accepté par les routes est exactement
    celui que `create_session` génère (si l'un bouge sans l'autre, toute session
    neuve deviendrait immédiatement introuvable)."""
    import re
    client, _, _ = _client(monkeypatch)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: True)
    monkeypatch.setattr(app_mod, "_internal_post_json", lambda *a, **k: True)

    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 202
    assert re.fullmatch(r"sess-[0-9a-f]{12}", r.json()["session_id"])


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
    r = client.post(f"/sessions/{_SID}/capture")
    assert r.status_code == 401


def test_capture_stores_blobs_and_returns_lean_result(monkeypatch, tmp_path):
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path))
    client, registry, _ = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="https://example.com",
        token="tok", secret="cap-secret", owner=_BEARER_OWNER,
        now_iso="2026-07-13T10:00:00+00:00",
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

    def fake_capture(url, secret, timeout=30.0, payload=None):
        calls.append((url, secret, payload))
        return wrapper

    monkeypatch.setattr(app_mod, "_internal_capture", fake_capture)

    r = client.post(f"/sessions/{_SID}/capture")
    assert r.status_code == 200
    # le web signe /capture avec le secret conteneur lu dans le registre
    assert calls == [(f"http://ocular-sess-{_SID}:8090/capture", "cap-secret", {"turnstile_passed": False})]

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
    sess = registry.get(_SID)
    assert sess["last_activity"] != sess["created_at"]


def test_capture_then_save_succeeds_for_interactive_result(monkeypatch, tmp_path):
    # BUG 1 (régression storage->retrieval) : un résultat de capture interactive
    # doit être sauvegardable de bout en bout — POST /sessions/{id}/capture
    # (stocke le résultat léger dans Redis + les blobs sur `/artifacts` via
    # `store_blobs`) puis POST /saved (relit ces MÊMES artefacts via
    # `_read_artifact_bytes`) doivent voir le même Redis/volume. Utilise la
    # composition RÉELLE de `build_capture_result` (pas un wrapper fabriqué à
    # la main) pour que ce test couvre aussi la parité console (BUG 2) : le
    # `console` capturé pendant la session survit jusque dans la sauvegarde.
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    client, registry, _ = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="https://example.com",
        token="tok", secret="cap-secret", owner=_BEARER_OWNER,
        now_iso="2026-07-13T10:00:00+00:00",
    )

    from runner_recon_vnc.session_server import build_capture_result

    result, blobs = build_capture_result(
        target="https://example.com/x",
        kind="url",
        png=b"\x89PNG\r\n\x1a\nAAA",
        dom=b"<html><body>hi</body></html>",
        title="t",
        final="https://example.com/x",
        network=[{"url": "https://example.com/x", "method": "GET", "status": 200}],
        console=[{"level": "error", "text": "boom"}],
    )
    wrapper = {
        "result": result.model_dump(mode="json"),
        "blobs": {ref: base64.b64encode(data).decode() for ref, data in blobs.items()},
    }
    monkeypatch.setattr(app_mod, "_internal_capture", lambda url, secret, timeout=30.0, payload=None: wrapper)

    cap = client.post(f"/sessions/{_SID}/capture")
    assert cap.status_code == 200
    job_id = cap.json()["job_id"]
    assert job_id

    # BUG 2 parity check : la console capturée pendant la session survit dans
    # le résultat léger stocké par /capture.
    assert cap.json()["console"] == [{"level": "error", "text": "boom", "location": None}]

    saved = client.post("/saved", json={"job_id": job_id, "label": "itest"})
    assert saved.status_code == 200
    sid = saved.json()["id"]

    listed = client.get("/saved")
    assert listed.status_code == 200
    assert any(x["id"] == sid for x in listed.json())

    saved_result = client.get(f"/saved/{sid}/result")
    assert saved_result.status_code == 200
    assert saved_result.json()["console"] == [{"level": "error", "text": "boom", "location": None}]


def test_capture_session_server_error_returns_502(monkeypatch):
    client, registry, _ = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="https://example.com",
        token="tok", owner=_BEARER_OWNER, now_iso="2026-07-13T10:00:00+00:00",
    )

    def boom(url, secret, timeout=30.0, payload=None):
        raise app_mod._CaptureError("boom")

    monkeypatch.setattr(app_mod, "_internal_capture", boom)

    r = client.post(f"/sessions/{_SID}/capture")
    assert r.status_code == 502


def test_live_unknown_session_returns_404(monkeypatch):
    client, *_ = _client(monkeypatch)
    r = client.get("/sessions/does-not-exist/live")
    assert r.status_code == 404


def test_live_requires_auth(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    redis_client = fakeredis.FakeStrictRedis()
    app.dependency_overrides[get_session_registry] = lambda: SessionRegistry(redis_client)
    app.dependency_overrides[get_cmd_queue] = lambda: SessionCmdQueue(redis_client)
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(redis_client)
    client = TestClient(app)
    r = client.get(f"/sessions/{_SID}/live")
    assert r.status_code == 401


def test_live_happy_path_proxies_and_touches(monkeypatch, caplog):
    client, registry, _ = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="https://example.com",
        token="tok", secret="live-secret", owner=_BEARER_OWNER,
        now_iso="2026-07-13T10:00:00+00:00",
    )
    live_payload = {
        "network": [{"url": "https://example.com/x", "method": "GET", "status": 200}],
        "findings": [],
        "counts": {"network": 1, "findings": 0},
        "verdict": "benign",
    }
    calls = []

    def fake_get_json(url, secret, timeout=5.0):
        calls.append((url, secret))
        return live_payload

    monkeypatch.setattr(app_mod, "_internal_get_json", fake_get_json)

    r = client.get(f"/sessions/{_SID}/live")
    assert r.status_code == 200
    assert r.json() == live_payload
    # le web signe /live avec le secret conteneur lu dans le registre
    assert calls == [(f"http://ocular-sess-{_SID}:8090/live", "live-secret")]
    # touch : last_activity rafraîchi vers l'heure réelle de la requête
    sess = registry.get(_SID)
    assert sess["last_activity"] != sess["created_at"]
    # secret jamais dans les logs
    assert "live-secret" not in caplog.text


def test_live_server_error_returns_502(monkeypatch):
    client, registry, _ = _client(monkeypatch)
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc", target="https://example.com",
        token="tok", secret="live-secret", owner=_BEARER_OWNER,
        now_iso="2026-07-13T10:00:00+00:00",
    )

    def boom(url, secret, timeout=5.0):
        raise app_mod._CaptureError("boom")

    monkeypatch.setattr(app_mod, "_internal_get_json", boom)

    r = client.get(f"/sessions/{_SID}/live")
    assert r.status_code == 502


def test_web_sessions_module_never_imports_docker():
    import pathlib
    for f in pathlib.Path("web").rglob("*.py"):
        text = f.read_text()
        assert "docker" not in text.lower(), f"{f} ne doit pas référencer docker"
        assert "broker.launcher" not in text, f"{f} ne doit pas importer broker.launcher"
        assert "subprocess" not in text, f"{f} ne doit pas utiliser subprocess"


def test_create_session_rejected_over_max_sessions(monkeypatch):
    # Plafond anti-épuisement : au-delà d'OCULAR_MAX_SESSIONS actives -> 429,
    # AVANT tout enqueue de launch.
    monkeypatch.setenv("OCULAR_MAX_SESSIONS", "2")
    client, registry, cmd_queue = _client(monkeypatch)
    for i in range(2):
        registry.create(f"s{i}", container=f"c{i}", kind="recon-vnc",
                        target="t", token=f"tok{i}", now_iso="2026-07-18T10:00:00+00:00")
    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 429
    assert cmd_queue.dequeue_cmd(timeout=1) is None  # aucun launch enqueue


def test_create_session_allowed_under_max_sessions(monkeypatch):
    # Sous le plafond, la création n'est pas bloquée par le cap (elle échoue
    # plus loin en 504 faute de conteneur réel — mais PAS en 429).
    monkeypatch.setenv("OCULAR_MAX_SESSIONS", "5")
    monkeypatch.setenv("OCULAR_SESSION_READY_TIMEOUT", "0")
    client, registry, _ = _client(monkeypatch)
    registry.create("s0", container="c0", kind="recon-vnc", target="t",
                    token="tok0", now_iso="2026-07-18T10:00:00+00:00")
    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code != 429


def test_create_session_dns_failure_is_distinguishable(monkeypatch):
    # Même distinction que sur /jobs : la création de session interactive valide
    # l'URL par le même garde, et aplatissait donc la même panne DNS en un
    # « url interdite » trompeur.
    import socket as _socket

    import engine.ssrf as ssrf_mod

    c = _client(monkeypatch)[0]

    def _boom(*_a, **_kw):
        raise _socket.gaierror(-3, "Temporary failure in name resolution")

    monkeypatch.setattr(ssrf_mod.socket, "getaddrinfo", _boom)
    r = c.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 400
    assert r.json()["detail"] == "résolution DNS impossible"


def test_create_session_policy_refusal_keeps_its_own_message(monkeypatch):
    c = _client(monkeypatch)[0]
    r = c.post("/sessions", json={"url": "http://127.0.0.1"})
    assert r.status_code == 400
    assert r.json()["detail"] == "url interdite"
