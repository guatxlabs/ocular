"""Proxy websocket noVNC `/sessions/{sid}/ws` (Tâche 6, phase 3b).

Sécu critique : auth par SOUS-PROTOCOLE (`Sec-WebSocket-Protocol:
binary, ocular.session.<token>`), JAMAIS de token en query string. Refus
fail-closed AVANT `accept()` si le token est absent/invalide. Le serveur
n'accepte (et ne renvoie) que le sous-protocole `binary` — jamais le token.
"""

from __future__ import annotations

import asyncio
import logging

import fakeredis
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import web.app as app_mod
from web.app import app, get_session_registry
from bus.sessions import SessionRegistry

_TOKEN = "super-secret-vnc-token"


class _FakeUpstreamConn:
    """Simule le websockify du conteneur de session : écho pur, octets bruts."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self._queue: asyncio.Queue = asyncio.Queue()
        self.closed = False

    async def send(self, data: bytes) -> None:
        self.sent.append(data)
        await self._queue.put(data)  # écho

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        item = await self._queue.get()
        if item is None:
            raise StopAsyncIteration
        return item

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            await self._queue.put(None)


class _FakeConnectCM:
    """Imite `websockets.connect(...)` utilisé en `async with`."""

    def __init__(self, conn: _FakeUpstreamConn) -> None:
        self.conn = conn

    async def __aenter__(self) -> _FakeUpstreamConn:
        return self.conn

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        await self.conn.close()
        return False


def _install_fake_upstream(monkeypatch):
    calls: list[tuple] = []
    conns: list[_FakeUpstreamConn] = []

    def _connect(url, subprotocols=None):
        conn = _FakeUpstreamConn()
        conns.append(conn)
        calls.append((url, subprotocols))
        return _FakeConnectCM(conn)

    monkeypatch.setattr(app_mod.websockets, "connect", _connect)
    return calls, conns


def _client(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    redis_client = fakeredis.FakeStrictRedis()
    registry = SessionRegistry(redis_client)
    app.dependency_overrides[get_session_registry] = lambda: registry
    client = TestClient(app)
    return client, registry


def _seed_session(registry: SessionRegistry, sid: str = "s1", token: str = _TOKEN) -> None:
    registry.create(
        sid, container="ocular-sess-" + sid, kind="recon-vnc", target="https://example.com",
        token=token, now_iso="2026-07-13T10:00:00+00:00",
    )


def test_ws_rejects_missing_subprotocol(monkeypatch):
    client, registry = _client(monkeypatch)
    _seed_session(registry)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/sessions/s1/ws"):
            pass
    assert exc.value.code == 1008


def test_ws_rejects_invalid_token(monkeypatch):
    client, registry = _client(monkeypatch)
    _seed_session(registry)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            "/sessions/s1/ws", subprotocols=["binary", "ocular.session.wrong-token"]
        ):
            pass
    assert exc.value.code == 1008


def test_ws_rejects_unknown_session(monkeypatch):
    client, registry = _client(monkeypatch)
    # aucune session créée pour "s1" : valid_token() -> False sans conteneur
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            "/sessions/s1/ws", subprotocols=["binary", f"ocular.session.{_TOKEN}"]
        ):
            pass
    assert exc.value.code == 1008


def test_ws_valid_token_accepted_binary_only_and_pumps_bytes(monkeypatch):
    client, registry = _client(monkeypatch)
    _seed_session(registry)
    calls, conns = _install_fake_upstream(monkeypatch)

    with client.websocket_connect(
        "/sessions/s1/ws", subprotocols=["binary", f"ocular.session.{_TOKEN}"]
    ) as ws:
        # le serveur n'accepte (et ne renvoie) QUE "binary", jamais le token
        assert ws.accepted_subprotocol == "binary"

        ws.send_bytes(b"\x00RFB client hello")
        echoed = ws.receive_bytes()
        assert echoed == b"\x00RFB client hello"

    # l'upstream a bien été contacté sur le conteneur de session, réseau interne
    assert len(calls) == 1
    url, subprotocols = calls[0]
    assert url == "ws://ocular-sess-s1:6080/websockify"
    assert subprotocols == ["binary"]
    assert conns[0].sent == [b"\x00RFB client hello"]


def test_ws_registry_touch_called_on_activity(monkeypatch):
    client, registry = _client(monkeypatch)
    _seed_session(registry)
    _install_fake_upstream(monkeypatch)

    touched = []
    orig_touch = registry.touch

    def spy_touch(sid, now_iso):
        touched.append(sid)
        return orig_touch(sid, now_iso)

    monkeypatch.setattr(registry, "touch", spy_touch)

    with client.websocket_connect(
        "/sessions/s1/ws", subprotocols=["binary", f"ocular.session.{_TOKEN}"]
    ) as ws:
        ws.send_bytes(b"ping")
        ws.receive_bytes()

    assert touched == ["s1"]


def test_ws_token_never_logged(monkeypatch, caplog):
    client, registry = _client(monkeypatch)
    _seed_session(registry)
    calls, conns = _install_fake_upstream(monkeypatch)

    caplog.set_level(logging.DEBUG, logger="ocular")

    # une tentative valide et une invalide : dans les deux cas, aucune trace du
    # token ni du header Sec-WebSocket-Protocol dans les logs applicatifs.
    with client.websocket_connect(
        "/sessions/s1/ws", subprotocols=["binary", f"ocular.session.{_TOKEN}"]
    ) as ws:
        ws.send_bytes(b"x")
        ws.receive_bytes()

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/sessions/s1/ws", subprotocols=["binary", "ocular.session.WRONG"]
        ):
            pass

    log_text = caplog.text
    assert _TOKEN not in log_text
    assert "WRONG" not in log_text
    assert "ocular.session." not in log_text
    assert "sec-websocket-protocol" not in log_text.lower()
