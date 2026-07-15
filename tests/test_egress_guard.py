"""Egress guard (Phase 3g, Task G1) : proxy CONNECT/HTTP filtrant côté
runner. Sépare clairement :
- tests SÉCU : le blocage réel (`resolve_allowed_ip` non mocké) refuse
  loopback/metadata avec 403, SANS jamais ouvrir de connexion sortante ;
- test RELAIS : `resolve_allowed_ip` est mocké pour bypasser le check et
  pointer vers un serveur de test local — ceci prouve uniquement que le
  pipe bidirectionnel fonctionne, pas la sécurité (le check est explicitement
  contourné pour ce test).
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest

import engine.egress_guard as egress_guard_mod
from engine.egress_guard import EgressGuard


async def _open_client(port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    return await asyncio.open_connection("127.0.0.1", port)


async def _read_status_line(reader: asyncio.StreamReader) -> str:
    line = await asyncio.wait_for(reader.readline(), timeout=5)
    return line.decode("latin-1")


@pytest.fixture
async def guard():
    g = EgressGuard(connect_timeout=2, idle_timeout=2)
    g.port = await g.start()  # test-only convenience attribute (public API contract is the return value)
    yield g
    await g.stop()


# --- SÉCU : blocage réel, aucune connexion sortante ------------------------


async def test_connect_to_loopback_blocked_with_403_and_no_upstream(guard, monkeypatch):
    called = False

    # Ouvre la connexion cliente AVANT de patcher asyncio.open_connection :
    # ce dernier est un module global, le patcher plus tôt casserait aussi
    # l'ouverture de la connexion cliente elle-même (pas seulement celle du
    # garde vers l'upstream qu'on veut surveiller ici).
    reader, writer = await _open_client(guard.port)

    async def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("aucune connexion sortante ne doit être ouverte")

    monkeypatch.setattr(egress_guard_mod.asyncio, "open_connection", _fail_if_called)

    writer.write(b"CONNECT 127.0.0.1:80 HTTP/1.1\r\n\r\n")
    await writer.drain()

    status = await _read_status_line(reader)
    assert "403" in status
    assert called is False

    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_connect_to_metadata_ip_blocked_with_403(guard, monkeypatch):
    called = False

    reader, writer = await _open_client(guard.port)

    async def _fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("aucune connexion sortante ne doit être ouverte")

    monkeypatch.setattr(egress_guard_mod.asyncio, "open_connection", _fail_if_called)

    writer.write(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n")
    await writer.drain()

    status = await _read_status_line(reader)
    assert "403" in status
    assert called is False

    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_connect_to_private_rfc1918_blocked_with_403(guard):
    reader, writer = await _open_client(guard.port)
    writer.write(b"CONNECT 10.0.0.5:443 HTTP/1.1\r\n\r\n")
    await writer.drain()

    status = await _read_status_line(reader)
    assert "403" in status

    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_malformed_first_line_returns_400(guard):
    reader, writer = await _open_client(guard.port)
    writer.write(b"NOT A VALID REQUEST LINE AT ALL\r\n\r\n")
    await writer.drain()

    status = await _read_status_line(reader)
    assert "400" in status

    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


async def test_connect_missing_port_and_garbage_target_is_400(guard):
    reader, writer = await _open_client(guard.port)
    writer.write(b"CONNECT ::::: HTTP/1.1\r\n\r\n")
    await writer.drain()

    status = await _read_status_line(reader)
    assert "400" in status

    writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


# --- RELAIS : check mocké, prouve uniquement le pipe bidirectionnel -------


async def _start_echo_server() -> tuple[asyncio.AbstractServer, int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def test_connect_relay_pipes_bytes_both_directions_with_mocked_check(guard, monkeypatch):
    echo_server, echo_port = await _start_echo_server()
    try:
        # SÉCURITÉ CONTOURNÉE INTENTIONNELLEMENT ICI : ce test ne prouve que
        # le relais d'octets, pas le blocage (le serveur d'écho est en
        # 127.0.0.1, donc non-global — sans ce mock, resolve_allowed_ip
        # renverrait None et la connexion serait bloquée en 403).
        monkeypatch.setattr(
            egress_guard_mod,
            "resolve_allowed_ip",
            lambda host, port=0: "127.0.0.1",
        )

        reader, writer = await _open_client(guard.port)
        writer.write(f"CONNECT internal-target.invalid:{echo_port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()

        status = await _read_status_line(reader)
        assert "200" in status
        # consomme la ligne vide de fin d'en-têtes de la réponse CONNECT
        await asyncio.wait_for(reader.readline(), timeout=5)

        payload = b"hello through the tunnel"
        writer.write(payload)
        await writer.drain()

        echoed = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=5)
        assert echoed == payload

        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    finally:
        echo_server.close()
        await echo_server.wait_closed()


async def test_absolute_http_relay_rewrites_to_origin_form_with_mocked_check(guard, monkeypatch):
    received: list[bytes] = []
    got_request = asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.readuntil(b"\r\n\r\n")
        received.append(data)
        got_request.set()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        monkeypatch.setattr(
            egress_guard_mod,
            "resolve_allowed_ip",
            lambda host, port=0: "127.0.0.1",
        )

        reader, writer = await _open_client(guard.port)
        target = f"http://internal-target.invalid:{port}/some/path"
        writer.write(f"GET {target} HTTP/1.1\r\nHost: internal-target.invalid:{port}\r\n\r\n".encode())
        await writer.drain()

        await asyncio.wait_for(got_request.wait(), timeout=5)
        first_line = received[0].split(b"\r\n", 1)[0]
        assert first_line == b"GET /some/path HTTP/1.1"

        body = await asyncio.wait_for(reader.read(4096), timeout=5)
        assert b"200 OK" in body
        assert b"ok" in body

        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
