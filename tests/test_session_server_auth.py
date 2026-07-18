"""Auth à la frontière conteneur (défense-en-profondeur F1/F2) : le
`session_server` exige le header `X-Session-Secret` sur /goto, /load, /capture
(PAS /health). Fail-closed (secret non configuré => 403), comparaison en temps
constant, secret jamais loggé. Testé sans Camoufox : le contrôle du secret
précède `_ensure_browser`, donc un secret manquant/faux n'atteint jamais le
navigateur (403 avant toute I/O réseau/navigateur)."""
import pytest
from fastapi.testclient import TestClient

import runner_recon_vnc.session_server as ss

_SECRET = "the-real-session-secret"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("OCULAR_SESSION_SECRET", _SECRET)
    ss._state.update(cm=None, page=None, cap=None, target=None, kind=None, html_input="")
    return TestClient(ss.app)


def test_health_needs_no_secret(client):
    """`/health` reste la seule route ouverte. Le code n'est plus
    inconditionnellement 200 : il porte désormais la DISPONIBILITÉ réelle
    (503 tant que le navigateur n'est pas lancé, cf.
    `tests/test_session_server_readiness.py`). Ce qui se teste ici, c'est
    l'ABSENCE d'exigence de secret — donc « pas 403 », dans les deux états."""
    assert client.get("/health").status_code == 503  # navigateur pas lancé
    ss._state["page"] = object()
    assert client.get("/health").status_code == 200


@pytest.mark.parametrize("path,body", [
    ("/goto", {"url": "https://example.com"}),
    ("/load", {"html": "<h1>x</h1>"}),
    ("/capture", {}),
])
def test_endpoint_rejects_missing_secret(client, path, body):
    r = client.post(path, json=body)
    assert r.status_code == 403


@pytest.mark.parametrize("path,body", [
    ("/goto", {"url": "https://example.com"}),
    ("/load", {"html": "<h1>x</h1>"}),
    ("/capture", {}),
])
def test_endpoint_rejects_wrong_secret(client, path, body):
    r = client.post(path, json=body, headers={"X-Session-Secret": "wrong"})
    assert r.status_code == 403


@pytest.mark.parametrize("path,body", [
    ("/goto", {"url": "https://example.com"}),
    ("/load", {"html": "<h1>x</h1>"}),
    ("/capture", {}),
])
def test_endpoint_fail_closed_when_secret_unset(monkeypatch, path, body):
    # Aucun OCULAR_SESSION_SECRET côté conteneur => jamais ouvert, même avec un
    # header (fail-closed). On délie l'env et on présente pourtant un header.
    monkeypatch.delenv("OCULAR_SESSION_SECRET", raising=False)
    ss._state.update(cm=None, page=None, cap=None, target=None, kind=None, html_input="")
    c = TestClient(ss.app)
    r = c.post(path, json=body, headers={"X-Session-Secret": "anything"})
    assert r.status_code == 403


def test_live_rejects_missing_secret(client):
    r = client.get("/live")
    assert r.status_code == 403


def test_live_rejects_wrong_secret(client):
    r = client.get("/live", headers={"X-Session-Secret": "wrong"})
    assert r.status_code == 403


def test_live_fail_closed_when_secret_unset(monkeypatch):
    # Aucun OCULAR_SESSION_SECRET côté conteneur => jamais ouvert, même avec un
    # header (fail-closed).
    monkeypatch.delenv("OCULAR_SESSION_SECRET", raising=False)
    ss._state.update(cm=None, page=None, cap=None, target=None, kind=None, html_input="")
    c = TestClient(ss.app)
    r = c.get("/live", headers={"X-Session-Secret": "anything"})
    assert r.status_code == 403


def test_live_passes_auth_with_correct_secret(client):
    r = client.get("/live", headers={"X-Session-Secret": _SECRET})
    assert r.status_code == 200


def test_capture_passes_auth_then_409_without_active_session(client):
    # Le bon secret franchit l'auth : /capture arrive à la logique métier et
    # renvoie 409 (aucune session active) — preuve que l'auth a laissé passer.
    r = client.post("/capture", json={}, headers={"X-Session-Secret": _SECRET})
    assert r.status_code == 409


def test_goto_passes_auth_with_correct_secret(client, monkeypatch):
    class _FakePage:
        url = "https://example.com"

        async def goto(self, *a, **k):
            return None

    async def _fake_ensure():
        ss._state["page"] = _FakePage()

    monkeypatch.setattr(ss, "_ensure_browser", _fake_ensure)

    r = client.post("/goto", json={"url": "https://example.com"},
                    headers={"X-Session-Secret": _SECRET})
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_secret_uses_constant_time_compare(client, monkeypatch):
    calls = []
    real = ss.secrets.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(ss.secrets, "compare_digest", spy)
    client.post("/capture", json={}, headers={"X-Session-Secret": _SECRET})
    assert len(calls) == 1
