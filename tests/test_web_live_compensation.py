# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Un poll `/live` en ÉCHEC prouve quand même que la session est utilisée.

`GET /sessions/{id}/live` appelle `registry.mark_connected()` + `touch()` — la
compensation M1 : « une session ACTIVEMENT pollée est vivante, même si son WS VNC
s'est déconnecté un instant, sinon le reaper la détruit alors que l'analyste s'en
sert ». Ces deux appels étaient placés APRÈS le `except`, donc sur le seul chemin
de succès.

Un poll qui échoue ne compensait donc RIEN : après une micro-coupure du WS VNC,
le reaper détruisait une session SAINE — exactement le symptôme S8 que 17a2fb6
déclarait fermé, atteint par le timeout de `/live` au lieu du gel de `/health`.

Le déclencheur mesuré à l'époque était l'expiration à 5,0 s de l'appel interne
sur un DOM hostile (reproduit bout en bout sur 2067ee7 : 64 Kio de `eval(`
répété -> 5 polls sur 5 en 502). Cette cause-là est fermée dans `engine.static`
(cf. tests/test_static_bounded.py), et le chiffre n'est donc PAS reconduit ici :
ce que ce fichier verrouille ne dépend pas d'un budget d'analyse. N'IMPORTE
QUELLE cause d'échec — conteneur qui redémarre, coupure du réseau interne,
réponse hors plafond de lecture — produit le même `CaptureError`, et aucune ne
prouve que l'analyste a cessé de se servir de la session.

Le fait d'être pollé est l'ÉVÉNEMENT qui prouve l'activité de l'analyste ; que le
conteneur ait su répondre est une autre question. La compensation appartient donc
au chemin d'entrée, pas au chemin de succès.
"""
import fakeredis
import pytest
from fastapi.testclient import TestClient

import web.app as app_mod
from bus.sessions import SessionCmdQueue, SessionRegistry
from bus.queue import RedisJobQueue
from web.app import app, get_cmd_queue, get_queue, get_session_registry

_SID = "sess-0123456789ab"
_BEARER = "t"
# Identité d'appelant telle que la pose `web.app` pour un Bearer statique
# (cf. tests/test_web_sessions.py::_BEARER_OWNER).
_OWNER = "token"


@pytest.fixture
def live_env(monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", _BEARER)
    redis_client = fakeredis.FakeStrictRedis()
    registry = SessionRegistry(redis_client)
    app.dependency_overrides[get_session_registry] = lambda: registry
    app.dependency_overrides[get_cmd_queue] = lambda: SessionCmdQueue(redis_client)
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(redis_client)
    client = TestClient(app, headers={"Authorization": f"Bearer {_BEARER}"})
    registry.create(
        _SID, container="ocular-sess-" + _SID, kind="recon-vnc",
        target="https://example.com", token="tok", secret="live-secret",
        owner=_OWNER, now_iso="2026-07-13T10:00:00+00:00",
    )
    return client, registry


def _disconnect(registry) -> None:
    """Micro-coupure du WS VNC : c'est l'état dans lequel la compensation est la
    seule chose qui empêche le reaper de détruire la session."""
    registry.mark_disconnected(_SID, 1_000_000.0)
    assert "disconnected_at" in registry.get(_SID)


def test_live_timeout_still_marks_the_session_connected(live_env, monkeypatch):
    """Le cas mesuré : l'analyse dépasse les 5 s, l'appel interne expire."""
    client, registry = live_env
    _disconnect(registry)

    def timeout(url, secret, timeout=5.0):
        raise app_mod._CaptureError("timed out")

    monkeypatch.setattr(app_mod, "_internal_get_json", timeout)

    assert client.get(f"/sessions/{_SID}/live").status_code == 502
    assert "disconnected_at" not in registry.get(_SID), (
        "un poll /live en échec ne réarme pas la session : après une coupure du "
        "WS VNC, le reaper détruit une session que l'analyste utilise"
    )


def test_live_timeout_still_touches_last_activity(live_env, monkeypatch):
    client, registry = live_env
    before = registry.get(_SID)["last_activity"]

    def timeout(url, secret, timeout=5.0):
        raise app_mod._CaptureError("timed out")

    monkeypatch.setattr(app_mod, "_internal_get_json", timeout)
    assert client.get(f"/sessions/{_SID}/live").status_code == 502
    assert registry.get(_SID)["last_activity"] != before, (
        "last_activity n'est pas rafraîchi quand le poll échoue"
    )


def test_live_happy_path_still_compensates(live_env, monkeypatch):
    """Non-régression : le chemin de succès compense exactement comme avant."""
    client, registry = live_env
    _disconnect(registry)
    payload = {"network": [], "console": [], "findings": [],
               "counts": {"network": 0, "findings": 0, "console": 0},
               "verdict": "benign"}
    monkeypatch.setattr(app_mod, "_internal_get_json", lambda url, secret, timeout=5.0: payload)

    r = client.get(f"/sessions/{_SID}/live")
    assert r.status_code == 200 and r.json() == payload
    assert "disconnected_at" not in registry.get(_SID)


def test_live_on_an_unknown_session_compensates_nothing(live_env, monkeypatch):
    """La compensation ne doit pas ressusciter une session inconnue : elle vient
    APRÈS le contrôle de propriété, jamais avant."""
    client, registry = live_env
    called = {"n": 0}

    def spy(url, secret, timeout=5.0):
        called["n"] += 1
        raise app_mod._CaptureError("boom")

    monkeypatch.setattr(app_mod, "_internal_get_json", spy)
    assert client.get("/sessions/sess-ffffffffffff/live").status_code == 404
    assert called["n"] == 0
    assert registry.get("sess-ffffffffffff") in (None, {})
