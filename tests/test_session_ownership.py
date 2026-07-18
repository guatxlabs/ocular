"""Appartenance des sessions interactives (défaut d'audit : aucun propriétaire).

Une session interactive est un CONTENEUR PILOTABLE : `/ws` est un proxy noVNC
complet (clavier + souris de la session d'un collègue, potentiellement connectée
à ses comptes), `/capture` et `/live` en exfiltrent l'état, `DELETE` la détruit,
et `GET /sessions` en listait les identifiants. Sans propriétaire stocké, tout
analyste authentifié agissait sur la session de n'importe quel autre dès que le
forward-auth était actif (chaque requête porte alors une identité DISTINCTE).

Invariants verrouillés ici, pour CHAQUE route et dans LES DEUX SENS :
- le propriétaire accède ; un autre utilisateur obtient 404 (jamais 403 : un 403
  confirmerait l'existence de l'identifiant — c'est déjà la réponse aux
  identifiants inconnus, donc les deux cas sont indistinguables) ;
- l'admin passe outre (mécanisme EXISTANT : `X-Admin-Token` ou groupe IdP) ;
- le mode bearer (défaut) n'est PAS régressé — identité partagée "token" ;
- une session sans propriétaire est refusée aux non-admins (fail-closed).
"""
from __future__ import annotations

import asyncio

import fakeredis
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import web.app as app_mod
from bus.queue import RedisJobQueue
from bus.sessions import SessionCmdQueue, SessionRegistry
from web.app import app, get_cmd_queue, get_queue, get_session_registry

_SID = "sess-0123456789ab"
_WS_TOKEN = "capability-token-de-session"
_ALICE = "alice@example.org"
_BOB = "bob@example.org"


def _stack(monkeypatch, *, forward_auth: bool):
    """Pile web + redis factice. `forward_auth=True` active l'opt-in IdP, où
    chaque requête porte une identité distincte (`X-Forwarded-User`)."""
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    if forward_auth:
        monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    else:
        monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("OCULAR_ADMIN_GROUP", raising=False)

    redis_client = fakeredis.FakeStrictRedis()
    registry = SessionRegistry(redis_client)
    cmd_queue = SessionCmdQueue(redis_client)
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(redis_client)
    app.dependency_overrides[get_session_registry] = lambda: registry
    app.dependency_overrides[get_cmd_queue] = lambda: cmd_queue
    return TestClient(app), registry, cmd_queue


def _as(user: str | None) -> dict:
    """En-têtes d'un analyste IdP donné (le bearer reste présent : en mode
    forward-auth l'en-tête d'identité PRIME sur le jeton, cf. resolve_identity)."""
    headers = {"Authorization": "Bearer t"}
    if user is not None:
        headers["X-Forwarded-User"] = user
    return headers


def _seed(registry: SessionRegistry, owner: str, sid: str = _SID) -> None:
    registry.create(
        sid, container="ocular-sess-" + sid, kind="recon-vnc",
        # cible SANS lien avec le propriétaire : sinon l'identité fuirait par le
        # champ `target` et les assertions anti-fuite seraient trompeuses.
        target="https://cible-" + sid, token=_WS_TOKEN,
        secret="cap-secret", owner=owner, now_iso="2026-07-13T10:00:00+00:00",
    )


# --- doublures des appels internes web -> session_server ---------------------

def _fake_session_server(monkeypatch):
    """Neutralise les appels réseau internes : toute route qui ATTEINT le
    session_server réussit. Un 404 dans ces tests ne peut donc venir QUE de la
    garde d'appartenance, jamais d'un échec réseau."""
    monkeypatch.setattr(
        app_mod, "_internal_capture",
        lambda url, secret, payload=None: {"result": {"verdict": "clean"}, "blobs": {}},
    )
    monkeypatch.setattr(
        app_mod, "_internal_get_json",
        lambda url, secret: {"network": [], "findings": [], "counts": {}},
    )


class _FakeUpstream:
    """websockify du conteneur de session : écho pur d'octets bruts."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue = asyncio.Queue()

    async def send(self, data: bytes) -> None:
        await self._queue.put(data)

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        item = await self._queue.get()
        if item is None:
            raise StopAsyncIteration
        return item

    async def close(self) -> None:
        await self._queue.put(None)


class _FakeConnectCM:
    def __init__(self) -> None:
        self.conn = _FakeUpstream()

    async def __aenter__(self) -> _FakeUpstream:
        return self.conn

    async def __aexit__(self, *exc) -> bool:
        await self.conn.close()
        return False


def _fake_upstream(monkeypatch):
    monkeypatch.setattr(
        app_mod.websockets, "connect", lambda url, subprotocols=None: _FakeConnectCM()
    )


def _ws_connect(client, headers: dict, sid: str = _SID):
    return client.websocket_connect(
        f"/sessions/{sid}/ws",
        subprotocols=["binary", f"ocular.session.{_WS_TOKEN}"],
        headers=headers,
    )


# =============================================================================
# 1. Le propriétaire accède — chaque route, mode IdP
# =============================================================================

def test_owner_can_delete_capture_live_and_list_her_session(monkeypatch):
    client, registry, cmd_queue = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)

    _seed(registry, owner=_ALICE)
    assert client.post(f"/sessions/{_SID}/capture", headers=_as(_ALICE)).status_code == 200
    assert client.get(f"/sessions/{_SID}/live", headers=_as(_ALICE)).status_code == 200

    listed = client.get("/sessions", headers=_as(_ALICE)).json()
    assert [s["session_id"] for s in listed] == [_SID]

    r = client.delete(f"/sessions/{_SID}", headers=_as(_ALICE))
    assert r.status_code == 200 and r.json() == {"deleted": _SID}
    assert registry.get(_SID) is None
    assert cmd_queue.dequeue_cmd(timeout=1) == {"action": "stop", "session_id": _SID}


def test_owner_can_open_the_vnc_websocket(monkeypatch):
    """Contre-épreuve du test de refus WS ci-dessous : la garde d'appartenance
    ne casse pas le chemin nominal du proxy noVNC."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_upstream(monkeypatch)
    _seed(registry, owner=_ALICE)

    with _ws_connect(client, _as(_ALICE)) as ws:
        assert ws.accepted_subprotocol == "binary"
        ws.send_bytes(b"\x00RFB")
        assert ws.receive_bytes() == b"\x00RFB"


# =============================================================================
# 2. Un autre utilisateur obtient 404 — chaque route
# =============================================================================

def test_other_user_gets_404_on_capture(monkeypatch):
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    _seed(registry, owner=_ALICE)

    r = client.post(f"/sessions/{_SID}/capture", headers=_as(_BOB))
    assert r.status_code == 404


def test_other_user_gets_404_on_live(monkeypatch):
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    _seed(registry, owner=_ALICE)

    assert client.get(f"/sessions/{_SID}/live", headers=_as(_BOB)).status_code == 404


def test_other_user_gets_404_on_delete_and_session_survives(monkeypatch):
    """Le 404 n'est pas cosmétique : AUCUN ordre d'arrêt ne doit atteindre le
    broker, et la session de la propriétaire doit rester intacte."""
    client, registry, cmd_queue = _stack(monkeypatch, forward_auth=True)
    _seed(registry, owner=_ALICE)

    assert client.delete(f"/sessions/{_SID}", headers=_as(_BOB)).status_code == 404
    assert registry.get(_SID) is not None
    assert cmd_queue.dequeue_cmd(timeout=1) is None


def test_other_user_does_not_see_the_session_in_the_list(monkeypatch):
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _seed(registry, owner=_ALICE)

    r = client.get("/sessions", headers=_as(_BOB))
    assert r.status_code == 200
    assert r.json() == []
    # ni l'identifiant, ni la cible d'Alice ne transparaissent dans la réponse
    assert _SID not in r.text and _ALICE not in r.text


def test_other_user_cannot_open_the_vnc_websocket(monkeypatch):
    """LA garde critique : le proxy WS donne le clavier et la souris de la
    session. Même en présentant un token capability VALIDE, un autre analyste
    est fermé (1008), l'équivalent WS du 404 — indistinguable d'une session
    inconnue ou d'un token invalide."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_upstream(monkeypatch)
    _seed(registry, owner=_ALICE)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _ws_connect(client, _as(_BOB)):
            pass
    assert exc.value.code == 1008


def test_ws_refusal_is_indistinguishable_from_unknown_session(monkeypatch):
    """Le code de fermeture d'une session d'autrui est le MÊME que celui d'une
    session inexistante : le proxy WS n'est pas un oracle d'existence."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_upstream(monkeypatch)
    _seed(registry, owner=_ALICE)

    codes = []
    for sid in (_SID, "sess-ffffffffffff"):  # celle d'Alice, puis une inconnue
        with pytest.raises(WebSocketDisconnect) as exc:
            with _ws_connect(client, _as(_BOB), sid=sid):
                pass
        codes.append(exc.value.code)
    assert codes == [1008, 1008]


def test_other_user_404_is_identical_to_unknown_session_404(monkeypatch):
    """Même corps et même statut sur la session d'autrui et sur une session
    inconnue : rien à distinguer pour qui sonderait des identifiants."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    _seed(registry, owner=_ALICE)

    foreign = client.post(f"/sessions/{_SID}/capture", headers=_as(_BOB))
    unknown = client.post("/sessions/sess-ffffffffffff/capture", headers=_as(_BOB))
    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json() == unknown.json()


# =============================================================================
# 3. L'admin passe outre (mécanisme existant, pas un second)
# =============================================================================

def test_admin_token_overrides_ownership_on_every_route(monkeypatch):
    client, registry, cmd_queue = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    _seed(registry, owner=_ALICE)

    admin = {**_as(_BOB), "X-Admin-Token": "adm-secret"}
    assert client.post(f"/sessions/{_SID}/capture", headers=admin).status_code == 200
    assert client.get(f"/sessions/{_SID}/live", headers=admin).status_code == 200
    assert [s["session_id"] for s in client.get("/sessions", headers=admin).json()] == [_SID]
    # …et il peut TOUT ARRÊTER, y compris la session d'une autre.
    assert client.delete(f"/sessions/{_SID}", headers=admin).status_code == 200
    assert cmd_queue.dequeue_cmd(timeout=1) == {"action": "stop", "session_id": _SID}


def test_admin_group_overrides_ownership(monkeypatch):
    """Second mécanisme admin EXISTANT (groupe IdP), pas un troisième."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    monkeypatch.setenv("OCULAR_ADMIN_GROUP", "ocular-admins")
    _seed(registry, owner=_ALICE)

    admin = {**_as(_BOB), "X-Forwarded-Groups": "staff,ocular-admins"}
    assert client.get(f"/sessions/{_SID}/live", headers=admin).status_code == 200
    assert [s["session_id"] for s in client.get("/sessions", headers=admin).json()] == [_SID]


def test_admin_can_open_the_websocket_of_another_users_session(monkeypatch):
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_upstream(monkeypatch)
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    _seed(registry, owner=_ALICE)

    with _ws_connect(client, {**_as(_BOB), "X-Admin-Token": "adm-secret"}) as ws:
        assert ws.accepted_subprotocol == "binary"


def test_wrong_admin_token_does_not_override(monkeypatch):
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    _seed(registry, owner=_ALICE)

    r = client.get(f"/sessions/{_SID}/live", headers={**_as(_BOB), "X-Admin-Token": "devine"})
    assert r.status_code == 404


# =============================================================================
# 4. Mode bearer (défaut) : AUCUNE régression
# =============================================================================

def test_bearer_mode_all_token_holders_share_the_same_owner(monkeypatch):
    """Tous les porteurs du jeton partagé ont l'identité "token" : ils
    continuent de tout voir et de tout faire. C'est CORRECT — c'est le MÊME
    identifiant partagé, pas une élévation de privilège."""
    client, registry, cmd_queue = _stack(monkeypatch, forward_auth=False)
    _fake_session_server(monkeypatch)
    _seed(registry, owner="token")

    bearer = {"Authorization": "Bearer t"}
    assert client.post(f"/sessions/{_SID}/capture", headers=bearer).status_code == 200
    assert client.get(f"/sessions/{_SID}/live", headers=bearer).status_code == 200
    assert [s["session_id"] for s in client.get("/sessions", headers=bearer).json()] == [_SID]
    assert client.delete(f"/sessions/{_SID}", headers=bearer).status_code == 200
    assert cmd_queue.dequeue_cmd(timeout=1) == {"action": "stop", "session_id": _SID}


def test_bearer_mode_websocket_still_works(monkeypatch):
    """Un navigateur ne peut PAS poser d'en-tête `Authorization` sur un
    websocket : en mode bearer l'identité est l'unique "token" partagé, sinon
    le panneau VNC serait cassé par défaut."""
    client, registry, _ = _stack(monkeypatch, forward_auth=False)
    _fake_upstream(monkeypatch)
    _seed(registry, owner="token")

    with _ws_connect(client, {}) as ws:  # aucun en-tête d'identité, comme un vrai navigateur
        assert ws.accepted_subprotocol == "binary"
        ws.send_bytes(b"ping")
        assert ws.receive_bytes() == b"ping"


def test_bearer_mode_ignores_spoofed_identity_header(monkeypatch):
    """Anti-spoofing : opt-in OFF => `X-Forwarded-User` n'est JAMAIS lu, donc un
    en-tête forgé ne fait pas d'un porteur du jeton un « autre utilisateur »
    (il resterait sinon bloqué sur ses propres sessions)."""
    client, registry, _ = _stack(monkeypatch, forward_auth=False)
    _fake_session_server(monkeypatch)
    _seed(registry, owner="token")

    r = client.get(f"/sessions/{_SID}/live", headers={**_as("attaquant"), })
    assert r.status_code == 200


def test_created_session_records_the_caller_as_owner(monkeypatch):
    """Bout en bout : la commande de lancement porte le propriétaire résolu —
    c'est le broker qui écrit l'entrée registre, le web ne peut pas l'y mettre."""
    client, _, cmd_queue = _stack(monkeypatch, forward_auth=True)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda registry, sid, deadline: True)
    monkeypatch.setattr(
        app_mod, "_internal_post_json", lambda url, payload, secret, timeout=5.0: True
    )

    r = client.post("/sessions", json={"url": "https://example.com"}, headers=_as(_ALICE))
    assert r.status_code == 200
    cmd = cmd_queue.dequeue_cmd(timeout=1)
    assert cmd["action"] == "launch"
    assert cmd["owner"] == _ALICE


def test_created_session_owner_is_token_in_bearer_mode(monkeypatch):
    client, _, cmd_queue = _stack(monkeypatch, forward_auth=False)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda registry, sid, deadline: True)
    monkeypatch.setattr(
        app_mod, "_internal_post_json", lambda url, payload, secret, timeout=5.0: True
    )

    client.post("/sessions", json={"url": "https://example.com"},
                headers={"Authorization": "Bearer t"})
    assert cmd_queue.dequeue_cmd(timeout=1)["owner"] == "token"


# =============================================================================
# 5. Mode mixte : bearer et IdP ne se voient pas
# =============================================================================

def test_mixed_mode_bearer_holder_and_idp_user_do_not_see_each_other(monkeypatch):
    """Opt-in ACTIF : un porteur du bearer (owner="token") et une utilisatrice
    IdP (owner="alice@…") sont deux identités distinctes. La comparaison des
    propriétaires suffit à les séparer."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    _seed(registry, owner=_ALICE, sid=_SID)
    _seed(registry, owner="token", sid="sess-bbbbbbbbbbbb")

    # le porteur du bearer (sans en-tête d'identité) ne voit QUE la sienne
    bearer_view = client.get("/sessions", headers={"Authorization": "Bearer t"}).json()
    assert [s["session_id"] for s in bearer_view] == ["sess-bbbbbbbbbbbb"]
    assert client.get(f"/sessions/{_SID}/live",
                      headers={"Authorization": "Bearer t"}).status_code == 404

    # …et Alice ne voit QUE la sienne
    alice_view = client.get("/sessions", headers=_as(_ALICE)).json()
    assert [s["session_id"] for s in alice_view] == [_SID]
    assert client.get("/sessions/sess-bbbbbbbbbbbb/live", headers=_as(_ALICE)).status_code == 404


# =============================================================================
# 6. Session sans propriétaire : refusée aux non-admins (fail-closed)
# =============================================================================

def test_session_without_owner_is_refused_to_non_admin(monkeypatch):
    """Une entrée sans champ `owner` (jamais produite par le web actuel) est
    refusée à tout non-admin, sur TOUTES les routes. Sûr : redis tourne sur un
    tmpfs, aucune session ne survit à un redémarrage — il n'existe donc aucune
    session « héritée » que ce durcissement rendrait subitement inaccessible."""
    client, registry, cmd_queue = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    _seed(registry, owner="")

    assert client.post(f"/sessions/{_SID}/capture", headers=_as(_ALICE)).status_code == 404
    assert client.get(f"/sessions/{_SID}/live", headers=_as(_ALICE)).status_code == 404
    assert client.delete(f"/sessions/{_SID}", headers=_as(_ALICE)).status_code == 404
    assert client.get("/sessions", headers=_as(_ALICE)).json() == []
    assert registry.get(_SID) is not None       # rien détruit
    assert cmd_queue.dequeue_cmd(timeout=1) is None


def test_session_without_owner_is_refused_on_websocket(monkeypatch):
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_upstream(monkeypatch)
    _seed(registry, owner="")

    with pytest.raises(WebSocketDisconnect) as exc:
        with _ws_connect(client, _as(_ALICE)):
            pass
    assert exc.value.code == 1008


def test_session_without_owner_is_still_reachable_by_admin(monkeypatch):
    """Corollaire indispensable du fail-closed : l'admin doit pouvoir ARRÊTER
    une session orpheline, sinon elle serait irrécupérable jusqu'au reaper."""
    client, registry, cmd_queue = _stack(monkeypatch, forward_auth=True)
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    _seed(registry, owner="")

    admin = {**_as(_ALICE), "X-Admin-Token": "adm-secret"}
    assert [s["session_id"] for s in client.get("/sessions", headers=admin).json()] == [_SID]
    assert client.delete(f"/sessions/{_SID}", headers=admin).status_code == 200
    assert cmd_queue.dequeue_cmd(timeout=1) == {"action": "stop", "session_id": _SID}


# =============================================================================
# 7. Le propriétaire ne fuit jamais dans une réponse d'API
# =============================================================================

def test_owner_is_never_returned_to_a_non_admin(monkeypatch):
    """Même précaution que `secret` et `token` : `owner` porte l'identité IdP
    d'un analyste et n'a pas à transiter vers un autre utilisateur."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _seed(registry, owner=_ALICE)

    r = client.get("/sessions", headers=_as(_ALICE))
    body = r.json()
    assert len(body) == 1
    assert "owner" not in body[0]
    assert "token" not in body[0] and "secret" not in body[0]
    assert _ALICE not in r.text


def test_admin_still_sees_the_owner(monkeypatch):
    """L'admin le conserve : « tout voir » sans savoir DE QUI est la session
    qu'on s'apprête à arrêter n'aurait pas de sens."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    _seed(registry, owner=_ALICE)

    body = client.get("/sessions", headers={**_as(_BOB), "X-Admin-Token": "adm-secret"}).json()
    assert body[0]["owner"] == _ALICE
    assert "token" not in body[0] and "secret" not in body[0]


# =============================================================================
# 8. Le durcissement n'ouvre pas de contournement par en-tête
# =============================================================================

def test_idp_mode_missing_identity_header_is_refused(monkeypatch):
    """Opt-in ACTIF + aucune identité sur un WS : refus (fail-closed). Sinon
    omettre l'en-tête suffirait à contourner toute la garde d'appartenance."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_upstream(monkeypatch)
    _seed(registry, owner=_ALICE)

    with pytest.raises(WebSocketDisconnect) as exc:
        with _ws_connect(client, {}):
            pass
    assert exc.value.code == 1008


def test_empty_identity_header_cannot_claim_an_ownerless_session(monkeypatch):
    """Une identité vide ne doit jamais « matcher » un propriétaire vide."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _fake_session_server(monkeypatch)
    _seed(registry, owner="")

    assert client.get(f"/sessions/{_SID}/live", headers=_as("")).status_code == 404
