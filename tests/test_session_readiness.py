# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Contrat ASYNCHRONE de création de session (défaut : `POST /sessions` était
SYNCHRONE et attendait ~7-9 s la disponibilité avant de répondre).

Un client qui abandonnait pendant cette attente — timeout, Ctrl-C, proxy amont,
onglet fermé — n'apprenait JAMAIS son `session_id` alors que la session existait
déjà : elle immobilisait un conteneur (~4 Go) et un sous-réseau du pool docker
jusqu'à son TTL, sans que PERSONNE ne puisse la supprimer.

Le contrat retenu :
  • `POST /sessions` -> **202** immédiat, même corps (`{session_id, token}`) ;
  • `GET /sessions/{id}` -> sonde de disponibilité, états `pending` /
    `starting` / `ready`, soumise au MÊME contrôle d'appartenance que les autres
    routes de session (404 indistinguable, admin passe outre).
"""
import time

import fakeredis
import pytest
from fastapi.testclient import TestClient

import web.app as app_mod
from bus.queue import RedisJobQueue
from bus.sessions import SessionCmdQueue, SessionRegistry
from web.app import app, get_cmd_queue, get_queue, get_session_registry

_SID = "sess-0123456789ab"
_ALICE = "alice@example.org"
_BOB = "bob@example.org"
_WS_TOKEN = "capability-token-de-session"
_CAP_SECRET = "secret-frontiere-conteneur"


def _stack(monkeypatch, *, forward_auth: bool = False):
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
    client = TestClient(app)
    # Bearer par défaut (mode nominal). Les tests forward-auth le complètent
    # d'un `X-Forwarded-User` via `_as()`, où l'identité IdP prime.
    client.headers.update({"Authorization": "Bearer t"})
    return client, registry, cmd_queue


def _as(user: str | None) -> dict:
    headers = {"Authorization": "Bearer t"}
    if user is not None:
        headers["X-Forwarded-User"] = user
    return headers


def _seed(registry: SessionRegistry, owner: str, *, sid: str = _SID, container: str | None = None):
    """Sème une session. `container=""` reproduit la RÉSERVATION *pending* que le
    broker pose avant `launch_session` (cf. `bus.sessions.SessionRegistry.create`)."""
    registry.create(
        sid,
        container=("ocular-sess-" + sid) if container is None else container,
        kind="recon-vnc",
        # cible sans lien avec le propriétaire : sinon l'identité fuirait par
        # `target` et les assertions anti-fuite seraient trompeuses.
        target="https://cible-" + sid,
        token=_WS_TOKEN,
        secret=_CAP_SECRET,
        owner=owner,
        now_iso="2026-07-13T10:00:00+00:00",
    )


def _health(monkeypatch, ok: bool):
    """Doublure du `/health` interne du session_server (le seul contrôle qui
    distingue `starting` de `ready`)."""
    monkeypatch.setattr(app_mod, "_internal_get_ok", lambda url, timeout=2.0: ok)


# =============================================================================
# 1. POST /sessions ne bloque PLUS
# =============================================================================

def test_create_session_answers_202_without_waiting_for_readiness(monkeypatch):
    """LA preuve du correctif : l'attente de disponibilité n'est plus sur le
    chemin de requête.

    `_wait_session_ready` est remplacée par une version qui dort LONGUEMENT (le
    temps réel de démarrage est de ~7-9 s). Si l'attente était restée dans la
    route, la réponse ne pourrait pas arriver avant ce délai. On mesure : elle
    arrive en une fraction de seconde, et l'attente s'exécute bien — ailleurs.
    """
    client, _, _ = _stack(monkeypatch)
    started = []
    slow = 5.0

    def slow_wait(registry, sid, deadline):
        started.append(sid)
        time.sleep(slow)
        return True

    monkeypatch.setattr(app_mod, "_wait_session_ready", slow_wait)
    monkeypatch.setattr(app_mod, "_internal_post_json", lambda *a, **k: True)

    t0 = time.monotonic()
    r = client.post("/sessions", json={"url": "https://example.com"})
    elapsed = time.monotonic() - t0

    assert r.status_code == 202
    assert r.json()["session_id"].startswith("sess-")
    # Marge très large : le point n'est pas la performance, c'est que l'attente
    # n'est PAS sérialisée avec la réponse.
    assert elapsed < slow / 2, f"POST /sessions a attendu {elapsed:.2f}s"

    # ... et l'amorçage tourne bien, en dehors de la requête.
    deadline = time.monotonic() + 5.0
    while not started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert started == [r.json()["session_id"]]


def test_create_session_returns_the_id_before_the_container_exists(monkeypatch):
    """Corollaire concret : au moment où le client reçoit sa réponse, aucune
    entrée registre n'a encore été écrite par le broker — et il détient pourtant
    déjà de quoi appeler `DELETE /sessions/{id}`. C'est exactement ce qui était
    impossible en synchrone."""
    client, registry, cmd_queue = _stack(monkeypatch)
    monkeypatch.setattr(app_mod, "_spawn_session_bootstrap", lambda *a: None)

    r = client.post("/sessions", json={"url": "https://example.com"})
    assert r.status_code == 202
    sid = r.json()["session_id"]
    assert registry.get(sid) is None            # le broker n'a encore rien fait
    assert cmd_queue.dequeue_cmd(timeout=1)["session_id"] == sid


# =============================================================================
# 2. Les trois états de disponibilité
# =============================================================================

def test_state_pending_when_container_not_launched_yet(monkeypatch):
    """Réservation posée par le broker, `container` encore vide."""
    client, registry, _ = _stack(monkeypatch)
    _seed(registry, owner="token", container="")
    _health(monkeypatch, False)

    body = client.get(f"/sessions/{_SID}").json()
    assert body["state"] == "pending"
    assert body["ready"] is False


def test_state_pending_does_not_probe_health(monkeypatch):
    """Sans conteneur, il n'y a rien à sonder : la route ne doit pas partir en
    appel réseau interne vers un hôte qui n'existe pas (2 s de timeout à chaque
    tour de sondage du client, pour rien)."""
    client, registry, _ = _stack(monkeypatch)
    _seed(registry, owner="token", container="")
    calls = []
    monkeypatch.setattr(
        app_mod, "_internal_get_ok", lambda url, timeout=2.0: calls.append(url) or False
    )

    assert client.get(f"/sessions/{_SID}").json()["state"] == "pending"
    assert calls == []


def test_state_starting_when_container_up_but_health_ko(monkeypatch):
    """Conteneur lancé, session_server pas encore debout."""
    client, registry, _ = _stack(monkeypatch)
    _seed(registry, owner="token")
    _health(monkeypatch, False)

    body = client.get(f"/sessions/{_SID}").json()
    assert body["state"] == "starting"
    assert body["ready"] is False


def test_state_ready_when_health_answers(monkeypatch):
    client, registry, _ = _stack(monkeypatch)
    _seed(registry, owner="token")
    _health(monkeypatch, True)

    body = client.get(f"/sessions/{_SID}").json()
    assert body["state"] == "ready"
    assert body["ready"] is True


def test_ready_flag_always_agrees_with_state(monkeypatch):
    """`ready` est un pur dérivé de `state` : le client peut s'arrêter sur l'un
    ou l'autre sans jamais les voir se contredire."""
    client, registry, _ = _stack(monkeypatch)
    for container, healthy in (("", False), ("ocular-sess-x", False), ("ocular-sess-x", True)):
        registry.delete(_SID)
        _seed(registry, owner="token", container=container)
        _health(monkeypatch, healthy)
        body = client.get(f"/sessions/{_SID}").json()
        assert body["ready"] == (body["state"] == "ready")


def test_probe_and_wait_share_the_same_readiness_logic(monkeypatch):
    """Anti-duplication : `_wait_session_ready` passe par `_session_state`. Si
    quelqu'un réimplémentait l'un des deux contrôles d'un côté seulement, la
    sonde et l'attente divergeraient — un client pourrait voir « prête » sur une
    session que le serveur, lui, considère encore en démarrage."""
    registry = SessionRegistry(fakeredis.FakeStrictRedis())
    _seed(registry, owner="token")
    seen = []

    def fake_state(reg, sid, sess=None):
        seen.append(sid)
        return app_mod.SESSION_STATE_READY

    monkeypatch.setattr(app_mod, "_session_state", fake_state)
    assert app_mod._wait_session_ready(registry, _SID, time.monotonic() + 5) is True
    assert seen == [_SID]


# =============================================================================
# 3. Appartenance : mêmes règles que les autres routes de session
# =============================================================================

def test_owner_can_probe_their_own_session(monkeypatch):
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _seed(registry, owner=_ALICE)
    _health(monkeypatch, True)

    r = client.get(f"/sessions/{_SID}", headers=_as(_ALICE))
    assert r.status_code == 200
    assert r.json()["session_id"] == _SID


def test_probing_another_users_session_returns_404(monkeypatch):
    """404, JAMAIS 403 : un 403 confirmerait l'existence de l'identifiant. Cette
    route est LA surface de sondage répété du nouveau contrat — c'est ici qu'un
    oracle d'existence serait le plus commode à exploiter."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _seed(registry, owner=_ALICE)
    _health(monkeypatch, True)

    r = client.get(f"/sessions/{_SID}", headers=_as(_BOB))
    assert r.status_code == 404


def test_unknown_and_foreign_sessions_are_indistinguishable(monkeypatch):
    """Le point précédent, formulé comme la propriété qu'il protège : la réponse
    à « session d'autrui » est OCTET POUR OCTET celle à « session inconnue »."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _seed(registry, owner=_ALICE)
    _health(monkeypatch, True)

    foreign = client.get(f"/sessions/{_SID}", headers=_as(_BOB))
    unknown = client.get("/sessions/sess-ffffffffffff", headers=_as(_BOB))
    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json() == unknown.json()


@pytest.mark.parametrize("bad", ["does-not-exist", "sess-*", "sess-XYZ123456789", "sess-0123456789"])
def test_malformed_session_id_is_rejected(monkeypatch, bad):
    """Même gabarit que toutes les routes de session (`_checked_session_id`) —
    404 et non 400/422, pour rester indistinguable d'un id inconnu. Le `sess-*`
    est le cas critique : interpolé tel quel, il devenait un GLOB Redis."""
    client, registry, _ = _stack(monkeypatch)
    _seed(registry, owner="token")
    _health(monkeypatch, True)

    assert client.get(f"/sessions/{bad}").status_code == 404


def test_admin_token_overrides_ownership(monkeypatch):
    """Mécanisme admin EXISTANT (`X-Admin-Token`), pas un nouveau."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    _seed(registry, owner=_ALICE)
    _health(monkeypatch, True)

    r = client.get(f"/sessions/{_SID}", headers={**_as(_BOB), "X-Admin-Token": "adm-secret"})
    assert r.status_code == 200
    assert r.json()["state"] == "ready"


def test_admin_group_overrides_ownership(monkeypatch):
    """Second mécanisme admin EXISTANT (groupe IdP)."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    monkeypatch.setenv("OCULAR_ADMIN_GROUP", "ocular-admins")
    _seed(registry, owner=_ALICE)
    _health(monkeypatch, True)

    r = client.get(
        f"/sessions/{_SID}", headers={**_as(_BOB), "X-Forwarded-Groups": "staff,ocular-admins"}
    )
    assert r.status_code == 200


def test_admin_on_an_unknown_session_still_gets_404(monkeypatch):
    """L'admin court-circuite l'appartenance, PAS l'existence : sans cette
    conclusion propre, la route lisait une session `None` et rendait un 500."""
    client, _, _ = _stack(monkeypatch, forward_auth=True)
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    _health(monkeypatch, True)

    r = client.get("/sessions/sess-ffffffffffff",
                   headers={**_as(_BOB), "X-Admin-Token": "adm-secret"})
    assert r.status_code == 404


def test_probe_requires_auth(monkeypatch):
    client, registry, _ = _stack(monkeypatch)
    _seed(registry, owner="token")
    client.headers.pop("Authorization", None)

    assert client.get(f"/sessions/{_SID}").status_code == 401


def test_session_without_owner_is_refused_to_non_admin(monkeypatch):
    """Fail-closed, cohérent avec les autres routes."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _seed(registry, owner="")
    _health(monkeypatch, True)

    assert client.get(f"/sessions/{_SID}", headers=_as(_ALICE)).status_code == 404


# =============================================================================
# 4. Anti-fuite : la sonde ne rend ni token ni secret
# =============================================================================

def test_probe_never_returns_token_nor_secret(monkeypatch):
    """Même filtrage que `list_active` : le token capability WS n'est JAMAIS
    rendu par une route de LECTURE (seul le 202 de création le donne, une fois),
    et le secret de frontière conteneur ne sort jamais du tout. La sonde étant
    appelée en boucle, une fuite ici serait la plus facile à ramasser."""
    client, registry, _ = _stack(monkeypatch)
    _seed(registry, owner="token")
    _health(monkeypatch, True)

    r = client.get(f"/sessions/{_SID}")
    body = r.json()
    assert "token" not in body
    assert "secret" not in body
    assert _WS_TOKEN not in r.text
    assert _CAP_SECRET not in r.text


def test_probe_hides_owner_from_non_admin_but_shows_it_to_admin(monkeypatch):
    """`owner` porte l'identité IdP d'un tiers : même traitement que dans
    `GET /sessions`."""
    client, registry, _ = _stack(monkeypatch, forward_auth=True)
    _seed(registry, owner=_ALICE)
    _health(monkeypatch, True)

    mine = client.get(f"/sessions/{_SID}", headers=_as(_ALICE))
    assert "owner" not in mine.json()
    assert _ALICE not in mine.text

    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    admin = client.get(f"/sessions/{_SID}", headers={**_as(_BOB), "X-Admin-Token": "adm-secret"})
    assert admin.json()["owner"] == _ALICE


# =============================================================================
# 5. Amorçage : la navigation initiale survit au déport hors requête
# =============================================================================

def test_bootstrap_pushes_goto_once_ready(monkeypatch):
    """La navigation initiale (`/goto`) n'a pas disparu avec l'attente : elle
    est simplement poussée par le thread d'amorçage, signée du MÊME secret."""
    registry = SessionRegistry(fakeredis.FakeStrictRedis())
    cmd_queue = SessionCmdQueue(fakeredis.FakeStrictRedis())
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: True)
    calls = []
    monkeypatch.setattr(
        app_mod, "_internal_post_json",
        lambda url, payload, secret, timeout=5.0: calls.append((url, payload, secret)) or True,
    )

    app_mod._session_bootstrap(registry, cmd_queue, _SID, "sec", "https://example.com/", None)

    assert len(calls) == 1
    assert calls[0][0].endswith("/goto")
    assert calls[0][1] == {"url": "https://example.com/"}
    assert calls[0][2] == "sec"


def test_bootstrap_pushes_load_for_inline_html(monkeypatch):
    registry = SessionRegistry(fakeredis.FakeStrictRedis())
    cmd_queue = SessionCmdQueue(fakeredis.FakeStrictRedis())
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: True)
    calls = []
    monkeypatch.setattr(
        app_mod, "_internal_post_json",
        lambda url, payload, secret, timeout=5.0: calls.append((url, payload)) or True,
    )

    app_mod._session_bootstrap(registry, cmd_queue, _SID, "sec", None, "<h1>x</h1>")

    assert calls[0][0].endswith("/load")
    assert calls[0][1] == {"html": "<h1>x</h1>"}


def test_bootstrap_stops_the_session_when_it_never_becomes_ready(monkeypatch):
    """Filet de sécurité conservé du contrat synchrone : un conteneur qui ne
    démarre pas est stoppé, il n'immobilise pas 4 Go jusqu'à son TTL. Le client,
    lui, verra un 404 sur la sonde — un échec terminal."""
    registry = SessionRegistry(fakeredis.FakeStrictRedis())
    redis_client = fakeredis.FakeStrictRedis()
    cmd_queue = SessionCmdQueue(redis_client)
    monkeypatch.setattr(app_mod, "_wait_session_ready", lambda *a, **k: False)
    monkeypatch.setattr(app_mod, "_internal_post_json", lambda *a, **k: pytest.fail("navigué !"))

    app_mod._session_bootstrap(registry, cmd_queue, _SID, "sec", "https://example.com/", None)

    assert cmd_queue.dequeue_cmd(timeout=1) == {"action": "stop", "session_id": _SID}
