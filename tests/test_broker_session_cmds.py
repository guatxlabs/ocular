# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
import fakeredis
import pytest

import broker.main as main_mod
import broker.sessions as sessions_mod
from broker.main import process_session_cmd
from broker.sessions import sweep_orphans
from bus.sessions import SessionRegistry


def _fake_redis(keys=None):
    r = fakeredis.FakeStrictRedis()
    for k in keys or []:
        r.set(k, b"1")
    return r


def _keys(r):
    return {k.decode() if isinstance(k, bytes) else k for k in r.keys()}


class _FakeRegistry:
    def __init__(self, redis_keys=None):
        self.created = []
        self.deleted = []
        self._r = _fake_redis(redis_keys)
        self.client = self._r  # cf. SessionRegistry.client (prod appelle registry.client)

    def create(self, session_id, container, kind, target, token, now_iso, secret="", owner=""):
        self.created.append({
            "session_id": session_id,
            "container": container,
            "kind": kind,
            "target": target,
            "token": token,
            "secret": secret,
            "owner": owner,
            "now_iso": now_iso,
        })

    def set_container(self, session_id, container):
        # complète la réservation *pending* (cf. SessionRegistry.set_container)
        for entry in self.created:
            if entry["session_id"] == session_id:
                entry["container"] = container

    def delete(self, session_id):
        self.deleted.append(session_id)


def test_launch_cmd_launches_container_and_creates_registry_entry(monkeypatch):
    launched = {}

    def fake_launch(sid, secret=""):
        launched["secret"] = secret
        return f"ocular-sess-{sid}"

    monkeypatch.setattr(main_mod, "launch_session", fake_launch)
    registry = _FakeRegistry()

    process_session_cmd(
        {"action": "launch", "session_id": "s1", "token": "tok-abc",
         "target": "https://example.com", "secret": "sekret-123",
         "owner": "alice@example.org"},
        registry,
    )

    assert len(registry.created) == 1
    entry = registry.created[0]
    assert entry["session_id"] == "s1"
    assert entry["container"] == "ocular-sess-s1"
    assert entry["kind"] == "recon-vnc"
    assert entry["target"] == "https://example.com"
    assert entry["token"] == "tok-abc"
    assert entry["secret"] == "sekret-123"
    # le propriétaire résolu côté web est threadé TEL QUEL jusqu'au registre :
    # c'est lui qui porte tout le contrôle d'appartenance des routes de session.
    assert entry["owner"] == "alice@example.org"
    assert entry["now_iso"]  # horodatage non vide
    # le secret est bien transmis au conteneur via launch_session
    assert launched["secret"] == "sekret-123"


def test_launch_cmd_defaults_missing_token_and_target(monkeypatch):
    monkeypatch.setattr(main_mod, "launch_session", lambda sid, secret="": f"ocular-sess-{sid}")
    registry = _FakeRegistry()

    process_session_cmd({"action": "launch", "session_id": "s1"}, registry)

    entry = registry.created[0]
    assert entry["token"] == ""
    assert entry["target"] == ""
    assert entry["secret"] == ""
    # une commande sans `owner` donne une session SANS propriétaire, que le web
    # refuse ensuite aux non-admins (fail-closed) — jamais une session ouverte.
    assert entry["owner"] == ""


def test_stop_cmd_stops_container_by_deterministic_name_and_deletes(monkeypatch):
    stopped = []
    monkeypatch.setattr(main_mod, "stop_session", lambda c: stopped.append(c))
    registry = _FakeRegistry(redis_keys=[
        "ocular:result:sesscap-s1-aa", "ocular:result:sesscap-s2-bb",
    ])

    process_session_cmd({"action": "stop", "session_id": "s1"}, registry)

    assert stopped == ["s1"]
    assert registry.deleted == ["s1"]
    # captures éphémères de s1 purgées ; celles de s2 intactes
    assert _keys(registry._r) == {"ocular:result:sesscap-s2-bb"}


def test_unknown_action_is_noop(monkeypatch):
    launched = []
    stopped = []
    monkeypatch.setattr(main_mod, "launch_session", lambda sid: launched.append(sid))
    monkeypatch.setattr(main_mod, "stop_session", lambda c: stopped.append(c))
    registry = _FakeRegistry()

    process_session_cmd({"action": "wat", "session_id": "s1"}, registry)

    assert launched == [] and stopped == []
    assert registry.created == [] and registry.deleted == []


def test_missing_session_id_is_noop(monkeypatch):
    launched = []
    monkeypatch.setattr(main_mod, "launch_session", lambda sid: launched.append(sid))
    registry = _FakeRegistry()

    process_session_cmd({"action": "launch"}, registry)

    assert launched == []
    assert registry.created == []


# --- Défaut A : le sweeper tuait une session EN COURS DE NAISSANCE -----------
# `process_session_cmd` faisait `launch_session()` PUIS `registry.create()`.
# Pendant `launch_session` (~0,6-3 s : network create + docker run + network
# connect) le conteneur existe pour `docker ps -a` mais n'est PAS au registre :
# le `_sweeper_loop` concurrent applique « pas au registre => résidu » et
# appelle `stop_session` -> il DÉTRUIT une session saine qui vient de démarrer
# (registre disant « vivante », conteneur et réseau supprimés). Pire variante :
# un sweep entre `network create` et `docker run` supprime le réseau et le
# `docker run --network …` échoue en « network not found ».
# Correctif : réserver l'entrée registre AVANT de lancer (entrée *pending*,
# container="") puis la compléter -> le sweeper ne voit jamais de trou.


def _docker_stub(calls, ps_out="", net_out=""):
    def fake_run(args, capture_output=None, check=None, text=None, timeout=None):
        calls.append(list(args))
        if args[:2] == ["docker", "ps"]:
            return type("P", (), {"returncode": 0, "stdout": ps_out, "stderr": ""})()
        if args[:3] == ["docker", "network", "ls"]:
            return type("P", (), {"returncode": 0, "stdout": net_out, "stderr": ""})()
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    return fake_run


def test_sweeper_concurrent_with_launch_does_not_kill_the_new_session(monkeypatch):
    """Fenêtre de course reproduite : le sweep tourne PENDANT `launch_session`,
    alors que le conteneur est déjà visible de `docker ps -a`. Il ne doit NI
    supprimer le conteneur NI supprimer son réseau dédié."""
    registry = SessionRegistry(fakeredis.FakeStrictRedis())
    calls = []
    monkeypatch.setattr(
        sessions_mod.subprocess, "run",
        _docker_stub(calls, ps_out="ocular-sess-s1\n", net_out="ocular-sess-net-s1\n"),
    )

    def fake_launch(sid, secret=""):
        # le _sweeper_loop tourne en parallèle du docker run
        sweep_orphans(registry)
        return f"ocular-sess-{sid}"

    monkeypatch.setattr(main_mod, "launch_session", fake_launch)

    process_session_cmd(
        {"action": "launch", "session_id": "s1", "token": "tok", "secret": "sek"}, registry
    )

    assert ["docker", "rm", "-f", "ocular-sess-s1"] not in calls, (
        "RÉGRESSION défaut A : le sweeper a détruit une session en cours de naissance"
    )
    assert ["docker", "kill", "ocular-sess-s1"] not in calls
    assert ["docker", "network", "rm", "ocular-sess-net-s1"] not in calls, (
        "RÉGRESSION défaut A : le réseau dédié d'une session naissante a été supprimé "
        "(le `docker run --network …` échouerait en « network not found »)"
    )
    sess = registry.get("s1")
    assert sess is not None and sess["container"] == "ocular-sess-s1"
    assert sess["token"] == "tok" and sess["secret"] == "sek"


def test_launch_reserves_pending_entry_before_starting_the_container(monkeypatch):
    """L'entrée est réservée AVANT `launch_session`, avec un `container` VIDE :
    `web._wait_session_ready` poll `sess.get("container")` non vide, donc il
    continue d'attendre le remplissage (pas de faux « prête »), tandis que le
    sweeper, lui, voit déjà une session vivante."""
    registry = SessionRegistry(fakeredis.FakeStrictRedis())
    seen = {}

    def fake_launch(sid, secret=""):
        seen["pending"] = registry.get(sid)
        return f"ocular-sess-{sid}"

    monkeypatch.setattr(main_mod, "launch_session", fake_launch)

    process_session_cmd({"action": "launch", "session_id": "s1", "token": "tok"}, registry)

    pending = seen["pending"]
    assert pending is not None, "l'entrée registre doit exister AVANT le lancement"
    assert pending["container"] == "", "l'entrée pending ne doit pas annoncer un conteneur prêt"
    # `expired()` lit created_at/last_activity : ils doivent être posés dès la réservation
    assert float(pending["created_at"]) > 0 and float(pending["last_activity"]) > 0
    assert registry.expired(0.0, ttl=1e9, idle=1e9) == []
    # …puis complétée
    assert registry.get("s1")["container"] == "ocular-sess-s1"


def test_launch_failure_does_not_leave_a_pending_ghost(monkeypatch):
    """Si `launch_session` lève, l'entrée réservée doit être retirée : sinon un
    fantôme sans conteneur resterait au registre (et protégerait indéfiniment
    un réseau orphelin du balayage)."""
    registry = SessionRegistry(fakeredis.FakeStrictRedis())

    def boom(sid, secret=""):
        raise RuntimeError("docker down")

    monkeypatch.setattr(main_mod, "launch_session", boom)

    with pytest.raises(RuntimeError):
        process_session_cmd({"action": "launch", "session_id": "s1"}, registry)

    assert registry.get("s1") is None
