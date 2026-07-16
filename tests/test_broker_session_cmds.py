import fakeredis

import broker.main as main_mod
from broker.main import process_session_cmd


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

    def create(self, session_id, container, kind, target, token, now_iso, secret=""):
        self.created.append({
            "session_id": session_id,
            "container": container,
            "kind": kind,
            "target": target,
            "token": token,
            "secret": secret,
            "now_iso": now_iso,
        })

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
         "target": "https://example.com", "secret": "sekret-123"},
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


def test_stop_cmd_stops_container_by_deterministic_name_and_deletes(monkeypatch):
    stopped = []
    monkeypatch.setattr(main_mod, "stop_session", lambda c: stopped.append(c))
    registry = _FakeRegistry(redis_keys=[
        "ocular:result:sesscap-s1-aa", "ocular:result:sesscap-s2-bb",
    ])

    process_session_cmd({"action": "stop", "session_id": "s1"}, registry)

    assert stopped == ["ocular-sess-s1"]
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
