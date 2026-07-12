import broker.main as main_mod
from broker.main import process_session_cmd


class _FakeRegistry:
    def __init__(self):
        self.created = []
        self.deleted = []

    def create(self, session_id, container, kind, target, token, now_iso):
        self.created.append({
            "session_id": session_id,
            "container": container,
            "kind": kind,
            "target": target,
            "token": token,
            "now_iso": now_iso,
        })

    def delete(self, session_id):
        self.deleted.append(session_id)


def test_launch_cmd_launches_container_and_creates_registry_entry(monkeypatch):
    monkeypatch.setattr(main_mod, "launch_session", lambda sid: f"ocular-sess-{sid}")
    registry = _FakeRegistry()

    process_session_cmd(
        {"action": "launch", "session_id": "s1", "token": "tok-abc", "target": "https://example.com"},
        registry,
    )

    assert len(registry.created) == 1
    entry = registry.created[0]
    assert entry["session_id"] == "s1"
    assert entry["container"] == "ocular-sess-s1"
    assert entry["kind"] == "recon-vnc"
    assert entry["target"] == "https://example.com"
    assert entry["token"] == "tok-abc"
    assert entry["now_iso"]  # horodatage non vide


def test_launch_cmd_defaults_missing_token_and_target(monkeypatch):
    monkeypatch.setattr(main_mod, "launch_session", lambda sid: f"ocular-sess-{sid}")
    registry = _FakeRegistry()

    process_session_cmd({"action": "launch", "session_id": "s1"}, registry)

    entry = registry.created[0]
    assert entry["token"] == ""
    assert entry["target"] == ""


def test_stop_cmd_stops_container_by_deterministic_name_and_deletes(monkeypatch):
    stopped = []
    monkeypatch.setattr(main_mod, "stop_session", lambda c: stopped.append(c))
    registry = _FakeRegistry()

    process_session_cmd({"action": "stop", "session_id": "s1"}, registry)

    assert stopped == ["ocular-sess-s1"]
    assert registry.deleted == ["s1"]


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
