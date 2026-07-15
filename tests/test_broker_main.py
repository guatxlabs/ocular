import json

import broker.main as main_mod
from broker.main import _gc_loop, _reaper_loop, _start_gc, _start_reaper, error_result


class _FakeStopEvent:
    """Simule un `threading.Event` sans dépendre du temps réel : reste
    "non déclenché" jusqu'à ce que `wait()` soit appelé une fois, ce qui le
    fait basculer -> garantit exactement une itération de `_reaper_loop`
    quel que soit `reaper_interval()`."""

    def __init__(self) -> None:
        self._set = False

    def is_set(self) -> bool:
        return self._set

    def wait(self, timeout: float) -> bool:
        self._set = True
        return True


def test_error_result_is_valid_json_even_with_special_chars():
    s = error_result("job-x", RuntimeError('runner a échoué: err "quote"\nline\\back'))
    d = json.loads(s)  # ne doit PAS lever
    assert d["job_id"] == "job-x"
    assert "runner a échoué" in d["error"]


def test_error_result_truncates_long_messages():
    s = error_result("job-y", RuntimeError("x" * 500))
    d = json.loads(s)
    assert len(d["error"]) <= 200


def test_reaper_loop_calls_reap_once_with_stop_event(monkeypatch):
    calls = []
    stop_event = _FakeStopEvent()

    def fake_reap(registry, now, ttl, idle, disconnect_grace):
        calls.append((registry, now, ttl, idle, disconnect_grace))

    monkeypatch.setattr(main_mod, "reap", fake_reap)
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)
    monkeypatch.setattr(main_mod, "_time", type("T", (), {"time": staticmethod(lambda: 42.0)})())

    registry = object()
    _reaper_loop(registry, stop_event=stop_event)  # une seule itération puis sort via wait()

    assert len(calls) == 1
    assert calls[0] == (registry, 42.0, 1800, 600, 45)


def test_reaper_loop_survives_reap_exception(monkeypatch):
    def boom(registry, now, ttl, idle, disconnect_grace):
        raise RuntimeError("redis down")

    monkeypatch.setattr(main_mod, "reap", boom)
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)

    stop_event = _FakeStopEvent()

    _reaper_loop(object(), stop_event=stop_event)  # ne doit PAS lever, malgré l'exception


def test_start_reaper_starts_a_daemon_thread(monkeypatch):
    started = {}

    def fake_reaper_loop(registry, stop_event=None):
        started["registry"] = registry
        started["called"] = True

    monkeypatch.setattr(main_mod, "_reaper_loop", fake_reaper_loop)
    monkeypatch.setattr(main_mod, "SessionRegistry", lambda client: ("registry-for", client))

    client = object()
    t = _start_reaper(client)
    t.join(timeout=2)

    assert t.daemon is True
    assert t.name == "ocular-reaper"
    assert started["called"] is True
    assert started["registry"] == ("registry-for", client)


def test_gc_loop_calls_collect_once_with_stop_event(monkeypatch):
    calls = []
    stop_event = _FakeStopEvent()

    def fake_collect(artifacts_dir, client):
        calls.append((artifacts_dir, client))

    monkeypatch.setattr(main_mod, "collect", fake_collect)
    monkeypatch.setattr(main_mod, "artifacts_dir", lambda: "/some/artifacts")
    monkeypatch.setattr(main_mod, "gc_interval", lambda: 600)

    client = object()
    _gc_loop(client, stop_event=stop_event)  # une seule itération puis sort via wait()

    assert calls == [("/some/artifacts", client)]


def test_gc_loop_survives_collect_exception(monkeypatch):
    def boom(artifacts_dir, client):
        raise RuntimeError("disk down")

    monkeypatch.setattr(main_mod, "collect", boom)
    monkeypatch.setattr(main_mod, "artifacts_dir", lambda: "/some/artifacts")
    monkeypatch.setattr(main_mod, "gc_interval", lambda: 600)

    stop_event = _FakeStopEvent()

    _gc_loop(object(), stop_event=stop_event)  # ne doit PAS lever, malgré l'exception


def test_start_gc_starts_a_daemon_thread(monkeypatch):
    started = {}

    def fake_gc_loop(client, stop_event=None):
        started["client"] = client
        started["called"] = True

    monkeypatch.setattr(main_mod, "_gc_loop", fake_gc_loop)

    client = object()
    t = _start_gc(client)
    t.join(timeout=2)

    assert t.daemon is True
    assert t.name == "ocular-gc"
    assert started["called"] is True
    assert started["client"] is client
