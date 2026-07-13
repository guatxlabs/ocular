import json

import broker.main as main_mod
from broker.main import _reaper_loop, _start_reaper, error_result


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

    def fake_reap(registry, now, ttl, idle):
        calls.append((registry, now, ttl, idle))

    monkeypatch.setattr(main_mod, "reap", fake_reap)
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "_time", type("T", (), {"time": staticmethod(lambda: 42.0)})())

    registry = object()
    _reaper_loop(registry, stop_event=stop_event)  # une seule itération puis sort via wait()

    assert len(calls) == 1
    assert calls[0] == (registry, 42.0, 1800, 600)


def test_reaper_loop_survives_reap_exception(monkeypatch):
    def boom(registry, now, ttl, idle):
        raise RuntimeError("redis down")

    monkeypatch.setattr(main_mod, "reap", boom)
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)

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
