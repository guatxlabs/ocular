import fakeredis

from bus import sessions as sessions_mod
from bus.sessions import SessionRegistry


def _registry():
    return SessionRegistry(fakeredis.FakeStrictRedis())


def test_create_then_get_roundtrip():
    reg = _registry()
    reg.create(
        "s1",
        container="ocular-sess-s1",
        kind="recon-vnc",
        target="https://example.com",
        token="tok-abc",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    got = reg.get("s1")
    assert got is not None
    assert got["session_id"] == "s1"
    assert got["container"] == "ocular-sess-s1"
    assert got["kind"] == "recon-vnc"
    assert got["target"] == "https://example.com"
    assert got["token"] == "tok-abc"
    assert float(got["created_at"]) == float(got["last_activity"])


def test_get_missing_session_returns_none():
    reg = _registry()
    assert reg.get("nope") is None


def test_touch_updates_last_activity_but_not_created_at():
    reg = _registry()
    reg.create(
        "s1",
        container="c1",
        kind="recon-vnc",
        target="https://example.com",
        token="tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    reg.touch("s1", now_iso="2026-07-13T10:05:00+00:00")
    got = reg.get("s1")
    assert float(got["created_at"]) < float(got["last_activity"])


def test_touch_on_missing_session_is_noop():
    reg = _registry()
    reg.touch("ghost", now_iso="2026-07-13T10:00:00+00:00")
    assert reg.get("ghost") is None


def test_delete_removes_session():
    reg = _registry()
    reg.create(
        "s1", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    reg.delete("s1")
    assert reg.get("s1") is None


def test_list_active_returns_all_sessions():
    reg = _registry()
    reg.create(
        "s1", container="c1", kind="recon-vnc", target="t1", token="tok1",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    reg.create(
        "s2", container="c2", kind="recon-vnc", target="t2", token="tok2",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    ids = {s["session_id"] for s in reg.list_active()}
    assert ids == {"s1", "s2"}


def test_expired_includes_ttl_exceeded_session():
    reg = _registry()
    # créée il y a longtemps, mais touchée récemment (idle OK, TTL dépassé)
    reg.create(
        "old-ttl", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T00:00:00+00:00",
    )
    reg.touch("old-ttl", now_iso="2026-07-13T09:59:00+00:00")
    now_epoch = sessions_mod._iso_to_epoch("2026-07-13T10:00:00+00:00")
    result = reg.expired(now_epoch, ttl=3600, idle=3600)
    assert "old-ttl" in result


def test_expired_includes_idle_exceeded_session():
    reg = _registry()
    # créée récemment, mais aucune activité depuis longtemps (idle dépassé, TTL OK)
    reg.create(
        "idle-out", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T09:00:00+00:00",
    )
    now_epoch = sessions_mod._iso_to_epoch("2026-07-13T10:00:00+00:00")
    result = reg.expired(now_epoch, ttl=100000, idle=600)
    assert "idle-out" in result


def test_expired_excludes_fresh_session():
    reg = _registry()
    reg.create(
        "fresh", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T09:59:30+00:00",
    )
    now_epoch = sessions_mod._iso_to_epoch("2026-07-13T10:00:00+00:00")
    result = reg.expired(now_epoch, ttl=3600, idle=3600)
    assert "fresh" not in result


def test_valid_token_true_for_correct_token():
    reg = _registry()
    reg.create(
        "s1", container="c1", kind="recon-vnc", target="t", token="secret-tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    assert reg.valid_token("s1", "secret-tok") is True


def test_valid_token_false_for_wrong_token():
    reg = _registry()
    reg.create(
        "s1", container="c1", kind="recon-vnc", target="t", token="secret-tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    assert reg.valid_token("s1", "wrong-tok") is False


def test_valid_token_false_for_missing_session():
    reg = _registry()
    assert reg.valid_token("ghost", "anything") is False


def test_valid_token_uses_constant_time_compare(monkeypatch):
    reg = _registry()
    reg.create(
        "s1", container="c1", kind="recon-vnc", target="t", token="secret-tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    calls = []
    real_compare = sessions_mod.secrets.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real_compare(a, b)

    monkeypatch.setattr(sessions_mod.secrets, "compare_digest", spy)
    reg.valid_token("s1", "secret-tok")
    assert len(calls) == 1
