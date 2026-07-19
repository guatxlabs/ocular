# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
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


def test_create_stores_secret_and_get_secret_returns_it():
    reg = _registry()
    reg.create(
        "s1", container="c1", kind="recon-vnc", target="t", token="tok",
        secret="sess-secret-xyz", now_iso="2026-07-13T10:00:00+00:00",
    )
    assert reg.get_secret("s1") == "sess-secret-xyz"


def test_get_secret_missing_session_returns_none():
    reg = _registry()
    assert reg.get_secret("ghost") is None


def test_list_active_never_leaks_secret():
    reg = _registry()
    reg.create(
        "s1", container="c1", kind="recon-vnc", target="t", token="tok",
        secret="super-secret", now_iso="2026-07-13T10:00:00+00:00",
    )
    for sess in reg.list_active():
        assert "secret" not in sess


def test_expired_with_disconnect_grace_includes_stale_disconnected_session():
    reg = _registry()
    reg.create(
        "disconnected", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    reg.touch("disconnected", now_iso="2026-07-13T10:00:00+00:00")
    now_epoch = sessions_mod._iso_to_epoch("2026-07-13T10:00:00+00:00")
    reg.mark_disconnected("disconnected", now_epoch - 100)  # déconnectée il y a 100s
    # ttl/idle très larges : seule la règle de grâce doit déclencher
    result = reg.expired(now_epoch, ttl=100000, idle=100000, disconnect_grace=45)
    assert "disconnected" in result


def test_expired_with_disconnect_grace_excludes_recently_disconnected_session():
    reg = _registry()
    reg.create(
        "disconnected-fresh", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    now_epoch = sessions_mod._iso_to_epoch("2026-07-13T10:00:00+00:00")
    reg.mark_disconnected("disconnected-fresh", now_epoch - 10)  # déconnectée il y a 10s < grâce
    result = reg.expired(now_epoch, ttl=100000, idle=100000, disconnect_grace=45)
    assert "disconnected-fresh" not in result


def test_mark_connected_clears_disconnected_at_so_not_reaped_by_grace():
    reg = _registry()
    reg.create(
        "reconnected", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    now_epoch = sessions_mod._iso_to_epoch("2026-07-13T10:00:00+00:00")
    reg.mark_disconnected("reconnected", now_epoch - 1000)  # bien au-delà de la grâce
    reg.mark_connected("reconnected")
    result = reg.expired(now_epoch, ttl=100000, idle=100000, disconnect_grace=45)
    assert "reconnected" not in result


def test_expired_never_connected_session_not_reaped_by_grace_but_still_by_idle():
    reg = _registry()
    # jamais connectée (pas de disconnected_at) : la règle de grâce ne doit
    # jamais la reaper, seules ttl/idle s'appliquent toujours.
    reg.create(
        "never-connected", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T09:00:00+00:00",
    )
    now_epoch = sessions_mod._iso_to_epoch("2026-07-13T10:00:00+00:00")
    # ttl/idle larges : pas reaper malgré disconnect_grace fourni (pas de disconnected_at)
    result = reg.expired(now_epoch, ttl=100000, idle=100000, disconnect_grace=45)
    assert "never-connected" not in result
    # mais idle dépassé -> reaper par la règle idle existante, disconnect_grace fourni ou non
    result_idle = reg.expired(now_epoch, ttl=100000, idle=600, disconnect_grace=45)
    assert "never-connected" in result_idle


def test_expired_disconnect_grace_default_none_keeps_backward_compat():
    reg = _registry()
    reg.create(
        "disconnected-no-grace-arg", container="c1", kind="recon-vnc", target="t", token="tok",
        now_iso="2026-07-13T10:00:00+00:00",
    )
    now_epoch = sessions_mod._iso_to_epoch("2026-07-13T10:00:00+00:00")
    reg.mark_disconnected("disconnected-no-grace-arg", now_epoch - 1000)
    # appel sans disconnect_grace (signature rétro-compatible) : la règle de
    # grâce ne s'applique pas, seules ttl/idle comptent (ici larges -> pas reaper).
    result = reg.expired(now_epoch, ttl=100000, idle=100000)
    assert "disconnected-no-grace-arg" not in result


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


# --- C1 : robustesse reaper vs ghost + anti-résurrection (audit 2026-07-18) ---

def test_expired_skips_and_heals_partial_ghost_hash():
    # Un hash partiel (ex. ressuscité par une TOCTOU touch/delete : uniquement
    # last_activity, pas de created_at) ne doit PAS faire lever expired() ; il
    # est ignoré ET supprimé (auto-guérison), sinon le reaper mourrait à vie.
    reg = _registry()
    reg.create("live", container="c", kind="k", target="t", token="tok",
               now_iso="2026-07-13T10:00:00+00:00")
    reg._r.hset("ocular:session:ghost", "last_activity", "123.0")  # ghost sans created_at
    ids = reg.expired(now_epoch=200.0, ttl=100000, idle=100000)  # rien à reaper
    assert ids == []                                    # pas de crash, ghost ignoré
    assert reg._r.exists("ocular:session:ghost") == 0   # ghost supprimé (auto-guérison)
    assert reg._r.exists("ocular:session:live") == 1    # session valide intacte


def test_touch_does_not_resurrect_deleted_session():
    # touch après delete concurrent ne doit JAMAIS recréer la clé (anti-ghost).
    reg = _registry()
    reg.create("s1", container="c", kind="k", target="t", token="tok",
               now_iso="2026-07-13T10:00:00+00:00")
    reg.delete("s1")
    reg.touch("s1", "2026-07-13T11:00:00+00:00")
    assert reg._r.exists("ocular:session:s1") == 0
    reg.mark_disconnected("s1", 123.0)
    assert reg._r.exists("ocular:session:s1") == 0


def test_touch_still_updates_live_session():
    reg = _registry()
    reg.create("s1", container="c", kind="k", target="t", token="tok",
               now_iso="2026-07-13T10:00:00+00:00")
    before = float(reg.get("s1")["last_activity"])
    reg.touch("s1", "2026-07-13T12:00:00+00:00")
    got = reg.get("s1")
    assert float(got["last_activity"]) > before
    assert "created_at" in got  # toujours vivant
