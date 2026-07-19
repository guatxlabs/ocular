# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test d'intégration reap() <-> SessionRegistry : couvre le couplage réel
entre `expired()` (bus/sessions.py) et `reap()` (broker/sessions.py), que
les tests unitaires de test_broker_sessions.py (avec _FakeRegistry) ne
peuvent pas vérifier — ils simulent `expired`/`get`/`delete` sans jamais
exercer la vraie logique TTL/idle ni le vrai stockage Redis."""
import fakeredis

from broker import sessions as broker_sessions_mod
from broker.sessions import reap
from bus.sessions import SessionRegistry, _iso_to_epoch


def test_reap_e2e_stops_and_purges_real_expired_session(monkeypatch):
    r = fakeredis.FakeStrictRedis()
    registry = SessionRegistry(r)
    registry.create(
        "s1",
        container="ocular-sess-s1",
        kind="recon-vnc",
        target="https://example.com",
        token="tok-abc",
        now_iso="2026-07-13T00:00:00+00:00",   # ancien : TTL sera dépassé
    )
    assert registry.get("s1") is not None  # confirme la session bien créée

    stopped = []
    monkeypatch.setattr(broker_sessions_mod, "stop_session", lambda c: stopped.append(c))

    now_epoch = _iso_to_epoch("2026-07-13T10:00:00+00:00")  # 10h plus tard

    count = reap(registry, now_epoch=now_epoch, ttl=3600, idle=3600)

    assert count == 1
    assert stopped == ["s1"]
    assert registry.get("s1") is None  # purgé du registre après reap


def test_reap_e2e_leaves_fresh_session_untouched(monkeypatch):
    r = fakeredis.FakeStrictRedis()
    registry = SessionRegistry(r)
    registry.create(
        "fresh",
        container="ocular-sess-fresh",
        kind="recon-vnc",
        target="https://example.com",
        token="tok",
        now_iso="2026-07-13T09:59:30+00:00",
    )

    stopped = []
    monkeypatch.setattr(broker_sessions_mod, "stop_session", lambda c: stopped.append(c))

    now_epoch = _iso_to_epoch("2026-07-13T10:00:00+00:00")

    count = reap(registry, now_epoch=now_epoch, ttl=3600, idle=3600)

    assert count == 0
    assert stopped == []
    assert registry.get("fresh") is not None  # toujours là : ni TTL ni idle dépassés
