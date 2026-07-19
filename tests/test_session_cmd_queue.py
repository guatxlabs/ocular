# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
import fakeredis

from bus.sessions import SessionCmdQueue


def test_enqueue_then_dequeue_launch_roundtrip():
    q = SessionCmdQueue(fakeredis.FakeStrictRedis())
    q.enqueue_cmd("launch", "s1", token="tok-abc", target="https://example.com")
    got = q.dequeue_cmd(timeout=1)
    assert got == {
        "action": "launch",
        "session_id": "s1",
        "token": "tok-abc",
        "target": "https://example.com",
    }


def test_enqueue_then_dequeue_stop_roundtrip():
    q = SessionCmdQueue(fakeredis.FakeStrictRedis())
    q.enqueue_cmd("stop", "s1")
    got = q.dequeue_cmd(timeout=1)
    assert got == {"action": "stop", "session_id": "s1"}


def test_dequeue_empty_returns_none():
    q = SessionCmdQueue(fakeredis.FakeStrictRedis())
    assert q.dequeue_cmd(timeout=1) is None


def test_fifo_order_preserved():
    q = SessionCmdQueue(fakeredis.FakeStrictRedis())
    q.enqueue_cmd("launch", "s1", token="t1", target="a")
    q.enqueue_cmd("launch", "s2", token="t2", target="b")
    first = q.dequeue_cmd(timeout=1)
    second = q.dequeue_cmd(timeout=1)
    assert first["session_id"] == "s1"
    assert second["session_id"] == "s2"
