import fakeredis

from broker.queue import Job, RedisJobQueue


def test_enqueue_then_dequeue_roundtrip():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    q.enqueue(Job(job_id="j1", profile="analysis", html="<h1>x</h1>"))
    got = q.dequeue(timeout=1)
    assert got is not None and got.job_id == "j1" and got.html == "<h1>x</h1>"


def test_result_roundtrip():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    q.set_result("j1", '{"ok": true}')
    assert q.get_result("j1") == '{"ok": true}'


def test_dequeue_empty_returns_none():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    assert q.dequeue(timeout=1) is None
