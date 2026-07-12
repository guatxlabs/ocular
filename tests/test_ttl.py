import fakeredis

from bus.queue import Job, RedisJobQueue, RESULT_PREFIX


def test_set_result_with_ttl_sets_expiry():
    r = fakeredis.FakeStrictRedis()
    q = RedisJobQueue(r)
    q.set_result("j", '{"ok":1}', ttl=120)
    assert 0 < r.ttl(RESULT_PREFIX + "j") <= 120


def test_set_result_without_ttl_persists():
    r = fakeredis.FakeStrictRedis()
    RedisJobQueue(r).set_result("j", "{}")
    assert r.ttl(RESULT_PREFIX + "j") == -1
