import fakeredis

from bus.queue import Job, RedisJobQueue


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


# --- Phase 3k : marqueur d'acceptation (anti job fantôme) --------------------

def test_mark_accepted_then_is_accepted():
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    assert q.is_accepted("j1") is False        # jamais soumis -> non accepté
    q.mark_accepted("j1", ttl=1800)
    assert q.is_accepted("j1") is True


def test_set_result_clears_accepted_marker():
    # Un job terminal (résultat) ne doit plus être considéré « en cours » : le
    # marqueur d'acceptation est retiré par set_result.
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    q.mark_accepted("j1", ttl=1800)
    q.set_result("j1", '{"ok": true}')
    assert q.is_accepted("j1") is False


def test_accepted_marker_expires_with_ttl():
    r = fakeredis.FakeStrictRedis()
    q = RedisJobQueue(r)
    q.mark_accepted("j1", ttl=1800)
    r.delete("ocular:accepted:j1")   # simule l'expiration TTL / vidage Redis
    assert q.is_accepted("j1") is False
