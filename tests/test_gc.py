import fakeredis

from broker.gc import collect


def test_gc_removes_orphans_keeps_referenced(tmp_path):
    r = fakeredis.FakeStrictRedis()
    kept = "sha256_" + "a" * 64
    orphan = "sha256_" + "b" * 64
    (tmp_path / kept).write_bytes(b"x")
    (tmp_path / orphan).write_bytes(b"y")
    r.set("ocular:result:j", '{"screenshots":[{"image_ref":"sha256:' + "a" * 64 + '"}]}')
    removed = collect(str(tmp_path), r)
    assert removed == 1
    assert (tmp_path / kept).exists() and not (tmp_path / orphan).exists()
