# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
import os
import time

import fakeredis

from broker.gc import collect


def test_gc_removes_orphans_keeps_referenced(tmp_path):
    r = fakeredis.FakeStrictRedis()
    kept = "sha256_" + "a" * 64
    orphan = "sha256_" + "b" * 64
    (tmp_path / kept).write_bytes(b"x")
    (tmp_path / orphan).write_bytes(b"y")
    old = time.time() - 10_000
    os.utime(tmp_path / orphan, (old, old))          # hors période de grâce
    os.utime(tmp_path / kept, (old, old))
    r.set("ocular:result:j", '{"screenshots":[{"image_ref":"sha256:' + "a" * 64 + '"}]}')
    removed = collect(str(tmp_path), r)
    assert removed == 1
    assert (tmp_path / kept).exists() and not (tmp_path / orphan).exists()


def test_gc_grace_period_keeps_fresh_orphans(tmp_path):
    r = fakeredis.FakeStrictRedis()
    fresh = "sha256_" + "c" * 64
    (tmp_path / fresh).write_bytes(b"z")             # mtime = maintenant
    assert collect(str(tmp_path), r, min_age_seconds=300) == 0
    assert (tmp_path / fresh).exists()


def test_gc_ignores_non_artifact_files(tmp_path):
    r = fakeredis.FakeStrictRedis()
    (tmp_path / ".gitkeep").write_bytes(b"")
    (tmp_path / "random.txt").write_bytes(b"junk")
    old = time.time() - 10_000
    os.utime(tmp_path / "random.txt", (old, old))
    assert collect(str(tmp_path), r) == 0
    assert (tmp_path / ".gitkeep").exists() and (tmp_path / "random.txt").exists()
