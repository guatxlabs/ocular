import pytest

import saved_store as ss


def _result(h="sha256:" + "a" * 64, refs=("sha256:" + "b" * 64,)):
    return {
        "input_hash": h, "job_id": "j", "verdict": "malicious",
        "screenshots": [{"image_ref": r} for r in refs],
        "artifacts": {"dom_html_ref": None},
    }


def _conn():
    return ss.connect(":memory:")


def test_save_and_get_by_hash_and_result_and_artifact():
    c = _conn()
    blobs = {"sha256:" + "b" * 64: b"PNGBYTES"}
    sid = ss.save(c, _result(), blobs, "note", "2026-07-12T00:00:00Z")
    meta = ss.get_by_hash(c, "sha256:" + "a" * 64)
    assert meta and meta["verdict"] == "malicious" and meta["label"] == "note"
    assert ss.get_result(c, sid)["verdict"] == "malicious"
    assert ss.get_artifact(c, sid, "sha256:" + "b" * 64) == b"PNGBYTES"


def test_upsert_replaces_same_hash():
    c = _conn()
    ss.save(c, _result(), {"sha256:" + "b" * 64: b"X"}, "v1", "t1")
    ss.save(c, {**_result(), "verdict": "benign"}, {"sha256:" + "b" * 64: b"Y"}, "v2", "t2")
    assert len(ss.list_all(c)) == 1
    meta = ss.get_by_hash(c, "sha256:" + "a" * 64)
    assert meta["verdict"] == "benign" and meta["label"] == "v2"


def test_multistep_stores_all_blobs():
    c = _conn()
    r = {"input_hash": "sha256:" + "c" * 64, "verdict": "suspicious",
         "screenshots": [{"image_ref": "sha256:" + "1" * 64}, {"image_ref": "sha256:" + "2" * 64}],
         "artifacts": {"dom_html_ref": "sha256:" + "3" * 64}}
    blobs = {"sha256:" + "1" * 64: b"A", "sha256:" + "2" * 64: b"B", "sha256:" + "3" * 64: b"C"}
    sid = ss.save(c, r, blobs, None, "t")
    assert ss.get_artifact(c, sid, "sha256:" + "2" * 64) == b"B"
    assert ss.get_artifact(c, sid, "sha256:" + "3" * 64) == b"C"


def test_delete_cascades_and_flush():
    c = _conn()
    sid = ss.save(c, _result(), {"sha256:" + "b" * 64: b"X"}, None, "t")
    assert ss.delete(c, sid) is True
    assert ss.get_artifact(c, sid, "sha256:" + "b" * 64) is None  # cascade
    ss.save(c, _result(), {"sha256:" + "b" * 64: b"X"}, None, "t")
    assert ss.flush(c) == 1 and ss.list_all(c) == []


def test_label_is_parameterized_not_injected():
    c = _conn()
    evil = "'); DROP TABLE saved_analysis;--"
    ss.save(c, _result(), {"sha256:" + "b" * 64: b"X"}, evil, "t")
    # la table existe toujours et le label est stocké littéralement
    assert ss.get_by_hash(c, "sha256:" + "a" * 64)["label"] == evil


# ---- unicité du nom (label) — Task D 3d-1 ----------------------------------

def test_duplicate_label_on_different_hash_raises():
    c = _conn()
    ss.save(c, _result(h="sha256:" + "a" * 64), {}, "x", "t1")
    with pytest.raises(ss.DuplicateLabelError):
        ss.save(c, _result(h="sha256:" + "f" * 64), {}, "x", "t2")
    # la 2e sauvegarde n'a pas été créée
    assert len(ss.list_all(c)) == 1


def test_duplicate_label_resave_same_hash_is_allowed_upsert():
    c = _conn()
    ss.save(c, _result(h="sha256:" + "a" * 64), {}, "x", "t1")
    sid = ss.save(c, _result(h="sha256:" + "a" * 64), {}, "x", "t2")
    assert sid
    assert len(ss.list_all(c)) == 1
    assert ss.get_by_hash(c, "sha256:" + "a" * 64)["label"] == "x"


def test_empty_or_none_label_has_no_uniqueness_constraint():
    c = _conn()
    ss.save(c, _result(h="sha256:" + "a" * 64), {}, "", "t1")
    ss.save(c, _result(h="sha256:" + "f" * 64), {}, "", "t2")
    ss.save(c, _result(h="sha256:" + "9" * 64), {}, None, "t3")
    assert len(ss.list_all(c)) == 3
