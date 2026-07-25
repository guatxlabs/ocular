# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
import sqlite3

import pytest

import saved_store
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


# ---- migration idempotente + rétro-compat (Phase 3e — Task 2) --------------

_OLD_SCHEMA = """
CREATE TABLE saved_analysis (
  id INTEGER PRIMARY KEY,
  input_hash TEXT NOT NULL UNIQUE,
  input_kind TEXT NOT NULL,
  job_id TEXT,
  verdict TEXT,
  label TEXT,
  result_json TEXT NOT NULL,
  saved_at TEXT NOT NULL
);
CREATE TABLE saved_artifact (
  saved_id INTEGER NOT NULL REFERENCES saved_analysis(id) ON DELETE CASCADE,
  ref TEXT NOT NULL,
  bytes BLOB NOT NULL,
  PRIMARY KEY (saved_id, ref)
);
"""

_NEW_COLUMN_NAMES = {
    "saved_by", "turnstile_solved", "analyst_verdict", "analyst", "analyst_at", "analyst_note",
}


def _column_names(path):
    raw = sqlite3.connect(path)
    try:
        return {row[1] for row in raw.execute("PRAGMA table_info(saved_analysis)")}
    finally:
        raw.close()


def test_migration_adds_missing_columns_to_existing_old_schema_db(tmp_path):
    db_path = str(tmp_path / "old.sqlite3")
    raw = sqlite3.connect(db_path)
    raw.executescript(_OLD_SCHEMA)
    raw.close()
    assert not _NEW_COLUMN_NAMES.issubset(_column_names(db_path))

    c = ss.connect(db_path)
    c.close()

    assert _NEW_COLUMN_NAMES.issubset(_column_names(db_path))


def test_migration_is_idempotent_on_existing_db(tmp_path):
    db_path = str(tmp_path / "old2.sqlite3")
    raw = sqlite3.connect(db_path)
    raw.executescript(_OLD_SCHEMA)
    raw.close()

    ss.connect(db_path).close()
    ss.connect(db_path).close()  # 2e connect() successif — ne doit pas lever

    assert _NEW_COLUMN_NAMES.issubset(_column_names(db_path))


def test_migration_is_idempotent_on_fresh_db(tmp_path):
    db_path = str(tmp_path / "fresh.sqlite3")
    ss.connect(db_path).close()
    ss.connect(db_path).close()  # idempotent sur base neuve aussi

    assert _NEW_COLUMN_NAMES.issubset(_column_names(db_path))


# ---- save : provenance (saved_by, turnstile_solved) -------------------------

def test_save_turnstile_solved_true():
    c = _conn()
    r = {**_result(), "stealth": {"turnstile_solved": True}}
    sid = ss.save(c, r, {}, None, "t")
    assert ss.get_meta(c, sid)["turnstile_solved"] == 1


def test_save_turnstile_solved_false():
    c = _conn()
    r = {**_result(), "stealth": {"turnstile_solved": False}}
    sid = ss.save(c, r, {}, None, "t")
    assert ss.get_meta(c, sid)["turnstile_solved"] == 0


def test_save_no_stealth_gives_null_turnstile_solved():
    c = _conn()
    sid = ss.save(c, _result(), {}, None, "t")
    assert ss.get_meta(c, sid)["turnstile_solved"] is None


def test_save_stealth_with_none_turnstile_is_null_not_zero():
    # Tri-état (Phase 3j) : un stealth PRÉSENT mais sans challenge
    # (turnstile_solved=None) doit donner NULL, PAS 0 — sinon l'UI afficherait à
    # tort « Turnstile non passé » sur une capture interactive sans Turnstile.
    c = _conn()
    r = {**_result(), "stealth": {"engine": "camoufox", "turnstile_solved": None}}
    sid = ss.save(c, r, {}, None, "t")
    assert ss.get_meta(c, sid)["turnstile_solved"] is None


def test_save_stores_and_returns_saved_by():
    c = _conn()
    sid = ss.save(c, _result(), {}, None, "t", saved_by="alice")
    assert ss.get_meta(c, sid)["saved_by"] == "alice"
    assert ss.get_by_hash(c, _result()["input_hash"])["saved_by"] == "alice"


def test_save_saved_by_defaults_to_none_retro_compat():
    c = _conn()
    sid = ss.save(c, _result(), {}, None, "t")  # ancienne signature positionnelle
    assert ss.get_meta(c, sid)["saved_by"] is None


# ---- set_analyst_verdict -----------------------------------------------------

@pytest.mark.parametrize("verdict", ["legitimate", "suspicious", "malicious"])
def test_set_analyst_verdict_valid_values(verdict):
    c = _conn()
    sid = ss.save(c, _result(), {}, None, "t")
    ok = ss.set_analyst_verdict(c, sid, verdict, "bob", "2026-07-15T00:00:00Z", note="ras")
    assert ok is True
    meta = ss.get_meta(c, sid)
    assert meta["analyst_verdict"] == verdict
    assert meta["analyst"] == "bob"
    assert meta["analyst_at"] == "2026-07-15T00:00:00Z"
    assert meta["analyst_note"] == "ras"


def test_set_analyst_verdict_invalid_raises_value_error():
    c = _conn()
    sid = ss.save(c, _result(), {}, None, "t")
    with pytest.raises(ValueError):
        ss.set_analyst_verdict(c, sid, "bogus", "bob", "t")


def test_set_analyst_verdict_unknown_sid_returns_false():
    c = _conn()
    assert ss.set_analyst_verdict(c, 999999, "legitimate", "bob", "t") is False


def test_set_analyst_verdict_note_is_truncated_to_2000():
    c = _conn()
    sid = ss.save(c, _result(), {}, None, "t")
    ss.set_analyst_verdict(c, sid, "legitimate", "bob", "t", note="x" * 3000)
    assert len(ss.get_meta(c, sid)["analyst_note"]) == 2000


# ---- list_all / get_by_hash exposent les nouveaux champs --------------------

def test_list_all_and_get_by_hash_expose_new_fields():
    c = _conn()
    r = {**_result(), "stealth": {"turnstile_solved": True}}
    sid = ss.save(c, r, {}, None, "t", saved_by="alice")
    ss.set_analyst_verdict(c, sid, "malicious", "bob", "2026-07-15T00:00:00Z")

    row = ss.list_all(c)[0]
    for field in ("saved_by", "turnstile_solved", "analyst_verdict", "analyst", "analyst_at"):
        assert field in row
    assert row["saved_by"] == "alice"
    assert row["turnstile_solved"] == 1
    assert row["analyst_verdict"] == "malicious"
    assert row["analyst"] == "bob"

    meta = ss.get_by_hash(c, _result()["input_hash"])
    for field in ("saved_by", "turnstile_solved", "analyst_verdict", "analyst", "analyst_at"):
        assert field in meta


def test_save_persists_triage(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    result = {
        "input_hash": "sha256:aa", "profile": "analysis", "job_id": "j",
        "verdict": "benign",
        "triage": {"score": 63, "band": "medium"},
    }
    sid = saved_store.save(conn, result, {}, "lbl", "2026-01-01T00:00:00Z")
    meta = saved_store.get_meta(conn, sid)
    assert meta["triage_score"] == 63
    assert meta["triage_band"] == "medium"


def test_save_without_triage_is_null(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    result = {"input_hash": "sha256:bb", "profile": "analysis", "verdict": "benign"}
    sid = saved_store.save(conn, result, {}, None, "2026-01-01T00:00:00Z")
    meta = saved_store.get_meta(conn, sid)
    assert meta["triage_score"] is None
    assert meta["triage_band"] is None


def _seed(conn, hash_, score, band):
    saved_store.save(conn, {"input_hash": hash_, "profile": "analysis", "verdict": "benign",
                            "triage": {"score": score, "band": band}}, {}, None,
                     "2026-01-01T00:00:00Z")


def test_list_all_sort_by_triage_desc(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    _seed(conn, "sha256:a", 10, "low")
    _seed(conn, "sha256:b", 80, "high")
    rows = saved_store.list_all(conn, sort="triage_score", order="desc")
    assert [r["triage_score"] for r in rows] == [80, 10]


def test_list_all_filter_min_band(tmp_path):
    conn = saved_store.connect(str(tmp_path / "s.db"))
    _seed(conn, "sha256:a", 10, "low")
    _seed(conn, "sha256:b", 80, "high")
    rows = saved_store.list_all(conn, min_band="high")
    assert [r["input_hash"] for r in rows] == ["sha256:b"]


def test_list_all_sort_triage_nulls_last(tmp_path):
    # Une sauvegarde SANS triage (score/band NULL) ne doit jamais remonter en
    # tête d'un tri par priorité — même en ASC (SQLite classerait sinon NULL
    # en premier). Elle finit toujours en bas.
    conn = saved_store.connect(str(tmp_path / "s.db"))
    _seed(conn, "sha256:a", 10, "low")
    saved_store.save(conn, {"input_hash": "sha256:n", "profile": "analysis",
                            "verdict": "benign"}, {}, None, "2026-01-01T00:00:00Z")
    asc = saved_store.list_all(conn, sort="triage_score", order="asc")
    assert asc[0]["triage_score"] == 10
    assert asc[-1]["triage_score"] is None
    desc = saved_store.list_all(conn, sort="triage_score", order="desc")
    assert desc[0]["triage_score"] == 10
    assert desc[-1]["triage_score"] is None
