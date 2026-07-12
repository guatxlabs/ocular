import json

import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from bus.queue import RedisJobQueue


def _client(tmp_path, monkeypatch, admin=None):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    (tmp_path / "artifacts").mkdir()
    if admin is None:
        monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    else:
        monkeypatch.setenv("OCULAR_ADMIN_TOKEN", admin)
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    c = TestClient(app)
    c.headers.update({"Authorization": "Bearer t"})
    return c, q, tmp_path


def _seed_saved(c, q, tp, job_id="jx", h="a"):
    ref = "sha256:" + "b" * 64
    (tp / "artifacts" / ("sha256_" + "b" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nX")
    q.set_result(job_id, json.dumps({"input_hash": "sha256:" + h * 64, "verdict": "benign",
                 "screenshots": [{"image_ref": ref}], "artifacts": {}}))
    return c.post("/saved", json={"job_id": job_id}).json()["id"]


def test_delete_without_admin_configured_is_503(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch, admin=None)
    sid = _seed_saved(c, q, tp)
    assert c.delete(f"/saved/{sid}").status_code == 503


def test_delete_wrong_admin_403_correct_200(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch, admin="ADM")
    sid = _seed_saved(c, q, tp)
    assert c.delete(f"/saved/{sid}").status_code == 403
    assert c.delete(f"/saved/{sid}", headers={"X-Admin-Token": "nope"}).status_code == 403
    assert c.delete(f"/saved/{sid}", headers={"X-Admin-Token": "ADM"}).status_code == 200
    assert c.get(f"/saved/{sid}/result").status_code == 404  # supprimé


def test_flush_requires_admin(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch, admin="ADM")
    _seed_saved(c, q, tp, job_id="j1", h="a")
    _seed_saved(c, q, tp, job_id="j2", h="c")
    assert c.delete("/saved").status_code == 403
    r = c.delete("/saved", headers={"X-Admin-Token": "ADM"})
    assert r.status_code == 200 and r.json()["flushed"] == 2
    assert c.get("/saved").json() == []
