import json

import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from bus.queue import RedisJobQueue


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    (tmp_path / "artifacts").mkdir()
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    c = TestClient(app)
    c.headers.update({"Authorization": "Bearer t"})
    return c, q, tmp_path


def _seed_job(q, tmp_path, job_id="jx"):
    ref = "sha256:" + "b" * 64
    (tmp_path / "artifacts" / ("sha256_" + "b" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nX")
    q.set_result(job_id, json.dumps({
        "input_hash": "sha256:" + "a" * 64, "job_id": job_id, "verdict": "malicious",
        "screenshots": [{"image_ref": ref}], "artifacts": {"dom_html_ref": None},
    }))
    return ref


def test_save_then_lookup_and_result(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp)
    r = c.post("/saved", json={"job_id": "jx", "label": "note"})
    assert r.status_code == 200 and r.json()["input_hash"] == "sha256:" + "a" * 64
    sid = r.json()["id"]
    assert c.get("/saved/sha256:" + "a" * 64).status_code == 200
    assert c.get("/saved/sha256:" + "z" * 64).status_code == 404
    assert c.get(f"/saved/{sid}/result").json()["verdict"] == "malicious"
    assert any(x["id"] == sid for x in c.get("/saved").json())


def test_save_requires_token(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    c.headers.pop("Authorization")
    assert c.post("/saved", json={"job_id": "jx"}).status_code == 401


def test_save_expired_artifact_409(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    # résultat référence un ref dont le fichier n'existe pas (GC-é)
    q.set_result("jy", json.dumps({"input_hash": "sha256:" + "d" * 64, "verdict": "benign",
                 "screenshots": [{"image_ref": "sha256:" + "e" * 64}], "artifacts": {}}))
    assert c.post("/saved", json={"job_id": "jy"}).status_code == 409
