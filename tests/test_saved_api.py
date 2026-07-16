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


def test_lookup_saved_url_finds_same_save_for_equivalent_urls(tmp_path, monkeypatch):
    # La normalisation est calculée côté serveur (un seul normaliseur Python
    # canonique) : deux URLs équivalentes (casse du host, port par défaut explicite)
    # doivent trouver la MÊME sauvegarde, sans dépendre d'un normaliseur JS côté client.
    c, q, tp = _client(tmp_path, monkeypatch)
    ref = "sha256:" + "b" * 64
    (tp / "artifacts" / ("sha256_" + "b" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nX")
    from engine.urlnorm import url_input_hash
    q.set_result("ju", json.dumps({
        "input_hash": url_input_hash("https://example.com/a"), "job_id": "ju",
        "profile": "capture", "verdict": "benign",
        "screenshots": [{"image_ref": ref}], "artifacts": {},
    }))
    saved = c.post("/saved", json={"job_id": "ju"})
    assert saved.status_code == 200
    sid = saved.json()["id"]

    r1 = c.post("/saved/lookup", json={"url": "https://EXAMPLE.com:443/a"})
    assert r1.status_code == 200 and r1.json()["id"] == sid

    r2 = c.post("/saved/lookup", json={"url": "https://example.com/a"})
    assert r2.status_code == 200 and r2.json()["id"] == sid


def test_lookup_saved_url_404_for_unknown_url(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    r = c.post("/saved/lookup", json={"url": "https://never-saved.example/x"})
    assert r.status_code == 404


def test_lookup_saved_url_422_without_url(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    r = c.post("/saved/lookup", json={})
    assert r.status_code == 422


def test_lookup_saved_url_422_on_malformed_url_not_500(tmp_path, monkeypatch):
    # audit sécu 3k : une URL malformée (normalize_url lève ValueError) doit
    # donner un 422 propre, pas un 500 (cohérent avec submit/create_session).
    c, q, tp = _client(tmp_path, monkeypatch)
    for bad in ("http://[::1", "http://a:notaport", "http://]"):
        r = c.post("/saved/lookup", json={"url": bad})
        assert r.status_code == 422, bad


def test_save_duplicate_label_on_different_content_409(tmp_path, monkeypatch):
    # Task D — unicité du nom : un label déjà pris par un input_hash différent
    # doit être refusé (409), sans écraser la sauvegarde existante.
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp, job_id="jx")
    r1 = c.post("/saved", json={"job_id": "jx", "label": "mon-rapport"})
    assert r1.status_code == 200

    ref2 = "sha256:" + "c" * 64
    (tp / "artifacts" / ("sha256_" + "c" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nY")
    q.set_result("jz", json.dumps({
        "input_hash": "sha256:" + "9" * 64, "job_id": "jz", "verdict": "benign",
        "screenshots": [{"image_ref": ref2}], "artifacts": {"dom_html_ref": None},
    }))
    r2 = c.post("/saved", json={"job_id": "jz", "label": "mon-rapport"})
    assert r2.status_code == 409
    assert "déjà" in r2.json()["detail"]
    # la sauvegarde d'origine n'a pas été altérée
    assert c.get("/saved/sha256:" + "a" * 64).json()["label"] == "mon-rapport"
    assert c.get("/saved/sha256:" + "9" * 64).status_code == 404


def test_save_same_label_resave_same_hash_ok(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp, job_id="jx")
    assert c.post("/saved", json={"job_id": "jx", "label": "note"}).status_code == 200
    assert c.post("/saved", json={"job_id": "jx", "label": "note"}).status_code == 200


def test_save_free_label_ok(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp, job_id="jx")
    assert c.post("/saved", json={"job_id": "jx", "label": "libre"}).status_code == 200


def test_saved_artifact_nosniff_and_dom_attachment(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    ref = _seed_job(q, tp)
    sid = c.post("/saved", json={"job_id": "jx"}).json()["id"]
    r = c.get(f"/saved/{sid}/artifact/{ref}")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert c.get(f"/saved/{sid}/artifact/sha256:{'A'*64}").status_code == 400  # anti-traversal
    assert c.get(f"/saved/{sid}/artifact/sha256:{'f'*64}").status_code == 404  # absent


# --- Task 3 : provenance (saved_by) + verdict analyste --------------------


def _client_forward_auth(tmp_path, monkeypatch, user):
    """Client authentifié uniquement via forward-auth (opt-in ON, pas de bearer)."""
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    (tmp_path / "artifacts").mkdir()
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    c = TestClient(app)
    c.headers.update({"X-Forwarded-User": user})
    return c, q, tmp_path


def test_save_records_saved_by_from_forward_auth_identity(tmp_path, monkeypatch):
    c, q, tp = _client_forward_auth(tmp_path, monkeypatch, "alice")
    _seed_job(q, tp)
    r = c.post("/saved", json={"job_id": "jx", "label": "note"})
    assert r.status_code == 200
    sid = r.json()["id"]
    entries = c.get("/saved").json()
    entry = next(x for x in entries if x["id"] == sid)
    assert entry["saved_by"] == "alice"


def test_save_records_saved_by_token_for_plain_bearer(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp)
    sid = c.post("/saved", json={"job_id": "jx", "label": "note"}).json()["id"]
    entry = next(x for x in c.get("/saved").json() if x["id"] == sid)
    assert entry["saved_by"] == "token"


def test_verdict_sets_analyst_fields_and_is_returned(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp)
    sid = c.post("/saved", json={"job_id": "jx"}).json()["id"]

    r = c.post(f"/saved/{sid}/verdict", json={"analyst_verdict": "legitimate", "note": "ras"})
    assert r.status_code == 200
    body = r.json()
    assert body["analyst_verdict"] == "legitimate"
    assert body["analyst"] == "token"
    assert body["analyst_at"]
    assert body["analyst_note"] == "ras"

    # relu depuis la liste : le champ persiste
    entry = next(x for x in c.get("/saved").json() if x["id"] == sid)
    assert entry["analyst_verdict"] == "legitimate"
    assert entry["analyst"] == "token"


def test_verdict_invalid_value_422(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp)
    sid = c.post("/saved", json={"job_id": "jx"}).json()["id"]
    r = c.post(f"/saved/{sid}/verdict", json={"analyst_verdict": "bidon"})
    assert r.status_code == 422


def test_verdict_unknown_sid_404(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    r = c.post("/saved/999999/verdict", json={"analyst_verdict": "legitimate"})
    assert r.status_code == 404


def test_verdict_does_not_require_admin_token(tmp_path, monkeypatch):
    # POST /saved/{id}/verdict n'est PAS une route admin : un bearer normal
    # suffit, X-Admin-Token n'est ni requis ni vérifié.
    c, q, tp = _client(tmp_path, monkeypatch)
    monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    _seed_job(q, tp)
    sid = c.post("/saved", json={"job_id": "jx"}).json()["id"]
    r = c.post(f"/saved/{sid}/verdict", json={"analyst_verdict": "suspicious"})
    assert r.status_code == 200


def test_saved_detail_and_list_expose_provenance_and_analyst_fields(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp)
    sid = c.post("/saved", json={"job_id": "jx"}).json()["id"]
    c.post(f"/saved/{sid}/verdict", json={"analyst_verdict": "malicious", "note": "confirmé"})

    expected_keys = {"saved_by", "turnstile_solved", "analyst_verdict", "analyst", "analyst_at"}
    entry = next(x for x in c.get("/saved").json() if x["id"] == sid)
    assert expected_keys.issubset(entry.keys())

    detail = c.get("/saved/sha256:" + "a" * 64).json()
    assert expected_keys.issubset(detail.keys())
    assert detail["analyst_verdict"] == "malicious"
