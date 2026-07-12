import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from bus.queue import RedisJobQueue


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(fakeredis.FakeStrictRedis())
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer t"})
    return client


def test_serves_png_as_image(tmp_path, monkeypatch):
    ref = "sha256:" + "a" * 64
    (tmp_path / ("sha256_" + "a" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nDATA")
    c = _client(tmp_path, monkeypatch)
    r = c.get(f"/jobs/j/artifact/{ref}")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"


def test_serves_dom_as_attachment_never_html(tmp_path, monkeypatch):
    ref = "sha256:" + "d" * 64
    (tmp_path / ("sha256_" + "d" * 64)).write_bytes(b"<script>alert(1)</script>")
    c = _client(tmp_path, monkeypatch)
    r = c.get(f"/jobs/j/artifact/{ref}")
    assert r.status_code == 200
    assert "text/html" not in r.headers["content-type"]
    assert "attachment" in r.headers.get("content-disposition", "")


def test_invalid_ref_400(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.get("/jobs/j/artifact/..%2f..%2fetc%2fpasswd").status_code in (400, 404)


def test_missing_artifact_404(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.get(f"/jobs/j/artifact/sha256:{'e'*64}").status_code == 404
