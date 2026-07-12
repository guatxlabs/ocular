import os

from fastapi.testclient import TestClient

from web.app import app


def test_index_served_at_root():
    os.environ["OCULAR_TOKEN"] = "t"
    c = TestClient(app)
    r = c.get("/")
    assert r.status_code == 200
    assert "Ocular" in r.text  # l'index se charge (route publique, pas /jobs)


def test_static_assets_served():
    c = TestClient(app)
    assert c.get("/style.css").status_code == 200
    assert c.get("/api.js").status_code == 200
    assert c.get("/boot.js").status_code == 200
