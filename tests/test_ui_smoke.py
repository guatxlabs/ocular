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


def test_saved_and_admin_views_served():
    # Les vues de la feature « analyses sauvegardées » (T7) sont servies en statique.
    c = TestClient(app)
    for path in ("/views/saved.js", "/views/admin.js"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert "javascript" in r.headers.get("content-type", "").lower(), path


def test_interactive_view_served():
    # La vue interactive (T8) est servie en statique.
    c = TestClient(app)
    r = c.get("/views/interactive.js")
    assert r.status_code == 200
    assert "javascript" in r.headers.get("content-type", "").lower()


def test_novnc_rfb_embedded_and_served():
    # noVNC est EMBARQUÉ localement (aucun CDN -> CSP) : le module ES rfb.js doit
    # être servi en 200 depuis le même origine.
    c = TestClient(app)
    r = c.get("/vendor/novnc/core/rfb.js")
    assert r.status_code == 200
    assert "javascript" in r.headers.get("content-type", "").lower()


def test_csp_allows_same_origin_ws():
    # La CSP de l'app shell doit autoriser le WebSocket same-origin (connect-src 'self').
    c = TestClient(app)
    csp = c.get("/").headers.get("content-security-policy", "")
    assert "connect-src 'self'" in csp
