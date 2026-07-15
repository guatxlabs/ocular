import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from bus.queue import RedisJobQueue


def _client(monkeypatch, token, *, trust_forward_auth=None):
    if token is None:
        monkeypatch.delenv("OCULAR_TOKEN", raising=False)
    else:
        monkeypatch.setenv("OCULAR_TOKEN", token)
    if trust_forward_auth is None:
        monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    else:
        monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1" if trust_forward_auth else "0")
    app.dependency_overrides[get_queue] = lambda: RedisJobQueue(fakeredis.FakeStrictRedis())
    return TestClient(app, raise_server_exceptions=False)


def test_503_when_token_unset(monkeypatch):
    c = _client(monkeypatch, None)
    assert c.get("/jobs/x").status_code == 503


def test_503_when_token_empty_string(monkeypatch):
    c = _client(monkeypatch, "")
    assert c.get("/jobs/x").status_code == 503


def test_401_without_or_wrong_header(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    assert c.get("/jobs/x").status_code == 401
    assert c.get("/jobs/x", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_200_with_correct_bearer(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    r = c.get("/jobs/x", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200  # {"status":"pending"}


def test_non_ascii_auth_header_is_401_not_500(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    # httpx refuse d'encoder un header str non-ASCII en ASCII -> on passe les octets
    # UTF-8 bruts directement (comme le ferait un client HTTP qui n'échappe pas la valeur).
    r = c.get("/jobs/x", headers={"Authorization": "Bearer café".encode("utf-8")})
    assert r.status_code == 401


# --- Forward-auth (opt-in strict) — anti-spoofing -------------------------------


def test_opt_in_off_forwarded_user_header_without_bearer_is_401(monkeypatch):
    """LE test critique anti-spoofing : opt-in OFF (défaut) + en-tête forgé par un
    attaquant, sans bearer => 401, l'en-tête est totalement ignoré."""
    c = _client(monkeypatch, "s3cret", trust_forward_auth=False)
    r = c.get("/jobs/x", headers={"X-Forwarded-User": "attacker"})
    assert r.status_code == 401


def test_opt_in_off_valid_bearer_still_works(monkeypatch):
    c = _client(monkeypatch, "s3cret", trust_forward_auth=False)
    r = c.get("/jobs/x", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200
    r2 = c.get("/auth/whoami", headers={"Authorization": "Bearer s3cret"})
    assert r2.status_code == 200
    assert r2.json() == {"identity": "token", "method": "bearer"}


def test_opt_in_on_forwarded_user_header_without_bearer_is_authorized(monkeypatch):
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True)
    r = c.get("/auth/whoami", headers={"X-Forwarded-User": "alice"})
    assert r.status_code == 200
    assert r.json() == {"identity": "alice", "method": "forward-auth"}


def test_opt_in_on_bearer_and_forwarded_user_header_prefers_header_identity(monkeypatch):
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True)
    r = c.get(
        "/auth/whoami",
        headers={"Authorization": "Bearer s3cret", "X-Forwarded-User": "alice"},
    )
    assert r.status_code == 200
    assert r.json() == {"identity": "alice", "method": "bearer"}


def test_opt_in_on_no_header_no_bearer_is_401(monkeypatch):
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True)
    r = c.get("/jobs/x")
    assert r.status_code == 401


def test_opt_in_off_no_token_configured_is_503(monkeypatch):
    c = _client(monkeypatch, None, trust_forward_auth=False)
    r = c.get("/jobs/x", headers={"X-Forwarded-User": "alice"})
    assert r.status_code == 503


def test_opt_in_on_no_token_configured_forward_auth_still_authorizes(monkeypatch):
    c = _client(monkeypatch, None, trust_forward_auth=True)
    r = c.get("/auth/whoami", headers={"X-Forwarded-User": "alice"})
    assert r.status_code == 200
    assert r.json() == {"identity": "alice", "method": "forward-auth"}


def test_admin_delete_saved_not_escalated_via_forward_auth(monkeypatch):
    """L'admin (DELETE /saved) reste inchangé : le forward-auth ne donne jamais
    les droits admin, même quand l'opt-in est actif."""
    monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True)
    r = c.delete("/saved", headers={"X-Forwarded-User": "alice"})
    assert r.status_code == 503  # OCULAR_ADMIN_TOKEN non configuré -> fail-closed
    assert r.status_code != 200
