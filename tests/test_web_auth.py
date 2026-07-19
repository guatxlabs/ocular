# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from bus.queue import RedisJobQueue


def _client(monkeypatch, token, *, trust_forward_auth=None, admin_group=None):
    if token is None:
        monkeypatch.delenv("OCULAR_TOKEN", raising=False)
    else:
        monkeypatch.setenv("OCULAR_TOKEN", token)
    if trust_forward_auth is None:
        monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    else:
        monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1" if trust_forward_auth else "0")
    if admin_group is None:
        monkeypatch.delenv("OCULAR_ADMIN_GROUP", raising=False)
    else:
        monkeypatch.setenv("OCULAR_ADMIN_GROUP", admin_group)
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
    assert r.status_code == 200  # corps {"status":"unknown"} pour un id inconnu — auth OK, c'est ce qu'on teste ici


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
    assert r2.json() == {"identity": "token", "method": "bearer", "groups": [], "is_admin": False}


def test_opt_in_on_forwarded_user_header_without_bearer_is_authorized(monkeypatch):
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True)
    r = c.get("/auth/whoami", headers={"X-Forwarded-User": "alice"})
    assert r.status_code == 200
    assert r.json() == {"identity": "alice", "method": "forward-auth", "groups": [], "is_admin": False}


def test_opt_in_on_bearer_and_forwarded_user_header_prefers_header_identity(monkeypatch):
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True)
    r = c.get(
        "/auth/whoami",
        headers={"Authorization": "Bearer s3cret", "X-Forwarded-User": "alice"},
    )
    assert r.status_code == 200
    assert r.json() == {"identity": "alice", "method": "bearer", "groups": [], "is_admin": False}


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
    assert r.json() == {"identity": "alice", "method": "forward-auth", "groups": [], "is_admin": False}


def test_admin_delete_saved_not_escalated_via_forward_auth(monkeypatch):
    """L'admin (DELETE /saved) reste inchangé : le forward-auth ne donne jamais
    les droits admin, même quand l'opt-in est actif."""
    monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True)
    r = c.delete("/saved", headers={"X-Forwarded-User": "alice"})
    assert r.status_code == 503  # OCULAR_ADMIN_TOKEN non configuré -> fail-closed
    assert r.status_code != 200


# --- Admin via groupe IdP (X-Forwarded-Groups), opt-in strict --------------------


def test_admin_delete_saved_valid_token_still_authorized(tmp_path, monkeypatch):
    """Non-régression : X-Admin-Token seul continue de fonctionner à l'identique."""
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    c = _client(monkeypatch, "s3cret")
    r = c.delete("/saved", headers={"Authorization": "Bearer s3cret", "X-Admin-Token": "adm-secret"})
    assert r.status_code == 200
    assert r.json() == {"flushed": 0}


def test_admin_delete_saved_via_admin_group_authorized(tmp_path, monkeypatch):
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True, admin_group="admins")
    r = c.delete(
        "/saved",
        headers={"Authorization": "Bearer s3cret", "X-Forwarded-Groups": "a,admins,b"},
    )
    assert r.status_code == 200
    assert r.json() == {"flushed": 0}


def test_admin_delete_saved_non_admin_group_is_403(monkeypatch):
    monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True, admin_group="admins")
    r = c.delete(
        "/saved",
        headers={"Authorization": "Bearer s3cret", "X-Forwarded-Groups": "users"},
    )
    assert r.status_code == 403


def test_admin_delete_saved_opt_in_off_spoofed_group_header_is_403_not_authorized(monkeypatch):
    """LE test critique anti-spoofing admin : opt-in OFF + X-Forwarded-Groups: admins
    spoofé par un attaquant, SANS X-Admin-Token => 403 (mécanisme groupe considéré
    non configuré car opt-in off), jamais autorisé."""
    monkeypatch.setenv("OCULAR_ADMIN_TOKEN", "adm-secret")
    c = _client(monkeypatch, "s3cret", trust_forward_auth=False, admin_group="admins")
    r = c.delete(
        "/saved",
        headers={"Authorization": "Bearer s3cret", "X-Forwarded-Groups": "admins"},
    )
    assert r.status_code == 403


def test_admin_delete_saved_no_mechanism_configured_is_503(monkeypatch):
    monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True, admin_group=None)
    r = c.delete("/saved", headers={"Authorization": "Bearer s3cret", "X-Forwarded-Groups": "admins"})
    assert r.status_code == 503


def test_admin_delete_saved_admin_group_set_but_no_trust_forward_auth_is_503(monkeypatch):
    """admin_group configuré mais forward-auth non fiable (opt-in off) : mécanisme
    groupe compté comme non disponible -> pas de token -> 503 fail-closed."""
    monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    c = _client(monkeypatch, "s3cret", trust_forward_auth=False, admin_group="admins")
    r = c.delete("/saved", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 503


# --- whoami : groups + is_admin ---------------------------------------------------


def test_whoami_opt_in_on_admin_group_reports_groups_and_is_admin_true(monkeypatch):
    c = _client(monkeypatch, "s3cret", trust_forward_auth=True, admin_group="admins")
    r = c.get(
        "/auth/whoami",
        headers={"Authorization": "Bearer s3cret", "X-Forwarded-Groups": "a,admins"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["groups"] == ["a", "admins"]
    assert body["is_admin"] is True


def test_whoami_opt_in_off_spoofed_admin_group_header_is_admin_false(monkeypatch):
    """Anti-spoofing whoami : opt-in OFF + header 'admins' => groups=[] et is_admin=False."""
    c = _client(monkeypatch, "s3cret", trust_forward_auth=False, admin_group="admins")
    r = c.get(
        "/auth/whoami",
        headers={"Authorization": "Bearer s3cret", "X-Forwarded-Groups": "admins"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["groups"] == []
    assert body["is_admin"] is False
