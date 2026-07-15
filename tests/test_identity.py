"""Tests unitaires pour web.identity.resolve_identity — anti-spoofing en priorité.

Le cas critique : opt-in OFF (défaut) ⇒ l'en-tête X-Forwarded-User n'est JAMAIS
consulté, même s'il est présent sur la requête. C'est ce qui empêche un
attaquant de s'auto-attribuer une identité sans passer par un bearer valide.
"""
from __future__ import annotations

from starlette.requests import Request

from web.identity import resolve_identity


def _request(headers: dict[str, str]) -> Request:
    raw_headers = [
        (k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()
    ]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/jobs/x",
        "headers": raw_headers,
    }
    return Request(scope)


def test_resolve_identity_bearer_ok_no_trust_returns_token(monkeypatch):
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    req = _request({})
    authorized, identity, method = resolve_identity(req, bearer_ok=True)
    assert (authorized, identity, method) == (True, "token", "bearer")


def test_resolve_identity_opt_in_off_ignores_header_even_with_bearer(monkeypatch):
    """CRUCIAL anti-spoofing : opt-in OFF => en-tête jamais lu, même avec bearer_ok=True."""
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    req = _request({"X-Forwarded-User": "attacker"})
    authorized, identity, method = resolve_identity(req, bearer_ok=True)
    assert (authorized, identity, method) == (True, "token", "bearer")


def test_resolve_identity_opt_in_off_no_bearer_header_present_is_unauthorized(monkeypatch):
    """LE test critique : opt-in OFF (défaut) + header attaquant, pas de bearer => refus total."""
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    req = _request({"X-Forwarded-User": "attacker"})
    authorized, identity, method = resolve_identity(req, bearer_ok=False)
    assert (authorized, identity, method) == (False, None, "none")


def test_resolve_identity_opt_in_on_header_present_no_bearer(monkeypatch):
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    req = _request({"X-Forwarded-User": "alice"})
    authorized, identity, method = resolve_identity(req, bearer_ok=False)
    assert (authorized, identity, method) == (True, "alice", "forward-auth")


def test_resolve_identity_opt_in_on_bearer_and_header_prefers_header_value_method_bearer(monkeypatch):
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    req = _request({"X-Forwarded-User": "alice"})
    authorized, identity, method = resolve_identity(req, bearer_ok=True)
    assert (authorized, identity, method) == (True, "alice", "bearer")


def test_resolve_identity_opt_in_on_no_header_no_bearer_unauthorized(monkeypatch):
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    req = _request({})
    authorized, identity, method = resolve_identity(req, bearer_ok=False)
    assert (authorized, identity, method) == (False, None, "none")


def test_resolve_identity_opt_in_on_empty_header_value_is_ignored(monkeypatch):
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    req = _request({"X-Forwarded-User": ""})
    authorized, identity, method = resolve_identity(req, bearer_ok=False)
    assert (authorized, identity, method) == (False, None, "none")


def test_resolve_identity_opt_in_off_header_never_read_proof(monkeypatch):
    """Prouve que l'en-tête n'est pas consulté quand opt-in OFF : on fait exploser
    le nom d'en-tête (forward_auth_user_header) si jamais il est appelé côté
    resolve_identity alors que trust_forward_auth() est False."""
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)

    def _boom():  # pragma: no cover - ne doit jamais être appelé
        raise AssertionError("forward_auth_user_header() consulté alors que trust_forward_auth() est False")

    monkeypatch.setattr("web.identity.forward_auth_user_header", _boom)

    req = _request({"X-Forwarded-User": "attacker"})
    # sans bearer -> ne doit jamais consulter l'en-tête d'identité
    authorized, identity, method = resolve_identity(req, bearer_ok=False)
    assert (authorized, identity, method) == (False, None, "none")

    # avec bearer -> ne doit pas non plus consulter l'en-tête (opt-in off)
    authorized, identity, method = resolve_identity(req, bearer_ok=True)
    assert (authorized, identity, method) == (True, "token", "bearer")
