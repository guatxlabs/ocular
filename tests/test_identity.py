# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests unitaires pour web.identity.resolve_identity — anti-spoofing en priorité.

Le cas critique : opt-in OFF (défaut) ⇒ l'en-tête X-Forwarded-User n'est JAMAIS
consulté, même s'il est présent sur la requête. C'est ce qui empêche un
attaquant de s'auto-attribuer une identité sans passer par un bearer valide.
"""
from __future__ import annotations

from starlette.requests import Request

from web.identity import has_admin_group, resolve_groups, resolve_identity


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


# --- resolve_groups / has_admin_group (admin via groupe IdP, opt-in strict) -----


def test_resolve_groups_opt_in_off_ignores_header_even_if_admin_present(monkeypatch):
    """CRUCIAL anti-spoofing : opt-in OFF => X-Forwarded-Groups totalement ignoré,
    même s'il contient 'admins'."""
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    monkeypatch.setenv("OCULAR_ADMIN_GROUP", "admins")
    req = _request({"X-Forwarded-Groups": "admins"})
    assert resolve_groups(req) == []
    assert has_admin_group(req) is False


def test_resolve_groups_opt_in_on_splits_strips_filters_empty(monkeypatch):
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    monkeypatch.setenv("OCULAR_ADMIN_GROUP", "admins")
    req = _request({"X-Forwarded-Groups": " a ,admins, b ,,"})
    assert resolve_groups(req) == ["a", "admins", "b"]
    assert has_admin_group(req) is True


def test_has_admin_group_false_when_admin_not_in_groups(monkeypatch):
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    monkeypatch.setenv("OCULAR_ADMIN_GROUP", "admins")
    req = _request({"X-Forwarded-Groups": "users,editors"})
    assert has_admin_group(req) is False


def test_has_admin_group_false_when_admin_group_unset_even_if_present(monkeypatch):
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    monkeypatch.delenv("OCULAR_ADMIN_GROUP", raising=False)
    req = _request({"X-Forwarded-Groups": "admins"})
    assert resolve_groups(req) == ["admins"]
    assert has_admin_group(req) is False


def test_resolve_groups_opt_in_off_no_header_never_read_proof(monkeypatch):
    """Prouve que le nom d'en-tête groupes n'est pas résolu quand opt-in OFF."""
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)

    def _boom():  # pragma: no cover - ne doit jamais être appelé
        raise AssertionError("forward_auth_groups_header() consulté alors que trust_forward_auth() est False")

    monkeypatch.setattr("web.identity.forward_auth_groups_header", _boom)

    req = _request({"X-Forwarded-Groups": "admins"})
    assert resolve_groups(req) == []


# --- IP cliente d'audit derrière le frontal L4 `gateway` ---------------------
# Régression mesurée : le gateway détient le port publié 8000 et relaie vers
# `web`, donc `request.client.host` est TOUJOURS l'IP du gateway (172.28.0.5) —
# chaque ligne d'audit « session create » portait cette IP au lieu de celle de
# l'analyste. La correction lit X-Forwarded-For, mais SOUS LA MÊME frontière de
# confiance que les en-têtes d'identité : sans l'opt-in, un client falsifierait
# sa propre IP dans le journal d'audit (empoisonnement de la piste d'audit).

from web.identity import client_ip

_GATEWAY_PEER = ("172.28.0.5", 51234)  # le pair TCP est le frontal, pas le client


def _request_from(headers: dict[str, str], peer=_GATEWAY_PEER) -> Request:
    raw_headers = [
        (k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()
    ]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/sessions",
        "headers": raw_headers,
        "client": peer,
    }
    return Request(scope)


def test_client_ip_honours_forwarded_header_when_trust_is_on(monkeypatch):
    """Drapeau ACTIF : l'en-tête posé par le frontal de confiance fait foi —
    sinon l'audit ne voit que l'IP du gateway."""
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    req = _request_from({"X-Forwarded-For": "203.0.113.7"})
    assert client_ip(req) == "203.0.113.7"


def test_client_ip_ignores_forwarded_header_when_trust_is_off(monkeypatch):
    """LE test anti-empoisonnement : opt-in OFF (défaut) => l'en-tête est
    totalement ignoré et on retombe sur le pair TCP. Sans cela, n'importe quel
    client écrit l'IP qu'il veut dans la piste d'audit."""
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    req = _request_from({"X-Forwarded-For": "1.2.3.4"})
    assert client_ip(req) == "172.28.0.5"  # l'IP du gateway, honnête et connue


def test_client_ip_takes_the_leftmost_element_of_the_list(monkeypatch):
    """XFF est une liste `client, proxy1, proxy2` construite par AJOUT : le
    client d'origine est le plus À GAUCHE. Prendre le dernier journaliserait un
    proxy intermédiaire."""
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    req = _request_from({"X-Forwarded-For": " 203.0.113.7 , 198.51.100.1 , 192.0.2.9 "})
    assert client_ip(req) == "203.0.113.7"


def test_client_ip_falls_back_to_peer_when_header_absent_or_empty(monkeypatch):
    """Opt-in actif mais en-tête absent/vide (appel interne direct au `web`,
    frontal mal configuré) : on ne renvoie JAMAIS une chaîne vide dans l'audit."""
    monkeypatch.setenv("OCULAR_TRUST_FORWARD_AUTH", "1")
    assert client_ip(_request_from({})) == "172.28.0.5"
    assert client_ip(_request_from({"X-Forwarded-For": "   "})) == "172.28.0.5"
    assert client_ip(_request_from({"X-Forwarded-For": " , 198.51.100.1"})) == "172.28.0.5"


def test_client_ip_without_peer_never_raises(monkeypatch):
    """Pas de pair TCP dans le scope (transport exotique/test) : repli `?`,
    jamais d'AttributeError sur un chemin de journalisation d'audit."""
    monkeypatch.delenv("OCULAR_TRUST_FORWARD_AUTH", raising=False)
    assert client_ip(_request_from({}, peer=None)) == "?"
