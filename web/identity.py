"""Résolution d'identité pour l'auth web — forward-auth opt-in strict.

Anti-spoofing : l'en-tête d'identité forward-auth (`X-Forwarded-User` par
défaut) n'est lu QUE si `OCULAR_TRUST_FORWARD_AUTH` est activé. Par défaut
(opt-in OFF), il est totalement ignoré et seul un bearer valide autorise —
comportement identique à avant l'introduction du forward-auth.

Le proxy en amont DOIT stripper toute copie de cet en-tête venant du client :
Ocular ne peut pas garantir seul l'absence de spoofing, c'est une
responsabilité de déploiement (voir README).
"""
from __future__ import annotations

from starlette.requests import Request

from ocular_settings import (
    admin_group,
    forward_auth_groups_header,
    forward_auth_user_header,
    trust_forward_auth,
)


def resolve_identity(request: Request, *, bearer_ok: bool) -> tuple[bool, str | None, str]:
    """Retourne (authorized, identity, method).

    - `bearer_ok` True -> autorisé. L'identité est la valeur de l'en-tête
      forward-auth SI `trust_forward_auth()` est actif et l'en-tête présent
      (le proxy prime pour la provenance), sinon "token". method="bearer".
    - sinon, si `trust_forward_auth()` est actif ET l'en-tête présent et non
      vide -> autorisé, identity=valeur, method="forward-auth".
    - sinon -> (False, None, "none").

    CRUCIAL anti-spoofing : l'en-tête n'est consulté (et même son nom
    résolu) que si `trust_forward_auth()` est vrai.
    """
    forward_identity: str | None = None
    if trust_forward_auth():
        header_name = forward_auth_user_header()
        value = request.headers.get(header_name, "")
        if value:
            forward_identity = value

    if bearer_ok:
        return True, forward_identity or "token", "bearer"

    if forward_identity is not None:
        return True, forward_identity, "forward-auth"

    return False, None, "none"


def resolve_groups(request: Request) -> list[str]:
    """Retourne les groupes IdP portés par l'en-tête forward-auth groupes,
    UNIQUEMENT si `trust_forward_auth()` est actif — même invariant
    anti-spoofing que `resolve_identity` : l'en-tête n'est ni lu, ni même son
    nom résolu, si l'opt-in est désactivé (défaut). Sinon `[]`."""
    if not trust_forward_auth():
        return []
    header_name = forward_auth_groups_header()
    raw = request.headers.get(header_name, "")
    return [g.strip() for g in raw.split(",") if g.strip()]


def has_admin_group(request: Request) -> bool:
    """True si le groupe admin configuré (`OCULAR_ADMIN_GROUP`) est présent
    parmi les groupes résolus. False si `admin_group()` est vide (admin-par-
    groupe désactivé) ou si l'opt-in forward-auth est désactivé (via
    `resolve_groups`, qui renvoie `[]` dans ce cas)."""
    g = admin_group()
    return bool(g) and g in resolve_groups(request)
