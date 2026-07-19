# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
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
    forward_for_header,
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


def client_ip(request: Request) -> str:
    """IP cliente à journaliser dans la piste d'audit.

    Le pair TCP (`request.client.host`) n'est plus l'analyste depuis
    l'introduction du frontal L4 `gateway` (deploy/) : celui-ci détient le port
    publié 8000 et relaie vers `web`, donc CHAQUE requête arrive avec l'IP du
    gateway. La vraie IP ne peut venir que d'un en-tête posé en amont.

    MÊME FRONTIÈRE DE CONFIANCE que `resolve_identity` : l'en-tête n'est lu que
    si `trust_forward_auth()` est actif — ce drapeau signifie déjà « un frontal
    de confiance est en amont et strippe les copies clientes des en-têtes
    transmis ». Sans lui, l'en-tête est TOTALEMENT ignoré : sinon n'importe
    quel client falsifie son IP dans le journal d'audit (empoisonnement de la
    piste d'audit), ce qui est pire qu'une IP de frontal, honnête et connue.

    Le gateway est du L4 (stream TCP) : il ne réécrit ni n'ajoute rien, donc un
    `X-Forwarded-For` posé par le reverse-proxy amont documenté arrive intact.

    CHOIX DE L'ÉLÉMENT — XFF est une liste `client, proxy1, proxy2` construite
    par AJOUT successif : le plus À GAUCHE est le client d'origine, chaque
    intermédiaire appendant le pair qu'il a vu. On prend donc le PREMIER.
    C'est correct ICI précisément à cause du contrat d'opt-in ci-dessus : le
    frontal de confiance strippe les copies clientes et repose la valeur
    lui-même, donc l'élément de gauche est celui qu'IL a observé, pas une
    valeur choisie par le client. (Sans ce contrat de strippage, le premier
    élément serait au contraire le plus falsifiable, et il faudrait remonter
    depuis la droite en sautant les proxys connus.)
    """
    if trust_forward_auth():
        raw = request.headers.get(forward_for_header(), "")
        first = raw.split(",")[0].strip()
        if first:
            return first
    peer = getattr(request, "client", None)
    return peer.host if peer else "?"


def has_admin_group(request: Request) -> bool:
    """True si le groupe admin configuré (`OCULAR_ADMIN_GROUP`) est présent
    parmi les groupes résolus. False si `admin_group()` est vide (admin-par-
    groupe désactivé) ou si l'opt-in forward-auth est désactivé (via
    `resolve_groups`, qui renvoie `[]` dans ce cas)."""
    g = admin_group()
    return bool(g) and g in resolve_groups(request)
