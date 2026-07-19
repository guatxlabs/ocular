# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Politique egress + kwargs de lancement Camoufox PARTAGÉS entre le tier batch
(`runner_recon/capture.py`) et le tier interactif (`runner_recon_vnc/
session_server.py`). Source UNIQUE : la décision (démarrer le garde / refuser en
mode strict / avertir) et les kwargs durcis étaient dupliqués à l'identique, y
compris les CHAÎNES d'avertissement — une dérive y serait un trou sécu (audit 3m).

Les deux tiers gardent leur cycle de vie propre (context-manager one-shot vs
`_state` persistant) ; seule la DÉCISION est factorisée ici."""
from __future__ import annotations

from typing import Any, Optional

from engine.browser_prefs import HARDENED_FIREFOX_PREFS
from engine.egress_guard import EgressGuard
from ocular_logging import get_logger
from ocular_settings import egress_guard_enabled, require_egress_guard

log = get_logger("egress-policy")


def hardened_launch_kwargs() -> dict[str, Any]:
    """Kwargs de lancement Camoufox durcis (headed Xvfb, anti-detect, prefs
    fermant les canaux egress hors-proxy). Copie fraîche à chaque appel."""
    return dict(
        headless=False,
        os="linux",
        humanize=0.3,
        i_know_what_im_doing=True,
        firefox_user_prefs=dict(HARDENED_FIREFOX_PREFS),
    )


async def maybe_start_egress_guard() -> tuple[Optional[EgressGuard], dict[str, Any]]:
    """Applique la politique egress AVANT tout lancement navigateur. Retourne
    `(guard | None, proxy_kwargs)` — `proxy_kwargs` à fusionner dans les
    launch kwargs (`{"proxy": {...}}` si garde actif, `{}` sinon).

    - garde activé (défaut) : démarre l'`EgressGuard` et route le navigateur
      dessus (fail-closed : si `start()` lève, l'exception remonte) ;
    - garde désactivé + **mode strict** (`OCULAR_REQUIRE_EGRESS_GUARD`) : lève
      `RuntimeError` (refus fail-closed d'un egress direct en réseau sensible) ;
    - garde désactivé, non strict : WARNING bruyant + egress DIRECT."""
    if egress_guard_enabled():
        guard = EgressGuard()
        port = await guard.start()
        return guard, {"proxy": {"server": f"http://127.0.0.1:{port}"}}
    if require_egress_guard():
        raise RuntimeError(
            "egress guard désactivé alors que OCULAR_REQUIRE_EGRESS_GUARD est actif "
            "— refus de démarrer (fail-closed)"
        )
    log.warning(
        "egress guard DÉSACTIVÉ — navigateur à accès réseau DIRECT non filtré "
        "(pivot SSRF possible vers le réseau interne). Interdit en réseau sensible."
    )
    return None, {}
