# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Accès centralisé à la configuration par variables d'environnement.

RÈGLE INVARIANTE — **un accesseur ne lève JAMAIS sur une valeur malformée ; il
retombe sur son défaut** (et applique un plancher). Ce n'est pas du confort :
ces accesseurs sont appelés depuis les boucles démon du broker (reaper, gc,
sweeper). Un `int()` nu sur `OCULAR_REAPER_INTERVAL=60s` levait un `ValueError`
qui tuait le thread SANS UN SEUL LOG — le broker continuait de servir, mais plus
aucune session n'était jamais reapée : fuite illimitée de conteneurs (~4 Go
chacun). De même, un intervalle à `0` produisait `sleep(0)`, soit une boucle
folle à 100 % CPU martelant Docker et Redis.

Tout nouvel accesseur numérique DOIT donc passer par `_env_int` / `_env_float`.
"""
from __future__ import annotations

import os
import re


def _env_num(name: str, default, minimum, maximum, cast):
    """Socle commun de `_env_int`/`_env_float` : lit `name`, le convertit avec
    `cast`, et retombe SILENCIEUSEMENT sur `default` si la variable est absente,
    vide ou illisible. Le résultat est ensuite borné à [`minimum`, `maximum`]
    (bornes ignorées si None) — c'est ce plancher qui interdit qu'un `0` ou un
    négatif ne devienne un intervalle de boucle."""
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        val = default
    else:
        try:
            val = cast(raw.strip())
        except (TypeError, ValueError):
            val = default
    if minimum is not None:
        val = max(minimum, val)
    if maximum is not None:
        val = min(maximum, val)
    return val


def _env_int(name: str, default: int, minimum: int | None = 1, maximum: int | None = None) -> int:
    """Entier de configuration. Ne lève jamais (cf. règle en tête de module).
    `minimum=1` par défaut : la quasi-totalité de ces réglages (intervalles,
    timeouts, quotas) n'a aucun sens à 0 ou en négatif."""
    return int(_env_num(name, default, minimum, maximum, int))


def _env_float(
    name: str, default: float, minimum: float | None = 1.0, maximum: float | None = None
) -> float:
    """Flottant de configuration. Mêmes garanties que `_env_int`."""
    return float(_env_num(name, default, minimum, maximum, float))


def redis_url() -> str:
    return os.environ.get("OCULAR_REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379"))


def runner_image() -> str:
    return os.environ.get("OCULAR_RUNNER_IMAGE", "ocular-runner-analysis:latest")


def job_memory() -> str:
    return os.environ.get("OCULAR_JOB_MEMORY", "2g")


def job_pids() -> int:
    return _env_int("OCULAR_JOB_PIDS", 256)


def job_timeout() -> int:
    return _env_int("OCULAR_JOB_TIMEOUT", 60)


def render_timeout_ms() -> int:
    return _env_int("OCULAR_RENDER_TIMEOUT_MS", 15000)


def result_ttl() -> int:
    return _env_int("OCULAR_RESULT_TTL", 86400)


def job_ttl() -> int:
    """Fenêtre d'acceptation d'un job (marqueur `ocular:accepted:*`) : au-delà,
    un job toujours sans résultat est déclaré perdu/expiré (GET /jobs -> unknown),
    ce qui arrête le polling fantôme. Doit couvrir largement le temps de
    traitement le plus long (capture scriptée ~3 min + attente en file)."""
    return _env_int("OCULAR_JOB_TTL", 1800)


def max_html_bytes() -> int:
    return _env_int("OCULAR_MAX_HTML_BYTES", 5000000)


def log_level() -> str:
    """Nom BRUT du niveau demandé (normalisé casse/espaces). La VALIDATION est
    faite par `ocular_logging.resolve_level`, qui retombe sur INFO si le nom est
    inconnu — un `setLevel` sur un niveau inconnu levait et faisait échouer
    l'import de tout le système (cf. règle en tête de module)."""
    return os.environ.get("OCULAR_LOG_LEVEL", "INFO").strip().upper()


def saved_db_path() -> str:
    return os.environ.get("OCULAR_SAVED_DB", "/saved/saved.db")


def admin_token() -> str | None:
    return os.environ.get("OCULAR_ADMIN_TOKEN")


def trust_forward_auth() -> bool:
    """Opt-in strict : par défaut False → l'en-tête d'identité forward-auth
    n'est JAMAIS lu (anti-spoofing, comportement bearer inchangé)."""
    return os.environ.get("OCULAR_TRUST_FORWARD_AUTH", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def forward_auth_user_header() -> str:
    return os.environ.get("OCULAR_FORWARD_USER_HEADER", "X-Forwarded-User")


def forward_auth_email_header() -> str:
    return os.environ.get("OCULAR_FORWARD_EMAIL_HEADER", "X-Forwarded-Email")


def admin_group() -> str:
    """Nom du groupe IdP accordant l'admin (`DELETE /saved`). Défaut `""` =
    admin-par-groupe désactivé (seul `OCULAR_ADMIN_TOKEN` fait foi)."""
    return os.environ.get("OCULAR_ADMIN_GROUP", "")


def forward_auth_groups_header() -> str:
    return os.environ.get("OCULAR_FORWARD_GROUPS_HEADER", "X-Forwarded-Groups")


def forward_for_header() -> str:
    """En-tête portant l'IP cliente transmise par le frontal de confiance.
    Lu UNIQUEMENT si `trust_forward_auth()` est actif — même surface de
    confiance que les en-têtes d'identité (cf. `web/identity.py`)."""
    return os.environ.get("OCULAR_FORWARD_FOR_HEADER", "X-Forwarded-For")


def session_ttl() -> int:
    return _env_int("OCULAR_SESSION_TTL", 1800)     # 30 min absolu


def session_idle() -> int:
    return _env_int("OCULAR_SESSION_IDLE", 600)     # 10 min inactivité


def reaper_interval() -> int:
    # plancher 1 s : `sleep(0)` ferait une boucle folle à 100 % CPU.
    return _env_int("OCULAR_REAPER_INTERVAL", 60, minimum=1)


def gc_interval() -> int:
    return _env_int("OCULAR_GC_INTERVAL", 600, minimum=1)  # plancher : cf. reaper_interval


def sweep_interval() -> int:
    """Période du balayage des orphelins (conteneurs `ocular-sess-*` et réseaux
    `ocular-sess-net-*` sans session vivante). Défaut 600 s : les résidus
    n'apparaissent qu'en cas d'anomalie (teardown partiel, conteneur tué hors
    flux), un passage toutes les 10 min récupère le pool d'adresses Docker sans
    marteler le démon Docker toutes les minutes."""
    return _env_int("OCULAR_SWEEP_INTERVAL", 600, minimum=1)  # plancher : cf. reaper_interval


_SCREEN_RE = re.compile(r"^\d{3,5}x\d{3,5}$")


def session_screen() -> str:
    """Résolution de l'Xvfb / du framebuffer de la session interactive, au format
    `LARGEURxHAUTEUR` (défaut `1920x1080`). Configurable via `OCULAR_SESSION_SCREEN`
    — non hardcodé, pour s'adapter à différentes tailles d'écran / cadres client.
    Valeur invalide -> défaut (jamais d'injection : validée par regex avant d'être
    passée à l'entrypoint du conteneur de session)."""
    val = os.environ.get("OCULAR_SESSION_SCREEN", "1920x1080").strip()
    return val if _SCREEN_RE.match(val) else "1920x1080"


def session_disconnect_grace() -> int:
    """Délai (secondes) laissé à une session dont le WS s'est déconnecté
    (y compris brutalement) avant que le reaper ne la nettoie — distinct de
    `session_idle()` : une session activement pollée via `/live` reste
    connectée (mark_connected efface `disconnected_at`)."""
    # minimum=0 : une grâce nulle (nettoyage dès la déconnexion) est un réglage
    # LÉGITIME, contrairement à un intervalle de boucle nul.
    return _env_int("OCULAR_SESSION_DISCONNECT_GRACE", 45, minimum=0)


def egress_guard_enabled() -> bool:
    """Secure-by-default (plan 3g) : le garde egress (`engine.egress_guard.
    EgressGuard`) est **ON** par défaut sur les runners réseau-ON (recon
    batch + session interactive) — `OCULAR_EGRESS_GUARD=0` (ou
    false/no/off) pour le désactiver explicitement. Le navigateur Camoufox
    n'a alors aucun bypass caché : c'est ce garde, résolution+pinning IP au
    moment de la connexion, qui défait le DNS-rebinding résiduel qu'un
    contrôle SSRF au submit (`engine.ssrf.validate_capture_url`) ne peut pas
    couvrir seul."""
    return os.environ.get("OCULAR_EGRESS_GUARD", "1").strip().lower() not in (
        "0", "false", "no", "off",
    )


def require_egress_guard() -> bool:
    """Mode STRICT (déploiement en réseau sensible : entreprise/prod/client).
    Quand `OCULAR_REQUIRE_EGRESS_GUARD` est actif, désactiver le garde egress est
    INTERDIT : un runner réseau-ON REFUSE de démarrer le navigateur si le garde
    est off (fail-closed), au lieu de lui donner un accès réseau direct non
    filtré. À poser sur tout déploiement où Ocular ne doit JAMAIS pouvoir pivoter
    vers le réseau interne. Défaut off (rétro-compat ; recommandé ON en prod —
    cf. docs/DEPLOY-SECURITY.md)."""
    return os.environ.get("OCULAR_REQUIRE_EGRESS_GUARD", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def session_ready_timeout() -> float:
    """Délai global (secondes) laissé au broker pour lancer le conteneur de
    session + au session_server pour répondre `/health`, avant de renvoyer
    504 côté web."""
    return _env_float("OCULAR_SESSION_READY_TIMEOUT", 30.0, minimum=1.0)


def artifacts_dir() -> str:
    """Répertoire des artefacts (screenshots/DOM/HAR) contenu-adressés.
    Défaut `artifacts` (relatif). Centralise l'accès à `OCULAR_ARTIFACTS_DIR`."""
    return os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts")


def web_container() -> str:
    """Nom du conteneur web, que le broker attache/détache aux réseaux
    per-session (`docker network connect`). Le compose dérive le
    `container_name` du service web de cette MÊME variable (source unique :
    les deux ne peuvent pas diverger, même si un opérateur la surcharge),
    avec `ocular-web` pour défaut — le nom reste ainsi DÉTERMINISTE (sinon
    Docker génère `<projet>-web-1`, non devinable par le broker).
    Surchargeable par `OCULAR_WEB_CONTAINER` ; une valeur vide retombe sur
    le défaut (un nom vide ferait échouer `network connect` de façon opaque)."""
    return os.environ.get("OCULAR_WEB_CONTAINER", "").strip() or "ocular-web"


def max_sessions() -> int:
    """Plafond de sessions interactives CONCURRENTES (anti-épuisement de
    ressources : chaque session = un conteneur ~4g). Le web refuse (429)
    au-delà. `0` = illimité (comportement historique). Défaut 25."""
    # minimum=0 : `0` = illimité, sémantique historique à préserver.
    return _env_int("OCULAR_MAX_SESSIONS", 25, minimum=0)


def llm_enabled() -> bool:
    """Option d'explication LLM (triage 3o). OFF par défaut : l'explication est
    strictement opt-in et n'entre JAMAIS dans le chemin de scoring. Ne s'arme
    qu'avec `OCULAR_LLM_ENABLED=1` ET un `OCULAR_LLM_BASE_URL` non vide."""
    return os.environ.get("OCULAR_LLM_ENABLED", "0") == "1"


def llm_base_url() -> str:
    """Base URL OpenAI-compatible (ex. `https://host/v1`). Vide par défaut =
    endpoint /explain désarmé (404)."""
    return os.environ.get("OCULAR_LLM_BASE_URL", "").strip()


def llm_model() -> str:
    return os.environ.get("OCULAR_LLM_MODEL", "").strip()


def llm_allow_internal() -> bool:
    """Opt-in explicite : autorise un `llm_base_url()` interne (loopback /
    RFC1918 / link-local) pour un LLM auto-hébergé. Par défaut False → la garde
    egress (`validate_capture_url`) rejette tout hôte interne avant l'appel."""
    return os.environ.get("OCULAR_LLM_ALLOW_INTERNAL", "0") == "1"
