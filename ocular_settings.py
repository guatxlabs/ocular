from __future__ import annotations

import os
import re


def redis_url() -> str:
    return os.environ.get("OCULAR_REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379"))


def runner_image() -> str:
    return os.environ.get("OCULAR_RUNNER_IMAGE", "ocular-runner-analysis:latest")


def job_memory() -> str:
    return os.environ.get("OCULAR_JOB_MEMORY", "2g")


def job_pids() -> int:
    return int(os.environ.get("OCULAR_JOB_PIDS", "256"))


def job_timeout() -> int:
    return int(os.environ.get("OCULAR_JOB_TIMEOUT", "60"))


def render_timeout_ms() -> int:
    return int(os.environ.get("OCULAR_RENDER_TIMEOUT_MS", "15000"))


def result_ttl() -> int:
    return int(os.environ.get("OCULAR_RESULT_TTL", "86400"))


def job_ttl() -> int:
    """Fenêtre d'acceptation d'un job (marqueur `ocular:accepted:*`) : au-delà,
    un job toujours sans résultat est déclaré perdu/expiré (GET /jobs -> unknown),
    ce qui arrête le polling fantôme. Doit couvrir largement le temps de
    traitement le plus long (capture scriptée ~3 min + attente en file)."""
    return int(os.environ.get("OCULAR_JOB_TTL", "1800"))


def max_html_bytes() -> int:
    return int(os.environ.get("OCULAR_MAX_HTML_BYTES", "5000000"))


def log_level() -> str:
    return os.environ.get("OCULAR_LOG_LEVEL", "INFO").upper()


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


def session_ttl() -> int:
    return int(os.environ.get("OCULAR_SESSION_TTL", "1800"))     # 30 min absolu


def session_idle() -> int:
    return int(os.environ.get("OCULAR_SESSION_IDLE", "600"))     # 10 min inactivité


def reaper_interval() -> int:
    return int(os.environ.get("OCULAR_REAPER_INTERVAL", "60"))


def gc_interval() -> int:
    return int(os.environ.get("OCULAR_GC_INTERVAL", "600"))


def sweep_interval() -> int:
    """Période du balayage des orphelins (conteneurs `ocular-sess-*` et réseaux
    `ocular-sess-net-*` sans session vivante). Défaut 600 s : les résidus
    n'apparaissent qu'en cas d'anomalie (teardown partiel, conteneur tué hors
    flux), un passage toutes les 10 min récupère le pool d'adresses Docker sans
    marteler le démon Docker toutes les minutes."""
    return int(os.environ.get("OCULAR_SWEEP_INTERVAL", "600"))


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
    return int(os.environ.get("OCULAR_SESSION_DISCONNECT_GRACE", "45"))


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
    return float(os.environ.get("OCULAR_SESSION_READY_TIMEOUT", "30"))


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
    try:
        return max(0, int(os.environ.get("OCULAR_MAX_SESSIONS", "25")))
    except ValueError:
        return 25


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
