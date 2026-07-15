from __future__ import annotations

import os


def redis_url() -> str:
    return os.environ.get("OCULAR_REDIS_URL", os.environ.get("REDIS_URL", "redis://localhost:6379"))


def artifacts_dir() -> str:
    return os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts")


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


def session_ready_timeout() -> float:
    """Délai global (secondes) laissé au broker pour lancer le conteneur de
    session + au session_server pour répondre `/health`, avant de renvoyer
    504 côté web."""
    return float(os.environ.get("OCULAR_SESSION_READY_TIMEOUT", "30"))
