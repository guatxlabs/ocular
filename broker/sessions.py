from __future__ import annotations

import subprocess

from broker.launcher import (
    _CAPTURE_MEMORY,
    _CAPTURE_PIDS_LIMIT,
    _RECON_SECCOMP,
    _base_hardening,
)
from ocular_logging import get_logger

log = get_logger("broker.sessions")

_SESSION_IMAGE = "ocular-runner-recon-vnc:latest"
_SESSION_NETWORK = "ocular-sessions"


def _session_name(session_id: str) -> str:
    return f"ocular-sess-{session_id}"


def build_session_args(session_id: str, image: str = _SESSION_IMAGE) -> list[str]:
    """docker run **détaché** (`-d`, jamais `--rm -i` : le conteneur est
    persistant, son cycle de vie géré explicitement via `stop_session`) pour
    une session interactive (noVNC). Réseau `ocular-sessions` ON (egress
    Internet nécessaire au recon) mais **aucun port hôte publié** (`-p`) :
    le web/broker parlent au conteneur via le réseau Docker interne
    uniquement — jamais docker.sock, jamais `--network host`, jamais
    `--privileged`. Durcissement (cap-drop/no-new-privileges/read-only/user)
    réutilisé de `launcher._base_hardening` (DRY, cf. audit phase 3a)."""
    return [
        "docker", "run", "-d",
        *_base_hardening(_session_name(session_id), rm=False),
        "--network", _SESSION_NETWORK,
        "--security-opt", f"seccomp={_RECON_SECCOMP}",
        "--tmpfs", "/work:size=512m,mode=1777",
        "--tmpfs", "/tmp:size=64m,mode=1777",
        "--memory", _CAPTURE_MEMORY,
        "--pids-limit", _CAPTURE_PIDS_LIMIT,
        image,
    ]


def launch_session(session_id: str) -> str:
    """Lance un conteneur de session détaché et retourne son nom
    (`ocular-sess-{session_id}`). Seul le broker (jamais le web) exécute
    ceci : le web n'a pas accès à Docker."""
    name = _session_name(session_id)
    log.info("session launch session_id=%s", session_id)
    subprocess.run(build_session_args(session_id), capture_output=True, check=False)
    return name


def stop_session(container: str) -> None:
    """Arrête et supprime un conteneur de session. Best-effort (`check=False`)
    : robuste au TOCTOU (conteneur déjà mort/absent entre le check d'expiration
    et l'arrêt effectif — `reap` peut appeler ceci sur un conteneur fantôme
    sans lever)."""
    subprocess.run(["docker", "kill", container], capture_output=True, check=False)
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)


def reap(registry, now_epoch: float, ttl: float, idle: float) -> int:
    """Détruit les sessions expirées (TTL absolu ou inactivité) : pour
    chaque id retourné par `registry.expired`, stoppe le conteneur associé
    puis le retire du registre. Retourne le nombre de sessions détruites."""
    count = 0
    for session_id in registry.expired(now_epoch, ttl, idle):
        sess = registry.get(session_id)
        if sess is not None:
            stop_session(sess["container"])
        registry.delete(session_id)
        count += 1
    return count
