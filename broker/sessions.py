from __future__ import annotations

import subprocess

from broker.launcher import (
    CAPTURE_MEMORY,
    CAPTURE_PIDS_LIMIT,
    RECON_SECCOMP,
    base_hardening,
)
from ocular_logging import get_logger

log = get_logger("broker.sessions")

_SESSION_IMAGE = "ocular-runner-recon-vnc:latest"
_SESSION_NETWORK = "ocular-sessions"


def _session_name(session_id: str) -> str:
    return f"ocular-sess-{session_id}"


def build_session_args(
    session_id: str, secret: str = "", image: str = _SESSION_IMAGE
) -> list[str]:
    """docker run **détaché** (`-d`, jamais `--rm -i` : le conteneur est
    persistant, son cycle de vie géré explicitement via `stop_session`) pour
    une session interactive (noVNC). Réseau `ocular-sessions` ON (egress
    Internet nécessaire au recon) mais **aucun port hôte publié** (`-p`) :
    le web/broker parlent au conteneur via le réseau Docker interne
    uniquement — jamais docker.sock, jamais `--network host`, jamais
    `--privileged`. Durcissement (cap-drop/no-new-privileges/read-only/user)
    réutilisé de `launcher.base_hardening` (DRY, cf. audit phase 3a)."""
    return [
        "docker", "run", "-d",
        *base_hardening(_session_name(session_id), rm=False),
        "--network", _SESSION_NETWORK,
        "--security-opt", f"seccomp={RECON_SECCOMP}",
        "--tmpfs", "/work:size=512m,mode=1777",
        "--tmpfs", "/tmp:size=64m,mode=1777",
        "--memory", CAPTURE_MEMORY,
        "--pids-limit", CAPTURE_PIDS_LIMIT,
        # Secret de session à la frontière conteneur (défense-en-profondeur
        # F1/F2) : le session_server exige ce secret sur /goto,/load,/capture.
        # SEUL le web le connaît ; jamais publié, jamais loggé. Fail-closed côté
        # conteneur (secret absent/vide => 403).
        "-e", f"OCULAR_SESSION_SECRET={secret}",
        image,
    ]


def launch_session(session_id: str, secret: str = "") -> str:
    """Lance un conteneur de session détaché et retourne son nom
    (`ocular-sess-{session_id}`). Seul le broker (jamais le web) exécute
    ceci : le web n'a pas accès à Docker. Le nom est toujours retourné même
    si `docker run` échoue (returncode != 0) : c'est le poll de santé aval
    qui décide de l'état réel de la session — on logue juste un warning ici."""
    name = _session_name(session_id)
    log.info("session launch session_id=%s", session_id)  # jamais le secret ici
    proc = subprocess.run(
        build_session_args(session_id, secret=secret), capture_output=True, check=False
    )
    if proc.returncode != 0:
        log.warning(
            "session launch failed session_id=%s returncode=%s stderr=%s",
            session_id, proc.returncode, proc.stderr.decode(errors="replace")[:200],
        )
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
    chaque id retourné par `registry.expired`, stoppe le conteneur par son
    nom **déterministe** `ocular-sess-{id}` (dérivé du session_id, jamais via
    `registry.get` qui peut renvoyer None sur une course entre l'expiration
    et le reap — le conteneur existe toujours indépendamment de l'état du
    registre) puis retire la session du registre. Retourne le nombre de
    sessions réellement traitées."""
    count = 0
    for session_id in registry.expired(now_epoch, ttl, idle):
        stop_session(_session_name(session_id))
        registry.delete(session_id)
        count += 1
    return count
