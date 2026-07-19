# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import json
import os
import subprocess
import time

from bus.queue import Job
from engine.artifacts import store_blobs
from ocular_logging import get_logger
from ocular_settings import artifacts_dir

log = get_logger("broker.launcher")

_IMAGE = "ocular-runner-analysis:latest"
_SECCOMP = "schemas/seccomp-analysis.json"
_RECON_IMAGE = "ocular-runner-recon:latest"
RECON_SECCOMP = "schemas/seccomp-recon.json"
_ARTIFACTS_DIR = artifacts_dir()

_ANALYSIS_TIMEOUT = 60
_CAPTURE_TIMEOUT = 90
# Job scripté (3c, `job.steps` non vide) : le runner applique son propre
# budget wall-clock TOTAL de 120s (`runner_recon/capture.py:SCRIPTED_EXEC_TIMEOUT_S`)
# et émet un résultat PARTIEL (journal + screenshots déjà pris) avant de
# rendre la main. Le timeout conteneur ici doit donc être STRICTEMENT
# supérieur à ce budget (marge de démarrage Camoufox + extraction DOM finale
# après l'arrêt du budget), sinon le broker `docker kill` le conteneur avant
# que le runner n'ait eu la chance d'émettre ce résultat partiel — perte
# totale (aucun stdout) au lieu d'un résultat dégradé mais exploitable.
# Constante DÉDIÉE, séparée de `_CAPTURE_TIMEOUT` (3a, capture sans steps,
# strictement inchangé à 90s).
_SCRIPTED_TIMEOUT = 180
_ANALYSIS_MEMORY = "2g"
_ANALYSIS_PIDS_LIMIT = "256"
CAPTURE_MEMORY = "4g"
CAPTURE_PIDS_LIMIT = "512"


def _proxy_env() -> list[str]:
    out: list[str] = []
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        if os.environ.get(k):
            out += ["-e", f"{k}={os.environ[k]}"]
    return out


def egress_policy_env() -> list[str]:
    """Propage la POLITIQUE egress du broker au conteneur runner réseau-ON, pour
    que la configuration soit cohérente de bout en bout : le garde egress
    (`OCULAR_EGRESS_GUARD`, défaut ON) et surtout le mode STRICT
    (`OCULAR_REQUIRE_EGRESS_GUARD`) sont lus DANS le runner — sans ce forwarding,
    poser le mode strict côté broker/compose n'aurait aucun effet sur le runner.
    Seules ces deux variables (booléennes, sûres) sont transmises."""
    out: list[str] = []
    for k in ("OCULAR_EGRESS_GUARD", "OCULAR_REQUIRE_EGRESS_GUARD"):
        v = os.environ.get(k)
        if v is not None:
            out += ["-e", f"{k}={v}"]
    return out


# Alias rétro-compat : le stockage d'artefacts vit désormais dans
# `engine.artifacts.store_blobs` (module neutre, sans Docker/subprocess),
# réutilisé tel quel par `web.app` pour la capture de session interactive —
# aucune duplication de la logique anti-traversal entre broker et web.
_store_blobs = store_blobs


def _parse_and_store(stdout: str, artifacts_dir: str) -> str:
    wrapper = json.loads(stdout)
    _store_blobs(wrapper.get("blobs", {}), artifacts_dir)
    return json.dumps(wrapper["result"])          # résultat léger, sans blobs


def base_hardening(name: str, rm: bool = True) -> list[str]:
    """Flags de durcissement communs à tous les conteneurs lancés par le
    broker (jobs jetables ET sessions interactives détachées) : nommage,
    aucune capability, no-new-privileges, rootfs read-only, utilisateur
    non-root. `rm=False` pour les conteneurs détachés persistants (sessions),
    dont le cycle de vie est géré explicitement (kill puis rm -f). Les
    specifics (network/seccomp/mémoire/tmpfs/proxy/image/args) restent
    composés par les appelants (`build_docker_args`, `build_session_args`)."""
    flags: list[str] = []
    if rm:
        flags.append("--rm")
    flags += [
        "--name", name,
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        "--user", "10001:10001",
    ]
    return flags


def build_docker_args(job: Job) -> list[str]:
    if job.profile == "analysis":
        return [
            "docker", "run", "-i",
            *base_hardening(f"ocular-job-{job.job_id}"),
            "--network", "none",
            "--security-opt", f"seccomp={_SECCOMP}",
            "--tmpfs", "/work:size=256m,mode=1777",
            "--memory", _ANALYSIS_MEMORY,
            "--pids-limit", _ANALYSIS_PIDS_LIMIT,
            _IMAGE,
            "--job-id", job.job_id,
        ]
    if job.profile == "capture":
        # Réseau ON (recon a besoin d'Internet) mais durci : pas de docker.sock,
        # pas de host-network, non-root, cap-drop ALL, seccomp dédié, read-only+tmpfs.
        # Chemin scripté (3c) : job.steps non vide -> stdin interactif (-i) requis
        # pour que le conteneur lise {url, steps} sur stdin (cf. scripted_stdin) ;
        # les steps ne sont JAMAIS ajoutés aux args (donc absents de docker inspect).
        # Sans steps -> chemin 3a strictement inchangé (pas de -i).
        scripted = bool(job.steps)
        return [
            "docker", "run",
            *(["-i"] if scripted else []),
            *base_hardening(f"ocular-job-{job.job_id}"),
            "--security-opt", f"seccomp={RECON_SECCOMP}",
            "--tmpfs", "/work:size=512m,mode=1777",
            "--tmpfs", "/tmp:size=64m,mode=1777",
            "--memory", CAPTURE_MEMORY,
            "--pids-limit", CAPTURE_PIDS_LIMIT,
            *_proxy_env(),
            *egress_policy_env(),   # OCULAR_EGRESS_GUARD / _REQUIRE_EGRESS_GUARD
            _RECON_IMAGE,
            "--url", job.url or "",
        ]
    raise ValueError(f"profil non géré: {job.profile}")


def scripted_stdin(job: Job) -> bytes:
    """Payload stdin JSON du chemin capture scripté (3c) : {url, steps}.
    Jamais passé par env/argument CLI (pas de fuite dans `docker inspect`)."""
    return json.dumps({"url": job.url or "", "steps": job.steps}).encode()


def run_job(job: Job) -> str:
    log.info("runner launch job_id=%s profile=%s", job.job_id, job.profile)
    if job.profile == "capture":
        log.warning("capture job job_id=%s : IP exposée (proxy=%s)",
                    job.job_id, bool(_proxy_env()))
    started = time.monotonic()
    if job.profile == "analysis":
        stdin = (job.html or "").encode()
    elif job.profile == "capture" and job.steps:
        stdin = scripted_stdin(job)
    else:
        stdin = None
    if job.profile == "analysis":
        timeout = _ANALYSIS_TIMEOUT
    elif job.profile == "capture" and job.steps:
        # Chemin scripté (3c) : cf. docstring de `_SCRIPTED_TIMEOUT`.
        timeout = _SCRIPTED_TIMEOUT
    else:
        # Chemin capture 3a (sans steps) : strictement inchangé.
        timeout = _CAPTURE_TIMEOUT
    try:
        proc = subprocess.run(
            build_docker_args(job),
            input=stdin,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", f"ocular-job-{job.job_id}"],
                       capture_output=True, check=False)
        log.error("runner timeout job_id=%s duration_ms=%d",
                   job.job_id, int((time.monotonic() - started) * 1000))
        raise RuntimeError(f"runner timeout (job {job.job_id})")
    duration_ms = int((time.monotonic() - started) * 1000)
    if proc.returncode != 0:
        log.error("runner failed job_id=%s duration_ms=%d", job.job_id, duration_ms)
        raise RuntimeError(f"runner a échoué: {proc.stderr.decode()[:500]}")
    log.info("runner done job_id=%s duration_ms=%d", job.job_id, duration_ms)
    return _parse_and_store(proc.stdout.decode(), _ARTIFACTS_DIR)


run_analysis_job = run_job  # rétro-compat pour les tests/imports existants
