from __future__ import annotations

import base64
import json
import os
import subprocess
import time

from bus.queue import Job
from engine.artifacts import ref_to_filename
from ocular_logging import get_logger

log = get_logger("broker.launcher")

_IMAGE = "ocular-runner-analysis:latest"
_SECCOMP = "schemas/seccomp-analysis.json"
_RECON_IMAGE = "ocular-runner-recon:latest"
_RECON_SECCOMP = "schemas/seccomp-recon.json"
_ARTIFACTS_DIR = os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts")


def _proxy_env() -> list[str]:
    out: list[str] = []
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        if os.environ.get(k):
            out += ["-e", f"{k}={os.environ[k]}"]
    return out


def _store_blobs(blobs: dict, artifacts_dir: str) -> None:
    os.makedirs(artifacts_dir, exist_ok=True)
    for ref, b64 in blobs.items():
        try:
            fname = ref_to_filename(ref)          # lève ValueError si ref non conforme (anti-traversal)
        except ValueError:
            continue
        with open(os.path.join(artifacts_dir, fname), "wb") as fh:
            fh.write(base64.b64decode(b64))


def _parse_and_store(stdout: str, artifacts_dir: str) -> str:
    wrapper = json.loads(stdout)
    _store_blobs(wrapper.get("blobs", {}), artifacts_dir)
    return json.dumps(wrapper["result"])          # résultat léger, sans blobs


def build_docker_args(job: Job) -> list[str]:
    if job.profile == "analysis":
        return [
            "docker", "run", "--rm", "-i",
            "--name", f"ocular-job-{job.job_id}",
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--security-opt", f"seccomp={_SECCOMP}",
            "--read-only",
            "--tmpfs", "/work:size=256m,mode=1777",
            "--user", "10001:10001",
            "--memory", "2g",
            "--pids-limit", "256",
            _IMAGE,
            "--job-id", job.job_id,
        ]
    if job.profile == "capture":
        # Réseau ON (recon a besoin d'Internet) mais durci : pas de docker.sock,
        # pas de host-network, non-root, cap-drop ALL, seccomp dédié, read-only+tmpfs.
        return [
            "docker", "run", "--rm",
            "--name", f"ocular-job-{job.job_id}",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--security-opt", f"seccomp={_RECON_SECCOMP}",
            "--read-only",
            "--tmpfs", "/work:size=512m,mode=1777",
            "--tmpfs", "/tmp:size=64m,mode=1777",
            "--user", "10001:10001",
            "--memory", "4g",
            "--pids-limit", "512",
            *_proxy_env(),
            _RECON_IMAGE,
            "--url", job.url or "",
        ]
    raise ValueError(f"profil non géré: {job.profile}")


def run_job(job: Job) -> str:
    log.info("runner launch job_id=%s profile=%s", job.job_id, job.profile)
    if job.profile == "capture":
        log.warning("capture job job_id=%s : IP exposée (proxy=%s)",
                    job.job_id, bool(_proxy_env()))
    started = time.monotonic()
    stdin = (job.html or "").encode() if job.profile == "analysis" else None
    timeout = 60 if job.profile == "analysis" else 90
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
