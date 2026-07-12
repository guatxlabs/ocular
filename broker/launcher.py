from __future__ import annotations

import subprocess

from broker.queue import Job

_IMAGE = "ocular-runner-analysis:latest"
_SECCOMP = "schemas/seccomp-analysis.json"


def build_docker_args(job: Job) -> list[str]:
    if job.profile != "analysis":
        raise ValueError("build_docker_args ne gère que le profil analysis")
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


def run_analysis_job(job: Job) -> str:
    try:
        proc = subprocess.run(
            build_docker_args(job),
            input=(job.html or "").encode(),
            capture_output=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", f"ocular-job-{job.job_id}"],
                       capture_output=True, check=False)
        raise RuntimeError(f"runner timeout (job {job.job_id})")
    if proc.returncode != 0:
        raise RuntimeError(f"runner a échoué: {proc.stderr.decode()[:500]}")
    return proc.stdout.decode()
