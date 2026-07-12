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
