from __future__ import annotations

import json
import os

import redis

from broker.launcher import run_analysis_job
from broker.queue import RedisJobQueue


def error_result(job_id: str, exc: Exception) -> str:
    """Résultat JSON TOUJOURS valide pour un job échoué (le message d'exception
    peut contenir des guillemets/newlines venant de stderr Docker)."""
    return json.dumps({"job_id": job_id, "error": str(exc)[:200]})


def run_forever() -> None:
    queue = RedisJobQueue(redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379")))
    while True:
        job = queue.dequeue(timeout=5)
        if job is None:
            continue
        try:
            result_json = run_analysis_job(job)
        except Exception as exc:  # le job échoue proprement, le broker survit
            result_json = error_result(job.job_id, exc)
        queue.set_result(job.job_id, result_json)


if __name__ == "__main__":
    run_forever()
