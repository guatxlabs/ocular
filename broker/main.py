from __future__ import annotations

import json

import redis

from broker.launcher import run_analysis_job
from bus.queue import RedisJobQueue
from ocular_settings import redis_url, result_ttl


def error_result(job_id: str, exc: Exception) -> str:
    """Résultat JSON TOUJOURS valide pour un job échoué (le message d'exception
    peut contenir des guillemets/newlines venant de stderr Docker)."""
    return json.dumps({"job_id": job_id, "error": str(exc)[:200]})


def run_forever() -> None:
    queue = RedisJobQueue(redis.Redis.from_url(redis_url()))
    while True:
        job = queue.dequeue(timeout=5)
        if job is None:
            continue
        try:
            result_json = run_analysis_job(job)
        except Exception as exc:  # le job échoue proprement, le broker survit
            result_json = error_result(job.job_id, exc)
        queue.set_result(job.job_id, result_json, ttl=result_ttl())


if __name__ == "__main__":
    run_forever()
