from __future__ import annotations

import json

import redis

from broker.launcher import run_job
from bus.queue import RedisJobQueue
from ocular_logging import get_logger
from ocular_settings import redis_url, result_ttl

log = get_logger("broker")


def error_result(job_id: str, exc: Exception) -> str:
    """Résultat JSON TOUJOURS valide pour un job échoué (le message d'exception
    peut contenir des guillemets/newlines venant de stderr Docker). `status`
    à "error" pour que l'UI distingue un échec réel d'un verdict "unknown"."""
    return json.dumps({"job_id": job_id, "status": "error", "error": str(exc)[:200]})


def process_one(queue: RedisJobQueue, job) -> None:
    """Une itération de la boucle : traite un job et stocke son résultat
    (ou l'erreur). Extrait de run_forever() pour être testable sans mocker
    une boucle infinie."""
    log.info("job start job_id=%s", job.job_id)
    try:
        result_json = run_job(job)
    except Exception as exc:  # le job échoue proprement, le broker survit
        log.error("job failed job_id=%s err=%s", job.job_id, str(exc)[:200])
        result_json = error_result(job.job_id, exc)
    else:
        log.info("job done job_id=%s", job.job_id)
    queue.set_result(job.job_id, result_json, ttl=result_ttl())


def run_forever() -> None:
    queue = RedisJobQueue(redis.Redis.from_url(redis_url()))
    while True:
        job = queue.dequeue(timeout=5)
        if job is None:
            continue
        process_one(queue, job)


if __name__ == "__main__":
    run_forever()
