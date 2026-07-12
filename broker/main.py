from __future__ import annotations

import os

import redis

from broker.launcher import run_analysis_job
from broker.queue import RedisJobQueue


def run_forever() -> None:
    queue = RedisJobQueue(redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379")))
    while True:
        job = queue.dequeue(timeout=5)
        if job is None:
            continue
        try:
            result_json = run_analysis_job(job)
        except Exception as exc:  # le job échoue proprement, le broker survit
            result_json = f'{{"job_id": "{job.job_id}", "error": "{str(exc)[:200]}"}}'
        queue.set_result(job.job_id, result_json)


if __name__ == "__main__":
    run_forever()
