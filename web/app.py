from __future__ import annotations

import json
import os
import uuid

import redis
from fastapi import Depends, FastAPI

from broker.queue import Job, RedisJobQueue
from web.models import JobRequest, JobResponse

app = FastAPI(title="Ocular")


def get_queue() -> RedisJobQueue:
    return RedisJobQueue(redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379")))


@app.post("/jobs", response_model=JobResponse)
def submit_job(req: JobRequest, queue: RedisJobQueue = Depends(get_queue)) -> JobResponse:
    job_id = "job-" + uuid.uuid4().hex[:12]
    queue.enqueue(Job(job_id=job_id, profile=req.profile, html=req.html, url=req.url))
    return JobResponse(job_id=job_id)


@app.get("/jobs/{job_id}")
def get_job(job_id: str, queue: RedisJobQueue = Depends(get_queue)) -> dict:
    result = queue.get_result(job_id)
    if result is None:
        return {"status": "pending"}
    return json.loads(result)
