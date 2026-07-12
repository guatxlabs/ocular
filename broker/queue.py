from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

_QUEUE_KEY = "ocular:jobs"
_RESULT_PREFIX = "ocular:result:"


class Job(BaseModel):
    job_id: str
    profile: str
    html: Optional[str] = None
    url: Optional[str] = None


class RedisJobQueue:
    def __init__(self, client) -> None:
        self._r = client

    def enqueue(self, job: Job) -> None:
        self._r.rpush(_QUEUE_KEY, job.model_dump_json())

    def dequeue(self, timeout: int = 0) -> Optional[Job]:
        item = self._r.blpop([_QUEUE_KEY], timeout=timeout)
        if item is None:
            return None
        _, raw = item
        return Job.model_validate_json(raw)

    def set_result(self, job_id: str, result_json: str) -> None:
        self._r.set(_RESULT_PREFIX + job_id, result_json)

    def get_result(self, job_id: str) -> Optional[str]:
        val = self._r.get(_RESULT_PREFIX + job_id)
        return val.decode() if isinstance(val, bytes) else val
