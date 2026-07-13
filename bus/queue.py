from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

_QUEUE_KEY = "ocular:jobs"
RESULT_PREFIX = "ocular:result:"


class Job(BaseModel):
    job_id: str
    profile: str
    html: Optional[str] = None
    url: Optional[str] = None
    steps: Optional[list] = None


class RedisJobQueue:
    def __init__(self, client) -> None:
        self._r = client

    def enqueue(self, job: Job) -> None:
        self._r.rpush(_QUEUE_KEY, job.model_dump_json())

    def dequeue(self, timeout: int = 0) -> Optional[Job]:
        try:
            item = self._r.blpop([_QUEUE_KEY], timeout=timeout)
        except Exception:  # noqa: BLE001
            # timeout/déconnexion redis transitoire : ne pas tuer le broker.
            # Effet volontairement étroit : on ne masque qu'un cycle de dépilage,
            # la boucle broker réessaie au tour suivant.
            return None
        if item is None:
            return None
        _, raw = item
        return Job.model_validate_json(raw)

    def set_result(self, job_id: str, result_json: str, ttl: Optional[int] = None) -> None:
        if ttl:
            self._r.set(RESULT_PREFIX + job_id, result_json, ex=ttl)
        else:
            self._r.set(RESULT_PREFIX + job_id, result_json)

    def get_result(self, job_id: str) -> Optional[str]:
        val = self._r.get(RESULT_PREFIX + job_id)
        return val.decode() if isinstance(val, bytes) else val
