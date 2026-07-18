from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

_QUEUE_KEY = "ocular:jobs"
RESULT_PREFIX = "ocular:result:"
# Marqueur « job accepté », posé à la soumission avec un TTL. Sert à distinguer,
# pour GET /jobs/{id} SANS résultat, un job RÉELLEMENT en cours (marqueur présent
# -> "pending") d'un job perdu/expiré (marqueur absent -> "unknown", terminal) :
# évite le job fantôme qui poll "en attente" à l'infini quand Redis a été vidé
# (compose down/up : file éphémère) ou que le job n'a jamais produit de résultat.
ACCEPTED_PREFIX = "ocular:accepted:"


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

    def mark_accepted(self, job_id: str, ttl: int) -> None:
        """Marque un job comme accepté (borné par `ttl`). Au-delà du TTL sans
        résultat, le job est considéré perdu/expiré (cf. `is_accepted`)."""
        self._r.set(ACCEPTED_PREFIX + job_id, "1", ex=ttl)

    def is_accepted(self, job_id: str) -> bool:
        """Le job est-il encore dans sa fenêtre d'acceptation (en file/traitement) ?"""
        return bool(self._r.exists(ACCEPTED_PREFIX + job_id))

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
        # ttl > 0 -> expiration ; None/0/négatif -> clé permanente (Redis
        # refuserait ex<=0). Le `> 0` explicite évite qu'un ttl négatif
        # accidentel ne provoque une erreur Redis.
        if ttl is not None and ttl > 0:
            self._r.set(RESULT_PREFIX + job_id, result_json, ex=ttl)
        else:
            self._r.set(RESULT_PREFIX + job_id, result_json)
        # Job terminal (résultat ou erreur) : le marqueur d'acceptation n'a plus
        # de raison d'être — on le retire (get_result prime de toute façon).
        self._r.delete(ACCEPTED_PREFIX + job_id)

    def get_result(self, job_id: str) -> Optional[str]:
        val = self._r.get(RESULT_PREFIX + job_id)
        return val.decode() if isinstance(val, bytes) else val
