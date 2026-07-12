from __future__ import annotations

import json
import os
import secrets
import uuid
from functools import lru_cache

import redis
from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse

from bus.queue import Job, RedisJobQueue
from engine.artifacts import ref_to_filename
from ocular_logging import get_logger
from ocular_settings import max_html_bytes, redis_url
from web.models import JobRequest, JobResponse

app = FastAPI(title="Ocular")
log = get_logger("web")

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@app.middleware("http")
async def _auth(request, call_next):
    if request.url.path.startswith("/jobs"):
        token = os.environ.get("OCULAR_TOKEN")
        if not token:                              # fail-closed : jamais ouvert par défaut
            log.warning("auth rejected path=%s status=%d", request.url.path, 503)
            return JSONResponse({"detail": "OCULAR_TOKEN non configuré"}, status_code=503)
        expected = f"Bearer {token}"
        provided = request.headers.get("authorization", "")
        if not secrets.compare_digest(provided, expected):
            # jamais le header/token dans les logs, seulement path + status
            log.warning("auth rejected path=%s status=%d", request.url.path, 401)
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


@lru_cache(maxsize=1)
def _redis_client():
    return redis.Redis.from_url(redis_url())


def get_queue() -> RedisJobQueue:
    return RedisJobQueue(_redis_client())


@app.post("/jobs", response_model=JobResponse)
def submit_job(req: JobRequest, queue: RedisJobQueue = Depends(get_queue)) -> JobResponse:
    if req.html and len(req.html.encode("utf-8")) > max_html_bytes():
        raise HTTPException(status_code=422, detail="html trop volumineux")
    job_id = "job-" + uuid.uuid4().hex[:12]
    queue.enqueue(Job(job_id=job_id, profile=req.profile, html=req.html, url=req.url))
    log.info("job submitted job_id=%s profile=%s html_bytes=%d",
              job_id, req.profile, len(req.html or ""))
    return JobResponse(job_id=job_id)


@app.get("/jobs/{job_id}")
def get_job(job_id: str, queue: RedisJobQueue = Depends(get_queue)) -> dict:
    result = queue.get_result(job_id)
    if result is None:
        return {"status": "pending"}
    return json.loads(result)


@app.get("/jobs/{job_id}/artifact/{ref}")
def get_artifact(job_id: str, ref: str) -> Response:
    try:
        fname = ref_to_filename(ref)  # valide ^sha256:[0-9a-f]{64}$ (anti-traversal)
    except ValueError:
        raise HTTPException(status_code=400, detail="ref invalide")
    artifacts_dir = os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts")
    path = os.path.join(artifacts_dir, fname)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="artefact absent")
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:8] == _PNG_MAGIC:
        return Response(content=data, media_type="image/png")
    # DOM hostile : JAMAIS servi en text/html inline
    return Response(
        content=data,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{fname}.html"'},
    )


# UI web statique (PWA vanilla-JS) montée sur "/" APRÈS les routes /jobs* pour ne
# pas les masquer. Le middleware auth ne touche que /jobs* -> l'UI reste publique.
app.mount(
    "/",
    StaticFiles(directory=os.path.join(os.path.dirname(__file__), "ui"), html=True),
    name="ui",
)
