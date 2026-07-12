from __future__ import annotations

import json
import os
import secrets
import uuid

import redis
from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse

from broker.queue import Job, RedisJobQueue
from engine.artifacts import ref_to_filename
from web.models import JobRequest, JobResponse

app = FastAPI(title="Ocular")

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@app.middleware("http")
async def _auth(request, call_next):
    if request.url.path.startswith("/jobs"):
        token = os.environ.get("OCULAR_TOKEN")
        if not token:                              # fail-closed : jamais ouvert par défaut
            return JSONResponse({"detail": "OCULAR_TOKEN non configuré"}, status_code=503)
        expected = f"Bearer {token}"
        provided = request.headers.get("authorization", "")
        if not secrets.compare_digest(provided, expected):
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


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
