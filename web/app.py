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

import saved_store
from bus.queue import Job, RedisJobQueue
from engine.artifacts import ref_to_filename
from ocular_logging import get_logger
from ocular_settings import max_html_bytes, redis_url, saved_db_path
from web.models import JobRequest, JobResponse

app = FastAPI(title="Ocular")
log = get_logger("web")

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_PROTECTED = ("/jobs", "/saved")


@app.middleware("http")
async def _auth(request, call_next):
    if request.url.path.startswith(_PROTECTED):
        token = os.environ.get("OCULAR_TOKEN")
        if not token:                              # fail-closed : jamais ouvert par défaut
            log.warning("auth rejected path=%s status=%d", request.url.path, 503)
            return JSONResponse({"detail": "OCULAR_TOKEN non configuré"}, status_code=503)
        expected = f"Bearer {token}"
        provided = request.headers.get("authorization", "")
        if not secrets.compare_digest(
            provided.encode("utf-8", "ignore"), expected.encode()
        ):
            # jamais le header/token dans les logs, seulement path + status
            log.warning("auth rejected path=%s status=%d", request.url.path, 401)
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return await call_next(request)


@app.middleware("http")
async def _csp(request, call_next):
    # CSP posée sur l'app shell (UI statique) ; /jobs* et /saved* renvoient des réponses
    # API/artefacts (JSON, image/png, text/plain) pour lesquelles cet en-tête n'a pas de sens.
    response = await call_next(request)
    if not request.url.path.startswith(_PROTECTED):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' blob: data:; object-src 'none'; base-uri 'self'"
        )
    return response


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
    try:
        return json.loads(result)
    except (ValueError, TypeError):
        raise HTTPException(status_code=500, detail="résultat corrompu")


def _serve_artifact_bytes(data: bytes, fname: str) -> Response:
    if data[:8] == _PNG_MAGIC:
        return Response(
            content=data,
            media_type="image/png",
            headers={"X-Content-Type-Options": "nosniff"},
        )
    # DOM hostile : JAMAIS servi en text/html inline
    return Response(
        content=data,
        media_type="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}.txt"',
            "X-Content-Type-Options": "nosniff",
        },
    )


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
    return _serve_artifact_bytes(data, fname)


def _saved_conn():
    path = saved_db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    return saved_store.connect(path)


def _read_artifact_bytes(ref: str) -> bytes | None:
    try:
        fname = ref_to_filename(ref)
    except ValueError:
        return None
    path = os.path.join(os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts"), fname)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


@app.post("/saved")
def create_saved(body: dict, queue: RedisJobQueue = Depends(get_queue)) -> dict:
    from datetime import datetime, timezone
    job_id = body.get("job_id")
    result_json = queue.get_result(job_id) if job_id else None
    if not result_json:
        raise HTTPException(status_code=404, detail="job inconnu")
    result = json.loads(result_json)
    blobs = {}
    for ref in saved_store.refs_of(result):
        data = _read_artifact_bytes(ref)
        if data is None:
            raise HTTPException(status_code=409, detail="artefacts expirés, relancer l'analyse")
        blobs[ref] = data
    conn = _saved_conn()
    try:
        sid = saved_store.save(conn, result, blobs, body.get("label"),
                               datetime.now(timezone.utc).isoformat())
    finally:
        conn.close()
    log.info("saved job_id=%s id=%s verdict=%s", job_id, sid, result.get("verdict"))
    return {"id": sid, "input_hash": result.get("input_hash")}


@app.get("/saved/{ref_or_id}")
def get_saved(ref_or_id: str) -> dict:
    conn = _saved_conn()
    try:
        if ref_or_id.startswith("sha256:"):
            meta = saved_store.get_by_hash(conn, ref_or_id)
            if not meta:
                raise HTTPException(status_code=404, detail="aucune sauvegarde")
            return meta
        raise HTTPException(status_code=404, detail="introuvable")
    finally:
        conn.close()


@app.get("/saved")
def list_saved() -> list:
    conn = _saved_conn()
    try:
        return saved_store.list_all(conn)
    finally:
        conn.close()


@app.get("/saved/{sid}/result")
def get_saved_result(sid: int) -> dict:
    conn = _saved_conn()
    try:
        res = saved_store.get_result(conn, sid)
        if res is None:
            raise HTTPException(status_code=404, detail="introuvable")
        return res
    finally:
        conn.close()


@app.get("/saved/{sid}/artifact/{ref}")
def get_saved_artifact(sid: int, ref: str) -> Response:
    try:
        fname = ref_to_filename(ref)  # valide ^sha256:[0-9a-f]{64}$ (anti-traversal)
    except ValueError:
        raise HTTPException(status_code=400, detail="ref invalide")
    conn = _saved_conn()
    try:
        data = saved_store.get_artifact(conn, sid, ref)
    finally:
        conn.close()
    if data is None:
        raise HTTPException(status_code=404, detail="artefact absent")
    return _serve_artifact_bytes(data, fname)


# UI web statique (PWA vanilla-JS) montée sur "/" APRÈS les routes /jobs* pour ne
# pas les masquer. Le middleware auth couvre /jobs* et /saved* ; l'UI statique
# montée sur / reste publique.
app.mount(
    "/",
    StaticFiles(directory=os.path.join(os.path.dirname(__file__), "ui"), html=True),
    name="ui",
)
