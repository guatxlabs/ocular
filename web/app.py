from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from functools import lru_cache

import redis
import websockets
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse
from starlette.websockets import WebSocketState

import saved_store
from bus.queue import Job, RedisJobQueue
from bus.sessions import SessionCmdQueue, SessionRegistry
from engine.artifacts import ref_to_filename
from engine.ssrf import validate_capture_url
from ocular_logging import get_logger
from ocular_settings import max_html_bytes, redis_url, saved_db_path, session_ready_timeout
from web.models import JobRequest, JobResponse, SessionRequest, SessionResponse

app = FastAPI(title="Ocular")
log = get_logger("web")

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_PROTECTED = ("/jobs", "/saved", "/sessions")


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
        if request.method == "DELETE" and request.url.path.startswith("/saved"):
            adm = os.environ.get("OCULAR_ADMIN_TOKEN")
            if not adm:                                # fail-closed : jamais ouvert par défaut
                log.warning("admin rejected path=%s status=%d", request.url.path, 503)
                return JSONResponse({"detail": "OCULAR_ADMIN_TOKEN non configuré"}, status_code=503)
            provided_adm = request.headers.get("x-admin-token", "")
            if not secrets.compare_digest(provided_adm.encode("utf-8", "ignore"), adm.encode()):
                # jamais le header/token dans les logs, seulement path + status
                log.warning("admin rejected path=%s status=%d", request.url.path, 403)
                return JSONResponse({"detail": "admin requis"}, status_code=403)
    return await call_next(request)


@app.middleware("http")
async def _csp(request, call_next):
    # CSP posée sur l'app shell (UI statique) ; /jobs*, /saved* et /sessions* renvoient
    # des réponses API/artefacts (JSON, image/png, text/plain) pour lesquelles cet
    # en-tête n'a pas de sens (skip via le même tuple `_PROTECTED` que l'auth).
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


def get_session_registry() -> SessionRegistry:
    return SessionRegistry(_redis_client())


def get_cmd_queue() -> SessionCmdQueue:
    return SessionCmdQueue(_redis_client())


@app.post("/jobs", response_model=JobResponse)
def submit_job(req: JobRequest, queue: RedisJobQueue = Depends(get_queue)) -> JobResponse:
    if req.html and len(req.html.encode("utf-8")) > max_html_bytes():
        raise HTTPException(status_code=422, detail="html trop volumineux")
    if req.profile == "capture":
        if not req.url:
            raise HTTPException(status_code=422, detail="url requis pour capture")
        try:
            validate_capture_url(req.url)
        except ValueError:
            raise HTTPException(status_code=400, detail="url interdite")
    if req.profile == "analysis" and not req.html:
        raise HTTPException(status_code=422, detail="html requis pour analysis")
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


def _session_host(session_id: str) -> str:
    """Nom réseau interne du conteneur de session — jamais de port hôte, le
    web parle au conteneur uniquement via le réseau applicatif interne."""
    return f"ocular-sess-{session_id}"


def _internal_get_ok(url: str, timeout: float = 2.0) -> bool:
    """GET interne (health) via la bibliothèque standard uniquement — pas de
    nouvelle dépendance, pas d'accès au moteur de conteneurs (le web reste
    sans accès conteneur, seul le broker en dispose)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - réseau interne uniquement
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def _internal_post_json(url: str, payload: dict, timeout: float = 5.0) -> bool:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - réseau interne uniquement
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


_SESSION_POLL_INTERVAL = 0.5


def _wait_session_ready(registry: SessionRegistry, session_id: str, deadline: float) -> bool:
    """Poll d'abord le registre (écrit par le broker une fois le conteneur
    lancé) puis le `/health` du session_server via le réseau interne, jusqu'à
    `deadline` (epoch monotonic). Extrait pour être monkeypatchable en test
    sans dépendre d'un vrai conteneur."""
    while time.monotonic() < deadline:
        sess = registry.get(session_id)
        if sess and sess.get("container"):
            break
        time.sleep(_SESSION_POLL_INTERVAL)
    else:
        return False

    health_url = f"http://{_session_host(session_id)}:8090/health"
    while time.monotonic() < deadline:
        if _internal_get_ok(health_url):
            return True
        time.sleep(_SESSION_POLL_INTERVAL)
    return False


@app.post("/sessions", response_model=SessionResponse)
def create_session(
    req: SessionRequest,
    request: Request,
    registry: SessionRegistry = Depends(get_session_registry),
    cmd_queue: SessionCmdQueue = Depends(get_cmd_queue),
) -> SessionResponse:
    if req.html and len(req.html.encode("utf-8")) > max_html_bytes():
        raise HTTPException(status_code=422, detail="html trop volumineux")
    if not req.url and not req.html:
        raise HTTPException(status_code=422, detail="url ou html requis")
    if req.url:
        try:
            validate_capture_url(req.url)
        except ValueError:
            raise HTTPException(status_code=400, detail="url interdite")

    session_id = "sess-" + uuid.uuid4().hex[:12]
    token = secrets.token_urlsafe(32)
    target = req.url if req.url else "inline-html"
    cmd_queue.enqueue_cmd("launch", session_id, token=token, target=target)

    client_ip = request.client.host if request.client else "?"
    # Avertissement délibéré : une session interactive expose l'IP du serveur
    # au site cible (URL live) et/ou rend du contenu potentiellement hostile
    # dans le conteneur — jamais le token dans ce log.
    log.warning(
        "session create session_id=%s client_ip=%s kind=%s",
        session_id, client_ip, "url" if req.url else "html",
    )

    deadline = time.monotonic() + session_ready_timeout()
    if not _wait_session_ready(registry, session_id, deadline):
        cmd_queue.enqueue_cmd("stop", session_id)
        log.warning("session start timeout session_id=%s", session_id)
        raise HTTPException(status_code=504, detail="session non prête")

    host = _session_host(session_id)
    if req.url:
        ok = _internal_post_json(f"http://{host}:8090/goto", {"url": req.url})
    else:
        ok = _internal_post_json(f"http://{host}:8090/load", {"html": req.html})
    if not ok:
        log.warning("session goto/load failed session_id=%s", session_id)

    return SessionResponse(session_id=session_id, token=token)


@app.get("/sessions")
def list_sessions(registry: SessionRegistry = Depends(get_session_registry)) -> list:
    # Anti-fuite (note sécu T2) : le token capability WS n'est JAMAIS renvoyé
    # dans une liste — seul un GET/DELETE ciblé côté serveur y a accès.
    return [
        {k: v for k, v in sess.items() if k != "token"}
        for sess in registry.list_active()
    ]


@app.delete("/sessions/{session_id}")
def delete_session(
    session_id: str,
    registry: SessionRegistry = Depends(get_session_registry),
    cmd_queue: SessionCmdQueue = Depends(get_cmd_queue),
) -> dict:
    cmd_queue.enqueue_cmd("stop", session_id)
    registry.delete(session_id)
    log.info("session delete session_id=%s", session_id)
    return {"deleted": session_id}


_WS_SUBPROTOCOL_PREFIX = "ocular.session."
_WS_TOUCH_INTERVAL = 5.0


def _extract_ws_token(websocket: WebSocket) -> str | None:
    """Extrait le token capability du sous-protocole WebSocket, JAMAIS de
    l'URL (anti-fuite logs/referrer). Le client envoie
    `Sec-WebSocket-Protocol: binary, ocular.session.<token>` ; on lit le 2e
    élément portant le préfixe `ocular.session.`. Ne jamais logger le résultat
    ni l'en-tête brut."""
    raw = websocket.headers.get("sec-websocket-protocol", "")
    if not raw:
        return None
    for part in (p.strip() for p in raw.split(",")):
        if part.startswith(_WS_SUBPROTOCOL_PREFIX):
            return part[len(_WS_SUBPROTOCOL_PREFIX):]
    return None


async def _ws_pump(websocket: WebSocket, upstream, registry: SessionRegistry, sid: str) -> None:
    """Pompe bidirectionnelle d'octets bruts (RFB) entre l'analyste et le
    websockify du conteneur de session. `registry.touch` est rafraîchi au
    plus une fois toutes les `_WS_TOUCH_INTERVAL` secondes, dès qu'il y a du
    trafic dans un sens ou dans l'autre — jamais le contenu des trames ni le
    token ne sont journalisés ici."""
    last_touch = 0.0

    def _maybe_touch() -> None:
        nonlocal last_touch
        now = time.monotonic()
        if now - last_touch >= _WS_TOUCH_INTERVAL:
            registry.touch(sid, datetime.now(timezone.utc).isoformat())
            last_touch = now

    async def client_to_upstream() -> None:
        async for msg in websocket.iter_bytes():
            await upstream.send(msg)
            _maybe_touch()

    async def upstream_to_client() -> None:
        async for msg in upstream:
            await websocket.send_bytes(msg)
            _maybe_touch()

    tasks = [asyncio.create_task(client_to_upstream()), asyncio.create_task(upstream_to_client())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()
        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except asyncio.CancelledError:
            # cette coroutine elle-même peut être annulée pendant le nettoyage
            # (arrêt serveur, déconnexion brutale déjà en cours) : les deux
            # sous-tâches ont déjà été cancel()-ées ci-dessus, rien de plus à
            # faire — ne jamais faire fuiter cette annulation plus loin
            # empêcherait le nettoyage best-effort du websocket appelant.
            pass


@app.websocket("/sessions/{sid}/ws")
async def session_ws_proxy(
    websocket: WebSocket,
    sid: str,
    registry: SessionRegistry = Depends(get_session_registry),
) -> None:
    """Proxy websocket noVNC : relaie le RFB entre l'analyste et le conteneur
    de session (réseau interne), sur l'origine web. Sécu critique : auth par
    sous-protocole (token HORS URL), fail-closed AVANT accept(), et le
    sous-protocole renvoyé au client est TOUJOURS "binary" seul — jamais le
    token. Rien de ceci n'est journalisé (ni token, ni en-tête)."""
    token = _extract_ws_token(websocket)
    if not token or not registry.valid_token(sid, token):
        await websocket.close(code=1008)
        return

    sess = registry.get(sid)
    if not sess or not sess.get("container"):
        await websocket.close(code=1008)
        return

    await websocket.accept(subprotocol="binary")

    upstream_url = f"ws://{sess['container']}:6080/websockify"
    try:
        async with websockets.connect(upstream_url, subprotocols=["binary"]) as upstream:
            await _ws_pump(websocket, upstream, registry, sid)
    except asyncio.CancelledError:
        # annulation de cette tâche pendant le nettoyage (arrêt serveur ou
        # déconnexion brutale déjà traitée par _ws_pump) : fermeture best-effort
        # ci-dessous, jamais de détail sensible loggé, ne pas re-propager pour
        # ne pas casser la fermeture propre du websocket appelant.
        pass
    except Exception:  # noqa: BLE001 - erreurs réseau/upstream : jamais de détail sensible loggé
        pass
    finally:
        if websocket.client_state != WebSocketState.DISCONNECTED:
            try:
                await websocket.close()
            except (RuntimeError, asyncio.CancelledError):
                pass  # déjà fermé côté ASGI, ou annulation en cours


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


@app.post("/saved/lookup")
def lookup_saved_url(body: dict) -> dict:
    from engine.urlnorm import url_input_hash
    url = body.get("url")
    if not url:
        raise HTTPException(status_code=422, detail="url requis")
    conn = _saved_conn()
    try:
        meta = saved_store.get_by_hash(conn, url_input_hash(url))
    finally:
        conn.close()
    if not meta:
        raise HTTPException(status_code=404, detail="aucune sauvegarde")
    return meta


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


@app.delete("/saved/{sid}")
def delete_saved(sid: int) -> dict:
    conn = _saved_conn()
    try:
        ok = saved_store.delete(conn, sid)
    finally:
        conn.close()
    if not ok:
        raise HTTPException(status_code=404, detail="introuvable")
    log.info("saved deleted id=%s", sid)
    return {"deleted": sid}


@app.delete("/saved")
def flush_saved() -> dict:
    conn = _saved_conn()
    try:
        n = saved_store.flush(conn)
    finally:
        conn.close()
    log.warning("saved flushed count=%d", n)
    return {"flushed": n}


# UI web statique (PWA vanilla-JS) montée sur "/" APRÈS les routes /jobs* pour ne
# pas les masquer. Le middleware auth couvre /jobs*, /saved* et /sessions* ; l'UI
# statique montée sur / reste publique.
app.mount(
    "/",
    StaticFiles(directory=os.path.join(os.path.dirname(__file__), "ui"), html=True),
    name="ui",
)
