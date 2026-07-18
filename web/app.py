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
from urllib.parse import urlsplit

import redis
import websockets
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse
from starlette.websockets import WebSocketState

import saved_store
from bus.queue import Job, RedisJobQueue
from bus.sessions import SessionCmdQueue, SessionRegistry
from engine.artifacts import ref_to_filename, store_blobs
from engine.ssrf import validate_capture_url
from engine.steps import StepValidationError, validate_steps
from engine.urlnorm import normalize_url
from ocular_logging import get_logger
from ocular_settings import (
    admin_group,
    job_ttl,
    llm_allow_internal,
    llm_base_url,
    llm_enabled,
    llm_model,
    max_html_bytes,
    redis_url,
    result_ttl,
    saved_db_path,
    session_ready_timeout,
    trust_forward_auth,
)
from web.identity import has_admin_group, resolve_groups, resolve_identity
from web.middleware import MaxBodySizeMiddleware
from web.models import AnalystVerdictRequest, JobRequest, JobResponse, SessionRequest, SessionResponse

app = FastAPI(title="Ocular")
log = get_logger("web")

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_PROTECTED = ("/jobs", "/saved", "/sessions", "/auth")


@app.middleware("http")
async def _auth(request, call_next):
    if request.url.path.startswith(_PROTECTED):
        token = os.environ.get("OCULAR_TOKEN")
        expected = f"Bearer {token}" if token else None
        provided = request.headers.get("authorization", "")
        bearer_ok = bool(expected) and secrets.compare_digest(
            provided.encode("utf-8", "ignore"), expected.encode()
        )
        if not token and not trust_forward_auth():
            # fail-closed : jamais ouvert par défaut. Le forward-auth peut
            # autoriser sans OCULAR_TOKEN, donc on ne 503 QUE si aucune des
            # deux voies d'authentification n'est disponible.
            log.warning("auth rejected path=%s status=%d", request.url.path, 503)
            return JSONResponse({"detail": "OCULAR_TOKEN non configuré"}, status_code=503)
        authorized, identity, method = resolve_identity(request, bearer_ok=bearer_ok)
        if not authorized:
            # jamais le header/token dans les logs, seulement path + status
            log.warning("auth rejected path=%s status=%d", request.url.path, 401)
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        request.state.identity = identity
        request.state.auth_method = method
        if request.method == "DELETE" and request.url.path.startswith("/saved"):
            denied = _check_admin(request)
            if denied is not None:
                return denied
    return await call_next(request)


def _check_admin(request) -> JSONResponse | None:
    """Garde admin de `DELETE /saved*` (extraite de `_auth`, audit 3m) : autorise
    via `X-Admin-Token` (temps-constant) OU appartenance au groupe admin IdP.
    Renvoie une `JSONResponse` d'erreur (503 = aucun mécanisme configuré ; 403 =
    configuré mais non accordé), ou `None` si l'accès admin est accordé. Jamais
    de token/groupe dans les logs — seulement path + status."""
    adm = os.environ.get("OCULAR_ADMIN_TOKEN")
    provided_adm = request.headers.get("x-admin-token", "")
    token_ok = bool(adm) and secrets.compare_digest(
        provided_adm.encode("utf-8", "ignore"), adm.encode()
    )
    # Le mécanisme groupe n'est "configuré" que si un groupe admin est défini ET
    # que le forward-auth est de confiance (opt-in) — sinon has_admin_group()
    # renvoie déjà False (anti-spoofing), mais on veut distinguer "non configuré"
    # (503) de "configuré mais non accordé" (403).
    group_mechanism_configured = bool(admin_group()) and trust_forward_auth()
    if not adm and not group_mechanism_configured:
        log.warning("admin rejected path=%s status=%d", request.url.path, 503)
        return JSONResponse({"detail": "aucun mécanisme admin configuré"}, status_code=503)
    if not (token_ok or has_admin_group(request)):
        log.warning("admin rejected path=%s status=%d", request.url.path, 403)
        return JSONResponse({"detail": "admin requis"}, status_code=403)
    return None


@app.middleware("http")
async def _csp(request, call_next):
    # CSP posée sur l'app shell (UI statique) ; /jobs*, /saved* et /sessions* renvoient
    # des réponses API/artefacts (JSON, image/png, text/plain) pour lesquelles cet
    # en-tête n'a pas de sens (skip via le même tuple `_PROTECTED` que l'auth).
    response = await call_next(request)
    if not request.url.path.startswith(_PROTECTED):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; "
            # frame-ancestors NE retombe PAS sur default-src -> à poser explicitement,
            # sinon l'UI est encadrable (clickjacking sur « Supprimer »/« Tout purger »).
            "base-uri 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"  # repli pour les vieux UA
    return response


# Plafond de taille de corps de requête (audit 3c, FIX2 — garde anti-OOM).
# Les endpoints POST (/jobs, /sessions, /saved) acceptent du JSON dont la
# taille légitime est bornée par `max_html_bytes()` (contenu `html`, déjà
# vérifié explicitement dans les routes ci-dessous) ; on ajoute une marge de
# 2 Mo pour couvrir l'enveloppe JSON (échappement des guillemets/retours à
# la ligne dans `html`, champ `steps`, autres clés). Sans cette garde, un
# appelant authentifié pourrait poster un corps `steps` de plusieurs
# dizaines de Mo : Pydantic désérialiserait la totalité en mémoire AVANT que
# `validate_steps` (qui borne à MAX_STEPS) ne s'exécute — OOM possible côté
# conteneur web. Ce middleware rejette en 413 sur la seule base du header
# `Content-Length`, sans lire le corps, donc avant toute désérialisation —
# c'est un court-circuit rapide pour le cas courant (header présent).
# Un corps envoyé en `Transfer-Encoding: chunked` (donc sans `Content-Length`)
# n'est PAS couvert par ce court-circuit ; c'est `_MaxBodySizeMiddleware`
# ci-dessous (garde F2/3f) qui comble ce trou en comptant les octets
# réellement reçus.
_MAX_BODY_BYTES = max_html_bytes() + 2_000_000


@app.middleware("http")
async def _body_size_guard(request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError:
            declared = None
        if declared is not None and declared > _MAX_BODY_BYTES:
            log.warning(
                "body rejected path=%s content_length=%d limit=%d",
                request.url.path, declared, _MAX_BODY_BYTES,
            )
            return JSONResponse({"detail": "corps de requête trop volumineux"}, status_code=413)
    return await call_next(request)


_BODY_TOO_LARGE_PAYLOAD = json.dumps(
    {"detail": "corps de requête trop volumineux"}, ensure_ascii=False
).encode("utf-8")


# `MaxBodySizeMiddleware` (classe ASGI, filet corps chunked) extraite dans
# web/middleware.py (audit 3m). Enregistré en DERNIER -> middleware utilisateur
# le plus externe (Starlette empile `add_middleware` en LIFO), donc la garde par
# comptage s'applique AVANT `_body_size_guard`/`_csp`/`_auth` et avant tout
# parsing de route (rejeter tôt). Ordre INCHANGÉ par rapport à avant l'extraction.
app.add_middleware(
    MaxBodySizeMiddleware, max_bytes=_MAX_BODY_BYTES, payload=_BODY_TOO_LARGE_PAYLOAD,
)


@lru_cache(maxsize=1)
def _redis_client():
    return redis.Redis.from_url(redis_url())


def get_queue() -> RedisJobQueue:
    return RedisJobQueue(_redis_client())


def get_session_registry() -> SessionRegistry:
    return SessionRegistry(_redis_client())


def get_cmd_queue() -> SessionCmdQueue:
    return SessionCmdQueue(_redis_client())


@app.get("/auth/whoami")
def whoami(request: Request) -> dict:
    # `is_admin` reflète UNIQUEMENT l'appartenance au groupe admin IdP : un GET
    # whoami ne porte pas d'X-Admin-Token (mécanisme par-requête propre à
    # DELETE /saved, pas un état de session), donc il n'entre pas dans ce
    # calcul. L'UI s'appuie sur ce champ pour masquer/afficher ses contrôles ;
    # le backend (`_auth`, bloc DELETE /saved) reste la seule vraie garde.
    return {
        "identity": getattr(request.state, "identity", None),
        "method": getattr(request.state, "auth_method", "none"),
        "groups": resolve_groups(request),
        "is_admin": has_admin_group(request),
    }


@app.post("/jobs", response_model=JobResponse)
def submit_job(req: JobRequest, queue: RedisJobQueue = Depends(get_queue)) -> JobResponse:
    if req.html and len(req.html.encode("utf-8")) > max_html_bytes():
        raise HTTPException(status_code=422, detail="html trop volumineux")
    if req.steps is not None and req.profile != "capture":
        raise HTTPException(status_code=422, detail="steps réservé au profil capture")
    if req.profile == "capture":
        if not req.url:
            raise HTTPException(status_code=422, detail="url requis pour capture")
        # Normalise AVANT la garde SSRF : un domaine nu ("example.com") se voit
        # préfixer "https://" (comportement attendu côté utilisateur), tandis
        # qu'un scheme explicite (http/https) reste inchangé. La validation
        # SSRF porte donc sur l'URL normalisée, et c'est elle qui est enqueue.
        # normalize_url() est couvert par le même try/except que la garde SSRF :
        # un scheme non-réseau (data:/mailto:/javascript:/...) ou une entrée
        # tordue ne doit jamais produire un 500, seulement un 400 propre.
        try:
            req.url = normalize_url(req.url)
            validate_capture_url(req.url)
        except ValueError:
            raise HTTPException(status_code=400, detail="url interdite")
    if req.profile == "analysis" and not req.html:
        raise HTTPException(status_code=422, detail="html requis pour analysis")
    steps = None
    if req.steps is not None:
        try:
            steps = validate_steps(req.steps)
        except StepValidationError as e:
            raise HTTPException(status_code=422, detail=str(e))
    job_id = "job-" + uuid.uuid4().hex[:12]
    queue.enqueue(Job(job_id=job_id, profile=req.profile, html=req.html, url=req.url, steps=steps))
    queue.mark_accepted(job_id, job_ttl())   # fenêtre d'acceptation (anti job fantôme)
    log.info("job submitted job_id=%s profile=%s html_bytes=%d",
              job_id, req.profile, len(req.html or ""))
    return JobResponse(job_id=job_id)


@app.get("/jobs/{job_id}")
def get_job(job_id: str, queue: RedisJobQueue = Depends(get_queue)) -> dict:
    result = queue.get_result(job_id)
    if result is None:
        # Pas de résultat : soit le job est réellement en cours (marqueur
        # d'acceptation présent -> "pending"), soit il est perdu/expiré (marqueur
        # absent : Redis vidé par un down/up, ou jamais traité -> "unknown"
        # TERMINAL). Ce dernier cas arrête le polling fantôme côté UI au lieu de
        # renvoyer "pending" indéfiniment (accumulation de jobs zombies en prod).
        if queue.is_accepted(job_id):
            return {"status": "pending"}
        return {"status": "unknown"}
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


# Appels HTTP internes web -> session_server : extraits dans web/internal_http.py
# (audit qualité 3m). Réimportés sous leurs noms `_préfixés` historiques pour ne
# rien changer aux appelants ni au monkeypatch des tests.
from web.internal_http import (  # noqa: E402
    CaptureError as _CaptureError,
    internal_capture as _internal_capture,
    internal_get_json as _internal_get_json,
    internal_get_ok as _internal_get_ok,
    internal_post_json as _internal_post_json,
    session_host as _session_host,
)


# --- Option LLM d'explication (triage 3o) -----------------------------------
# OFF par défaut, JAMAIS dans le chemin de scoring. L'explication est opt-in et
# disciplinée côté egress : le LLM ne voit qu'un résumé structuré (jamais le HTML
# brut ni les artefacts), et l'appel sortant passe par la garde SSRF.

_LLM_SYSTEM_PROMPT = (
    "Tu es analyste SOC. À partir du résumé structuré fourni (verdict, triage, "
    "findings, formulaires/mailto), explique en français, de façon concise, "
    "pourquoi la page peut être suspecte et quoi vérifier ensuite. Ne donne "
    "JAMAIS de verdict définitif : ce sont des pistes, pas une conclusion."
)
_LLM_TIMEOUT_S = 20
_LLM_MAX_CHARS = 4000


def _llm_summary_payload(result: dict) -> dict:
    """Résumé structuré envoyé au LLM — fonction PURE (aucun réseau).

    Garde anti-exfil : n'inclut QUE `verdict`, `triage` (score/band/
    second_opinion/signals) et des vues RÉDUITES de `static_findings`
    (rule+severity) et `dom` (forms+mailtos). N'inclut JAMAIS le HTML brut,
    les `artifacts` (dom_html_ref/har_ref), les screenshots, les post-bodies
    réseau, ni le DOM complet — le LLM ne voit jamais la page réelle."""
    findings = [
        {"rule": f.get("rule"), "severity": f.get("severity")}
        for f in (result.get("static_findings") or [])
        if isinstance(f, dict)
    ]
    dom = result.get("dom") or {}
    dom_reduced = {
        "forms": dom.get("forms", []) if isinstance(dom, dict) else [],
        "mailtos": dom.get("mailtos", []) if isinstance(dom, dict) else [],
    }

    summary: dict = {
        "verdict": result.get("verdict"),
        "static_findings": findings,
        "dom": dom_reduced,
    }

    triage = result.get("triage")
    if isinstance(triage, dict):
        summary["triage"] = {
            "score": triage.get("score"),
            "band": triage.get("band"),
            "second_opinion": triage.get("second_opinion"),
            "signals": triage.get("signals", []),
        }
    else:
        summary["triage"] = None

    return summary


def _llm_explain(summary: dict) -> tuple[str, str]:
    """Appel LLM gardé egress. Retourne `(texte, modèle)`.

    Garde egress : sauf `llm_allow_internal()`, `validate_capture_url` est
    appelée AVANT tout appel sortant (rejette loopback/RFC1918/link-local).
    Si `llm_allow_internal()`, on saute ce contrôle (l'opérateur a explicitement
    autorisé un hôte interne) mais on exige quand même un scheme http/https +
    un host non vide. Toute erreur de validation ou réseau -> `_CaptureError`
    (502 côté route) SANS émettre d'appel sortant en cas d'échec de validation."""
    base = llm_base_url()
    if llm_allow_internal():
        parts = urlsplit(base)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            raise _CaptureError(f"OCULAR_LLM_BASE_URL invalide: {base!r}")
    else:
        try:
            validate_capture_url(base)
        except ValueError as exc:
            raise _CaptureError(f"LLM base_url refusée par la garde egress: {exc}") from exc

    endpoint = base.rstrip("/") + "/chat/completions"
    body = json.dumps({
        "model": llm_model(),
        "messages": [
            {"role": "system", "content": _LLM_SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(summary)},
        ],
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_LLM_TIMEOUT_S) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        text = payload["choices"][0]["message"]["content"]
    except (urllib.error.URLError, OSError) as exc:
        raise _CaptureError(f"appel LLM échoué: {exc}") from exc
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise _CaptureError("réponse LLM invalide") from exc

    if not isinstance(text, str):
        raise _CaptureError("réponse LLM invalide")
    return text[:_LLM_MAX_CHARS], llm_model()


@app.post("/jobs/{job_id}/explain")
def explain_job(job_id: str, queue: RedisJobQueue = Depends(get_queue)) -> dict:
    if not llm_enabled() or not llm_base_url():
        raise HTTPException(status_code=404, detail="option LLM désactivée")
    result_json = queue.get_result(job_id)
    if result_json is None:
        raise HTTPException(status_code=404, detail="job introuvable")
    try:
        result = json.loads(result_json)
    except (ValueError, TypeError):
        raise HTTPException(status_code=500, detail="résultat corrompu")
    summary = _llm_summary_payload(result)  # verdict/triage/findings — JAMAIS le HTML brut
    try:
        text, model = _llm_explain(summary)
    except _CaptureError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"explanation": text, "model": model}


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
        # Même normalisation qu'à la soumission d'un job capture (cf.
        # submit_job) : AVANT la garde SSRF, pour que "example.com" devienne
        # "https://example.com" tout en respectant un scheme explicite.
        # normalize_url() est couvert par le même try/except que la garde SSRF
        # (jamais de 500 pour un scheme non-réseau ou une entrée tordue).
        try:
            req.url = normalize_url(req.url)
            validate_capture_url(req.url)
        except ValueError:
            raise HTTPException(status_code=400, detail="url interdite")

    session_id = "sess-" + uuid.uuid4().hex[:12]
    token = secrets.token_urlsafe(32)
    # Secret de session à la frontière conteneur (défense-en-profondeur F1/F2),
    # DISTINCT du token WS : le session_server l'exige sur /goto,/load,/capture.
    # SEUL le web le connaît — jamais renvoyé dans les réponses, jamais loggé.
    session_secret = secrets.token_urlsafe(24)
    target = req.url if req.url else "inline-html"
    cmd_queue.enqueue_cmd(
        "launch", session_id, token=token, target=target, secret=session_secret
    )

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
        ok = _internal_post_json(f"http://{host}:8090/goto", {"url": req.url}, session_secret)
    else:
        ok = _internal_post_json(f"http://{host}:8090/load", {"html": req.html}, session_secret)
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


@app.post("/sessions/{session_id}/capture")
def capture_session(
    session_id: str,
    body: dict | None = None,
    registry: SessionRegistry = Depends(get_session_registry),
    queue: RedisJobQueue = Depends(get_queue),
) -> dict:
    """Capture l'état courant d'une session interactive : appelle le
    `session_server` du conteneur (réseau interne uniquement — le web n'a
    aucun accès au moteur de conteneurs, seul le broker en dispose), stocke
    les artefacts renvoyés via `store_blobs` (même logique anti-traversal
    que le broker, factorisée dans `engine.artifacts`) et le résultat léger
    dans Redis comme un job normal (récupérable ensuite via
    `GET /jobs/{job_id}`), puis renvoie ce résultat."""
    sess = registry.get(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="session inconnue")

    url = f"http://{_session_host(session_id)}:8090/capture"
    # secret conteneur lu au registre pour signer l'appel /capture (le web ne
    # regénère pas : c'est le broker qui l'a injecté au conteneur).
    secret = registry.get_secret(session_id) or ""
    # Seul le flag booléen `turnstile_passed` est relayé (déclaration manuelle
    # de l'analyste) — jamais le corps brut, pour ne pas exposer d'autre champ
    # au session_server.
    payload = {"turnstile_passed": bool((body or {}).get("turnstile_passed"))}
    try:
        wrapper = _internal_capture(url, secret, payload=payload)
    except _CaptureError:
        log.warning("session capture failed session_id=%s", session_id)
        raise HTTPException(status_code=502, detail="capture échouée")

    store_blobs(wrapper.get("blobs", {}), os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts"))

    result = wrapper.get("result", {})
    result_id = "sesscap-" + session_id + "-" + uuid.uuid4().hex[:8]
    result["job_id"] = result_id                  # aligné sur GET /jobs/{job_id}
    # Capture interactive ÉPHÉMÈRE : TTL (défense en profondeur — la sauvegarde
    # effective copie le résultat en SQLite via POST /saved ; une capture non
    # nommée n'est jamais persistée et expire, en plus de la purge au nettoyage
    # de session côté broker `purge_session_results`).
    queue.set_result(result_id, json.dumps(result), ttl=result_ttl())
    registry.touch(session_id, datetime.now(timezone.utc).isoformat())
    log.info("session capture session_id=%s result_id=%s", session_id, result_id)
    return result


@app.get("/sessions/{session_id}/live")
def session_live(
    session_id: str,
    registry: SessionRegistry = Depends(get_session_registry),
) -> dict:
    """Proxy vers `GET /live` du `session_server` (panneau live, C4) : appels
    réseau + analyse statique en continu, canal données séparé du flux
    pixels VNC. Même schéma d'accès que `capture_session` (secret conteneur
    lu au registre, jamais régénéré ici, jamais renvoyé/loggé)."""
    sess = registry.get(session_id)
    if sess is None:
        raise HTTPException(status_code=404, detail="session inconnue")

    url = f"http://{_session_host(session_id)}:8090/live"
    secret = registry.get_secret(session_id) or ""
    try:
        live = _internal_get_json(url, secret)
    except _CaptureError:
        log.warning("session live failed session_id=%s", session_id)
        raise HTTPException(status_code=502, detail="live échoué")

    # Une session ACTIVEMENT pollée via /live (panneau live ouvert) est vivante,
    # même si son WS VNC s'est déconnecté un instant : on réarme `mark_connected`
    # (efface `disconnected_at`) en plus de `touch`, sinon le reaper la détruit
    # après la grâce de déconnexion alors que l'analyste s'en sert (corrige M1).
    registry.mark_connected(session_id)
    registry.touch(session_id, datetime.now(timezone.utc).isoformat())
    return live


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
            # réarme AUSSI mark_connected : ce WS est vivant et pompe des octets.
            # Sans ça, le teardown d'un ANCIEN socket (reconnexion/flapping) pose
            # `disconnected_at` APRÈS l'accept du nouveau, et le reaper détruirait
            # la session pourtant connectée (corrige M2).
            registry.mark_connected(sid)
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
    # session activement connectée (WS ouvert) : efface toute marque de
    # déconnexion antérieure pour que le reaper (règle de grâce) ne la
    # nettoie jamais tant qu'elle reste connectée.
    registry.mark_connected(sid)

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
        # déconnexion (propre ou brutale, y compris crash navigateur) : marque
        # l'heure pour le reaper (grâce `session_disconnect_grace`), qui
        # nettoiera une session abandonnée sans navigateur pour la reconnecter.
        registry.mark_disconnected(sid, time.time())
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
def create_saved(body: dict, request: Request, queue: RedisJobQueue = Depends(get_queue)) -> dict:
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
                               datetime.now(timezone.utc).isoformat(),
                               saved_by=getattr(request.state, "identity", None))
    except saved_store.DuplicateLabelError:
        raise HTTPException(status_code=409, detail="nom déjà utilisé")
    finally:
        conn.close()
    log.info("saved job_id=%s id=%s verdict=%s", job_id, sid, result.get("verdict"))
    return {"id": sid, "input_hash": result.get("input_hash")}


@app.post("/saved/{sid}/verdict")
def set_saved_verdict(sid: int, body: AnalystVerdictRequest, request: Request) -> dict:
    # Route non-admin : un bearer/forward-auth normal suffit pour classer une
    # sauvegarde ; seul DELETE /saved (flush) exige X-Admin-Token (cf. middleware _auth).
    analyst = getattr(request.state, "identity", None)
    analyst_at = datetime.now(timezone.utc).isoformat()
    note = (body.note or "")[:2000]
    conn = _saved_conn()
    try:
        try:
            ok = saved_store.set_analyst_verdict(conn, sid, body.analyst_verdict, analyst, analyst_at, note)
        except ValueError:
            raise HTTPException(status_code=422, detail="verdict analyste invalide")
        if not ok:
            raise HTTPException(status_code=404, detail="sauvegarde inconnue")
        meta = saved_store.get_meta(conn, sid)
    finally:
        conn.close()
    log.info("saved verdict id=%s analyst_verdict=%s", sid, body.analyst_verdict)
    return meta


@app.post("/saved/lookup")
def lookup_saved_url(body: dict) -> dict:
    from engine.urlnorm import url_input_hash
    url = body.get("url")
    if not url:
        raise HTTPException(status_code=422, detail="url requis")
    # normalize_url (via url_input_hash) lève ValueError sur une URL malformée
    # ([::1 sans crochet fermant, port non numérique…) -> 422 propre, pas un 500
    # (cohérent avec submit_job/create_session).
    try:
        input_hash = url_input_hash(url)
    except ValueError:
        raise HTTPException(status_code=422, detail="url invalide")
    conn = _saved_conn()
    try:
        meta = saved_store.get_by_hash(conn, input_hash)
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
def list_saved(sort: str = "saved_at", order: str = "desc",
               min_band: str | None = None) -> list:
    conn = _saved_conn()
    try:
        return saved_store.list_all(conn, sort=sort, order=order, min_band=min_band)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
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
