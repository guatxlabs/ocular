from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import secrets
import threading
import time
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
from engine.artifacts import ref_to_filename, store_blobs
from engine.ssrf import DnsResolutionError, validate_capture_url
from engine.steps import StepValidationError, validate_steps
from engine.urlnorm import normalize_url
from ocular_logging import get_logger
from ocular_settings import (
    admin_group,
    artifacts_dir,
    job_ttl,
    llm_base_url,
    llm_enabled,
    max_html_bytes,
    max_sessions,
    redis_url,
    result_ttl,
    saved_db_path,
    session_ready_timeout,
    trust_forward_auth,
)
from web.identity import client_ip, has_admin_group, resolve_groups, resolve_identity
from web.llm import llm_explain, llm_summary_payload
from web.middleware import MaxBodySizeMiddleware
from web.models import AnalystVerdictRequest, JobRequest, JobResponse, SessionRequest, SessionResponse

app = FastAPI(title="Ocular")
log = get_logger("web")

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
# Distinct d'« url interdite » (refus de POLITIQUE : scheme, IP interne). Ici
# le nom n'a pas pu être RÉSOLU : panne d'infrastructure, rien à corriger dans
# les règles de sécurité. Confondre les deux fait perdre un temps considérable
# — quand le DNS des conteneurs est tombé, toutes les captures répondaient
# « url interdite » et envoyaient chercher une règle SSRF inexistante.
# Le nom d'hôte n'est PAS renvoyé (pas de réflexion de l'entrée client).
_DNS_DETAIL = "résolution DNS impossible"
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


def _admin_granted(conn) -> bool:
    """Cœur BOOLÉEN du mécanisme admin : `X-Admin-Token` (comparaison en temps
    constant) OU appartenance au groupe admin IdP. Extrait de `_check_admin`
    pour être réutilisé PAR LE CONTRÔLE D'APPARTENANCE DES SESSIONS (l'admin
    passe outre le propriétaire) sans dupliquer un second mécanisme admin.

    `conn` est une `Request` OU un `WebSocket` : seuls `.headers` sont lus (via
    `has_admin_group` -> `resolve_groups`), tous deux étant des
    `starlette.requests.HTTPConnection`. Aucun token/groupe n'est journalisé."""
    adm = os.environ.get("OCULAR_ADMIN_TOKEN")
    provided_adm = conn.headers.get("x-admin-token", "")
    token_ok = bool(adm) and secrets.compare_digest(
        provided_adm.encode("utf-8", "ignore"), adm.encode()
    )
    return token_ok or has_admin_group(conn)


def _check_admin(request) -> JSONResponse | None:
    """Garde admin de `DELETE /saved*` (extraite de `_auth`, audit 3m) : autorise
    via `X-Admin-Token` (temps-constant) OU appartenance au groupe admin IdP.
    Renvoie une `JSONResponse` d'erreur (503 = aucun mécanisme configuré ; 403 =
    configuré mais non accordé), ou `None` si l'accès admin est accordé. Jamais
    de token/groupe dans les logs — seulement path + status."""
    adm = os.environ.get("OCULAR_ADMIN_TOKEN")
    # Le mécanisme groupe n'est "configuré" que si un groupe admin est défini ET
    # que le forward-auth est de confiance (opt-in) — sinon has_admin_group()
    # renvoie déjà False (anti-spoofing), mais on veut distinguer "non configuré"
    # (503) de "configuré mais non accordé" (403).
    group_mechanism_configured = bool(admin_group()) and trust_forward_auth()
    if not adm and not group_mechanism_configured:
        log.warning("admin rejected path=%s status=%d", request.url.path, 503)
        return JSONResponse({"detail": "aucun mécanisme admin configuré"}, status_code=503)
    if not _admin_granted(request):
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
        except DnsResolutionError:
            raise HTTPException(status_code=400, detail=_DNS_DETAIL)
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
    path = os.path.join(artifacts_dir(), fname)
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
    summary = llm_summary_payload(result)  # verdict/triage/findings — JAMAIS le HTML brut
    try:
        text, model = llm_explain(summary)
    except _CaptureError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    return {"explanation": text, "model": model}


_SESSION_POLL_INTERVAL = 0.5

# Gabarit EXACT des identifiants produits par `create_session`
# ("sess-" + uuid4().hex[:12]). Toute route prenant un `session_id` le filtre
# par ici AVANT de le transmettre au broker ou au registre : le broker
# interpole l'identifiant dans un motif `SCAN MATCH` Redis (un GLOB), donc un
# `*` accepté ici purgeait les captures éphémères de TOUTES les sessions
# actives, tous analystes confondus (défaut E).
_SESSION_ID_RE = re.compile(r"sess-[0-9a-f]{12}")


def _is_session_id(session_id: str) -> bool:
    return bool(_SESSION_ID_RE.fullmatch(session_id))


def _checked_session_id(session_id: str) -> str:
    """404 (jamais 400/422) sur un identifiant hors gabarit : un id impossible
    à produire dénote une session qui n'existe pas — même réponse qu'un id bien
    formé mais inconnu, donc rien à distinguer pour un appelant qui sonderait."""
    if not _is_session_id(session_id):
        raise HTTPException(status_code=404, detail="session inconnue")
    return session_id


# --- Appartenance des sessions -----------------------------------------------
# Une session interactive est un CONTENEUR PILOTABLE : le proxy WS `/ws` donne
# le clavier et la souris de la session (noVNC complet), `/capture` et `/live`
# en exfiltrent l'état, `DELETE` la détruit. Sans propriétaire, tout analyste
# authentifié agissait sur la session de n'importe quel autre — sans effet en
# mode bearer (identité partagée "token") mais critique dès que le forward-auth
# est actif, où chaque requête porte une identité DISTINCTE.
#
# RÉPONSE SUR SESSION D'AUTRUI : 404, jamais 403. Un 403 confirmerait
# l'existence de l'identifiant ; le 404 est déjà la réponse aux identifiants
# inconnus (et hors gabarit, cf. `_checked_session_id`), donc les deux cas sont
# indistinguables pour qui sonderait.


def _session_identity(conn) -> str | None:
    """Identité à comparer au propriétaire d'une session.

    Sur une requête HTTP, `_auth` a déjà posé `request.state.identity` (bearer
    -> "token", forward-auth -> l'identité IdP) : on la relit telle quelle.

    Sur un WEBSOCKET, il n'y a PAS de middleware HTTP (`@app.middleware("http")`
    ne voit pas les connexions WS) et un navigateur ne peut pas poser d'en-tête
    `Authorization` sur un WS : l'identité doit être résolue ici.
    - forward-auth actif et en-tête présent -> l'identité IdP (le proxy la pose
      sur le handshake WS comme sur toute requête, et strippe les copies
      clientes : c'est le contrat d'opt-in de `web/identity.py`) ;
    - forward-auth actif mais AUCUNE identité -> None => refus (fail-closed :
      en mode IdP, une connexion sans identité n'est pas identifiable) ;
    - forward-auth INACTIF (mode bearer, défaut) -> "token", l'identité unique
      et partagée de tous les porteurs du jeton. C'est exactement ce que
      `resolve_identity` renvoie à un bearer valide, et c'est le propriétaire
      inscrit par `create_session` dans ce mode : le mode par défaut n'est donc
      pas régressé, alors que le WS reste par ailleurs gardé par son token
      capability propre à la session.
    """
    state_identity = getattr(getattr(conn, "state", None), "identity", None)
    if state_identity:
        return state_identity
    authorized, identity, _ = resolve_identity(conn, bearer_ok=False)
    if authorized:
        return identity
    return None if trust_forward_auth() else "token"


def _owns_session(conn, sess: dict | None) -> bool:
    """True si `conn` a le droit d'agir sur cette session. L'admin (même
    mécanisme que `DELETE /saved` : `X-Admin-Token` ou groupe admin IdP) passe
    outre — il doit pouvoir tout voir et tout arrêter."""
    if _admin_granted(conn):
        return True
    if not sess:
        return False
    owner = sess.get("owner") or ""
    if not owner:
        # Session SANS propriétaire -> refusée aux non-admins (fail-closed).
        # Sûr en pratique : redis tourne désormais sur un tmpfs (cf. la pile de
        # `deploy/`, `tmpfs: ["/data:mode=1777"]`), donc AUCUNE session ne
        # survit à un redémarrage — il n'existe pas de session « héritée »
        # d'avant ce déploiement qui deviendrait subitement inaccessible.
        return False
    identity = _session_identity(conn)
    if not identity:
        return False
    return secrets.compare_digest(owner.encode(), identity.encode())


def _owned_session_or_404(conn, registry: SessionRegistry, session_id: str) -> dict:
    """Charge une session et vérifie l'appartenance, ou lève 404 — MÊME réponse
    pour « inconnue » et « appartient à autrui » (cf. note ci-dessus)."""
    sess = registry.get(session_id)
    if not _owns_session(conn, sess):
        raise HTTPException(status_code=404, detail="session inconnue")
    return sess


# --- Disponibilité d'une session : états et sonde ----------------------------
# Trois états, DANS CET ORDRE (une session ne recule jamais) :
#   "pending"  — l'entrée registre existe (réservation posée par le broker) mais
#                le conteneur n'est PAS encore lancé (`container` vide) ;
#   "starting" — conteneur lancé, mais son `session_server` ne répond pas encore
#                `/health` (Xvfb + navigateur + websockify démarrent) ;
#   "ready"    — `/health` répond : le WS noVNC et /capture sont utilisables.
# Une session INCONNUE n'a pas d'état : c'est un 404 (cf. `_owned_session_or_404`),
# jamais un quatrième état — sans quoi la route deviendrait un oracle d'existence.
SESSION_STATE_PENDING = "pending"
SESSION_STATE_STARTING = "starting"
SESSION_STATE_READY = "ready"


def _session_state(registry: SessionRegistry, session_id: str, sess: dict | None = None) -> str:
    """Sonde NON BLOQUANTE de disponibilité : un seul tour des deux contrôles
    (registre puis `/health` interne), sans aucun `sleep`. C'est la brique
    UNIQUE partagée par `GET /sessions/{id}` (qui la rend telle quelle) et par
    `_wait_session_ready` (qui la répète jusqu'à une échéance) — les deux
    chemins ne peuvent donc pas diverger sur ce qu'est « prête ».

    `sess` permet de réutiliser l'entrée déjà chargée par le contrôle
    d'appartenance, sans deuxième aller-retour Redis."""
    if sess is None:
        sess = registry.get(session_id)
    if not sess or not sess.get("container"):
        return SESSION_STATE_PENDING
    if _internal_get_ok(f"http://{_session_host(session_id)}:8090/health"):
        return SESSION_STATE_READY
    return SESSION_STATE_STARTING


def _wait_session_ready(registry: SessionRegistry, session_id: str, deadline: float) -> bool:
    """Répète `_session_state` jusqu'à `ready` ou `deadline` (epoch monotonic).

    N'est PLUS sur le chemin d'une requête HTTP depuis que `POST /sessions`
    répond 202 : seul le thread d'amorçage (`_session_bootstrap`) l'appelle,
    pour savoir quand pousser la navigation initiale. Reste monkeypatchable en
    test sans dépendre d'un vrai conteneur."""
    while time.monotonic() < deadline:
        if _session_state(registry, session_id) == SESSION_STATE_READY:
            return True
        time.sleep(_SESSION_POLL_INTERVAL)
    return False


def _session_bootstrap(
    registry: SessionRegistry,
    cmd_queue: SessionCmdQueue,
    session_id: str,
    secret: str,
    url: str | None,
    html: str | None,
) -> None:
    """Amorçage HORS du chemin de requête : attend que la session soit prête,
    puis pousse la navigation initiale (`/goto` ou `/load`) dans le conteneur.

    Tourne dans un thread démon lancé par `create_session`. C'est CE travail
    qui prenait ~7-9 s en synchrone et privait le client de son `session_id`
    quand il abandonnait : il n'a plus rien à voir avec la réponse HTTP.

    En cas d'échec de démarrage, la session est stoppée (même filet de sécurité
    qu'avant : un conteneur qui ne démarre pas n'immobilise pas 4 Go jusqu'à son
    TTL). Le client, lui, DÉTIENT l'identifiant depuis la première milliseconde
    et peut de toute façon `DELETE` — il verra alors un 404 sur la sonde, qu'il
    traite comme un échec terminal."""
    deadline = time.monotonic() + session_ready_timeout()
    if not _wait_session_ready(registry, session_id, deadline):
        cmd_queue.enqueue_cmd("stop", session_id)
        log.warning("session start timeout session_id=%s", session_id)
        return
    host = _session_host(session_id)
    if url:
        ok = _internal_post_json(f"http://{host}:8090/goto", {"url": url}, secret)
    else:
        ok = _internal_post_json(f"http://{host}:8090/load", {"html": html}, secret)
    if not ok:
        log.warning("session goto/load failed session_id=%s", session_id)


def _spawn_session_bootstrap(*args) -> None:
    """Lance `_session_bootstrap` dans un thread démon. Indirection délibérée :
    les tests la monkeypatchent pour exécuter (ou non) l'amorçage de façon
    déterministe, sans avoir à joindre un thread."""
    threading.Thread(
        target=_session_bootstrap, args=args, daemon=True, name="ocular-session-bootstrap"
    ).start()


# 202 Accepted, PAS 200 : la session est ACCEPTÉE, pas encore PRÊTE. Le client
# reçoit `session_id` + `token` immédiatement (< 1 ms de travail en propre), puis
# sonde `GET /sessions/{id}` jusqu'à l'état "ready". C'est tout l'objet du
# changement : en synchrone, un client qui abandonnait pendant les ~7-9 s
# d'attente n'apprenait JAMAIS son `session_id` et laissait donc une session
# — un conteneur ~4 Go et un sous-réseau du pool — que PERSONNE ne pouvait
# supprimer avant son TTL.
@app.post("/sessions", response_model=SessionResponse, status_code=202)
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
    # Plafond anti-épuisement de ressources : chaque session = un conteneur
    # ~4g. Refuse (429) au-delà d'OCULAR_MAX_SESSIONS sessions actives (0 =
    # illimité). Le reaper libère les slots (idle/ttl/déconnexion).
    cap = max_sessions()
    if cap and len(registry.list_active()) >= cap:
        raise HTTPException(status_code=429, detail="trop de sessions actives, réessayez plus tard")
    if req.url:
        # Même normalisation qu'à la soumission d'un job capture (cf.
        # submit_job) : AVANT la garde SSRF, pour que "example.com" devienne
        # "https://example.com" tout en respectant un scheme explicite.
        # normalize_url() est couvert par le même try/except que la garde SSRF
        # (jamais de 500 pour un scheme non-réseau ou une entrée tordue).
        try:
            req.url = normalize_url(req.url)
            validate_capture_url(req.url)
        except DnsResolutionError:
            raise HTTPException(status_code=400, detail=_DNS_DETAIL)
        except ValueError:
            raise HTTPException(status_code=400, detail="url interdite")

    session_id = "sess-" + uuid.uuid4().hex[:12]
    token = secrets.token_urlsafe(32)
    # Secret de session à la frontière conteneur (défense-en-profondeur F1/F2),
    # DISTINCT du token WS : le session_server l'exige sur /goto,/load,/capture.
    # SEUL le web le connaît — jamais renvoyé dans les réponses, jamais loggé.
    session_secret = secrets.token_urlsafe(24)
    target = req.url if req.url else "inline-html"
    # Propriétaire de la session = identité de l'appelant, posée par `_auth`
    # (bearer -> "token", identité partagée par tous les porteurs du jeton ;
    # forward-auth -> l'identité IdP). C'est le broker qui écrit l'entrée
    # registre, donc le propriétaire transite par la commande de lancement.
    owner = _session_identity(request) or ""
    cmd_queue.enqueue_cmd(
        "launch", session_id, token=token, target=target, secret=session_secret,
        owner=owner,
    )

    # Pas `request.client.host` : depuis le frontal L4 `gateway`, le pair TCP
    # est TOUJOURS le gateway (mesuré : client_ip=172.28.0.5 sur chaque ligne).
    # `client_ip()` porte la frontière de confiance (cf. web/identity.py).
    ip = client_ip(request)
    # Avertissement délibéré : une session interactive expose l'IP du serveur
    # au site cible (URL live) et/ou rend du contenu potentiellement hostile
    # dans le conteneur — jamais le token dans ce log.
    log.warning(
        "session create session_id=%s client_ip=%s kind=%s",
        session_id, ip, "url" if req.url else "html",
    )

    # Attente de disponibilité + navigation initiale : DÉPORTÉES hors du chemin
    # de requête (cf. `_session_bootstrap`). On répond tout de suite.
    _spawn_session_bootstrap(registry, cmd_queue, session_id, session_secret, req.url, req.html)

    return SessionResponse(session_id=session_id, token=token)


@app.get("/sessions/{session_id}")
def get_session(
    session_id: str,
    request: Request,
    registry: SessionRegistry = Depends(get_session_registry),
) -> dict:
    """État de disponibilité d'une session — la sonde que le client interroge
    après le 202 de `POST /sessions`, jusqu'à `state == "ready"`.

    Renvoie `{session_id, state, ready, kind, target, created_at,
    last_activity}` :
      • `state` ∈ "pending" | "starting" | "ready" (cf. `_session_state`) ;
      • `ready` est le booléen de commodité `state == "ready"`, pour que le
        client n'ait pas à coder en dur la liste des états intermédiaires — un
        état ajouté plus tard ne cassera pas sa condition d'arrêt.

    NI `token` NI `secret` NE SORTENT (même filtrage que `list_active` : le
    token capability WS n'est jamais renvoyé par une route de lecture, le secret
    conteneur ne sort jamais du tout). `owner` non plus, sauf à l'admin — il
    porte l'identité IdP d'un tiers.

    Appartenance appliquée EXACTEMENT comme les autres routes de session :
    `_checked_session_id` puis `_owned_session_or_404`, donc 404 indistinguable
    entre « inconnue », « hors gabarit » et « appartient à autrui » (l'admin
    passe outre). Cette route est un point de sondage répété : c'est
    précisément là qu'un 403 aurait fait un oracle d'existence commode."""
    session_id = _checked_session_id(session_id)
    sess = _owned_session_or_404(request, registry, session_id)
    if not sess:
        # `_owned_session_or_404` laisse passer l'ADMIN même sur une session
        # absente (il court-circuite l'appartenance) et rend alors None. Les
        # autres routes ignorent sa valeur de retour ; celle-ci la LIT, donc
        # elle doit conclure elle-même : inconnue = 404, admin ou pas.
        raise HTTPException(status_code=404, detail="session inconnue")
    state = _session_state(registry, session_id, sess=sess)
    out = {
        "session_id": session_id,
        "state": state,
        "ready": state == SESSION_STATE_READY,
        "kind": sess.get("kind", ""),
        "target": sess.get("target", ""),
        "created_at": sess.get("created_at", ""),
        "last_activity": sess.get("last_activity", ""),
    }
    if _admin_granted(request):
        out["owner"] = sess.get("owner", "")
    return out


@app.get("/sessions")
def list_sessions(
    request: Request,
    registry: SessionRegistry = Depends(get_session_registry),
) -> list:
    # Anti-fuite (note sécu T2) : le token capability WS n'est JAMAIS renvoyé
    # dans une liste — seul un GET/DELETE ciblé côté serveur y a accès.
    #
    # FILTRAGE PAR PROPRIÉTAIRE : on ne liste que SES sessions (l'admin voit
    # tout). Sans ce filtre, la liste divulguait à chaque analyste les
    # identifiants — et donc la surface d'attaque — des sessions de tous les
    # autres, en plus de leurs URL cibles.
    is_admin = _admin_granted(request)
    # `owner` ne sort JAMAIS vers un non-admin (même précaution que `token` et
    # `secret`) : il porte l'identité IdP d'un tiers. L'admin le conserve, sans
    # quoi « tout voir » ne lui dirait pas de QUI est la session qu'il arrête.
    hidden = {"token"} if is_admin else {"token", "owner"}
    return [
        {k: v for k, v in sess.items() if k not in hidden}
        for sess in registry.list_active()
        if is_admin or _owns_session(request, sess)
    ]


@app.delete("/sessions/{session_id}")
def delete_session(
    session_id: str,
    request: Request,
    registry: SessionRegistry = Depends(get_session_registry),
    cmd_queue: SessionCmdQueue = Depends(get_cmd_queue),
) -> dict:
    session_id = _checked_session_id(session_id)
    # 404 sur session inconnue COMME sur session d'autrui. La suppression n'est
    # donc plus idempotente sur un id bien formé mais inconnu (elle renvoyait
    # 200 « deleted ») : c'est le prix de l'indistinguabilité — un 200 sur
    # l'inconnu et un 404 sur celle d'autrui auraient fait de DELETE un oracle
    # d'existence de session.
    _owned_session_or_404(request, registry, session_id)
    cmd_queue.enqueue_cmd("stop", session_id)
    registry.delete(session_id)
    log.info("session delete session_id=%s", session_id)
    return {"deleted": session_id}


@app.post("/sessions/{session_id}/capture")
def capture_session(
    session_id: str,
    request: Request,
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
    session_id = _checked_session_id(session_id)
    # 404 indistinguable : session inconnue OU appartenant à un autre analyste.
    _owned_session_or_404(request, registry, session_id)

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

    store_blobs(wrapper.get("blobs", {}), artifacts_dir())

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
    request: Request,
    registry: SessionRegistry = Depends(get_session_registry),
) -> dict:
    """Proxy vers `GET /live` du `session_server` (panneau live, C4) : appels
    réseau + analyse statique en continu, canal données séparé du flux
    pixels VNC. Même schéma d'accès que `capture_session` (secret conteneur
    lu au registre, jamais régénéré ici, jamais renvoyé/loggé)."""
    session_id = _checked_session_id(session_id)
    # 404 indistinguable : session inconnue OU appartenant à un autre analyste.
    _owned_session_or_404(request, registry, session_id)

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
    # Même grille que les routes HTTP de session, appliquée AVANT toute
    # interrogation du registre (fail-closed en entrée, pas par accident
    # d'authentification).
    if not _is_session_id(sid):
        await websocket.close(code=1008)
        return

    token = _extract_ws_token(websocket)
    if not token or not registry.valid_token(sid, token):
        await websocket.close(code=1008)
        return

    sess = registry.get(sid)
    if not sess or not sess.get("container"):
        await websocket.close(code=1008)
        return

    # APPARTENANCE — la garde la plus critique du service : ce proxy relaie le
    # RFB, donc le CLAVIER ET LA SOURIS de la session, potentiellement connectée
    # aux comptes de son propriétaire. Le token capability seul ne suffit pas
    # comme preuve d'identité (il peut fuiter, être partagé, ou survivre à un
    # changement de titulaire). Fermeture 1008 comme pour une session inconnue
    # ou un token invalide : indistinguable, l'équivalent WS du 404 HTTP.
    if not _owns_session(websocket, sess):
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


@contextlib.contextmanager
def saved_conn():
    """Connexion SQLite aux sauvegardes, FERMÉE automatiquement en sortie de
    bloc `with` (y compris sur exception/HTTPException). Remplace le motif
    dupliqué `conn = _saved_conn(); try: ... finally: conn.close()` sur toutes
    les routes /saved."""
    path = saved_db_path()
    if os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = saved_store.connect(path)
    try:
        yield conn
    finally:
        conn.close()


def _read_artifact_bytes(ref: str) -> bytes | None:
    try:
        fname = ref_to_filename(ref)
    except ValueError:
        return None
    path = os.path.join(artifacts_dir(), fname)
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
    try:
        result = json.loads(result_json)
    except (ValueError, TypeError):
        # cohérent avec get_job/explain_job : une valeur Redis corrompue -> 500
        # propre plutôt qu'un JSONDecodeError non géré.
        raise HTTPException(status_code=500, detail="résultat corrompu")
    blobs = {}
    for ref in saved_store.refs_of(result):
        data = _read_artifact_bytes(ref)
        if data is None:
            raise HTTPException(status_code=409, detail="artefacts expirés, relancer l'analyse")
        blobs[ref] = data
    with saved_conn() as conn:
        try:
            sid = saved_store.save(conn, result, blobs, body.get("label"),
                                   datetime.now(timezone.utc).isoformat(),
                                   saved_by=getattr(request.state, "identity", None))
        except saved_store.DuplicateLabelError:
            raise HTTPException(status_code=409, detail="nom déjà utilisé")
    log.info("saved job_id=%s id=%s verdict=%s", job_id, sid, result.get("verdict"))
    return {"id": sid, "input_hash": result.get("input_hash")}


@app.post("/saved/{sid}/verdict")
def set_saved_verdict(sid: int, body: AnalystVerdictRequest, request: Request) -> dict:
    # Route non-admin : un bearer/forward-auth normal suffit pour classer une
    # sauvegarde ; seul DELETE /saved (flush) exige X-Admin-Token (cf. middleware _auth).
    analyst = getattr(request.state, "identity", None)
    analyst_at = datetime.now(timezone.utc).isoformat()
    note = (body.note or "")[:2000]
    with saved_conn() as conn:
        try:
            ok = saved_store.set_analyst_verdict(conn, sid, body.analyst_verdict, analyst, analyst_at, note)
        except ValueError:
            raise HTTPException(status_code=422, detail="verdict analyste invalide")
        if not ok:
            raise HTTPException(status_code=404, detail="sauvegarde inconnue")
        meta = saved_store.get_meta(conn, sid)
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
    with saved_conn() as conn:
        meta = saved_store.get_by_hash(conn, input_hash)
    if not meta:
        raise HTTPException(status_code=404, detail="aucune sauvegarde")
    return meta


@app.get("/saved/{ref_or_id}")
def get_saved(ref_or_id: str) -> dict:
    with saved_conn() as conn:
        if ref_or_id.startswith("sha256:"):
            meta = saved_store.get_by_hash(conn, ref_or_id)
            if not meta:
                raise HTTPException(status_code=404, detail="aucune sauvegarde")
            return meta
        raise HTTPException(status_code=404, detail="introuvable")


@app.get("/saved")
def list_saved(sort: str = "saved_at", order: str = "desc",
               min_band: str | None = None) -> list:
    with saved_conn() as conn:
        try:
            return saved_store.list_all(conn, sort=sort, order=order, min_band=min_band)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))


@app.get("/saved/{sid}/result")
def get_saved_result(sid: int) -> dict:
    with saved_conn() as conn:
        res = saved_store.get_result(conn, sid)
        if res is None:
            raise HTTPException(status_code=404, detail="introuvable")
        return res


@app.get("/saved/{sid}/artifact/{ref}")
def get_saved_artifact(sid: int, ref: str) -> Response:
    try:
        fname = ref_to_filename(ref)  # valide ^sha256:[0-9a-f]{64}$ (anti-traversal)
    except ValueError:
        raise HTTPException(status_code=400, detail="ref invalide")
    with saved_conn() as conn:
        data = saved_store.get_artifact(conn, sid, ref)
    if data is None:
        raise HTTPException(status_code=404, detail="artefact absent")
    return _serve_artifact_bytes(data, fname)


@app.delete("/saved/{sid}")
def delete_saved(sid: int) -> dict:
    with saved_conn() as conn:
        ok = saved_store.delete(conn, sid)
    if not ok:
        raise HTTPException(status_code=404, detail="introuvable")
    log.info("saved deleted id=%s", sid)
    return {"deleted": sid}


@app.delete("/saved")
def flush_saved() -> dict:
    with saved_conn() as conn:
        n = saved_store.flush(conn)
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
