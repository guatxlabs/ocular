# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`session_server` — serveur FastAPI PERSISTANT (contrairement à
`runner_recon/capture.py` qui est un one-shot CLI) : garde une session
Camoufox headed vivante entre les appels HTTP `/goto`, `/load`, `/capture`,
pour le tier interactif (VNC) de la phase 3b.

Réutilise `engine.wrapper` (ResultBuilder/NetworkCapture) EXACTEMENT comme
`runner_recon/capture.py` — aucune duplication de la mécanique wrapper
(hash de blobs, construction OcularResult, etc.). Le seul code propre à ce
module est :
  - le pilotage Camoufox (`_ensure_browser`, garde le `page`/`NetworkCapture`
    vivants entre requêtes au lieu d'un `async with` one-shot) ;
  - `build_capture_result(...)`, la composition PURE (sans navigateur) du
    résultat à partir de données déjà capturées — testée sans Camoufox dans
    `tests/test_session_server_logic.py`, à l'image de `build_result` dans
    `runner_recon/capture.py`.

`/capture` renvoie le MÊME format `{result, blobs}` que `capture.py` (via
`engine.wrapper.emit_wrapper`'s payload shape), pour que le reste du pipeline
(broker, stockage `/saved`, UI) n'ait pas à distinguer tier batch vs tier
interactif.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import secrets
from typing import Any, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from engine.browser_js import CF_INDICATOR_JS, SCROLL_TO_LOAD_JS
from engine.egress_policy import hardened_launch_kwargs, maybe_start_egress_guard
from engine.limits import source_budget
from engine.result import DomInfo, OcularResult, StealthInfo, Truncation
from engine.static import HtmlScan, extract_forms, extract_mailtos, scan_html
from engine.urlnorm import url_input_hash
from engine.verdict import compute_verdict
from engine.wrapper import NetworkCapture, ResultBuilder, _max_findings, wrapper_payload


log = logging.getLogger("ocular.session_server")


@contextlib.asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Au démarrage : lance le navigateur EN TÂCHE DE FOND (`_boot_browser`).

    C'est le cœur de la correction « disponibilité ≠ vivacité ». Avant, la page
    Camoufox ne démarrait qu'au premier `/goto` (paresseusement) tandis que
    `/health` répondait OK dès qu'uvicorn écoutait : le web annonçait `ready`
    ~4 s avant que la session sache réellement servir, et une capture lancée
    immédiatement après `ready` — ce que le contrat documenté prescrit —
    tombait sur `/capture` -> 409 « no active session », rendu 502 au client.

    La tâche est lancée SANS être attendue : uvicorn doit accepter les
    connexions tout de suite pour que `/health` puisse répondre « pas encore
    prête » (503) au lieu de faire expirer la sonde en connexion refusée. C'est
    `/health` qui porte désormais l'information, pas le fait d'écouter.

    À l'arrêt PROPRE du conteneur
    (SIGTERM géré par uvicorn), ferme au mieux le navigateur puis stoppe le
    garde egress (`_state["guard"]`) — best-effort : ne lève jamais (le
    conteneur s'arrête de toute façon). Si le conteneur est tué net
    (SIGKILL/OOM) ce hook ne s'exécute pas : le garde meurt avec le process,
    accepté (cf. docstring `_ensure_browser`, c'est un enfant du même
    conteneur éphémère — aucune ressource ne fuit au-delà de sa durée de
    vie)."""
    task = asyncio.create_task(_boot_browser())
    yield
    # L'amorçage peut être encore en vol si le conteneur est arrêté tôt : on
    # l'annule avant de démonter, sinon `cm.__aexit__` court contre un
    # `__aenter__` non terminé.
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await task
    cm = _state.get("cm")
    if cm is not None:
        with contextlib.suppress(Exception):
            await cm.__aexit__(None, None, None)
    guard = _state.get("guard")
    if guard is not None:
        with contextlib.suppress(Exception):
            await guard.stop()


app = FastAPI(lifespan=_lifespan)


def require_session_secret(
    x_session_secret: Optional[str] = Header(default=None),
) -> None:
    """Auth à la frontière conteneur (défense-en-profondeur F1/F2) : les
    endpoints qui pilotent le navigateur (`/goto`, `/load`, `/capture` — PAS
    `/health`) exigent le header `X-Session-Secret` == `OCULAR_SESSION_SECRET`
    (injecté par le broker au `docker run`, connu du seul web). Comparaison en
    **temps constant**. **Fail-closed** : si le secret n'est pas configuré côté
    conteneur, on refuse TOUJOURS (jamais ouvert par défaut). Le secret n'est
    jamais loggé — aucune trace ici."""
    expected = os.environ.get("OCULAR_SESSION_SECRET")
    provided = x_session_secret or ""
    if not expected or not secrets.compare_digest(
        provided.encode("utf-8", "ignore"), expected.encode()
    ):
        raise HTTPException(status_code=403, detail="forbidden")

# État de session unique (un conteneur = une session interactive = une page
# Camoufox vivante). Pas de multi-session dans cette tâche : le broker lance
# un conteneur par session (tâches suivantes de la phase 3b).
# `guard` (plan 3g Task G2) : l'EgressGuard démarré par `_ensure_browser`
# quand `egress_guard_enabled()` — vit tant que la session vit, un seul par
# conteneur (comme `page`/`cap`), stoppé par `_shutdown` (best-effort — cf.
# docstring `_ensure_browser`).
# `boot_error` : type de l'exception qui a fait échouer le lancement du
# navigateur à l'amorçage, lu par `/health` pour rester NON prêt (fail-closed)
# plutôt que d'annoncer une session qui ne servira jamais.
_state: dict[str, Any] = {
    "cm": None, "page": None, "cap": None, "target": None, "kind": None,
    "guard": None, "boot_error": None,
}

# Sérialise `_ensure_browser` : depuis que le navigateur démarre à l'amorçage,
# un `/goto` peut arriver PENDANT ce lancement. Sans verrou, les deux appels
# voient `page is None` et lancent chacun un Camoufox (et un garde egress) —
# le premier fuirait, écrasé dans `_state`. Créé au niveau module : depuis
# Python 3.10 `asyncio.Lock()` ne se lie plus à une boucle à la construction.
_browser_lock = asyncio.Lock()

# Snippets JS partagés (source unique engine/browser_js) : indicateur de
# challenge Turnstile (on l'évalue à la capture pour distinguer « challenge
# présent » de « aucun challenge ») + parcours pour le lazy-load avant full-page.
_CF_INDICATOR_JS = CF_INDICATOR_JS
_SCROLL_TO_LOAD_JS = SCROLL_TO_LOAD_JS


def build_capture_result(
    target: str,
    kind: Literal["url", "html"],
    png: bytes,
    dom: bytes,
    title: str,
    final: str,
    network: list[dict[str, Any]],
    html_input: str = "",
    console: Optional[list[dict[str, Any]]] = None,
    turnstile_solved: Optional[bool] = None,
    challenge: Optional[str] = None,
    truncation: Optional[Truncation] = None,
) -> tuple[OcularResult, dict[str, bytes]]:
    """Logique pure (aucune dépendance Camoufox) : compose l'`OcularResult`
    à partir de données déjà capturées par le pilotage du navigateur. Miroir
    de `runner_recon.capture.build_result`, adapté aux deux origines possibles
    d'une session interactive : navigation (`kind="url"`, profil `capture`,
    input_hash dérivé de l'URL normalisée) ou injection HTML directe
    (`kind="html"`, profil `analysis`, input_hash dérivé du HTML fourni —
    même convention que `runner_analysis/render.py`).

    `console` (parité avec `runner_analysis/render.py`) : le journal
    console accumulé par `NetworkCapture.attach` sur la page de session (même
    mécanique que le tier statique) — sans ce paramètre, le résultat interactif
    n'était PAS un sur-ensemble du résultat statique (`OcularResult.console`
    restait toujours vide côté interactif)."""
    builder = ResultBuilder()
    if png:
        builder.add_screenshot(0, "interactive", png)
    builder.set_dom(dom)

    dom_str = dom.decode("utf-8", "replace") if dom else ""
    scan = scan_html(dom_str) if dom else HtmlScan([], 0)
    findings = scan.findings

    if kind == "url":
        profile = "capture"
        input_hash = url_input_hash(target)
    else:
        profile = "analysis"
        input_hash = "sha256:" + hashlib.sha256(html_input.encode()).hexdigest()

    return builder.build(
        job_id="",
        profile=profile,
        target=target,
        input_hash=input_hash,
        verdict=compute_verdict(findings),
        dom_info=DomInfo(
            title=title, final_url=final,
            forms=extract_forms(dom_str), mailtos=extract_mailtos(dom_str),
        ),
        # Tri-état Turnstile (session interactive : résolution MANUELLE, non
        # introspectable de façon fiable — l'iframe CF subsiste dans le DOM
        # après résolution). turnstile_solved=None quand aucun challenge n'est
        # détecté (pas de faux « non passé ») ; l'analyste peut marquer
        # explicitement « passé manuellement » (True) via l'UI de capture.
        stealth=StealthInfo(engine="camoufox", turnstile_solved=turnstile_solved, challenge=challenge),
        static_findings=scan,
        network=network,
        console=console,
        # Ce que les plafonds anti-OOM de `NetworkCapture` ont déjà rejeté :
        # reporté dans le résultat, jamais tu (cf. `engine.result.Truncation`).
        truncation=truncation,
    )


async def _ensure_browser() -> None:
    """Garantit qu'une page Camoufox est vivante (idempotent, et SÛR en
    concurrence : un seul lancement même si l'amorçage et un `/goto` entrent
    ensemble — cf. `_browser_lock`). Le lancement lui-même est dans
    `_launch_browser`."""
    if _state["page"] is not None:
        return
    async with _browser_lock:
        # Re-vérification SOUS verrou : l'appelant qui attendait le verrou
        # pendant que l'autre lançait ne doit pas relancer derrière lui.
        if _state["page"] is not None:
            return
        await _launch_browser()


async def _boot_browser() -> None:
    """Lancement à l'amorçage du conteneur (tâche de fond de `_lifespan`).

    Ne propage JAMAIS : une panne de lancement ne doit pas tuer le conteneur,
    elle doit rendre la session durablement NON prête. `/health` reste alors
    503, la sonde du web n'atteint jamais `ready`, son échéance
    (`session_ready_timeout`) expire et la session est stoppée — filet de
    sécurité déjà en place dans `web._session_bootstrap`. On ne consigne que le
    TYPE de l'exception : les messages Camoufox portent des chemins internes."""
    try:
        await _ensure_browser()
    except Exception as exc:  # pragma: no cover - dépend de l'environnement réel
        _state["boot_error"] = type(exc).__name__
        log.warning("session browser boot failed error=%s", type(exc).__name__)


async def _launch_browser() -> None:
    """Démarre la page Camoufox unique de cette session. Appelé UNIQUEMENT
    sous `_browser_lock` (via `_ensure_browser`).

    Egress guard (plan 3g Task G2) : ce tier interactif est réseau-ON comme
    le tier batch (`runner_recon/capture.py`) — même câblage. Quand
    `egress_guard_enabled()` (défaut), un `EgressGuard` local est démarré
    AVANT Camoufox et le navigateur est routé à travers lui via l'option
    `proxy` STANDARD Playwright (`{"server": "http://127.0.0.1:<port>"}`) —
    `AsyncCamoufox` déroule ses kwargs directement dans
    `playwright.firefox.launch(...)`, cf. `runner_recon/capture.py::
    _camoufox_session` pour la vérification détaillée de cette voie.

    Le garde est gardé vivant dans `_state["guard"]` tant que la session vit
    (une page = un garde, pas de restart entre `/goto`/`/load`/`/capture`) et
    stoppé au mieux par `_lifespan` (hook FastAPI, déclenché sur arrêt propre
    du conteneur — SIGTERM). Si le conteneur est tué net
    (SIGKILL/OOM), le garde meurt avec le process : acceptable, c'est un
    process enfant du même conteneur éphémère, aucune ressource ne fuit
    au-delà de sa durée de vie.

    Fail-safe : si `guard.start()` lève, l'exception remonte — jamais de
    fallback silencieux vers un Camoufox sans proxy (même politique que le
    tier batch)."""
    # Kwargs durcis + politique egress (garde/strict/warning) FACTORISÉS dans
    # engine.egress_policy — source unique partagée avec le tier batch.
    launch_kwargs = hardened_launch_kwargs()
    guard, proxy_kwargs = await maybe_start_egress_guard()
    launch_kwargs.update(proxy_kwargs)
    if guard is not None:
        _state["guard"] = guard

    from camoufox.async_api import AsyncCamoufox
    # Si le lancement Camoufox échoue APRÈS le démarrage du garde, on doit
    # STOPPER le garde : sinon `_state["page"]` reste None, la requête suivante
    # re-rentre dans `_ensure_browser`, crée un NOUVEAU garde et écrase
    # `_state["guard"]` -> l'ancien socket/serveur asyncio fuit à chaque retry.
    try:
        cm = AsyncCamoufox(**launch_kwargs)
        ctx = await cm.__aenter__()
        page = await ctx.new_page()
    except Exception:
        g = _state.get("guard")
        if g is not None:
            with contextlib.suppress(Exception):
                await g.stop()
            _state["guard"] = None
        raise
    # `keep="last"` : le tier interactif INVERSE le choix du tier batch. La
    # capture est armée UNE fois pour toute la session (ni `/goto` ni `/load` ne
    # la réarment), donc le plafond de cardinalité est CUMULÉ sur la session
    # entière ; or l'analyste pilote la page précisément pour DÉCLENCHER
    # l'exfiltration, qui arrive donc en fin de session. Garder les premières
    # entrées y jetait en silence exactement la preuve recherchée.
    cap = NetworkCapture(keep="last")
    cap.attach(page)
    _state.update(cm=cm, page=page, cap=cap)
    # Le plein écran de la fenêtre est assuré par matchbox-window-manager, démarré
    # dans entrypoint_vnc.sh (kiosk) : la fenêtre couvre exactement l'Xvfb (défaut
    # 1920x1080, OCULAR_SESSION_SCREEN), plus de crop bas/droite. Rien à faire ici.


@app.get("/health")
async def health() -> Any:
    """DISPONIBILITÉ réelle, pas vivacité du process : vert UNIQUEMENT quand la
    page Camoufox est vivante, donc quand `/goto` et `/capture` savent servir.

    C'est le signal que consomme `web._session_state` — la sonde partagée par
    `GET /sessions/{id}` et `_wait_session_ready`, qui ne tient pour prête
    qu'une réponse 2xx (`web.internal_http.internal_get_ok`). Un 503 la laisse
    donc en `starting`, sans qu'aucun des deux consommateurs n'ait à changer :
    ils ne peuvent pas diverger, ils lisent le même `/health`.

    Le signal est un ÉTAT OBSERVÉ (`_state["page"]`), jamais une temporisation :
    il arrive exactement quand le navigateur est prêt, aussi vite sur une
    machine rapide que tard sur une machine chargée.

    Reste la seule route SANS secret (cf. `require_session_secret`) : c'est une
    sonde d'infrastructure, et elle ne divulgue que « prête / pas encore »."""
    if _state["page"] is not None:
        return {"ok": True, "state": "ready"}
    state = "error" if _state.get("boot_error") else "starting"
    return JSONResponse({"ok": False, "state": state}, status_code=503)


@app.post("/goto", dependencies=[Depends(require_session_secret)])
async def goto(body: dict[str, Any]) -> dict[str, Any]:
    # Valider AVANT de démarrer le navigateur / muter l'état : un body sans `url`
    # -> 400 propre (pas un KeyError 500, et pas de mutation d'état partielle).
    url = body.get("url")
    if not isinstance(url, str) or not url:
        return JSONResponse({"error": "url requis"}, status_code=400)
    await _ensure_browser()
    _state["target"], _state["kind"] = url, "url"
    try:
        await _state["page"].goto(url, wait_until="domcontentloaded", timeout=45000)
    except Exception as exc:  # pragma: no cover - dépend du réseau/cible réelle
        return JSONResponse({"error": type(exc).__name__}, status_code=502)
    return {"ok": True}


@app.post("/load", dependencies=[Depends(require_session_secret)])
async def load(body: dict[str, Any]) -> dict[str, Any]:
    html = body.get("html")
    if not isinstance(html, str) or not html:
        return JSONResponse({"error": "html requis"}, status_code=400)
    await _ensure_browser()
    _state["target"], _state["kind"] = "inline-html", "html"
    _state["html_input"] = html
    try:
        await _state["page"].set_content(html, wait_until="domcontentloaded", timeout=45000)
    except Exception as exc:  # pragma: no cover - dépend du contenu réel
        return JSONResponse({"error": type(exc).__name__}, status_code=502)
    return {"ok": True}


# Mémo d'analyse de `/live`, clefé par empreinte du DOM. `/live` est pollé
# toutes les 2 s PAR SESSION (web/ui/views/interactive.js) et `analyze_html`
# balaye 64 regex sur le document ENTIER. Recalculer à chaque tour, c'est offrir
# à la page ANALYSÉE — donc hostile — un cœur en permanence par session.
# Un conteneur = une page : une seule entrée suffit (DOM inchangé -> zéro coût).
#
# CE QUI BORNE RÉELLEMENT CE CHEMIN — et ce que ce mémo ne borne PAS.
#
# Le mémo ne fait qu'éviter de REFAIRE une analyse ; il ne borne pas ce qu'UNE
# analyse coûte, et une page qui mute d'un octet par poll ne le rencontre jamais
# (le single-flight non plus : sa clef est la même empreinte de DOM). Ce qui
# borne le coût est dans `engine.static`, en deux temps : des motifs à
# quantificateurs BORNÉS (coût linéaire en la taille, quelle que soit la forme du
# contenu) et une FENÊTRE d'analyse `OCULAR_MAX_ANALYZED_HTML_CHARS` (défaut
# 524 288 caractères) qui borne la taille balayée et déclare ce qu'elle écarte
# dans `truncation.html_chars_dropped`.
#
# CHIFFRES MESURÉS, et seulement eux. Sur cette machine (Python 3.14), chemin
# complet `scan_html` + `extract_forms` + `extract_mailtos`, batterie de 65
# formes hostiles dérivées des motifs eux-mêmes, chacune répétée jusqu'au plafond
# de fenêtre : pire cas 784 ms — contre 5,0 s de timeout `internal_get_json`.
# Au-delà de la fenêtre, agrandir le document ne coûte plus rien : la même
# batterie à 4 Mio donne le même pire cas (704 ms).
#
# Ces chiffres sont une MESURE SUR UNE MACHINE, pas une garantie universelle :
# ils bornent le coût parce que la fenêtre borne la taille, et le rapport au
# timeout est ce qu'il faut re-mesurer si l'on relève
# `OCULAR_MAX_ANALYZED_HTML_CHARS` (tests/test_static_bounded.py rejoue la
# mesure à chaque exécution de la suite et échoue si le pire cas franchit 5,0 s).
#
# Pour référence, l'état AVANT ce correctif, mesuré de la même façon : la forme
# `eval(` répétée coûtait 27 295 ms à 128 Kio et la forme `<input` 52 608 ms, en
# produisant ZÉRO détection — 64 Kio suffisaient à faire rendre 502 à CHAQUE
# poll, indéfiniment. `OCULAR_MAX_HTML_BYTES` ne borne PAS ce chemin (il ne borne
# que le `html` SOUMIS à l'API) : le DOM live est ce que la page rend.
_LIVE_ANALYSIS: dict[str, dict[str, Any]] = {}


def _analyze_dom(dom: str) -> dict[str, Any]:
    """Analyse statique complète du DOM courant. SYNCHRONE et pure : appelée via
    `run_in_threadpool` pour ne jamais tenir la boucle d'évènements (celle qui
    pilote Camoufox et sert `/health`, `/goto`, `/capture`).

    SEUL producteur d'une analyse live — donc le seul endroit où décider ce que
    la session RETIENT. `_max_findings()` s'applique ICI, avant la mise en mémo,
    et pas plus loin : appliqué à la réponse seulement, il bornait ce que
    l'analyste voit sans borner ce que le conteneur garde. Mesuré avant, DOM
    hostile de 1 Mio : 65 536 détections produites, 5 000 rendues, 65 536
    RETENUES dans `_LIVE_ANALYSIS`, RSS 47 -> 140 Mio après UN poll. Le mémo
    survit tant que le DOM ne change pas : la part écartée n'avait aucune borne.

    Le verdict est calculé sur les détections CONSERVÉES, comme côté batch
    (`ResultBuilder.build` plafonne aussi avant `compute_triage`)."""
    scan = scan_html(dom)
    cap = _max_findings()
    kept = scan.findings[:cap]
    return {
        "findings": [f.model_dump(mode="json") for f in kept],
        "findings_dropped": len(scan.findings) - len(kept),
        "html_chars_dropped": scan.chars_dropped,
        "forms": extract_forms(dom),
        "mailtos": extract_mailtos(dom),
        "verdict": compute_verdict(kept),
    }


# Analyses EN VOL, clefées comme le mémo. Le mémo seul ne déduplique que les
# polls SÉQUENTIELS : il est écrit APRÈS l'analyse, donc N polls concurrents du
# même DOM le manquent tous et lancent N analyses (mesuré : 20 polls -> pic de
# concurrence 20). Or `analyze_html` était auparavant appelée en ligne dans la
# coroutine, donc STRICTEMENT sérialisée : mémoïser sans single-flight
# remplaçait une sérialisation par une concurrence non bornée, et l'UI poste via
# `setInterval(pollLive, 2000)` sans attendre la requête précédente.
_LIVE_INFLIGHT: dict[str, "asyncio.Future[dict[str, Any]]"] = {}


async def _live_analysis(dom: str) -> dict[str, Any]:
    """`_analyze_dom` mémoïsé sur `sha256(dom)`, déporté hors de la boucle, et
    à UNE SEULE analyse en vol par empreinte : les polls concurrents du même DOM
    attendent le même résultat au lieu d'en relancer chacun un."""
    digest = hashlib.sha256(dom.encode("utf-8", "replace")).hexdigest()
    cached = _LIVE_ANALYSIS.get(digest)
    if cached is not None:
        return cached
    inflight = _LIVE_INFLIGHT.get(digest)
    if inflight is not None:
        # `shield` : un appelant qui abandonne (poll annulé, client parti) ne doit
        # pas annuler l'analyse partagée par les autres.
        return await asyncio.shield(inflight)
    future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
    _LIVE_INFLIGHT[digest] = future
    try:
        analysis = await run_in_threadpool(_analyze_dom, dom)
    except BaseException as exc:
        if not future.done():
            future.set_exception(exc)
        # Consommé par les attentes ci-dessus ; sans ce retrait, l'exception
        # resterait non récupérée si personne n'attendait.
        future.exception()
        raise
    finally:
        _LIVE_INFLIGHT.pop(digest, None)
    _LIVE_ANALYSIS.clear()  # une seule entrée : le DOM courant
    _LIVE_ANALYSIS[digest] = analysis
    if not future.done():
        future.set_result(analysis)
    return analysis


_LIVE_WINDOW = 500


def _max_live_json_bytes() -> int:
    """Budget de la réponse `/live` SÉRIALISÉE (`OCULAR_MAX_LIVE_JSON_BYTES`,
    défaut 8 Mio). L'écart avec `OCULAR_MAX_INTERNAL_JSON_BYTES` (16 Mio, le
    plafond de LECTURE côté web) est ce qui empêche la page analysée de
    transformer le fail-closed en refus permanent — et cet écart est désormais
    GARANTI, pas espéré : `engine.limits.resolve` lit les DEUX variables et
    ramène ce budget sous le plafond de lecture si la configuration l'y fait
    passer. Mesuré avant, avec `=33554432` (la borne haute que le code
    AUTORISAIT) : corps `/live` de 23,45 Mio annoncé COMPLET et `502` à chaque
    poll, sans le moindre WARNING."""
    return source_budget("live")


def _fit_live_payload(payload: dict[str, Any], cap: int) -> dict[str, Any]:
    """Ramène la réponse `/live` sérialisée sous `cap` octets, en délestant les
    fenêtres affichées (console -> réseau -> détections) et en COMPTANT tout dans
    `truncation`. Mesure avec `json.dumps` par défaut (`ensure_ascii=True`) :
    Starlette sérialise en `ensure_ascii=False`, toujours plus compact, donc la
    mesure est pessimiste — jamais optimiste."""
    for _ in range(8):
        size = len(json.dumps(payload))
        if size <= cap:
            return payload
        ratio = max(0.0, (cap / size) * 0.9)
        emptied = True
        for key, counter in (("console", "console_dropped"),
                             ("network", "network_dropped"),
                             ("findings", "findings_dropped")):
            entries = payload[key]
            kept = int(len(entries) * ratio)
            if kept < len(entries):
                payload["truncation"][counter] += len(entries) - kept
                payload[key] = entries[:kept]
            emptied = emptied and not payload[key]
        if emptied:
            break
    return payload


@app.get("/live", dependencies=[Depends(require_session_secret)])
async def live() -> dict[str, Any]:
    """Panneau live (canal données séparé du flux pixels VNC, ~C4) : appels
    réseau + console capturés jusqu'ici + analyse statique du DOM COURANT (pas
    figée à la dernière `/capture`). Réutilise `analyze_html`/`compute_verdict`
    exactement comme `/capture` — aucune duplication de la mécanique.

    Bornage `[-500:]` sur le réseau ET la console : `counts` porte le compte
    total NON BORNÉ des éléments émis depuis le début de la session, y compris
    ceux que le plafond de cardinalité a écartés du tampon — la garantie est
    tenue, pas retirée de la docstring. Ce que le tampon ne contient plus est
    dit explicitement par `truncation`, jamais tu : sans ce marqueur, un POST
    d'exfiltration écarté par le plafond disparaissait sans trace côté analyste.

    La réponse entière est bornée par `OCULAR_MAX_LIVE_JSON_BYTES`, SOUS le
    plafond de lecture du web : une page hostile ne peut donc pas se rendre
    illisible et provoquer un `502` à chaque poll pour le restant de la session.

    L'analyse passe par `_live_analysis` : mémoïsée sur l'empreinte du DOM,
    exécutée dans le threadpool, et à une seule analyse en vol par empreinte."""
    page, cap = _state["page"], _state["cap"]
    empty_truncation = Truncation().model_dump(mode="json")
    if page is None:
        return {
            "network": [], "console": [], "findings": [],
            "counts": {"network": 0, "findings": 0, "console": 0},
            "truncation": empty_truncation,
            "verdict": "benign",
        }

    try:
        dom = await page.content()
    except Exception:  # pragma: no cover - dépend de l'état réel de la page
        dom = ""

    analysis = await _live_analysis(dom)
    network = cap.network if cap else []
    console = cap.console if cap else []
    forms, mailtos = analysis["forms"], analysis["mailtos"]
    # Ce que la capture a déjà écarté sur la durée de la session, plus ce que le
    # plafond de détections écarte ici : le résultat dit ce qu'il ne contient pas.
    # `getattr` : une capture qui ne tient pas de compteurs de rejet n'a, par
    # définition, rien rejeté à déclarer. Le `NetworkCapture` réel en tient
    # toujours — ce repli ne masque donc aucune troncature, il tolère un double
    # de test réduit à `.network`/`.console`.
    _truncation_of = getattr(cap, "truncation", None)
    truncation = (_truncation_of() if callable(_truncation_of) else Truncation()).model_dump(
        mode="json"
    )
    # Le plafond de détections a déjà mordu dans `_analyze_dom` (là où la
    # session RETIENT la liste) ; ici on ne fait que reporter ce qu'il a écarté.
    findings = analysis["findings"]
    truncation["findings_dropped"] += analysis["findings_dropped"]
    truncation["html_chars_dropped"] += analysis["html_chars_dropped"]
    payload = {
        "network": network[-_LIVE_WINDOW:],
        "console": console[-_LIVE_WINDOW:],
        "findings": findings,
        "forms": forms,
        "mailtos": mailtos,
        # Compte TOTAL émis depuis le début de la session : le tampon est borné,
        # pas le compteur.
        "counts": {"network": len(network) + truncation["network_dropped"],
                   "findings": len(findings) + analysis["findings_dropped"],
                   "console": len(console) + truncation["console_dropped"],
                   "forms": len(forms), "mailtos": len(mailtos)},
        "truncation": truncation,
        "verdict": analysis["verdict"],
    }
    return _fit_live_payload(payload, _max_live_json_bytes())


@app.post("/capture", dependencies=[Depends(require_session_secret)])
async def capture(body: dict[str, Any]) -> dict[str, Any]:
    page, cap = _state["page"], _state["cap"]
    if page is None:
        return JSONResponse({"error": "no active session — call /goto or /load first"}, status_code=409)

    # L'analyste peut déclarer avoir passé le Turnstile à la main (impossible à
    # introspecter de façon fiable — cf. build_capture_result). `turnstile_passed`
    # True -> turnstile_solved=True. Sinon on détecte la simple présence d'un
    # challenge CF dans le DOM courant pour un statut honnête : présent -> False
    # (challenge non déclaré passé) ; absent -> None (aucun challenge, N.A.).
    manual_passed = bool(body.get("turnstile_passed"))
    try:
        # full_page=True : capture la page ENTIÈRE (pas seulement le viewport
        # visible ~1/3). Parcours préalable (pas à pas) pour déclencher le
        # lazy-loading, PUIS attente que le réseau se calme -> la capture ne part
        # qu'une fois le scroll ET les chargements déclenchés terminés. Best-effort.
        with contextlib.suppress(Exception):
            await page.evaluate(_SCROLL_TO_LOAD_JS)
        with contextlib.suppress(Exception):
            await page.wait_for_load_state("networkidle", timeout=5000)
        png = await page.screenshot(full_page=True)
        dom = (await page.content()).encode()
        title = await page.title()
        final = page.url
        try:
            challenge_present = bool(await page.evaluate(_CF_INDICATOR_JS))
        except Exception:  # pragma: no cover - page instable
            challenge_present = False
    except Exception as exc:  # pragma: no cover - dépend de l'état réel de la page
        return JSONResponse({"error": type(exc).__name__}, status_code=502)

    if manual_passed:
        turnstile_solved, challenge = True, "cloudflare-turnstile"
    elif challenge_present:
        turnstile_solved, challenge = False, "cloudflare-turnstile"
    else:
        turnstile_solved, challenge = None, None

    result, blobs = build_capture_result(
        target=_state["target"] or "",
        kind=_state["kind"] or "url",
        png=png,
        dom=dom,
        title=title,
        final=final,
        network=cap.network if cap else [],
        html_input=_state.get("html_input", ""),
        console=cap.console if cap else [],
        turnstile_solved=turnstile_solved,
        challenge=challenge,
        truncation=cap.truncation() if cap else None,
    )
    return wrapper_payload(result, blobs)
