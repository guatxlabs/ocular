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
import logging
import os
import secrets
from typing import Any, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from engine.browser_js import CF_INDICATOR_JS, SCROLL_TO_LOAD_JS
from engine.egress_policy import hardened_launch_kwargs, maybe_start_egress_guard
from engine.result import DomInfo, OcularResult, StealthInfo
from engine.static import analyze_html, extract_forms, extract_mailtos
from engine.urlnorm import url_input_hash
from engine.verdict import compute_verdict
from engine.wrapper import NetworkCapture, ResultBuilder, wrapper_payload


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
) -> tuple[OcularResult, dict[str, bytes]]:
    """Logique pure (aucune dépendance Camoufox) : compose l'`OcularResult`
    à partir de données déjà capturées par le pilotage du navigateur. Miroir
    de `runner_recon.capture.build_result`, adapté aux deux origines possibles
    d'une session interactive : navigation (`kind="url"`, profil `capture`,
    input_hash dérivé de l'URL normalisée) ou injection HTML directe
    (`kind="html"`, profil `analysis`, input_hash dérivé du HTML fourni —
    même convention que `runner_analysis/render.py`).

    `console` (audit parité 3b/3c vs `runner_analysis/render.py`) : le journal
    console accumulé par `NetworkCapture.attach` sur la page de session (même
    mécanique que le tier statique) — sans ce paramètre, le résultat interactif
    n'était PAS un sur-ensemble du résultat statique (`OcularResult.console`
    restait toujours vide côté interactif)."""
    builder = ResultBuilder()
    if png:
        builder.add_screenshot(0, "interactive", png)
    builder.set_dom(dom)

    dom_str = dom.decode("utf-8", "replace") if dom else ""
    findings = analyze_html(dom_str) if dom else []

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
        static_findings=findings,
        network=network,
        console=console,
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
    # engine.egress_policy — source unique partagée avec le tier batch (audit 3m).
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
    cap = NetworkCapture()
    cap.attach(page)
    _state.update(cm=cm, page=page, cap=cap)
    # Le plein écran de la fenêtre est assuré par matchbox-window-manager, démarré
    # dans entrypoint_vnc.sh (kiosk) : la fenêtre couvre exactement l'Xvfb 1280x720,
    # plus de crop bas/droite. Rien à faire ici.


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


@app.get("/live", dependencies=[Depends(require_session_secret)])
async def live() -> dict[str, Any]:
    """Panneau live (canal données séparé du flux pixels VNC, ~C4) : appels
    réseau + console capturés jusqu'ici + analyse statique du DOM COURANT (pas
    figée à la dernière `/capture`). Réutilise `analyze_html`/`compute_verdict`
    exactement comme `/capture` — aucune duplication de la mécanique.
    Bornage `[-500:]` sur le réseau ET la console (charge/DoS ; le compte
    total non borné reste dans `counts`)."""
    page, cap = _state["page"], _state["cap"]
    if page is None:
        return {
            "network": [], "console": [], "findings": [],
            "counts": {"network": 0, "findings": 0, "console": 0},
            "verdict": "benign",
        }

    try:
        dom = await page.content()
    except Exception:  # pragma: no cover - dépend de l'état réel de la page
        dom = ""

    findings = analyze_html(dom)
    network = cap.network if cap else []
    console = cap.console if cap else []
    forms = extract_forms(dom)
    mailtos = extract_mailtos(dom)
    return {
        "network": network[-500:],
        "console": console[-500:],
        "findings": [f.model_dump(mode="json") for f in findings],
        "forms": forms,
        "mailtos": mailtos,
        "counts": {"network": len(network), "findings": len(findings), "console": len(console),
                   "forms": len(forms), "mailtos": len(mailtos)},
        "verdict": compute_verdict(findings),
    }


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
    )
    return wrapper_payload(result, blobs)
