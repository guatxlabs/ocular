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

import base64
import hashlib
import os
import secrets
from typing import Any, Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from engine.result import DomInfo, OcularResult, StealthInfo
from engine.static import analyze_html
from engine.urlnorm import url_input_hash
from engine.verdict import compute_verdict
from engine.wrapper import NetworkCapture, ResultBuilder, sha256_ref  # noqa: F401  (sha256_ref réutilisé ici)

app = FastAPI()


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
_state: dict[str, Any] = {"cm": None, "page": None, "cap": None, "target": None, "kind": None}


def build_capture_result(
    target: str,
    kind: Literal["url", "html"],
    png: bytes,
    dom: bytes,
    title: str,
    final: str,
    network: list[dict[str, Any]],
    html_input: str = "",
) -> tuple[OcularResult, dict[str, bytes]]:
    """Logique pure (aucune dépendance Camoufox) : compose l'`OcularResult`
    à partir de données déjà capturées par le pilotage du navigateur. Miroir
    de `runner_recon.capture.build_result`, adapté aux deux origines possibles
    d'une session interactive : navigation (`kind="url"`, profil `capture`,
    input_hash dérivé de l'URL normalisée) ou injection HTML directe
    (`kind="html"`, profil `analysis`, input_hash dérivé du HTML fourni —
    même convention que `runner_analysis/render.py`)."""
    builder = ResultBuilder()
    if png:
        builder.add_screenshot(0, "interactive", png)
    builder.set_dom(dom)

    findings = analyze_html(dom.decode("utf-8", "replace")) if dom else []

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
        dom_info=DomInfo(title=title, final_url=final),
        stealth=StealthInfo(engine="camoufox"),
        static_findings=findings,
        network=network,
    )


async def _ensure_browser() -> None:
    if _state["page"] is not None:
        return
    from camoufox.async_api import AsyncCamoufox

    cm = AsyncCamoufox(headless=False, os="linux", humanize=0.3, i_know_what_im_doing=True)
    ctx = await cm.__aenter__()
    page = await ctx.new_page()
    cap = NetworkCapture()
    cap.attach(page)
    _state.update(cm=cm, page=page, cap=cap)


@app.get("/health")
async def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/goto", dependencies=[Depends(require_session_secret)])
async def goto(body: dict[str, Any]) -> dict[str, Any]:
    await _ensure_browser()
    _state["target"], _state["kind"] = body["url"], "url"
    try:
        await _state["page"].goto(body["url"], wait_until="domcontentloaded", timeout=45000)
    except Exception as exc:  # pragma: no cover - dépend du réseau/cible réelle
        return JSONResponse({"error": type(exc).__name__}, status_code=502)
    return {"ok": True}


@app.post("/load", dependencies=[Depends(require_session_secret)])
async def load(body: dict[str, Any]) -> dict[str, Any]:
    await _ensure_browser()
    _state["target"], _state["kind"] = "inline-html", "html"
    _state["html_input"] = body.get("html", "")
    try:
        await _state["page"].set_content(body["html"], wait_until="domcontentloaded", timeout=45000)
    except Exception as exc:  # pragma: no cover - dépend du contenu réel
        return JSONResponse({"error": type(exc).__name__}, status_code=502)
    return {"ok": True}


@app.get("/live", dependencies=[Depends(require_session_secret)])
async def live() -> dict[str, Any]:
    """Panneau live (canal données séparé du flux pixels VNC, ~C4) : appels
    réseau capturés jusqu'ici + analyse statique du DOM COURANT (pas figée à
    la dernière `/capture`). Réutilise `analyze_html`/`compute_verdict`
    exactement comme `/capture` — aucune duplication de la mécanique.
    Bornage `[-500:]` sur le réseau (charge/DoS ; le compte total non borné
    reste dans `counts`)."""
    page, cap = _state["page"], _state["cap"]
    if page is None:
        return {"network": [], "findings": [], "counts": {"network": 0, "findings": 0}, "verdict": "benign"}

    try:
        dom = await page.content()
    except Exception:  # pragma: no cover - dépend de l'état réel de la page
        dom = ""

    findings = analyze_html(dom)
    network = cap.network if cap else []
    return {
        "network": network[-500:],
        "findings": [f.model_dump(mode="json") for f in findings],
        "counts": {"network": len(network), "findings": len(findings)},
        "verdict": compute_verdict(findings),
    }


@app.post("/capture", dependencies=[Depends(require_session_secret)])
async def capture(body: dict[str, Any]) -> dict[str, Any]:
    page, cap = _state["page"], _state["cap"]
    if page is None:
        return JSONResponse({"error": "no active session — call /goto or /load first"}, status_code=409)

    try:
        png = await page.screenshot(full_page=False)
        dom = (await page.content()).encode()
        title = await page.title()
        final = page.url
    except Exception as exc:  # pragma: no cover - dépend de l'état réel de la page
        return JSONResponse({"error": type(exc).__name__}, status_code=502)

    result, blobs = build_capture_result(
        target=_state["target"] or "",
        kind=_state["kind"] or "url",
        png=png,
        dom=dom,
        title=title,
        final=final,
        network=cap.network if cap else [],
        html_input=_state.get("html_input", ""),
    )
    return {
        "result": result.model_dump(mode="json"),
        "blobs": {ref: base64.b64encode(data).decode() for ref, data in blobs.items()},
    }
