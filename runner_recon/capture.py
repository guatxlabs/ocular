from __future__ import annotations

import argparse
import asyncio
import sys

from engine.result import DomInfo, OcularResult, StealthInfo
from engine.static import analyze_html
from engine.urlnorm import url_input_hash
from engine.verdict import compute_verdict
from engine.wrapper import NetworkCapture, ResultBuilder, emit_wrapper
from ocular_logging import get_logger

# CRITIQUE : comme runner_analysis/render.py — stdout = wrapper JSON pur consommé
# par broker/launcher.py. Tous les logs partent sur stderr.
log = get_logger("runner-recon", stream=sys.stderr)


def build_result(
    url: str,
    screenshots: list[tuple[int, str, bytes]],
    network: list[dict],
    console: list[dict],
    dom_html: bytes,
    title: str,
    final_url: str,
    turnstile_solved: bool,
) -> tuple[OcularResult, dict[str, bytes]]:
    """Logique pure (aucune dépendance navigateur) : compose l'`OcularResult`
    profil `capture` à partir de données déjà capturées. Testable directement
    sans Camoufox — c'est `capture_url` qui pilote le navigateur et lui fournit
    ces données."""
    builder = ResultBuilder()
    for step, phase, png in screenshots:
        builder.add_screenshot(step, phase, png)
    builder.set_dom(dom_html)

    findings = analyze_html(dom_html.decode("utf-8", "replace")) if dom_html else []

    return builder.build(
        job_id="",
        profile="capture",
        target=url,
        input_hash=url_input_hash(url),
        verdict=compute_verdict(findings),
        dom_info=DomInfo(title=title, final_url=final_url),
        stealth=StealthInfo(engine="camoufox", turnstile_solved=turnstile_solved),
        static_findings=findings,
        network=network,
        console=console,
    )


async def capture_url(url: str, timeout_ms: int = 45000) -> tuple[OcularResult, dict[str, bytes]]:
    """Pilote Camoufox (anti-detect Firefox headed, Xvfb) : navigue vers `url`,
    tente de résoudre un Turnstile interactif via la vision (template matching)
    + clic OS xdotool (cf. runner_recon/vision.py, porté depuis
    YesWeHack/toolkit/browser-automation), capture screenshots/réseau/DOM, puis
    délègue l'assemblage du résultat à `build_result`."""
    import vision  # copié dans runner_recon/, sur le PYTHONPATH du conteneur
    from camoufox.async_api import AsyncCamoufox

    capture = NetworkCapture()
    screenshots: list[tuple[int, str, bytes]] = []
    turnstile_solved = False
    dom_html, title, final_url = b"", "", url

    async with AsyncCamoufox(
        headless=False, os="linux", humanize=0.3, i_know_what_im_doing=True
    ) as ctx:
        page = await ctx.new_page()
        capture.attach(page)

        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:
            capture.console.append({"level": "error", "text": f"goto: {type(exc).__name__}"})

        png0 = await page.screenshot(full_page=False)
        screenshots.append((0, "initial", png0))

        # Turnstile : détection vision (template matching) + clic OS xdotool
        try:
            det = vision.detect(vision.png_to_bgr(png0), strategy="turnstile")
            if det is not None:
                x, y = det[0], det[1]
                await vision.human_click_xdotool(x, y)
                await asyncio.sleep(4)
                png1 = await page.screenshot(full_page=False)
                screenshots.append((1, "post-turnstile", png1))
                turnstile_solved = True
        except Exception as exc:
            capture.console.append({"level": "warning", "text": f"turnstile: {type(exc).__name__}"})

        try:
            dom_html = (await page.content()).encode()
            title = await page.title()
            final_url = page.url
        except Exception as exc:
            log.warning("url=%s dom capture failed err=%s", url, type(exc).__name__)

    return build_result(
        url, screenshots, capture.network, capture.console, dom_html, title,
        final_url, turnstile_solved,
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    args = ap.parse_args()
    # CRITIQUE (résilience) : les pages visitées sont hostiles (Cloudflare/Auth0)
    # et peuvent faire mourir le driver/navigateur Camoufox en cours de capture
    # (ex. "Connection closed"). On n'a plus de patch driver pour absorber ça
    # (cf. Dockerfile) : toute exception non catchée par `capture_url` doit
    # quand même produire un wrapper `OcularResult` valide sur stdout, sinon le
    # broker/launcher.py qui lit stdout reste sans résultat exploitable.
    try:
        result, blobs = asyncio.run(capture_url(args.url))
    except Exception as exc:
        log.warning("url=%s capture failed err=%s", args.url, type(exc).__name__)
        result, blobs = build_result(
            url=args.url,
            screenshots=[],
            network=[],
            console=[{"level": "error", "text": f"capture failed: {type(exc).__name__}"}],
            dom_html=b"",
            title="",
            final_url=args.url,
            turnstile_solved=False,
        )
    emit_wrapper(result, blobs)


if __name__ == "__main__":
    main()
