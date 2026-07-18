from __future__ import annotations

import argparse
import sys
import time

from playwright.sync_api import sync_playwright

from engine.result import DomInfo, OcularResult, StealthInfo
from engine.static import analyze_html, extract_forms, extract_mailtos
from engine.verdict import compute_verdict
from engine.wrapper import NetworkCapture, ResultBuilder, emit_wrapper, sha256_ref
from ocular_logging import get_logger

# CRITIQUE : stdout du runner = wrapper JSON pur consommé par broker/launcher.py.
# Tous les logs partent donc sur stderr, jamais sur stdout — garanti par
# `ocular_logging.get_logger` lui-même, qui n'expose PLUS de paramètre `stream`
# (le flux n'est pas un choix d'appelant : cf. sa docstring).
log = get_logger("runner")


def render_html(html: str, job_id: str, render_timeout_ms: int = 15000) -> tuple[OcularResult, dict[str, bytes]]:
    started = time.monotonic()
    log.info("job_id=%s render start html_bytes=%d", job_id, len(html.encode("utf-8")))
    # L'analyse static ne dépend PAS du navigateur : toujours disponible, même si le rendu échoue.
    static_findings = analyze_html(html)
    capture = NetworkCapture()
    builder = ResultBuilder()
    dom = DomInfo()
    render_error: str | None = None

    try:
        with sync_playwright() as p:
            # isolation réseau assurée par le conteneur (--network none) ; on désactive la
            # same-origin policy pour que les réponses réseau (y compris cross-origin) soient
            # bien remontées via l'event "response" (sinon CORS masque le status même quand le
            # réseau est réellement joignable, cf. task-6-report.md)
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-web-security"])
            context = browser.new_context(viewport={"width": 1280, "height": 720})
            page = context.new_page()
            capture.attach(page)
            try:
                page.set_content(html, wait_until="networkidle", timeout=render_timeout_ms)
            except Exception as exc:  # rendu partiel : on capture ce qu'on peut
                render_error = f"render timeout/error: {type(exc).__name__}"
            try:
                png = page.screenshot(full_page=True)
                builder.add_screenshot(0, "initial", png)
            except Exception as exc:
                log.warning("job_id=%s screenshot failed err=%s", job_id, type(exc).__name__)
            try:
                dom_html = page.content().encode()
                builder.set_dom(dom_html)
                dom_str = dom_html.decode("utf-8", "replace")
                dom = DomInfo(
                    title=page.title(), final_url=page.url,
                    forms=extract_forms(dom_str), mailtos=extract_mailtos(dom_str),
                )
            except Exception as exc:
                log.warning("job_id=%s dom capture failed err=%s", job_id, type(exc).__name__)
            browser.close()
    except Exception as exc:  # échec du navigateur lui-même : on rend quand même les findings static
        render_error = f"browser failure: {type(exc).__name__}"
        log.warning("job_id=%s browser failure err=%s", job_id, type(exc).__name__)

    if render_error:
        capture.console.append({"level": "error", "text": render_error, "location": "ocular-runner"})

    result, blobs = builder.build(
        job_id=job_id,
        profile="analysis",
        target="inline-html",
        input_hash=sha256_ref(html.encode()),
        verdict=compute_verdict(static_findings),
        dom_info=dom,
        stealth=StealthInfo(engine="chromium"),
        static_findings=static_findings,
        network=capture.network,
        console=capture.console,
    )
    duration_ms = int((time.monotonic() - started) * 1000)
    log.info("job_id=%s render done verdict=%s duration_ms=%d",
              job_id, result.verdict, duration_ms)
    return result, blobs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    args = ap.parse_args()
    html = sys.stdin.read()
    result, blobs = render_html(html, args.job_id)
    emit_wrapper(result, blobs)


if __name__ == "__main__":
    main()
