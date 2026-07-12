from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
from datetime import datetime, timezone

from playwright.sync_api import sync_playwright

from engine.result import (
    Artifacts,
    ConsoleEntry,
    DomInfo,
    NetworkEntry,
    OcularResult,
    Screenshot,
    StealthInfo,
)
from engine.static import analyze_html
from engine.verdict import compute_verdict
from ocular_logging import get_logger

# CRITIQUE : stdout du runner = wrapper JSON pur consommé par broker/launcher.py.
# Tous les logs partent donc sur stderr, jamais sur stdout.
log = get_logger("runner", stream=sys.stderr)


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def render_html(html: str, job_id: str, render_timeout_ms: int = 15000) -> tuple[OcularResult, dict[str, bytes]]:
    started = time.monotonic()
    log.info("job_id=%s render start html_bytes=%d", job_id, len(html.encode("utf-8")))
    network: list[NetworkEntry] = []
    console: list[ConsoleEntry] = []
    # L'analyse static ne dépend PAS du navigateur : toujours disponible, même si le rendu échoue.
    static_findings = analyze_html(html)
    screenshots: list[Screenshot] = []
    dom = DomInfo()
    artifacts = Artifacts()
    blobs: dict[str, bytes] = {}
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
            req_index: dict = {}

            def _on_request(req):
                entry = NetworkEntry(
                    url=req.url, method=req.method, resource_type=req.resource_type,
                    post_data=req.post_data,
                )
                network.append(entry)
                req_index[req] = entry

            def _on_response(resp):
                entry = req_index.get(resp.request)
                if entry is not None:
                    entry.status = resp.status

            page.on("request", _on_request)
            page.on("response", _on_response)
            page.on("console", lambda msg: console.append(ConsoleEntry(level=msg.type, text=msg.text)))
            try:
                page.set_content(html, wait_until="networkidle", timeout=render_timeout_ms)
            except Exception as exc:  # rendu partiel : on capture ce qu'on peut
                render_error = f"render timeout/error: {type(exc).__name__}"
            try:
                png = page.screenshot(full_page=True)
                ref = _sha256_ref(png)
                blobs[ref] = png
                screenshots.append(
                    Screenshot(step=0, phase="initial", image_ref=ref, viewport="1280x720")
                )
            except Exception as exc:
                log.warning("job_id=%s screenshot failed err=%s", job_id, type(exc).__name__)
            try:
                dom_html = page.content().encode()
                ref = _sha256_ref(dom_html)
                blobs[ref] = dom_html
                dom = DomInfo(title=page.title(), final_url=page.url)
                artifacts = Artifacts(dom_html_ref=ref)
            except Exception as exc:
                log.warning("job_id=%s dom capture failed err=%s", job_id, type(exc).__name__)
            browser.close()
    except Exception as exc:  # échec du navigateur lui-même : on rend quand même les findings static
        render_error = f"browser failure: {type(exc).__name__}"
        log.warning("job_id=%s browser failure err=%s", job_id, type(exc).__name__)

    if render_error:
        console.append(ConsoleEntry(level="error", text=render_error, location="ocular-runner"))

    result = OcularResult(
        job_id=job_id,
        profile="analysis",
        target="inline-html",
        input_hash=_sha256_ref(html.encode()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        screenshots=screenshots,
        network=network,
        console=console,
        dom=dom,
        static_findings=static_findings,
        verdict=compute_verdict(static_findings),
        stealth=StealthInfo(engine="chromium"),
        artifacts=artifacts,
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
    payload = {
        "result": result.model_dump(mode="json"),
        "blobs": {ref: base64.b64encode(data).decode() for ref, data in blobs.items()},
    }
    sys.stdout.write(json.dumps(payload) + "\n")


if __name__ == "__main__":
    main()
