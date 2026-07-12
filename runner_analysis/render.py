from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone

from playwright.sync_api import sync_playwright

from engine.result import (
    ConsoleEntry,
    DomInfo,
    NetworkEntry,
    OcularResult,
    Screenshot,
    StealthInfo,
)
from engine.static import analyze_html


def _sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def render_html(html: str, job_id: str) -> OcularResult:
    network: list[NetworkEntry] = []
    console: list[ConsoleEntry] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])  # sandbox assuré par le conteneur
        context = browser.new_context(viewport={"width": 1280, "height": 720})
        page = context.new_page()
        page.on(
            "request",
            lambda req: network.append(
                NetworkEntry(
                    url=req.url, method=req.method, resource_type=req.resource_type,
                    post_data=req.post_data,
                )
            ),
        )
        page.on(
            "console",
            lambda msg: console.append(ConsoleEntry(level=msg.type, text=msg.text)),
        )
        page.set_content(html, wait_until="networkidle", timeout=15000)
        png = page.screenshot(full_page=True)
        title = page.title()
        final_url = page.url
        dom_html = page.content().encode()
        browser.close()

    return OcularResult(
        job_id=job_id,
        profile="analysis",
        target="inline-html",
        timestamp=datetime.now(timezone.utc).isoformat(),
        verdict="unknown",
        screenshots=[Screenshot(step=0, phase="initial", image_ref=_sha256_ref(png), viewport="1280x720")],
        network=network,
        console=console,
        dom=DomInfo(title=title, final_url=final_url),
        static_findings=analyze_html(html),
        stealth=StealthInfo(engine="chromium"),
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--job-id", required=True)
    args = ap.parse_args()
    html = sys.stdin.read()
    result = render_html(html, args.job_id)
    sys.stdout.write(result.model_dump_json())


if __name__ == "__main__":
    main()
