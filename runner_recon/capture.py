from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

from engine.result import DomInfo, DynamicStep, OcularResult, StealthInfo
from engine.static import analyze_html
from engine.steps import validate_steps
from engine.urlnorm import url_input_hash
from engine.verdict import compute_verdict
from engine.wrapper import NetworkCapture, ResultBuilder, emit_wrapper
from ocular_logging import get_logger
from runner_recon.steps_exec import run_steps

# CRITIQUE : comme runner_analysis/render.py — stdout = wrapper JSON pur consommé
# par broker/launcher.py. Tous les logs partent sur stderr.
log = get_logger("runner-recon", stream=sys.stderr)

# Budget wall-clock TOTAL de l'exécution des steps scriptés (3c Global
# Constraint : « timeout d'exécution total 120s -> arrêt + résultat partiel »).
# Séparé du timeout conteneur broker (`broker/launcher.py:_SCRIPTED_TIMEOUT`,
# 180s) : ce budget est appliqué PAR le runner (via `run_steps(deadline=...)`)
# pour émettre un résultat partiel AVANT que le broker ne `docker kill` le
# conteneur — la marge de 60s couvre le démarrage Camoufox + l'extraction DOM
# finale après l'arrêt du budget.
SCRIPTED_EXEC_TIMEOUT_S = 120


def _scripted_deadline() -> float:
    """Instant absolu `time.monotonic()` au-delà duquel le budget wall-clock
    total de la séquence de steps est épuisé. Fonction pure, isolée pour être
    testable sans navigateur (cf. tests/test_capture_scripted_logic.py)."""
    return time.monotonic() + SCRIPTED_EXEC_TIMEOUT_S


def _analyze(dom_html: bytes) -> list:
    """Factorisé entre le chemin 3a (`build_result`) et le chemin scripté 3c
    (`capture_scripted`) — même calcul de findings statiques à partir du DOM
    capturé, une seule implémentation."""
    return analyze_html(dom_html.decode("utf-8", "replace")) if dom_html else []


def journal_to_dynamic_steps(
    journal: list[dict[str, Any]], capture_refs: list[str]
) -> list[DynamicStep]:
    """Traduit le journal `run_steps` (déjà redigé — chaque entrée porte
    `step` passé par `engine.steps.redact_step`, jamais de valeur `fill` en
    clair) en `list[DynamicStep]` — le schéma EXISTANT de `OcularResult`
    (pas de nouveau champ `actions`, cf. plan 3c). Fonction pure, testable
    sans navigateur.

    `action` : libellé lisible du step (JSON compact du step redigé).
    `screenshot_ref` : renseigné UNIQUEMENT pour un step `capture`, associé
    PAR ORDRE (Nième `capture` du journal <-> Nième ref) et NON par label —
    `screenshot_cb` est appelé une fois par `capture` dans l'ordre et empile
    les refs dans une liste ordonnée (cf. `capture_scripted`). Associer par
    label écraserait la clé pour deux captures homonymes -> les deux
    `DynamicStep` pointeraient le même (dernier) screenshot : preuve
    forensique mal associée. Un `capture` en échec (ex. screenshot qui lève,
    toujours le dernier step puisque l'échec arrête la séquence) n'a produit
    aucune ref -> `screenshot_ref=None`.
    `ok`/`duration_ms`/`error` : issus tels quels du journal.
    """
    refs_iter = iter(capture_refs)
    out: list[DynamicStep] = []
    for entry in journal:
        step = entry["step"]
        verb = next(iter(step))
        ref = next(refs_iter, None) if verb == "capture" else None
        out.append(
            DynamicStep(
                action=json.dumps(step, sort_keys=True, ensure_ascii=False),
                screenshot_ref=ref,
                ok=entry["ok"],
                duration_ms=entry.get("ms"),
                error=entry.get("error"),
            )
        )
    return out


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

    findings = _analyze(dom_html)

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


async def _goto_with_fallback(page: Any, url: str, timeout_ms: int, console: list[dict]) -> None:
    """Navigue `page` vers `url` ; si CETTE PREMIÈRE tentative lève ET que le
    schéma est `https`, retente UNE SEULE fois avec le même hôte/chemin/query
    en `http://` (jamais de boucle : au plus un fallback). Journalise l'échec
    initial (`console` "error", comme avant — inchangé) puis, si le fallback
    réussit, un `console` "warning" `scheme-fallback https->http` (jamais
    l'URL en clair). Un `goto` déjà en `http` qui échoue n'a PAS de fallback
    (il n'y a pas de schéma plus permissif à essayer).

    Factorisé entre `capture_url` (chemin 3a) et `capture_scripted` (chemin
    3c) : même politique de résilience réseau, une seule implémentation.
    Pas de valeur de retour : `page` porte déjà l'état de navigation (succès
    ou dernier échec) que les appelants lisent ensuite via `page.url` /
    `page.content()` / `page.title()`, exactement comme avant l'introduction
    du fallback."""
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        return
    except Exception as exc:
        console.append({"level": "error", "text": f"goto: {type(exc).__name__}"})

    scheme = urlsplit(url).scheme.lower()
    if scheme != "https":
        return

    parts = urlsplit(url)
    fallback_url = urlunsplit(("http", parts.netloc, parts.path, parts.query, parts.fragment))

    try:
        await page.goto(fallback_url, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception as exc:
        console.append({"level": "error", "text": f"goto: {type(exc).__name__}"})
        return

    console.append({"level": "warning", "text": "scheme-fallback https->http"})


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

        await _goto_with_fallback(page, url, timeout_ms, capture.console)

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


async def capture_scripted(
    url: str, steps: list, timeout_ms: int = 45000
) -> tuple[OcularResult, dict[str, bytes]]:
    """Mode scripté (3c) : rejoue `steps` sur `url` (même pilotage Camoufox
    headed que `capture_url`, NetworkCapture armé de la même façon) pour
    révéler les appels réseau post-interaction (ex. un `fetch` déclenché par
    un clic). Assemble l'`OcularResult` via `ResultBuilder`/`DynamicStep`
    déjà existants — aucune nouvelle structure de résultat.

    DÉCISION D'ARCHI (tranchée) : `url` (top-level) N'EST PAS re-SSRF-validée
    ici. Source unique de validation SSRF pour l'URL de soumission :
    `engine.ssrf.validate_capture_url`, appelée côté web à la soumission du
    job (Task 5 du plan 3c) — ce runner ne reçoit `url` QUE via le broker de
    confiance (jamais d'entrée utilisateur directe sur ce process). En
    revanche `validate_steps(steps)` ci-dessous SSRF-valide bien CHAQUE step
    `goto` (la seule navigation réellement pilotée par l'utilisateur dans le
    DSL) — défense en profondeur, pas duplication de la validation `url`. Ce
    choix est aussi ce qui permet à la fixture d'intégration privée (réseau
    docker dédié, IP non routable publiquement) de fonctionner : re-valider
    `url` la rejetterait à tort alors qu'elle vient déjà d'une source de
    confiance.
    """
    # défense en profondeur AVANT tout lancement navigateur : des steps
    # invalides (verbe hors allowlist, `goto` SSRF, bornes) lèvent ici, sans
    # payer le coût d'un démarrage Camoufox — et l'exception remonte à `main()`
    # qui émet quand même un wrapper valide (chemin résilient).
    validated_steps = validate_steps(steps)  # cf. docstring (SSRF des `goto`)
    # Budget wall-clock TOTAL démarré ICI (avant le lancement Camoufox, qui a
    # lui-même un coût non négligeable) -> `run_steps` reçoit un `deadline`
    # absolu et coupe la séquence net (résultat partiel) avant que le broker
    # ne tue le conteneur (cf. SCRIPTED_EXEC_TIMEOUT_S ci-dessus).
    deadline = _scripted_deadline()

    from camoufox.async_api import AsyncCamoufox

    capture = NetworkCapture()
    builder = ResultBuilder()
    # refs des screenshots `capture` empilées DANS L'ORDRE des appels (une par
    # step `capture`) — association par ordre, pas par label (cf.
    # journal_to_dynamic_steps).
    capture_refs: list[str] = []
    shot_idx = 0
    page = None  # affecté dans le `async with` ci-dessous, capturé par le closure

    async def screenshot_cb(label: str) -> None:
        nonlocal shot_idx
        png = await page.screenshot(full_page=False)
        ref = builder.add_screenshot(shot_idx, label, png)
        capture_refs.append(ref)
        shot_idx += 1

    dom_html, title, final_url = b"", "", url

    async with AsyncCamoufox(
        headless=False, os="linux", humanize=0.3, i_know_what_im_doing=True
    ) as ctx:
        page = await ctx.new_page()
        capture.attach(page)

        await _goto_with_fallback(page, url, timeout_ms, capture.console)

        journal = await run_steps(
            page, validated_steps, screenshot_cb=screenshot_cb, deadline=deadline
        )
        if journal and journal[-1].get("error") == "timeout budget":
            # Note console (pas une exception) : le résultat partiel (journal +
            # screenshots déjà pris) est quand même émis ci-dessous — jamais de
            # stdout vide sur dépassement de budget.
            capture.console.append({
                "level": "warning",
                "text": f"scripted execution: budget de {SCRIPTED_EXEC_TIMEOUT_S}s atteint, steps restants abandonnés",
            })

        try:
            dom_html = (await page.content()).encode()
            title = await page.title()
            final_url = page.url
        except Exception as exc:
            log.warning("url=%s scripted dom capture failed err=%s", url, type(exc).__name__)

    builder.set_dom(dom_html)
    findings = _analyze(dom_html)

    return builder.build(
        job_id="",
        profile="capture",
        target=url,
        input_hash=url_input_hash(url),
        verdict=compute_verdict(findings),
        dom_info=DomInfo(title=title, final_url=final_url),
        stealth=StealthInfo(engine="camoufox", turnstile_solved=False),
        static_findings=findings,
        network=capture.network,
        console=capture.console,
        dynamic_steps=journal_to_dynamic_steps(journal, capture_refs),
    )


def _read_stdin_payload() -> Optional[dict[str, Any]]:
    """Lit un éventuel job scripté JSON `{"url":..., "steps":[...]}` sur
    stdin. Retourne `None` si stdin est vide/absente/non-scripté — dans ce cas
    le chemin 3a (`--url`) prend le relais, STRICTEMENT inchangé (aucun step).

    `sys.stdin.isatty()` : en CLI interactive (terminal), `sys.stdin.read()`
    bloquerait sur EOF ; on saute donc la lecture et on bascule sur le chemin
    3a argparse. Le chemin de production (broker sans `-i`, stdin fermé) n'est
    pas un TTY -> lecture normale. La lecture reste protégée par `try/except`
    (isatty ET read) : certains contextes n'ont aucun stdin exploitable (ex.
    la capture par défaut de pytest hors `-s`) — ce n'est pas une erreur de
    payload, juste l'absence de stdin.

    LÈVE `ValueError` (anti double-fault) quand stdin porte CLAIREMENT un job
    scripté (dict avec les clés `url` ET `steps`) mais avec des TYPES
    invalides (`url` non-str, `steps` non-list). Garantit ainsi que si cette
    fonction RETOURNE un payload, `url` est TOUJOURS un str et `steps` une
    list — le fallback résilient de `main()` (`build_result(url=...)`) ne peut
    donc plus re-crasher sur un `url` None (double-fault -> zéro octet stdout,
    interdit par le contrat runner). `main()` traite ce `ValueError` comme un
    payload scripté invalide et émet quand même un wrapper valide."""
    try:
        if sys.stdin.isatty():
            return None
        raw = sys.stdin.read()
    except Exception:
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or "url" not in payload or "steps" not in payload:
        return None
    # Dès ici stdin contient clairement un job scripté : valider les types
    # (voir docstring — garantie "url toujours str dans le chemin scripté").
    if not isinstance(payload["url"], str):
        raise ValueError("scripted payload: 'url' doit être une chaîne")
    if not isinstance(payload["steps"], list):
        raise ValueError("scripted payload: 'steps' doit être une liste")
    return payload


def _error_wrapper(url: str, text: str) -> tuple[OcularResult, dict[str, bytes]]:
    """Wrapper `OcularResult` minimal mais VALIDE, émis quand la capture ne
    peut pas produire de résultat exploitable (page hostile, driver Camoufox
    mort, payload scripté malformé, steps invalides). Contrat runner : stdout
    ne doit JAMAIS être vide, sinon broker/launcher.py perd tout résultat.
    `url` DOIT être un str (garanti par les appelants ; `""` si inconnu)."""
    return build_result(
        url=url,
        screenshots=[],
        network=[],
        console=[{"level": "error", "text": text}],
        dom_html=b"",
        title="",
        final_url=url,
        turnstile_solved=False,
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    # --url reste l'entrée du chemin 3a (one-shot classique). En mode
    # scripté (3c) l'URL vient du JSON stdin {"url","steps"} (jamais d'un
    # argument CLI/env — pas de fuite dans `docker inspect`) : optionnel ici,
    # re-imposé plus bas seulement si aucun job scripté n'est reçu.
    ap.add_argument("--url", required=False, default=None)
    args = ap.parse_args()

    try:
        payload = _read_stdin_payload()
    except ValueError as exc:
        # stdin porte un job scripté mais malformé (types url/steps invalides).
        # Résilience : émettre quand même un wrapper valide (jamais zéro octet,
        # jamais de bascule à tort sur le chemin 3a). `url` inconnu -> "".
        log.warning("scripted payload invalide err=%s", exc)
        emit_wrapper(*_error_wrapper("", f"scripted payload invalide: {exc}"))
        return

    if payload is not None:
        # `url` garanti str, `steps` garanti list par `_read_stdin_payload`.
        url = payload["url"]
        steps = payload["steps"]
        # CRITIQUE (résilience, même contrat que le chemin 3a ci-dessous) :
        # toute exception (page hostile, driver Camoufox mort en cours de
        # route, steps invalides détectés par validate_steps en défense en
        # profondeur, ...) doit quand même produire un wrapper `OcularResult`
        # valide sur stdout.
        try:
            result, blobs = asyncio.run(capture_scripted(url, steps))
        except Exception as exc:
            log.warning("url=%s scripted capture failed err=%s", url, type(exc).__name__)
            result, blobs = _error_wrapper(url, f"capture failed: {type(exc).__name__}")
        emit_wrapper(result, blobs)
        return

    # Chemin 3a strictement inchangé : sans job scripté valide sur stdin,
    # --url reste requis (comme avant l'introduction du mode scripté).
    if args.url is None:
        ap.error("--url requis (aucun job scripté valide reçu sur stdin)")

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
        result, blobs = _error_wrapper(args.url, f"capture failed: {type(exc).__name__}")
    emit_wrapper(result, blobs)


if __name__ == "__main__":
    main()
