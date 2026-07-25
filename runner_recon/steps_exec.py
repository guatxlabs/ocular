# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exécuteur de steps 3c côté runner : rejoue une séquence VALIDÉE via l'API
locator Playwright (aucun eval de contenu utilisateur), journalise, déclenche
les screenshots `capture`. La validation vit dans engine.steps (source
unique) — ce module ne revalide pas la forme des steps, il les exécute."""
import asyncio
import time

from engine.steps import MAX_WAIT_MS, redact_step

SCROLL_JS_TOP = "window.scrollTo(0, 0)"
SCROLL_JS_BOTTOM = "window.scrollTo(0, document.body.scrollHeight)"


async def _apply(page, step, screenshot_cb):
    (verb, arg), = step.items()
    if verb == "goto":
        await page.goto(arg, wait_until="networkidle")
    elif verb == "fill":
        await page.fill(arg["sel"], arg["value"])
    elif verb == "click":
        await page.click(arg)
    elif verb == "wait":
        if isinstance(arg, int):
            await page.wait_for_timeout(arg)
        else:
            await page.wait_for_selector(arg["selector"], timeout=MAX_WAIT_MS)
    elif verb == "press":
        await page.keyboard.press(arg)
    elif verb == "sleep":
        # `arg` en SECONDES (borné 0..MAX_SLEEP_S par engine.steps) -> converti en
        # ms pour Playwright. Pause fixe.
        await page.wait_for_timeout(arg * 1000)
    elif verb == "hide":
        # Sélecteur validé (_sel). JS FIXE (jamais de contenu utilisateur
        # interpolé) ; `evaluate_all` tolère 0 correspondance (best-effort,
        # n'échoue pas comme `click`).
        await page.locator(arg).evaluate_all(
            "els => els.forEach(el => { el.style.display = 'none'; })"
        )
    elif verb == "capture":
        # Forme simple (str) -> viewport ; forme étendue (dict) -> région
        # (selector) ou full_page. screenshot_cb honore selector/full_page.
        if isinstance(arg, str):
            await screenshot_cb(arg)
        else:
            await screenshot_cb(
                arg.get("label", "capture"),
                selector=arg.get("selector"),
                full_page=bool(arg.get("full_page")),
            )
    elif verb == "scroll":
        if arg == "top":
            await page.evaluate(SCROLL_JS_TOP)
        elif arg == "bottom":
            await page.evaluate(SCROLL_JS_BOTTOM)
        else:
            # `arg` est un int déjà borné par engine.steps.validate_steps
            # (0..MAX_SCROLL_PX) ; jamais une chaîne utilisateur interpolée.
            # `int(arg)` est une défense en profondeur : si un `arg` non-int
            # arrivait (validate_steps contourné), il lève AVANT tout evaluate.
            await page.evaluate(f"window.scrollTo(0, {int(arg)})")
    else:
        raise ValueError(f"verbe non exécutable: {verb}")


async def run_steps(page, steps, *, screenshot_cb, deadline: float | None = None):
    """Exécute `steps` (déjà validés par engine.steps) sur `page`.

    Retourne le journal `[{index, verb, ok, ms, step, error?}]` — `step` est
    passé par `redact_step` (valeur `fill` jamais en clair). Une erreur sur
    un step est journalisée `ok:false` puis arrête la séquence : le journal
    reflète uniquement les steps réellement tentés.

    `deadline` (optionnel) : instant absolu `time.monotonic()` au-delà duquel
    le budget wall-clock total de la séquence est épuisé (cf. spec 3c Global
    Constraint « timeout d'exécution total 120s -> arrêt + résultat partiel »).
    `None` (défaut) -> comportement STRICTEMENT inchangé (aucun garde). Avec un
    `deadline` : avant chaque step, si déjà dépassé, journalise une entrée
    `error:"timeout budget"` et arrête (même sémantique que l'arrêt-sur-erreur
    existant). De plus CHAQUE step est encadré par `asyncio.wait_for` avec le
    temps restant, pour qu'un step qui pend (ex. `click` sur un sélecteur
    absent, actionabilité Playwright ~30s) soit coupé net sans jamais dépasser
    le budget — journalisé de la même façon.
    """
    journal = []
    for i, step in enumerate(steps):
        verb = next(iter(step))
        if deadline is not None and time.monotonic() >= deadline:
            journal.append({
                "index": i,
                "verb": verb,
                "ok": False,
                "ms": 0,
                "error": "timeout budget",
                "step": redact_step(step),
            })
            break
        t0 = time.monotonic()
        try:
            if deadline is not None:
                remaining = max(deadline - t0, 0.0)
                await asyncio.wait_for(_apply(page, step, screenshot_cb), timeout=remaining)
            else:
                await _apply(page, step, screenshot_cb)
            journal.append({
                "index": i,
                "verb": verb,
                "ok": True,
                "ms": int((time.monotonic() - t0) * 1000),
                "step": redact_step(step),
            })
        except asyncio.TimeoutError:
            # Step coupé par le budget wall-clock (pas une erreur applicative) :
            # message fixe, jamais dérivé de l'exception -> aucun risque de fuite
            # d'une valeur `fill` (cf. règle ci-dessous pour les vraies erreurs).
            journal.append({
                "index": i,
                "verb": verb,
                "ok": False,
                "ms": int((time.monotonic() - t0) * 1000),
                "error": "timeout budget",
                "step": redact_step(step),
            })
            break
        except Exception as e:  # noqa: BLE001 — journalise et arrête la séquence
            # Un `fill` en échec peut échoter sa valeur dans le message
            # d'exception → ne jamais mettre `str(e)` pour ce verbe, seul le
            # type d'exception (jamais de contenu utilisateur).
            error = type(e).__name__ if verb == "fill" else str(e)[:200]
            journal.append({
                "index": i,
                "verb": verb,
                "ok": False,
                "ms": int((time.monotonic() - t0) * 1000),
                "error": error,
                "step": redact_step(step),
            })
            break
    return journal
