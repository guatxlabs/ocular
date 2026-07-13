"""Exécuteur de steps 3c côté runner : rejoue une séquence VALIDÉE via l'API
locator Playwright (aucun eval de contenu utilisateur), journalise, déclenche
les screenshots `capture`. La validation vit dans engine.steps (source
unique) — ce module ne revalide pas la forme des steps, il les exécute."""
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
    elif verb == "capture":
        await screenshot_cb(arg)
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


async def run_steps(page, steps, *, screenshot_cb):
    """Exécute `steps` (déjà validés par engine.steps) sur `page`.

    Retourne le journal `[{index, verb, ok, ms, step, error?}]` — `step` est
    passé par `redact_step` (valeur `fill` jamais en clair). Une erreur sur
    un step est journalisée `ok:false` puis arrête la séquence : le journal
    reflète uniquement les steps réellement tentés.
    """
    journal = []
    for i, step in enumerate(steps):
        verb = next(iter(step))
        t0 = time.monotonic()
        try:
            await _apply(page, step, screenshot_cb)
            journal.append({
                "index": i,
                "verb": verb,
                "ok": True,
                "ms": int((time.monotonic() - t0) * 1000),
                "step": redact_step(step),
            })
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
