"""Exécuteur de steps 3c (runner) — page Playwright mockée, pas de vrai navigateur.

Vérifie : dispatch de chaque verbe vers l'API locator, journal redigé (jamais
la valeur `fill` en clair), arrêt de la séquence à la première erreur, et que
le seul `evaluate` est le JS de scroll constant (jamais de contenu utilisateur
interpolé en dehors d'un int contrôlé).

Couvre aussi le budget wall-clock total (`deadline`, cf. spec 3c Global
Constraint « timeout d'exécution total 120s -> arrêt + résultat partiel ») :
sans `deadline`, comportement strictement inchangé ; avec `deadline`, un step
qui pend est coupé net (`asyncio.wait_for`) et journalisé, et un budget déjà
dépassé avant le premier step arrête la séquence sans rien exécuter.
"""
import asyncio
import time

import pytest

from runner_recon.steps_exec import run_steps


class FakePage:
    def __init__(self):
        self.calls = []
        self.keyboard = self

    async def goto(self, url, **k):
        self.calls.append(("goto", url))

    async def fill(self, sel, val, **k):
        self.calls.append(("fill", sel, val))

    async def click(self, sel, **k):
        self.calls.append(("click", sel))

    async def wait_for_timeout(self, ms):
        self.calls.append(("wait_ms", ms))

    async def wait_for_selector(self, sel, **k):
        self.calls.append(("wait_sel", sel))

    async def press(self, key):
        self.calls.append(("press", key))

    async def evaluate(self, js):
        self.calls.append(("eval", js))

    async def screenshot(self, **k):
        return b"PNG"


@pytest.mark.asyncio
async def test_run_steps_dispatches_each_verb():
    page = FakePage()
    shots = []

    async def cb(label):
        shots.append(label)

    steps = [
        {"fill": {"sel": "i", "value": "secret"}},
        {"click": "#b"},
        {"wait": 500},
        {"press": "Enter"},
        {"capture": "fin"},
    ]
    journal = await run_steps(page, steps, screenshot_cb=cb)
    assert ("fill", "i", "secret") in page.calls
    assert ("click", "#b") in page.calls
    assert ("wait_ms", 500) in page.calls
    assert ("press", "Enter") in page.calls
    assert shots == ["fin"]
    # valeur redigée dans le journal
    fill_entry = next(e for e in journal if e["verb"] == "fill")
    assert "secret" not in str(fill_entry)
    assert fill_entry["step"] == {"fill": {"sel": "i", "value": "***"}}
    assert all(e["ok"] for e in journal)
    assert [e["index"] for e in journal] == [0, 1, 2, 3, 4]


@pytest.mark.asyncio
async def test_run_steps_stops_on_error():
    class Boom(FakePage):
        async def click(self, sel, **k):
            raise RuntimeError("no element")

    page = Boom()

    async def cb(label):
        pass

    journal = await run_steps(
        page,
        [{"click": "#x"}, {"fill": {"sel": "i", "value": "v"}}],
        screenshot_cb=cb,
    )
    assert journal[0]["ok"] is False and "no element" in journal[0]["error"]
    assert len(journal) == 1  # arrêt après l'échec


@pytest.mark.asyncio
async def test_run_steps_fill_error_never_leaks_value():
    # Un `page.fill` qui échote la valeur secrète dans son message d'exception
    # ne doit JAMAIS faire fuiter cette valeur — ni dans `step` (redigé) ni
    # dans `error` (type d'exception seul pour un fill en échec).
    secret = "hunter2-super-secret"

    class Leaky(FakePage):
        async def fill(self, sel, val, **k):
            raise RuntimeError(f"echec de saisie de {val}")

    page = Leaky()

    async def cb(label):
        pass

    journal = await run_steps(
        page, [{"fill": {"sel": "i", "value": secret}}], screenshot_cb=cb
    )
    assert journal[0]["ok"] is False
    assert journal[0]["error"] == "RuntimeError"
    assert secret not in str(journal[0])


@pytest.mark.asyncio
async def test_run_steps_unknown_verb_logged_not_silently_ok():
    # Défense en profondeur : un verbe sans branche d'exécution (ex. ajouté à
    # l'allowlist de engine.steps mais pas ici) échoue explicitement, journalisé
    # ok:false, plutôt que de réussir silencieusement.
    page = FakePage()

    async def cb(label):
        pass

    journal = await run_steps(page, [{"newverb": "x"}], screenshot_cb=cb)
    assert journal[0]["ok"] is False
    assert "newverb" in journal[0]["error"]
    assert page.calls == []


@pytest.mark.asyncio
async def test_run_steps_error_message_truncated_to_200():
    class Boom(FakePage):
        async def click(self, sel, **k):
            raise RuntimeError("x" * 500)

    page = Boom()

    async def cb(label):
        pass

    journal = await run_steps(page, [{"click": "#x"}], screenshot_cb=cb)
    assert len(journal[0]["error"]) == 200


@pytest.mark.asyncio
async def test_run_steps_scroll_top_bottom_and_px():
    page = FakePage()

    async def cb(label):
        pass

    steps = [{"scroll": "top"}, {"scroll": "bottom"}, {"scroll": 250}]
    journal = await run_steps(page, steps, screenshot_cb=cb)
    evals = [c for c in page.calls if c[0] == "eval"]
    assert evals[0] == ("eval", "window.scrollTo(0, 0)")
    assert evals[1] == ("eval", "window.scrollTo(0, document.body.scrollHeight)")
    assert evals[2] == ("eval", "window.scrollTo(0, 250)")
    assert all(e["ok"] for e in journal)


@pytest.mark.asyncio
async def test_run_steps_scroll_injection_never_reaches_evaluate():
    # Défense en profondeur de l'exécuteur : un `scroll` malveillant qui
    # aurait contourné validate_steps (str d'injection au lieu d'un int)
    # doit être journalisé ok:false SANS jamais atteindre page.evaluate avec
    # du JS d'attaque — `int(arg)` lève ValueError AVANT l'appel.
    page = FakePage()

    async def cb(label):
        pass

    journal = await run_steps(page, [{"scroll": "1);alert(1)"}], screenshot_cb=cb)
    assert journal[0]["ok"] is False
    # aucun evaluate n'a été émis (l'int() échoue avant l'appel)
    assert not [c for c in page.calls if c[0] == "eval"]
    # et surtout jamais de JS contenant l'injection
    assert not [c for c in page.calls if c[0] == "eval" and "alert" in c[1]]


@pytest.mark.asyncio
async def test_run_steps_wait_selector_form_calls_wait_for_selector():
    page = FakePage()

    async def cb(label):
        pass

    journal = await run_steps(page, [{"wait": {"selector": ".x"}}], screenshot_cb=cb)
    assert ("wait_sel", ".x") in page.calls
    assert journal[0]["ok"] is True


@pytest.mark.asyncio
async def test_run_steps_goto_uses_page_goto():
    page = FakePage()

    async def cb(label):
        pass

    journal = await run_steps(page, [{"goto": "https://example.com/"}], screenshot_cb=cb)
    assert ("goto", "https://example.com/") in page.calls
    assert journal[0]["ok"] is True


# --- budget wall-clock total (`deadline`) ---


@pytest.mark.asyncio
async def test_run_steps_without_deadline_behaviour_unchanged():
    # `deadline` par défaut à None -> aucun garde ajouté, comportement identique
    # à avant l'introduction du budget (steps normaux tous exécutés).
    page = FakePage()

    async def cb(label):
        pass

    steps = [{"click": "#a"}, {"click": "#b"}]
    journal = await run_steps(page, steps, screenshot_cb=cb)
    assert [e["ok"] for e in journal] == [True, True]
    assert ("click", "#a") in page.calls and ("click", "#b") in page.calls


@pytest.mark.asyncio
async def test_run_steps_deadline_already_passed_logs_timeout_and_stops():
    page = FakePage()

    async def cb(label):
        pass

    steps = [{"click": "#a"}, {"click": "#b"}]
    deadline = time.monotonic() - 1  # déjà dépassé avant le premier step
    journal = await run_steps(page, steps, screenshot_cb=cb, deadline=deadline)

    assert len(journal) == 1
    assert journal[0]["ok"] is False
    assert journal[0]["error"] == "timeout budget"
    assert journal[0]["index"] == 0
    assert journal[0]["verb"] == "click"
    # aucun step n'a réellement été tenté sur la page
    assert page.calls == []


@pytest.mark.asyncio
async def test_run_steps_pending_step_cut_by_deadline_and_logged_timeout():
    class Pending(FakePage):
        async def click(self, sel, **k):
            # simule un step qui pend (ex. sélecteur absent -> actionabilité
            # Playwright qui attend ~30s) : doit être coupé net par le budget.
            await asyncio.sleep(30)
            self.calls.append(("click", sel))  # jamais atteint si coupé

    page = Pending()

    async def cb(label):
        pass

    t0 = time.monotonic()
    deadline = t0 + 0.1  # budget restant très court
    journal = await run_steps(
        page, [{"click": "#missing"}], screenshot_cb=cb, deadline=deadline
    )
    elapsed = time.monotonic() - t0

    assert elapsed < 5  # coupé net, n'attend jamais les 30s du step qui pend
    assert len(journal) == 1
    assert journal[0]["ok"] is False
    assert journal[0]["error"] == "timeout budget"
    assert page.calls == []  # le `click` n'a jamais complété


@pytest.mark.asyncio
async def test_run_steps_deadline_not_reached_executes_normally():
    page = FakePage()

    async def cb(label):
        pass

    steps = [{"click": "#a"}, {"wait": 10}]
    deadline = time.monotonic() + 30  # large marge, jamais atteint
    journal = await run_steps(page, steps, screenshot_cb=cb, deadline=deadline)
    assert [e["ok"] for e in journal] == [True, True]
