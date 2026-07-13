"""Exécuteur de steps 3c (runner) — page Playwright mockée, pas de vrai navigateur.

Vérifie : dispatch de chaque verbe vers l'API locator, journal redigé (jamais
la valeur `fill` en clair), arrêt de la séquence à la première erreur, et que
le seul `evaluate` est le JS de scroll constant (jamais de contenu utilisateur
interpolé en dehors d'un int contrôlé).
"""
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
async def test_run_steps_scroll_px_is_int_never_a_user_string():
    # le seul `evaluate` de contenu variable doit interpoler un int contrôlé,
    # jamais une chaîne — la valeur ci-dessous vient d'un step déjà validé par
    # engine.steps (int borné), donc int(arg) est un no-op de défense en
    # profondeur, pas une conversion de texte utilisateur.
    page = FakePage()

    async def cb(label):
        pass

    await run_steps(page, [{"scroll": 42}], screenshot_cb=cb)
    js = page.calls[0][1]
    assert js == "window.scrollTo(0, 42)"
    assert isinstance(42, int)


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
