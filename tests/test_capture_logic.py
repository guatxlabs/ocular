import asyncio

import pytest

import runner_recon.capture as cap
from runner_recon.capture import _capture_dom, _goto_with_fallback, build_result, solve_turnstile
from runner_recon.vision import image_to_screen


# --- Task H : fallback runtime https->http (page mockée, aucun navigateur réel) ---


class _FakePage:
    """Page minimale : `goto` piloté par une liste de résultats (exception ou
    None pour un succès), consommée dans l'ORDRE des appels. Enregistre chaque
    URL tentée pour vérifier le nombre d'essais et l'URL de fallback."""

    def __init__(self, outcomes):
        self._outcomes = list(outcomes)
        self.calls: list[str] = []

    async def goto(self, url, **kwargs):
        self.calls.append(url)
        outcome = self._outcomes.pop(0)
        if outcome is not None:
            raise outcome


@pytest.mark.asyncio
async def test_goto_with_fallback_retries_http_once_when_https_fails():
    page = _FakePage([RuntimeError("boom"), None])  # https lève, http réussit
    console: list[dict] = []

    await _goto_with_fallback(page, "https://example.com/path?q=1", 45000, console)

    assert page.calls == ["https://example.com/path?q=1", "http://example.com/path?q=1"]
    assert any(c["level"] == "warning" and c["text"] == "scheme-fallback https->http" for c in console)


@pytest.mark.asyncio
async def test_goto_with_fallback_no_retry_when_https_succeeds():
    page = _FakePage([None])
    console: list[dict] = []

    await _goto_with_fallback(page, "https://example.com/", 45000, console)

    assert page.calls == ["https://example.com/"]
    assert not any(c["text"] == "scheme-fallback https->http" for c in console)


@pytest.mark.asyncio
async def test_goto_with_fallback_no_fallback_when_already_http():
    page = _FakePage([RuntimeError("boom")])  # http lève : pas de schéma "plus permissif"
    console: list[dict] = []

    await _goto_with_fallback(page, "http://example.com/", 45000, console)

    assert page.calls == ["http://example.com/"]  # une seule tentative, jamais 2
    assert not any(c["text"] == "scheme-fallback https->http" for c in console)
    assert any(c["level"] == "error" for c in console)


@pytest.mark.asyncio
async def test_goto_with_fallback_gives_up_after_one_fallback_attempt():
    # https échoue, http échoue aussi -> pas de boucle, deux tentatives max.
    page = _FakePage([RuntimeError("boom1"), RuntimeError("boom2")])
    console: list[dict] = []

    await _goto_with_fallback(page, "https://example.com/", 45000, console)

    assert page.calls == ["https://example.com/", "http://example.com/"]
    assert not any(c["text"] == "scheme-fallback https->http" for c in console)
    assert sum(1 for c in console if c["level"] == "error") == 2


def test_build_result_capture_profile_and_hash():
    r, blobs = build_result(
        url="https://example.com/x",
        screenshots=[(0, "initial", b"\x89PNG\r\n\x1a\nAAA")],
        network=[{"url": "https://example.com/x", "method": "GET", "status": 200}],
        console=[], dom_html=b"<script>eval(atob('x'))</script>",
        title="t", final_url="https://example.com/x", turnstile_solved=True,
    )
    assert r.profile == "capture"
    assert r.stealth.engine == "camoufox" and r.stealth.turnstile_solved is True
    assert r.input_hash.startswith("sha256:")
    assert r.verdict == "malicious"          # static détecte eval/atob dans le DOM capturé
    assert r.screenshots[0].image_ref in blobs
    # le DOM est aussi un blob
    assert r.artifacts.dom_html_ref in blobs


# --- Task B1 : solve_turnstile — retry détection + mapping viewport->écran + vérif ---
#
# `vision` (numpy/opencv/xdotool) n'est pas installé dans ce venv de test (il ne
# vit que dans l'image runner_recon, cf. Dockerfile) : on injecte un module
# `vision` entièrement mocké (`_FakeVision`) pour tester la boucle sans
# navigateur ni dépendance lourde. `image_to_screen`, lui, est pur (pas de
# numpy) et importé pour de vrai afin de vérifier le VRAI mapping.


class _FakeTurnstilePage:
    """Page minimale : `screenshot` renvoie des octets bidon (jamais décodés,
    `_FakeVision.png_to_bgr` est l'identité) ; `evaluate` distingue le script
    indicateur CF (`cap._CF_INDICATOR_JS` -> True, un Turnstile est présent
    dans tous les tests B ci-dessous) de l'offset mozInnerScreen/dpr fourni au
    constructeur (n'importe quel autre script -> l'offset)."""

    def __init__(self, offset):
        self._offset = offset
        self.screenshot_calls = 0

    async def screenshot(self, **kw):
        self.screenshot_calls += 1
        return b"png-%d" % self.screenshot_calls

    async def evaluate(self, script):
        if script == cap._CF_INDICATOR_JS:
            return True
        return self._offset


class _FakeVision:
    """Mock du module `vision` : `detect` consomme une séquence de résultats
    dans l'ordre des appels (un par screenshot), `human_click_xdotool`
    enregistre les coords reçues (pour vérifier le MAPPING), `image_to_screen`
    délègue au vrai helper pur."""

    def __init__(self, detections):
        self._detections = list(detections)
        self.detect_calls = 0
        self.click_calls: list[tuple[int, int]] = []

    def png_to_bgr(self, png):
        return png  # identité : jamais réellement décodé dans ces tests

    def detect(self, frame, strategy="color", **kw):
        self.detect_calls += 1
        return self._detections.pop(0) if self._detections else None

    def image_to_screen(self, det, moz_x, moz_y, dpr):
        return image_to_screen(det, moz_x, moz_y, dpr)

    async def human_click_xdotool(self, sx, sy, **kw):
        self.click_calls.append((sx, sy))
        return sx, sy


@pytest.fixture(autouse=True)
def _fast_sleep(monkeypatch):
    # Les tests Turnstile ne doivent pas payer les vraies pauses (~4-5s) :
    # neutralise `asyncio.sleep` dans le module capture pour ce fichier.
    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(cap.asyncio, "sleep", _noop)


@pytest.mark.asyncio
async def test_solve_turnstile_retries_until_detected_then_clicks_mapped_coords():
    # detect() rate les 2 premières tentatives (widget async pas encore rendu)
    # puis trouve la case au 3e essai ; après le clic, la case a disparu
    # (4e appel detect() -> None) : résolu.
    vision_mod = _FakeVision(detections=[None, None, (50, 60), None])
    page = _FakeTurnstilePage(offset={"x": 100, "y": 40, "d": 2})
    screenshots: list[tuple[int, str, bytes]] = []
    console: list[dict] = []

    solved = await solve_turnstile(page, screenshots, console, vision_mod, next_index=1)

    assert solved is True
    assert vision_mod.detect_calls == 4          # 3 tentatives + 1 vérif post-clic
    assert page.screenshot_calls == 4
    # clic aux coords MAPPÉES (offset + dpr), pas aux coords image brutes.
    expected = image_to_screen((50, 60), 100, 40, 2)
    assert vision_mod.click_calls == [expected]
    assert expected != (50, 60)                  # le mapping a bien changé les coords
    # le screenshot post-clic est bien empilé, à l'index demandé.
    assert screenshots == [(1, "post-turnstile", b"png-4")]
    assert console == []                          # rien à logger côté warning : résolu


@pytest.mark.asyncio
async def test_solve_turnstile_still_present_after_click_is_not_solved():
    # La case est détectée puis reste détectée après le clic (échec réel du
    # challenge) : turnstile_solved DOIT refléter ça, pas un optimiste True.
    vision_mod = _FakeVision(detections=[(10, 10), (10, 10)])
    page = _FakeTurnstilePage(offset={"x": 0, "y": 0, "d": 1})
    screenshots: list[tuple[int, str, bytes]] = []
    console: list[dict] = []

    solved = await solve_turnstile(page, screenshots, console, vision_mod)

    assert solved is False
    assert vision_mod.click_calls == [(10, 10)]   # le clic a bien eu lieu
    assert any(c["level"] == "warning" and "non résolu" in c["text"] for c in console)


@pytest.mark.asyncio
async def test_solve_turnstile_no_widget_never_clicks_no_regression():
    # Page sans Turnstile (ex. example.com) : detect() ne trouve jamais rien.
    # Comportement 3a inchangé -> pas de clic, pas de screenshot post-turnstile
    # ajouté, pas d'appel evaluate (pas besoin de l'offset).
    vision_mod = _FakeVision(detections=[])       # toujours None
    page = _FakeTurnstilePage(offset={"x": 0, "y": 0, "d": 1})
    screenshots: list[tuple[int, str, bytes]] = []
    console: list[dict] = []

    solved = await solve_turnstile(page, screenshots, console, vision_mod)

    assert solved is False
    assert vision_mod.click_calls == []
    assert screenshots == []                      # aucun screenshot post-turnstile
    assert vision_mod.detect_calls == cap._TURNSTILE_RETRY_ATTEMPTS
    assert page.screenshot_calls == cap._TURNSTILE_RETRY_ATTEMPTS


@pytest.mark.asyncio
async def test_solve_turnstile_bounded_retry_total_sleep_under_5s(monkeypatch):
    # Vérifie le budget temps annoncé par le plan (~5s max avant d'abandonner
    # la détection) : capte la somme des `asyncio.sleep` de la boucle de
    # retry plutôt que de patcher `_noop` (fixture autouse) pour ce test.
    slept = []

    async def _record_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(cap.asyncio, "sleep", _record_sleep)
    vision_mod = _FakeVision(detections=[])       # jamais détecté -> boucle complète
    page = _FakeTurnstilePage(offset={"x": 0, "y": 0, "d": 1})

    await solve_turnstile(page, [], [], vision_mod)

    assert sum(slept) < 5.0


# --- Task F1a : gating Turnstile sur l'indicateur DOM CF ---
#
# Avant le plan phase3f, `solve_turnstile` payait TOUJOURS les ~4s de la
# boucle de retry (screenshot + detect + sleep x6), même sur une page sans
# Turnstile (le cas courant). Le gating vérifie un indicateur DOM booléen
# (`cap._CF_INDICATOR_JS`, `page.evaluate`) en tout premier : absent -> 0
# latence ; présent -> comportement de retry inchangé (couvert par les tests
# B ci-dessus, où `_FakeTurnstilePage.evaluate` renvoie `True` pour ce script).


class _FakeGatingPage:
    """Page dédiée au gating : `evaluate` renvoie le prochain élément de
    `indicator_seq` pour le script `cap._CF_INDICATOR_JS` (poll de l'indicateur
    CF, un booléen par tour — modélise l'injection ASYNC : peut être False
    plusieurs tours puis True), `offset` pour n'importe quel autre script
    (mapping viewport->écran). Une séquence épuisée retourne son dernier élément
    (indicateur stable)."""

    def __init__(self, indicator_seq, offset=None):
        self._indicator_seq = list(indicator_seq)
        self._offset = offset or {"x": 0, "y": 0, "d": 1}
        self.screenshot_calls = 0
        self.indicator_calls = 0

    async def screenshot(self, **kw):
        self.screenshot_calls += 1
        return b"png-%d" % self.screenshot_calls

    async def evaluate(self, script):
        if script == cap._CF_INDICATOR_JS:
            self.indicator_calls += 1
            if self._indicator_seq:
                val = self._indicator_seq.pop(0)
                self._last_indicator = val
                return val
            return getattr(self, "_last_indicator", False)
        return self._offset


@pytest.mark.asyncio
async def test_solve_turnstile_no_cf_indicator_returns_false_after_bounded_poll(monkeypatch):
    sleep_calls = []

    async def _record_sleep(seconds):
        sleep_calls.append(seconds)

    monkeypatch.setattr(cap.asyncio, "sleep", _record_sleep)

    # indicateur JAMAIS présent -> poll complet puis abandon.
    page = _FakeGatingPage(indicator_seq=[False] * cap._CF_INDICATOR_POLL_ATTEMPTS)
    vision_mod = _FakeVision(detections=[])
    screenshots: list[tuple[int, str, bytes]] = []
    console: list[dict] = []

    solved = await solve_turnstile(page, screenshots, console, vision_mod)

    assert solved is False
    # fenêtre de poll bornée, PUIS abandon : 0 screenshot, 0 detect, 0 clic.
    assert page.indicator_calls == cap._CF_INDICATOR_POLL_ATTEMPTS
    assert page.screenshot_calls == 0
    assert vision_mod.detect_calls == 0
    assert vision_mod.click_calls == []
    # les sleeps de la fenêtre de poll (bornés : ~3.6s réels, ici neutralisés).
    assert len(sleep_calls) == cap._CF_INDICATOR_POLL_ATTEMPTS
    assert screenshots == []
    assert console == []


@pytest.mark.asyncio
async def test_solve_turnstile_cf_indicator_appears_late_runs_full_retry_loop():
    # Injection ASYNC : indicateur absent les 2 premiers tours de poll puis
    # présent au 3e (False, False, True) -> le gating NE saute PAS, la boucle
    # de retry vision + solve EXISTANTE s'exécute ensuite (ici widget jamais
    # matché par la vision -> boucle complète, comportement inchangé).
    page = _FakeGatingPage(indicator_seq=[False, False, True])
    vision_mod = _FakeVision(detections=[])  # jamais détecté par la vision
    screenshots: list[tuple[int, str, bytes]] = []
    console: list[dict] = []

    solved = await solve_turnstile(page, screenshots, console, vision_mod)

    assert solved is False
    assert page.indicator_calls == 3            # poll s'arrête dès l'indicateur True
    # la boucle de retry vision s'est bien exécutée intégralement après le gating.
    assert vision_mod.detect_calls == cap._TURNSTILE_RETRY_ATTEMPTS
    assert page.screenshot_calls == cap._TURNSTILE_RETRY_ATTEMPTS


# --- Task F1b : `_capture_dom` — extraction DOM factorisée capture_url/capture_scripted ---


class _FakeDomPage:
    """Page minimale pour `_capture_dom` : `content`/`title` pilotables
    (valeur normale OU exception), `url` un attribut simple comme la vraie
    API Playwright/Camoufox (pas une coroutine)."""

    def __init__(self, content="<html></html>", title="t", url="https://example.com/", raise_on=None):
        self._content = content
        self._title = title
        self.url = url
        self._raise_on = raise_on  # "content" | "title" | None

    async def content(self):
        if self._raise_on == "content":
            raise RuntimeError("boom")
        return self._content

    async def title(self):
        if self._raise_on == "title":
            raise RuntimeError("boom")
        return self._title


@pytest.mark.asyncio
async def test_capture_dom_returns_html_title_url_on_success():
    page = _FakeDomPage(content="<p>hi</p>", title="Hello", url="https://example.com/x")

    dom_html, title, final_url = await _capture_dom(page, "https://example.com/x")

    assert dom_html == b"<p>hi</p>"
    assert title == "Hello"
    assert final_url == "https://example.com/x"


@pytest.mark.asyncio
async def test_capture_dom_content_raises_falls_back_to_url_no_crash():
    # dom/title vides sur exception, MAIS final_url retombe sur l'URL cible
    # (pas "") — cohérent avec _error_wrapper, comportement d'avant le refactor.
    page = _FakeDomPage(raise_on="content")

    dom_html, title, final_url = await _capture_dom(page, "https://target.example/p")

    assert dom_html == b""
    assert title == ""
    assert final_url == "https://target.example/p"


@pytest.mark.asyncio
async def test_capture_dom_title_raises_falls_back_to_url_no_crash():
    page = _FakeDomPage(raise_on="title")

    dom_html, title, final_url = await _capture_dom(page, "https://target.example/p")

    assert dom_html == b""
    assert title == ""
    assert final_url == "https://target.example/p"


# --- Task F1c : finalisation DOM sous timeout (capture_scripted) ---
#
# `camoufox` n'est pas installé dans ce venv de test (cf. test_capture_scripted_logic.py) :
# le module `camoufox.async_api` est mocké via `sys.modules`, comme
# `test_capture_scripted_passes_deadline_to_run_steps`. `content()` bloque
# indéfiniment (`asyncio.Event().wait()`, pas `asyncio.sleep` : la fixture
# `_fast_sleep` autouse de ce fichier patche `asyncio.sleep` au niveau module,
# donc un `sleep` ne bloquerait pas réellement) pour simuler un `page` bancal
# après un `run_steps` compromis -> `asyncio.wait_for` doit couper au budget
# court et laisser `capture_scripted` retourner un résultat partiel valide.


@pytest.mark.asyncio
async def test_capture_scripted_finalization_timeout_still_returns_partial_result(monkeypatch):
    import sys
    import types

    class FakePage:
        url = "https://example.com/"

        async def goto(self, url, **k):
            pass

        async def content(self):
            await asyncio.Event().wait()  # pend indéfiniment -> coupé par wait_for
            return "<html></html>"  # jamais atteint

        async def title(self):
            return "t"

        async def screenshot(self, **k):
            return b"PNG"

        def on(self, event, handler):
            pass

    class FakeCtx:
        async def new_page(self):
            return FakePage()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class FakeAsyncCamoufox:
        def __init__(self, **k):
            pass

        async def __aenter__(self):
            return FakeCtx()

        async def __aexit__(self, *a):
            return False

    fake_async_api = types.ModuleType("camoufox.async_api")
    fake_async_api.AsyncCamoufox = FakeAsyncCamoufox
    fake_camoufox = types.ModuleType("camoufox")
    fake_camoufox.async_api = fake_async_api
    monkeypatch.setitem(sys.modules, "camoufox", fake_camoufox)
    monkeypatch.setitem(sys.modules, "camoufox.async_api", fake_async_api)

    # budget de finalisation court -> le test ne paie pas les 15s réels.
    monkeypatch.setattr(cap, "_DOM_FINALIZE_TIMEOUT_S", 0.05)

    result, blobs = await cap.capture_scripted("https://example.com/", [])

    # Résultat partiel : dom vide, mais un OcularResult VALIDE quand même
    # (emit_wrapper, appelé par main(), aurait toujours quelque chose à écrire).
    assert result.dom.title == ""
    assert result.dom.final_url == "https://example.com/"
    assert any(
        c.level == "warning" and "timeout" in c.text for c in result.console
    )


def _install_fake_camoufox(monkeypatch, page):
    """Installe un `camoufox.async_api` mocké dont `new_page` renvoie `page`."""
    import sys
    import types

    class FakeCtx:
        async def new_page(self):
            return page

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class FakeAsyncCamoufox:
        def __init__(self, **k):
            pass

        async def __aenter__(self):
            return FakeCtx()

        async def __aexit__(self, *a):
            return False

    fake_async_api = types.ModuleType("camoufox.async_api")
    fake_async_api.AsyncCamoufox = FakeAsyncCamoufox
    fake_camoufox = types.ModuleType("camoufox")
    fake_camoufox.async_api = fake_async_api
    monkeypatch.setitem(sys.modules, "camoufox", fake_camoufox)
    monkeypatch.setitem(sys.modules, "camoufox.async_api", fake_async_api)


@pytest.mark.asyncio
async def test_capture_scripted_dom_extraction_raises_final_url_falls_back_to_url(monkeypatch):
    # Régression dédup : quand l'extraction DOM finale LÈVE (driver mort /
    # page hostile), `_capture_dom` absorbe l'exception mais `dom.final_url`
    # DOIT retomber sur l'URL cible (pas ""), comme avant le refactor.
    class FakePage:
        url = "https://target.example/x"

        async def goto(self, url, **k):
            pass

        async def content(self):
            raise RuntimeError("driver dead")  # extraction DOM en échec

        async def title(self):
            return "t"

        async def screenshot(self, **k):
            return b"PNG"

        def on(self, event, handler):
            pass

    _install_fake_camoufox(monkeypatch, FakePage())

    result, blobs = await cap.capture_scripted("https://target.example/x", [])

    assert result.dom.title == ""            # dom vide (exception absorbée)
    assert result.dom.final_url == "https://target.example/x"  # PAS "" : fallback URL


@pytest.mark.asyncio
async def test_capture_url_dom_extraction_raises_final_url_falls_back_to_url(monkeypatch):
    # Même garantie côté chemin 3a (`capture_url`) : extraction DOM en échec
    # -> `dom.final_url` = URL cible, jamais "".
    class FakePage:
        url = "https://target.example/y"

        async def goto(self, url, **k):
            pass

        async def content(self):
            raise RuntimeError("driver dead")

        async def title(self):
            return "t"

        async def screenshot(self, **k):
            return b"PNG"

        def on(self, event, handler):
            pass

    _install_fake_camoufox(monkeypatch, FakePage())
    # `capture_url` fait `import vision` : neutralise le gating Turnstile pour
    # éviter d'exécuter la vision (pas installée dans ce venv). Un module
    # `vision` minimal suffit : le gating poll `page.evaluate` -> ici la
    # FakePage n'a pas `evaluate`, donc on court-circuite solve_turnstile.
    import sys
    import types
    monkeypatch.setitem(sys.modules, "vision", types.ModuleType("vision"))

    result, blobs = await cap.capture_url("https://target.example/y")

    assert result.dom.title == ""
    assert result.dom.final_url == "https://target.example/y"
