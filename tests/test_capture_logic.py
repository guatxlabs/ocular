import pytest

import runner_recon.capture as cap
from runner_recon.capture import _goto_with_fallback, build_result, solve_turnstile
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
    `_FakeVision.png_to_bgr` est l'identité) ; `evaluate` renvoie l'offset
    mozInnerScreen/dpr fourni au constructeur."""

    def __init__(self, offset):
        self._offset = offset
        self.screenshot_calls = 0

    async def screenshot(self, **kw):
        self.screenshot_calls += 1
        return b"png-%d" % self.screenshot_calls

    async def evaluate(self, script):
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
