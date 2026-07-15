import pytest

from runner_recon.capture import _goto_with_fallback, build_result


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
