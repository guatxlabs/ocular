# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""LE TRAVAIL COÛTEUX A DEUX PORTES ; ELLES DOIVENT PARTAGER LA MÊME BORNE.

La borne de concurrence posée au tour précédent vit dans `_live_analysis` : elle
ferme `/live`, et seulement `/live`. Le même balayage (`scan_html` +
`extract_forms` + `extract_mailtos`) a un SECOND appelant —
`build_capture_result` — que `/capture` invoquait EN LIGNE dans sa coroutine :
sans threadpool, sans borne, donc en tenant la boucle d'évènements pendant tout
le balayage.

MESURÉ sur 5d37457 (banc hors dépôt : uvicorn servant cette app + le VRAI client
`web.internal_http.internal_get_json` et son échéance de 5,0 s ; page de 512 Kio
de contenu hostile ; DOM mutant d'un octet par lecture) :

    1 /capture concurrent  -> polls /live servis 4/4 (pire latence 3 960 ms)
    3 /capture concurrents -> polls /live servis 4/4 (pire latence 3 155 ms)
    6 /capture concurrents -> polls /live servis 0/4, tous en 502 « timed out »
                              (pire latence 5 225 ms)

Après correction, même banc, même page :

    1 /capture  -> 4/4 servis, pire latence   205 ms
    3 /capture  -> 4/4 servis, pire latence   160 ms
    6 /capture  -> 4/4 servis, pire latence   187 ms

La latence de `/live` ne dépend plus du nombre de captures en vol.

CE QUI EST VÉRIFIÉ ICI est structurel, pas anecdotique :
  1. aucune fonction de balayage d'`engine.static` n'est appelée hors des deux
     ouvriers PURS — et la liste de ces fonctions est DÉRIVÉE du module
     (celles qui prennent un document en premier argument), pas écrite ici ;
  2. aucun de ces ouvriers n'est invoqué hors de `_bounded_scan` ;
  3. et la propriété opérationnelle : des captures concurrentes n'affament pas
     le panneau live.
"""
import ast
import asyncio
import inspect
import threading
import time

import pytest

import engine.static as static
import runner_recon_vnc.session_server as ss
from engine.wrapper import NetworkCapture

SOURCE = inspect.getsource(ss)
TREE = ast.parse(SOURCE)

# Ouvriers PURS : le balayage y vit, et il n'a pas le droit d'en sortir.
OUVRIERS = ("_analyze_dom", "build_capture_result")


def _scanners() -> list[str]:
    """Fonctions de balayage d'`engine.static`, DÉRIVÉES du module : celles qui
    prennent un DOCUMENT en premier argument. Écrite à la main, cette liste
    raterait la fonction ajoutée demain — exactement le défaut que ce fichier
    ferme."""
    out = []
    for name, obj in vars(static).items():
        if name.startswith("_") or not inspect.isfunction(obj):
            continue
        params = list(inspect.signature(obj).parameters)
        if params and params[0] == "html":
            out.append(name)
    return sorted(out)


def _enclosing(node_lineno: int) -> str:
    """Nom de la fonction (ou coroutine) qui contient cette ligne."""
    best, best_line = "<module>", -1
    for node in ast.walk(TREE):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fin = max(getattr(n, "lineno", node.lineno) for n in ast.walk(node))
            if node.lineno <= node_lineno <= fin and node.lineno > best_line:
                best, best_line = node.name, node.lineno
    return best


def _calls(name: str) -> list[int]:
    return [n.lineno for n in ast.walk(TREE)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == name]


def test_the_module_actually_uses_the_scanners_we_derived():
    """Garde de la garde : si plus aucun balayage n'est appelé dans ce module,
    les deux tests ci-dessous passeraient à vide."""
    utilises = [s for s in _scanners() if _calls(s)]
    assert utilises, (
        f"aucune fonction de balayage d'engine.static ({_scanners()}) n'est "
        f"appelée dans session_server : cette garde ne vérifie plus rien"
    )


@pytest.mark.parametrize("scanner", _scanners())
def test_no_scan_happens_outside_the_pure_workers(scanner):
    """Un balayage appelé ailleurs que dans un ouvrier pur échapperait à la
    place unique — c'est exactement ce que faisait `/capture`."""
    for ligne in _calls(scanner):
        porteur = _enclosing(ligne)
        assert porteur in OUVRIERS, (
            f"{scanner}() appelé ligne {ligne} depuis `{porteur}` : hors des "
            f"ouvriers purs {OUVRIERS}, donc hors de la place unique"
        )


@pytest.mark.parametrize("ouvrier", OUVRIERS)
def test_every_worker_is_invoked_through_the_single_slot(ouvrier):
    """Et les ouvriers eux-mêmes ne sont invoqués QUE par `_bounded_scan` — donc
    hors de la boucle d'évènements, et un à la fois."""
    for node in ast.walk(TREE):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != ouvrier:
            continue
        pytest.fail(
            f"`{ouvrier}` appelé directement ligne {node.lineno} : le balayage "
            f"doit passer par `_bounded_scan`, sinon il tient la boucle"
        )
    passages = [n for n in ast.walk(TREE)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "_bounded_scan"
                and any(isinstance(a, ast.Name) and a.id == ouvrier for a in n.args)]
    assert passages, f"`{ouvrier}` n'est jamais confié à `_bounded_scan`"


class _HostilePage:
    """Page hostile MUTANTE (un octet de plus par lecture) : ni le mémo ni le
    single-flight ne peuvent la dédupliquer."""

    def __init__(self, pad: int = 8 * 1024) -> None:
        self._n = 0
        self._body = "<script>" + "atob(" * (pad // 5) + "</script>"
        self.url = "https://hostile.test/"

    async def content(self) -> str:
        self._n += 1
        return f"<!--{self._n}-->" + self._body

    async def title(self) -> str:
        return "t"

    async def evaluate(self, *a, **k):
        return False

    async def wait_for_load_state(self, *a, **k):
        return None

    async def screenshot(self, **k) -> bytes:
        return b"\x89PNG" + b"\x00" * 32


def test_concurrent_captures_do_not_starve_the_live_panel():
    """La propriété opérationnelle : `/capture` et `/live` partagent UNE place.
    Le pic de concurrence du balayage reste à 1 quel que soit le nombre de
    captures, et chaque poll `/live` reçoit une réponse — périmée si la place
    est prise, mais DITE périmée, jamais une attente qui franchit l'échéance."""
    pic = {"cur": 0, "peak": 0}
    verrou = threading.Lock()
    vrai = ss.scan_html

    def _spy(html):
        with verrou:
            pic["cur"] += 1
            pic["peak"] = max(pic["peak"], pic["cur"])
        time.sleep(0.05)
        try:
            return vrai(html)
        finally:
            with verrou:
                pic["cur"] -= 1

    async def _scenario():
        ss._LIVE_ANALYSIS.clear()
        ss._LIVE_INFLIGHT.clear()
        ss._state.update(page=_HostilePage(), cap=NetworkCapture(keep="last"),
                         target="https://hostile.test/", kind="url", html_input="")
        ss.scan_html = _spy
        try:
            captures = [ss.capture({}) for _ in range(6)]
            polls = [ss.live() for _ in range(4)]
            return await asyncio.gather(*captures, *polls)
        finally:
            ss.scan_html = vrai

    sorties = asyncio.run(_scenario())
    captures, polls = sorties[:6], sorties[6:]

    assert pic["peak"] == 1, (
        f"pic de concurrence {pic['peak']} : les deux portes du balayage ne "
        f"partagent pas la même place, et la latence de /live suit le nombre de "
        f"captures"
    )
    assert all("result" in c for c in captures), "une capture n'a pas rendu de résultat"
    assert len(polls) == 4 and all("verdict" in p for p in polls), (
        "un poll /live est resté sans réponse pendant les captures"
    )
    assert all("counts" in p and "truncation" in p for p in polls)


def test_a_live_poll_during_a_capture_says_it_is_stale():
    """Ce qui est rendu pendant qu'une capture tient la place N'EST PAS l'analyse
    du DOM de ce poll : c'est dit, jamais absorbé."""
    async def _scenario():
        ss._LIVE_ANALYSIS.clear()
        ss._LIVE_INFLIGHT.clear()
        ss._state.update(page=_HostilePage(), cap=NetworkCapture(keep="last"),
                         target="https://hostile.test/", kind="url", html_input="")
        capture = asyncio.create_task(ss.capture({}))
        await asyncio.sleep(0)
        poll = await ss.live()
        await capture
        return poll

    poll = asyncio.run(_scenario())
    assert poll["analysis_stale"] is True, (
        "une analyse rendue pendant une capture doit se déclarer périmée"
    )
