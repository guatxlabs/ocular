# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""`/live` : le tier où l'analyste regarde EN CONTINU, donc celui où une borne
mal posée coûte le plus cher.

Trois défauts mesurés sur 57f9d6a, tous alimentés par la page analysée :

  1. DÉNI DE SERVICE. Le fail-closed en lecture (`_read_capped`) est correct en
     soi, mais rien ne bornait la taille d'une entrée : un seul `console.log` de
     20 Mio faisait rendre 20,0 Mio par `/live`, au-dessus des 16 Mio de
     `OCULAR_MAX_INTERNAL_JSON_BYTES` -> `CaptureError` -> 502 à CHAQUE poll pour
     le restant de la session. L'entrée étant unique, elle ne sortait jamais de
     la fenêtre `[-500:]`. Avant le correctif le contenu passait au prix de la
     RAM ; après, il VERROUILLAIT l'outil depuis le contenu analysé. Un outil
     d'analyse qui se laisse désarmer par la page qu'il analyse est inutilisable.

  2. PERTE D'ÉLÉMENTS DE PREUVE SILENCIEUSE. `NetworkCapture` est armé une fois
     dans `_ensure_browser` et n'est jamais réarmé : le plafond de 5000 est
     CUMULÉ sur toute la session et gardait les PREMIÈRES entrées. Justifiable
     pour une capture one-shot, inversé pour une session où l'analyste pilote la
     page précisément pour DÉCLENCHER l'exfiltration. Mesuré avec
     `OCULAR_MAX_NETWORK_ENTRIES=3` : `dropped_network=48` et `/live` répondait
     `counts` SANS aucune clé `truncation` — le POST d'exfiltration émis après le
     plafond disparaissait sans trace côté analyste.

  3. CACHE STAMPEDE. Le mémo est écrit APRÈS l'analyse : 20 polls simultanés du
     même DOM lançaient 20 analyses (pic de concurrence mesuré : 20). Avant la
     mémoïsation, `analyze_html` était appelée en ligne dans la coroutine, donc
     STRICTEMENT sérialisée — le correctif avait remplacé une sérialisation par
     une concurrence non bornée.
"""
import asyncio
import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

import runner_recon_vnc.session_server as ss
from engine.result import Truncation
from engine.wrapper import NetworkCapture


def _reset_live_state() -> None:
    """Remet à zéro les états de module de `/live`. `getattr` : le mémo
    single-flight n'existe pas encore sur l'arbre défectueux, et un
    `AttributeError` ici masquerait l'échec RÉEL que ces tests mesurent."""
    ss._LIVE_ANALYSIS.clear()
    getattr(ss, "_LIVE_INFLIGHT", {}).clear()

_SECRET = "the-live-secret"
# Défaut publié de `OCULAR_MAX_LIVE_JSON_BYTES` (§2.10), sous les 16 Mio de
# `OCULAR_MAX_INTERNAL_JSON_BYTES` : c'est l'écart qui interdit le refus permanent.
DOC_LIVE_JSON_BYTES = 8 * 1024 * 1024


class _FakePage:
    def __init__(self, dom: str = "<html><body>x</body></html>") -> None:
        self._dom = dom

    def set_dom(self, dom: str) -> None:
        self._dom = dom

    async def content(self) -> str:
        return self._dom


class _MutatingPage:
    """DOM qui change d'UN OCTET à chaque lecture : ni le mémo ni le
    single-flight ne peuvent le dédupliquer. C'est la forme qui fabrique N
    analyses pour N polls simultanés."""

    def __init__(self, body: str = "<html><body>x</body></html>") -> None:
        self._body = body
        self._n = 0

    async def content(self) -> str:
        self._n += 1
        return f"<!--{self._n}-->{self._body}"


def _hostile_dom(pad: str = "\x00") -> str:
    """Page dont TOUT le volume est dicté par elle : formulaires, mailto,
    détections. `\\x00` coûte six octets par caractère une fois échappé en
    JSON — c'est la forme qui gonfle le plus la réponse `/live`.

    `eval(atob(...))` ci-dessous est une chaîne d'octets INERTE (faux DOM
    capturé), jamais exécutée : elle ne sert qu'à faire mordre un motif
    d'engine.static — même convention que tests/test_session_server_live_cpu.py."""
    return "".join(
        f'<form action="{pad * 500}" method="POST"></form>'
        f'<a href="mailto:{i:04d}{pad * 310}">x</a>'
        f'<script>eval(atob("x"))</script>'
        for i in range(120)
    )


class _Req:
    def __init__(self, url: str, post_data=None) -> None:
        self.url, self.method, self.resource_type, self.post_data = url, "POST", "xhr", post_data


@pytest.fixture
def live_client(monkeypatch):
    monkeypatch.setenv("OCULAR_SESSION_SECRET", _SECRET)
    ss._state.update(cm=None, page=None, cap=None, target=None, kind=None, html_input="")
    _reset_live_state()
    return TestClient(ss.app)


def _live(client):
    return client.get("/live", headers={"X-Session-Secret": _SECRET})


def _wire(cap: NetworkCapture) -> dict:
    hooks: dict = {}

    class _Page:
        def on(self, event, fn):
            hooks[event] = fn

    cap.attach(_Page())
    return hooks


# --- 1. la page ne peut pas verrouiller /live -------------------------------

def test_live_payload_never_exceeds_the_read_cap(live_client):
    """Le scénario exact de la revue : une entrée unique, énorme, qui ne sort
    jamais de la fenêtre `[-500:]`."""
    cap = NetworkCapture()
    cap.console.append({"level": "log", "text": "A" * (20 * 1024 * 1024)})
    ss._state.update(page=_FakePage(), cap=cap)

    body = _live(live_client).content
    assert len(body) <= DOC_LIVE_JSON_BYTES, (
        f"/live rend {len(body)} octets ; au-delà de "
        f"OCULAR_MAX_INTERNAL_JSON_BYTES le web rend 502 à chaque poll"
    )


def test_live_stays_readable_by_the_web_across_repeated_polls(live_client, monkeypatch):
    """Bout en bout : c'est `internal_get_json` (côté web) qui doit accepter la
    réponse, poll après poll — un 502 ici est définitif, l'entrée hostile restant
    dans le tampon pour toute la session."""
    from web.internal_http import CaptureError, _read_capped, _max_bytes

    cap = NetworkCapture()
    cap.console.append({"level": "log", "text": "A" * (20 * 1024 * 1024)})
    ss._state.update(page=_FakePage(), cap=cap)

    read_cap = _max_bytes("OCULAR_MAX_INTERNAL_JSON_BYTES", 16 * 1024 * 1024)

    class _Resp:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self, n: int) -> bytes:
            return self._payload[:n]

    for poll in range(3):
        payload = _live(live_client).content
        try:
            _read_capped(_Resp(payload), read_cap, "live")
        except CaptureError as exc:
            pytest.fail(f"poll {poll + 1} refusé par le web -> 502 permanent : {exc}")


def test_live_findings_cardinality_is_capped(live_client, monkeypatch):
    """Un DOM hostile fabrique autant de détections qu'il veut : 131 072 pour
    2 Mio de `document.cookie;`, soit 21,9 Mio de JSON pour ce seul champ."""
    monkeypatch.setenv("OCULAR_MAX_FINDINGS", "25")
    ss._state.update(page=_FakePage("document.cookie;" * 5000), cap=NetworkCapture())
    data = _live(live_client).json()
    assert len(data["findings"]) == 25
    assert data["truncation"]["findings_dropped"] > 0


# --- 1 bis. le délestage porte sur TOUTES les fenêtres, pas sur trois noms ---

def test_every_variable_volume_window_is_shed_including_ones_never_named():
    """Le délestage bouclait sur le tuple littéral (console, network, findings)
    et laissait `forms` et `mailtos` — deux listes du même payload, 100 %
    dictées par la page — hors de son champ. Mesuré sur 651840c : réponse de
    490 631 octets, `truncation` à ZÉRO donc annoncée COMPLÈTE, aux plafonds
    1 024, 65 536 et 262 144.

    LA MUTATION QUI COMPTE est dans ce test : `fenetre_inventee_2027` n'est
    nommée nulle part dans le code de production. Si le délestage redevient une
    liste de noms, ce champ (et le prochain champ ajouté au payload) survit au
    plafond et ce test échoue."""
    payload = {
        "network": [{"url": "u" * 1000} for _ in range(300)],
        "console": [{"text": "c" * 1000} for _ in range(300)],
        "findings": [{"rule": "r" * 1000} for _ in range(300)],
        "forms": [{"action": "a" * 500, "method": "POST"} for _ in range(100)],
        "mailtos": ["m" * 320 for _ in range(100)],
        "fenetre_inventee_2027": ["z" * 1000 for _ in range(300)],
        "counts": {"network": 300, "findings": 300, "console": 300},
        "truncation": Truncation().model_dump(mode="json"),
        "analysis_stale": False,
        "verdict": "benign",
    }
    for cap in (1024, 65536, 262144):
        fitted = ss._fit_live_payload(json.loads(json.dumps(payload)), cap)
        size = len(json.dumps(fitted))
        assert size <= cap, (
            f"cap={cap} : réponse de {size} octets. Une fenêtre de volume "
            f"variable échappe au délestage"
        )
        for window in ("forms", "mailtos", "fenetre_inventee_2027"):
            counter = f"{window}_dropped"
            assert fitted["truncation"].get(counter, 0) > 0, (
                f"cap={cap} : `{window}` délestée SANS le dire — "
                f"la réponse s'annonce complète alors qu'elle ne l'est pas"
            )


def test_the_live_response_stays_under_its_budget_whatever_the_page_emits(live_client, monkeypatch):
    """La propriété, mesurée en bout de chaîne sur la réponse RÉELLE : quel que
    soit le budget, `/live` reste sous son plafond et le web l'accepte poll
    après poll. Bout en bout sur 651840c avec
    `OCULAR_MAX_INTERNAL_JSON_BYTES=262144` — un RESSERREMENT, l'opération que
    §2.10 sanctionne comme légitime : 0 poll servi sur 3, tous en 502."""
    from web.internal_http import CaptureError, _read_capped

    cap = NetworkCapture(keep="last")
    hooks = _wire(cap)
    for i in range(60):
        hooks["request"](_Req(f"https://x.test/{i}?q={'a' * 300}", post_data="p" * 300))
    ss._state.update(page=_FakePage(_hostile_dom()), cap=cap)

    class _Resp:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self, n: int) -> bytes:
            return self._payload[:n]

    for budget in (1024, 65536, 262144, DOC_LIVE_JSON_BYTES):
        monkeypatch.setenv("OCULAR_MAX_LIVE_JSON_BYTES", str(budget))
        _reset_live_state()
        for poll in range(3):
            body = _live(live_client).content
            assert len(body) <= budget, (
                f"budget={budget} poll={poll + 1} : réponse de {len(body)} octets"
            )
            try:
                _read_capped(_Resp(body), budget, "live")
            except CaptureError as exc:
                pytest.fail(f"budget={budget} poll={poll + 1} refusé par le web : {exc}")


# --- 2. plus de perte de preuve silencieuse ---------------------------------

def test_live_reports_what_the_session_cap_dropped(live_client, monkeypatch):
    """La mesure de la revue, à l'identique : `OCULAR_MAX_NETWORK_ENTRIES=3`,
    50 requêtes émises, puis le POST d'exfiltration."""
    monkeypatch.setenv("OCULAR_MAX_NETWORK_ENTRIES", "3")
    cap = NetworkCapture(keep="last")
    hooks = _wire(cap)
    for i in range(50):
        hooks["request"](_Req(f"https://benin.test/asset{i}.js"))
    hooks["request"](_Req("https://evil.test/exfil?cookie=SECRET"))
    ss._state.update(page=_FakePage(), cap=cap)

    data = _live(live_client).json()

    assert "truncation" in data, "troncature muette : /live ne dit pas ce qu'il a jeté"
    assert data["truncation"]["network_dropped"] == 48
    assert data["counts"]["network"] == 51, (
        "`counts` doit rester le compte TOTAL émis, pas le contenu du tampon"
    )
    assert any("evil.test" in e["url"] for e in data["network"]), (
        "le POST d'exfiltration émis après le plafond a disparu sans trace"
    )


def test_interactive_capture_keeps_the_most_recent_entries():
    """Le tier interactif INVERSE le choix du tier batch : l'analyste pilote la
    page pour déclencher l'exfiltration, elle arrive donc en fin de session."""
    import os
    os.environ["OCULAR_MAX_NETWORK_ENTRIES"] = "3"
    try:
        cap = NetworkCapture(keep="last")
        hooks = _wire(cap)
        for i in range(10):
            hooks["request"](_Req(f"https://x.test/{i}"))
        assert [e["url"] for e in cap.network] == [
            "https://x.test/7", "https://x.test/8", "https://x.test/9",
        ]
        assert cap.dropped_network == 7
        # ... et l'index de requêtes ne fuit pas avec la fenêtre glissante.
        assert len(cap._req_index) == 3
    finally:
        del os.environ["OCULAR_MAX_NETWORK_ENTRIES"]


def test_batch_capture_still_keeps_the_first_entries():
    """Non-régression : la justification du tier batch (« la chaîne de
    chargement initiale documente la page ») reste vraie par défaut."""
    import os
    os.environ["OCULAR_MAX_NETWORK_ENTRIES"] = "3"
    try:
        cap = NetworkCapture()
        hooks = _wire(cap)
        for i in range(10):
            hooks["request"](_Req(f"https://x.test/{i}"))
        assert [e["url"] for e in cap.network] == [
            "https://x.test/0", "https://x.test/1", "https://x.test/2",
        ]
        assert cap.dropped_network == 7
    finally:
        del os.environ["OCULAR_MAX_NETWORK_ENTRIES"]


def test_session_capture_is_armed_to_keep_the_most_recent(monkeypatch):
    """La politique doit être posée là où la session arme sa capture, sinon le
    tier interactif retombe sur le défaut batch."""
    import inspect
    source = inspect.getsource(ss._launch_browser)
    assert 'NetworkCapture(keep="last")' in source, (
        "le tier interactif arme une capture batch : le plafond cumulé sur toute "
        "la session jetterait les entrées les plus tardives"
    )


# --- 3. une seule analyse en vol par DOM ------------------------------------

def test_concurrent_polls_of_the_same_dom_run_a_single_analysis():
    """20 polls simultanés -> 1 analyse. Le mémo seul ne suffit pas : il est
    écrit APRÈS l'analyse, donc 20 appels concurrents le manquent tous."""
    inflight = {"cur": 0, "peak": 0, "total": 0}
    lock = threading.Lock()
    real = ss.scan_html

    def _spy(html):
        with lock:
            inflight["cur"] += 1
            inflight["total"] += 1
            inflight["peak"] = max(inflight["peak"], inflight["cur"])
        time.sleep(0.05)
        try:
            return real(html)
        finally:
            with lock:
                inflight["cur"] -= 1

    async def _scenario():
        _reset_live_state()
        ss._state.update(page=_FakePage("<html><body>même dom</body></html>"),
                         cap=NetworkCapture())
        ss.scan_html = _spy
        try:
            return await asyncio.gather(*[ss.live() for _ in range(20)])
        finally:
            ss.scan_html = real

    results = asyncio.run(_scenario())

    assert inflight["peak"] == 1, (
        f"pic de concurrence {inflight['peak']} : une sérialisation a été "
        f"remplacée par une concurrence non bornée"
    )
    assert inflight["total"] == 1, f"{inflight['total']} analyses pour un DOM unique"
    # ... et les 20 appelants reçoivent bien le même résultat, pas un cache vide.
    assert all(r["findings"] == results[0]["findings"] for r in results)


def test_a_mutating_dom_still_runs_one_analysis_at_a_time():
    """LA PORTE QUE LE SINGLE-FLIGHT NE FERME PAS. Sa clef est l'empreinte du
    DOM : une page qui change d'un octet par poll la manque à tous les coups, et
    N polls simultanés redevenaient N analyses sérialisées par le GIL. Mesuré
    bout en bout (uvicorn + le vrai client interne et son échéance de 5,0 s,
    512 Kio de `atob(`) : N=1 -> 1/1 servi ; N=2 -> 2/2 ; N=4 -> 0/4 ; N=20 ->
    0/20, toutes en 502.

    La borne ne dépend d'aucune liste d'appelants : `_live_analysis` ne lance
    une analyse que lorsque `_LIVE_INFLIGHT` est vide, et c'est le seul endroit
    qui y écrit."""
    inflight = {"cur": 0, "peak": 0, "total": 0}
    lock = threading.Lock()
    real = ss.scan_html

    def _spy(html):
        with lock:
            inflight["cur"] += 1
            inflight["total"] += 1
            inflight["peak"] = max(inflight["peak"], inflight["cur"])
        time.sleep(0.05)
        try:
            return real(html)
        finally:
            with lock:
                inflight["cur"] -= 1

    async def _scenario():
        _reset_live_state()
        ss._state.update(page=_MutatingPage(), cap=NetworkCapture())
        ss.scan_html = _spy
        try:
            # deux vagues : la première sans rien en mémo, la seconde avec.
            first = await asyncio.gather(*[ss.live() for _ in range(20)])
            second = await asyncio.gather(*[ss.live() for _ in range(20)])
            return first, second
        finally:
            ss.scan_html = real

    first, second = asyncio.run(_scenario())

    assert inflight["peak"] == 1, (
        f"pic de concurrence {inflight['peak']} : N onglets se multiplient en N "
        f"analyses, et la latence franchit l'échéance du client"
    )
    assert inflight["total"] == 2, (
        f"{inflight['total']} analyses pour 40 polls d'un DOM mutant : la borne "
        f"n'est pas tenue"
    )
    assert len(first) == 20 and len(second) == 20, "des polls sont restés sans réponse"
    # ... et ceux qui reçoivent une analyse d'un autre tour le DISENT.
    assert sum(1 for r in first + second if r["analysis_stale"]) == 38
    assert all("verdict" in r and "counts" in r for r in first + second)


def test_a_lone_poller_never_gets_a_stale_analysis():
    """Non-régression sur l'usage NORMAL (un onglet, polls séquentiels) : la
    borne de concurrence ne doit jamais s'y déclencher — chaque tour analyse le
    DOM du tour."""
    async def _scenario():
        _reset_live_state()
        page = _FakePage("<html><body>rien</body></html>")
        ss._state.update(page=page, cap=NetworkCapture())
        out = []
        for i in range(5):
            page.set_dom(f'<form action="https://evil.example/{i}" method="POST"></form>')
            out.append(await ss.live())
        return out

    polls = asyncio.run(_scenario())
    assert [p["analysis_stale"] for p in polls] == [False] * 5
    assert polls[-1]["forms"] == [{"action": "https://evil.example/4", "method": "POST"}]


def test_a_changed_dom_is_still_reanalyzed():
    """Non-régression : le single-flight ne doit pas figer l'analyse."""
    calls = {"n": 0}
    real = ss.scan_html

    def _spy(html):
        calls["n"] += 1
        return real(html)

    async def _scenario():
        _reset_live_state()
        page = _FakePage("<html><body>rien</body></html>")
        ss._state.update(page=page, cap=NetworkCapture())
        ss.scan_html = _spy
        try:
            first = await ss.live()
            page.set_dom('<form action="https://evil.example/collect" method="POST"></form>')
            second = await ss.live()
            return first, second
        finally:
            ss.scan_html = real

    first, second = asyncio.run(_scenario())
    assert calls["n"] == 2
    assert first["forms"] == []
    assert second["forms"] == [{"action": "https://evil.example/collect", "method": "POST"}]


# --- 4. non-régression sur une session LÉGITIME -----------------------------

def test_a_benign_live_poll_is_unchanged_and_declares_itself_complete(live_client):
    cap = NetworkCapture(keep="last")
    hooks = _wire(cap)
    for i in range(12):
        hooks["request"](_Req(f"https://banque.example/app/{i}.js"))
    hooks["console"](type("M", (), {"type": "log", "text": "prêt"})())
    ss._state.update(page=_FakePage('<form action="/login" method="POST"></form>'), cap=cap)

    data = _live(live_client).json()

    assert data["counts"]["network"] == 12 and len(data["network"]) == 12
    assert data["counts"]["console"] == 1
    assert data["forms"] == [{"action": "/login", "method": "POST"}]
    # Attendu DÉRIVÉ du modèle : recopié à la main, ce dict devenait faux au
    # premier compteur ajouté à `Truncation` — et il l'a été (`other_dropped`,
    # `over_cap_bytes`). La propriété testée est « TOUS les compteurs à zéro »,
    # pas « ces six-là à zéro ».
    from engine.result import Truncation as _T
    assert json.loads(json.dumps(data["truncation"])) == {k: 0 for k in _T.model_fields}
