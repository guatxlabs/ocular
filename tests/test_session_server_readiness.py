"""`/health` du `session_server` = DISPONIBILITÉ, pas simple vivacité.

Défaut corrigé ici : `/health` renvoyait `{"ok": True}` dès qu'uvicorn écoutait,
alors que Camoufox n'était lancé que PARESSEUSEMENT, au premier `/goto`. Le
signal annonçait donc « prête » ~4 s avant que la session sache réellement
servir `/goto` / `/capture`. Un client suivant le contrat documenté (202 puis
sonde `GET /sessions/{id}` jusqu'à `ready`, puis capture) recevait un 502 sur
une session pourtant saine — `/capture` répondait 409 « no active session »,
que le web traduit en 502.

Le correctif : le navigateur est démarré À L'AMORÇAGE du conteneur (tâche de
`_lifespan`) et `/health` ne passe au vert QU'UNE FOIS `_state["page"]` vivante.
Aucune temporisation en dur : c'est l'existence réelle de la page qui fait foi.

Ces tests portent sur la SÉMANTIQUE du signal, sans Camoufox : ils pilotent
directement `_state["page"]`, exactement comme `test_session_server_logic.py`
teste la composition du résultat sans navigateur.
"""
import asyncio

import pytest
from fastapi.testclient import TestClient

import runner_recon_vnc.session_server as ss


@pytest.fixture(autouse=True)
def _clean_state():
    ss._state.update(
        cm=None, page=None, cap=None, target=None, kind=None,
        html_input="", guard=None, boot_error=None,
    )
    yield
    ss._state.update(
        cm=None, page=None, cap=None, target=None, kind=None,
        html_input="", guard=None, boot_error=None,
    )


class _FakePage:
    """Suffit à `/health` : il ne teste que la PRÉSENCE d'une page."""


def test_health_not_ok_while_browser_not_started():
    """LE test qui mord : sans navigateur, `/health` ne doit PAS être 2xx.

    `web.internal_http.internal_get_ok` ne considère prête qu'une réponse
    `200 <= status < 300` ; un 503 laisse donc `_session_state` en `starting`,
    ce qui est exactement le comportement recherché.
    """
    c = TestClient(ss.app)
    r = c.get("/health")
    assert r.status_code == 503
    assert r.json()["ok"] is False


def test_health_ok_once_browser_is_up():
    ss._state["page"] = _FakePage()
    c = TestClient(ss.app)
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_health_needs_no_secret_even_when_not_ready():
    """`/health` reste la SEULE route sans secret (cf. test_session_server_auth) :
    le passage à 503 ne doit pas la transformer en route authentifiée."""
    c = TestClient(ss.app)
    assert c.get("/health").status_code == 503  # 503, pas 403


def test_health_reports_boot_failure_without_leaking_details():
    """Un échec de lancement doit rester NON prêt (fail-closed) : le web ne
    verra jamais `ready`, son échéance expirera et la session sera stoppée —
    plutôt qu'une session annoncée prête qui répond 502 à chaque capture.
    Le détail de l'erreur ne sort pas (type seul, pas de message/chemin)."""
    ss._state["boot_error"] = "RuntimeError"
    c = TestClient(ss.app)
    r = c.get("/health")
    assert r.status_code == 503
    body = r.json()
    assert body["ok"] is False
    assert body["state"] == "error"


def test_ensure_browser_is_serialised_and_launches_once():
    """Le démarrage à l'amorçage et un `/goto` concurrent entrent tous deux
    dans `_ensure_browser` : sans verrou, DEUX Camoufox (et deux gardes egress)
    seraient lancés et le premier fuirait. Le verrou + la re-vérification sous
    verrou garantissent UN SEUL lancement."""
    calls = []

    async def _fake_launch():
        calls.append(1)
        await asyncio.sleep(0)  # cède la main : force l'entrelacement
        ss._state["page"] = _FakePage()

    async def _race():
        await asyncio.gather(*(ss._ensure_browser() for _ in range(5)))

    original = ss._launch_browser
    ss._launch_browser = _fake_launch
    try:
        asyncio.run(_race())
    finally:
        ss._launch_browser = original

    assert calls == [1]


def test_boot_browser_records_failure_instead_of_crashing():
    """L'amorçage ne doit JAMAIS tuer le conteneur : une panne de lancement est
    consignée dans `_state["boot_error"]` (et lue par `/health`), pas propagée."""
    async def _boom():
        raise RuntimeError("camoufox indisponible")

    original = ss._launch_browser
    ss._launch_browser = _boom
    try:
        asyncio.run(ss._boot_browser())
    finally:
        ss._launch_browser = original

    assert ss._state["boot_error"] == "RuntimeError"
    assert ss._state["page"] is None
