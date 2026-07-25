# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Limites de taille du RÉSULTAT — symétrie avec la garde anti-OOM des artefacts.

Les artefacts (screenshot, DOM) sont plafonnés depuis l'origine
(`_max_artifact_bytes`, 32 Mio, cf. tests/test_wrapper.py) parce qu'« une page
HOSTILE peut gonfler son DOM ». Les entrées RÉSEAU ne l'étaient pas : le corps
des requêtes capturées (`post_data`) était stocké BRUT, `network`/`console`
n'avaient aucun plafond de CARDINALITÉ, `_req_index` n'était jamais purgé, et la
lecture des réponses internes du web (`internal_capture`, `internal_get_json`)
n'était pas bornée.

La chaîne complète part de la page analysée : page hostile -> `network` massif ->
stdout du runner -> broker (`mem_limit 1g`) -> Redis monté sur **tmpfs**, donc en
RAM de l'hôte -> recopie en SQLite.

FAIL-CLOSED : une lecture hors-cap est une ERREUR rendue à l'appelant (502) ; une
liste ou un corps tronqué est SIGNALÉ dans le résultat (`OcularResult.truncation`,
`NetworkEntry.post_data_truncated`) — jamais une amputation muette.
"""
import io
import urllib.request

import pytest
from pydantic import ValidationError

from engine.result import POST_DATA_MAX_CHARS, NetworkEntry, OcularResult
from engine.wrapper import NetworkCapture, ResultBuilder
from web.internal_http import CaptureError, internal_capture, internal_get_json


# --- doublures Playwright (mêmes formes que tests/test_wrapper.py) -------------
class _FakePage:
    def __init__(self):
        self._handlers = {}

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)

    def fire(self, event, *args):
        for h in self._handlers.get(event, []):
            h(*args)


class _FakeRequest:
    def __init__(self, url, method="POST", resource_type="xhr", post_data=None):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data = post_data


class _FakeConsoleMsg:
    def __init__(self, type_, text):
        self.type = type_
        self.text = text


# --- (a) corps de requête : plafond d'OCTETS + marqueur ------------------------
def test_post_data_is_truncated_and_flagged(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_POST_DATA_BYTES", "64")
    page, cap = _FakePage(), NetworkCapture()
    cap.attach(page)
    # Une page hostile qui exfiltre par POST : 4 Mio de corps, gardés BRUTS.
    page.fire("request", _FakeRequest("https://evil.example/collect", post_data="A" * 4_000_000))
    page.fire("request", _FakeRequest("https://evil.example/ok", post_data="court"))

    assert len(cap.network[0]["post_data"]) == 64, "corps de requête stocké sans plafond"
    # Marqueur PAR ENTRÉE, posé par le point unique de coupe : il NOMME le champ
    # amputé, là où `truncation` ne désigne aucune entrée.
    assert cap.network[0]["truncated_fields"] == ["post_data"]
    assert NetworkEntry(**cap.network[0]).post_data_truncated is True, (
        "l'alias historique doit rester servi pour les payloads déjà stockés"
    )
    # ... et une requête normale n'est PAS marquée (pas de faux positif). Le
    # marqueur est POSÉ UNIQUEMENT quand il y a troncature : une entrée intacte
    # garde exactement la forme historique du dict.
    assert cap.network[1]["post_data"] == "court"
    assert "truncated_fields" not in cap.network[1]
    assert "post_data_truncated" not in cap.network[1]
    assert NetworkEntry(**cap.network[1]).post_data_truncated is False
    assert NetworkEntry(**cap.network[1]).truncated_fields == []
    assert cap.truncation().post_data_truncated == 1


def test_network_entry_model_rejects_oversized_post_data():
    # Backstop de contrat : même hors du chemin `NetworkCapture`, le modèle
    # refuse un corps hors-cap (erreur explicite, pas un stockage silencieux).
    NetworkEntry(url="https://x/", method="POST", post_data="x" * POST_DATA_MAX_CHARS)
    with pytest.raises(ValidationError):
        NetworkEntry(url="https://x/", method="POST", post_data="x" * (POST_DATA_MAX_CHARS + 1))


# --- (b) cardinalité network / console + purge de `_req_index` -----------------
def test_network_cardinality_is_capped_and_counted(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_NETWORK_ENTRIES", "50")
    page, cap = _FakePage(), NetworkCapture()
    cap.attach(page)
    for i in range(500):
        page.fire("request", _FakeRequest(f"https://evil.example/{i}"))

    assert len(cap.network) == 50, "cardinalité réseau sans plafond"
    # `_req_index` grandissait à l'infini en parallèle de `network`.
    assert len(cap._req_index) <= 50, "index des requêtes jamais purgé"
    assert cap.truncation().network_dropped == 450


def test_console_cardinality_is_capped_and_counted(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_CONSOLE_ENTRIES", "10")
    page, cap = _FakePage(), NetworkCapture()
    cap.attach(page)
    for i in range(100):
        page.fire("console", _FakeConsoleMsg("log", f"spam {i}"))

    assert len(cap.console) == 10, "cardinalité console sans plafond"
    assert cap.truncation().console_dropped == 90


# --- marqueur de troncature DANS le résultat rendu à l'analyste ---------------
def test_result_carries_an_explicit_truncation_marker(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_NETWORK_ENTRIES", "5")
    monkeypatch.setenv("OCULAR_MAX_CONSOLE_ENTRIES", "5")
    monkeypatch.setenv("OCULAR_MAX_POST_DATA_BYTES", "8")
    result, _ = ResultBuilder().build(
        job_id="j", profile="capture", target="https://evil.example/", input_hash=None,
        verdict="unknown",
        network=[{"url": f"https://evil.example/{i}", "method": "POST",
                  "post_data": "A" * 4096} for i in range(20)],
        console=[{"level": "log", "text": f"spam {i}"} for i in range(20)],
    )
    # Le résultat est amputé ...
    assert len(result.network) == 5 and len(result.console) == 5
    # ... et le DIT : l'analyste doit savoir qu'il ne regarde pas tout.
    assert result.truncation.network_dropped == 15
    assert result.truncation.console_dropped == 15
    assert result.truncation.post_data_truncated == 5
    assert result.network[0].post_data_truncated is True
    assert len(result.network[0].post_data) == 8


def test_untruncated_result_reports_no_truncation():
    result, _ = ResultBuilder().build(
        job_id="j", profile="capture", target="https://example.com/", input_hash=None,
        verdict="benign",
        network=[{"url": "https://example.com/a", "method": "GET"}],
        console=[{"level": "log", "text": "ok"}],
    )
    assert result.truncation.network_dropped == 0
    assert result.truncation.console_dropped == 0
    assert result.truncation.post_data_truncated == 0
    assert result.network[0].post_data_truncated is False


def test_truncation_field_is_backward_compatible():
    # Un payload 1.0 SANS `truncation` (résultat déjà en base) reste valide.
    payload = {
        "schema_version": "1.0", "job_id": "j", "profile": "analysis",
        "target": "inline-html", "timestamp": "2026-07-12T10:00:00Z", "verdict": "benign",
    }
    r = OcularResult.model_validate(payload)
    assert r.truncation.network_dropped == 0


# --- (c) lecture bornée des réponses internes du web --------------------------
class _FakeHTTPResponse(io.BytesIO):
    """Doublure de la réponse d'`urlopen` : `read(n)` borné comme le vrai."""

    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _serve(monkeypatch, body: bytes):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: _FakeHTTPResponse(body))


def test_internal_capture_refuses_oversized_response(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_INTERNAL_CAPTURE_BYTES", "1024")
    _serve(monkeypatch, b'{"result": {}, "blobs": {"x": "' + b"A" * 4096 + b'"}}')
    with pytest.raises(CaptureError):
        internal_capture("http://ocular-sess-x:8080/capture", "s")


def test_internal_capture_accepts_response_under_cap(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_INTERNAL_CAPTURE_BYTES", "1024")
    _serve(monkeypatch, b'{"result": {"job_id": "j"}, "blobs": {}}')
    assert internal_capture("http://ocular-sess-x:8080/capture", "s")["result"]["job_id"] == "j"


def test_internal_get_json_refuses_oversized_response(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_INTERNAL_JSON_BYTES", "512")
    _serve(monkeypatch, b'{"network": [' + b'{"url": "https://x/"},' * 1000 + b'{}]}')
    with pytest.raises(CaptureError):
        internal_get_json("http://ocular-sess-x:8080/live", "s")


def test_internal_get_json_accepts_response_under_cap(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_INTERNAL_JSON_BYTES", "512")
    _serve(monkeypatch, b'{"network": [], "verdict": "benign"}')
    assert internal_get_json("http://ocular-sess-x:8080/live", "s")["verdict"] == "benign"
