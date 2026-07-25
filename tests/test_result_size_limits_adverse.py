# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Plafonds du résultat mesurés sur une entrée ADVERSE, pas sur un échantillon bénin.

`tests/test_result_size_limits.py` verrouille la CARDINALITÉ (« pas plus de 5000
entrées ») et le corps `post_data`. Il ne dit RIEN de la TAILLE d'une entrée : une
page hostile n'a donc pas besoin d'émettre beaucoup d'entrées, il lui suffit d'en
émettre UNE énorme. Mesuré sur le dépôt avant ce fichier :

  - un seul `console.log` de 20 Mio -> `OcularResult` sérialisé de 20,0 Mio,
    annoncé COMPLET (`truncation` à zéro) ;
  - 5000 entrées réseau dont l'URL fait 20 Ko -> 96,2 Mio (linéaire en la taille
    d'URL : à 200 Ko/URL on atteint ~1 Gio).

Ce que ce fichier verrouille :
  1. chaque champ de texte dicté par la page est borné EN OCTETS à la source ;
  2. le nombre de `static_findings` est borné (une page en fabrique des centaines
     de milliers — cf. tests/test_static_linear.py) ;
  3. le JSON sérialisé du résultat tient sous un plafond MESURÉ, quoi qu'émette
     la page — c'est ce qui empêche le plafond de LECTURE côté web de se
     transformer en refus permanent (cf. tests/test_session_server_live_bounds.py) ;
  4. tout ce qui est coupé est COMPTÉ dans `OcularResult.truncation` ;
  5. les plafonds eux-mêmes ne sont pas retirables, et une valeur illisible ou
     hors bornes est journalisée, jamais substituée en silence.

Les valeurs écrites en dur ici (8192 octets, 32 Mio…) sont les DÉFAUTS PUBLIÉS de
docs/DEPLOY-SECURITY.md §2.10 : le test est le garde-fou de la doc.
"""
import json
import logging

import pytest

from engine.result import DomInfo, OcularResult, StaticFinding, Truncation
from engine.wrapper import NetworkCapture, ResultBuilder, _max_console_entries, _max_network_entries

# Défauts publiés (§2.10). Écrits en dur : si un défaut change, ce test doit
# changer AVEC la doc, jamais en silence.
DOC_POST_DATA_BYTES = 8192
DOC_CONSOLE_TEXT_BYTES = 8192
DOC_URL_BYTES = 4096
DOC_RESULT_JSON_BYTES = 32 * 1024 * 1024


def _build(**kw) -> OcularResult:
    result, _ = ResultBuilder().build(
        job_id="j", profile="capture", target="https://x.test/",
        input_hash=None, verdict="unknown", **kw,
    )
    return result


def _json_bytes(result: OcularResult) -> int:
    """Même sérialiseur que `emit_wrapper` (stdout du runner) : c'est cette
    taille-là qui traverse le broker, Redis (tmpfs = RAM hôte) puis SQLite."""
    return len(json.dumps(result.model_dump(mode="json")))


def _marked(result: OcularResult, field: str) -> int:
    """Compteur de troncature, 0 s'il n'existe pas — un résultat qui ne PEUT PAS
    signaler une coupe est un résultat qui s'annonce complet à tort."""
    return getattr(result.truncation, field, 0)


class _Req:
    def __init__(self, url: str, post_data=None) -> None:
        self.url, self.method, self.resource_type, self.post_data = url, "POST", "xhr", post_data


class _Msg:
    def __init__(self, text: str) -> None:
        self.type, self.text = "log", text


@pytest.fixture
def warnings_of():
    """Capture les WARNING d'un logger NOMMÉ, sans dépendre de l'état global du
    module `logging`. `caplog` ne convient pas ici : il s'appuie sur la
    propagation jusqu'à la racine, et `tests/test_logging.py` laisse le logger
    « ocular » à CRITICAL (état de module, que `monkeypatch` ne restaure pas) —
    le test passait donc seul et échouait dans la suite complète."""
    installed = []

    def _capture(name: str) -> list[str]:
        logger = logging.getLogger(name)
        records: list[str] = []

        class _Sink(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        sink = _Sink(logging.WARNING)
        logger.addHandler(sink)
        previous = logger.level
        logger.setLevel(logging.WARNING)
        installed.append((logger, sink, previous))
        return records

    yield _capture
    for logger, sink, previous in installed:
        logger.removeHandler(sink)
        logger.setLevel(previous)


def _attach() -> tuple[NetworkCapture, dict]:
    cap, hooks = NetworkCapture(), {}

    class _Page:
        def on(self, event, fn):
            hooks[event] = fn

    cap.attach(_Page())
    return cap, hooks


# --- 1. taille d'UNE entrée -------------------------------------------------

def test_a_single_giant_console_message_is_clipped_and_counted():
    """L'entrée UNIQUE de 20 Mio : la cardinalité (1 < 5000) ne mord pas, seule
    une borne de TAILLE peut mordre."""
    result = _build(console=[{"level": "log", "text": "A" * (20 * 1024 * 1024)}])
    size = _json_bytes(result)
    assert size < 1024 * 1024, f"un seul message console dicte {size} octets de résultat"
    assert _marked(result, "text_truncated") >= 1, (
        "message console coupé sans être compté : le résultat s'annonce complet"
    )


def test_a_single_giant_url_is_clipped_and_counted():
    result = _build(network=[{"url": "https://e.test/" + "u" * (2 * 1024 * 1024), "method": "GET"}])
    size = _json_bytes(result)
    assert size < 1024 * 1024, f"une seule URL dicte {size} octets de résultat"
    assert _marked(result, "text_truncated") >= 1


def test_giant_headers_are_clipped_and_counted():
    headers = {f"x-{i}": "v" * 20000 for i in range(50)}
    result = _build(network=[{"url": "https://e.test/", "method": "GET", "headers": headers}])
    size = _json_bytes(result)
    assert size < 1024 * 1024, f"les en-têtes d'une entrée dictent {size} octets"
    assert _marked(result, "text_truncated") >= 1


def test_a_giant_page_title_is_clipped_and_counted():
    """`document.title = 'x'.repeat(1e7)` : le titre suit le même chemin que le
    reste et n'est borné nulle part."""
    result = _build(dom_info=DomInfo(title="T" * (10 * 1024 * 1024), final_url="https://x.test/"))
    size = _json_bytes(result)
    assert size < 1024 * 1024, f"le titre de la page dicte {size} octets de résultat"
    assert _marked(result, "text_truncated") >= 1


def test_five_thousand_fat_urls_stay_under_the_published_budget():
    """La mesure de la revue : 5000 × URL de 20 Ko -> 96,2 Mio."""
    net = [{"url": "https://e.test/" + "u" * 20000, "method": "GET"} for _ in range(5000)]
    size = _json_bytes(_build(network=net))
    assert size <= DOC_RESULT_JSON_BYTES, f"résultat de {size} octets"


# --- 2. cardinalité des findings -------------------------------------------

def test_static_findings_cardinality_is_capped_and_counted(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_FINDINGS", "10")
    findings = [
        StaticFinding(rule="r", severity="low", match="m", line=i, context="c")
        for i in range(100)
    ]
    result = _build(static_findings=findings)
    assert len(result.static_findings) == 10, "cardinalité des findings sans plafond"
    assert _marked(result, "findings_dropped") == 90


# --- 3. garantie MESURÉE sur le JSON sérialisé ------------------------------

@pytest.mark.parametrize("hostile", [
    pytest.param(lambda: {"console": [{"level": "log", "text": "\x00" * 8192} for _ in range(5000)]},
                 id="console-nuls-echappement-x6"),
    pytest.param(lambda: {"network": [{"url": "https://e.test/x", "method": "POST",
                                       "post_data": "\x00" * 8192} for _ in range(5000)]},
                 id="post-data-nuls-echappement-x6"),
    pytest.param(lambda: {"network": [{"url": "https://e.test/" + "u" * 4096, "method": "POST",
                                       "post_data": "p" * 8192,
                                       "headers": {"h": "v" * 8192}} for _ in range(5000)]},
                 id="tout-au-plafond"),
])
def test_serialized_result_always_fits_the_budget(hostile):
    """Les plafonds PAR ENTRÉE ne suffisent pas à eux seuls : `json.dumps`
    échappe un octet de contrôle en `\\u00XX`, soit ×6. La garantie ne peut donc
    pas être arithmétique — elle est MESURÉE puis rétablie par délestage."""
    size = _json_bytes(_build(**hostile()))
    assert size <= DOC_RESULT_JSON_BYTES, (
        f"résultat sérialisé de {size} octets > plafond publié {DOC_RESULT_JSON_BYTES}"
    )


def test_worst_case_capture_payload_fits_the_internal_read_cap():
    """Le maillon suivant : `/capture` transporte le résultat ET les blobs en
    base64, et le web REFUSE (502) au-delà d'`OCULAR_MAX_INTERNAL_CAPTURE_BYTES`.
    Si le pire cas ne tient pas sous ce plafond, une page hostile reprend le
    pouvoir de rendre la capture irrécupérable — le défaut même qu'on ferme.

    Pire cas aux DÉFAUTS : deux artefacts au plafond (screenshot + DOM) plus un
    résultat saturé d'octets nuls (échappement JSON ×6). Mesuré : 114,10 Mio
    pour un plafond de 128 Mio, soit 13,90 Mio de marge."""
    import os
    from engine.wrapper import _max_artifact_bytes, wrapper_payload
    from web.internal_http import _max_bytes

    builder = ResultBuilder()
    art = _max_artifact_bytes()
    builder.add_screenshot(0, "interactive", b"\x89PNG" + os.urandom(art - 4))
    builder.set_dom(b"<html>" + os.urandom(art - 6))
    result, blobs = builder.build(
        job_id="j", profile="capture", target="https://x.test/", input_hash=None,
        verdict="unknown",
        console=[{"level": "log", "text": "\x00" * 8192} for _ in range(5000)],
        network=[{"url": "https://e.test/" + "u" * 4096, "method": "POST",
                  "post_data": "\x00" * 8192, "headers": {"h": "v" * 8192}}
                 for _ in range(5000)],
    )
    payload = len(json.dumps(wrapper_payload(result, blobs)))
    cap = _max_bytes("OCULAR_MAX_INTERNAL_CAPTURE_BYTES", 128 * 1024 * 1024)
    assert payload <= cap, (
        f"payload /capture de {payload} octets > plafond de lecture {cap} : "
        f"la capture serait refusée en 502, donc irrécupérable"
    )


def test_shedding_is_counted_never_silent():
    result = _build(console=[{"level": "log", "text": "\x00" * 8192} for _ in range(5000)])
    assert result.truncation != Truncation(), (
        "des entrées ont été délestées sans que le résultat le dise"
    )


# --- 4. non-régression sur une capture LÉGITIME -----------------------------

def test_a_benign_result_is_untouched_and_declares_itself_complete():
    """Aucune borne ne doit mordre sur une capture normale d'analyste."""
    net = [{"url": f"https://site.test/a{i}.js", "method": "GET", "status": 200} for i in range(40)]
    con = [{"level": "log", "text": "chargement ok"} for _ in range(10)]
    result = _build(network=net, console=con,
                    dom_info=DomInfo(title="Connexion — Banque Exemple",
                                     final_url="https://site.test/login"))
    assert len(result.network) == 40 and len(result.console) == 10
    assert result.network[0].url == "https://site.test/a0.js"
    assert result.dom.title == "Connexion — Banque Exemple"
    assert result.truncation == Truncation()


# --- 5. unité RÉELLE des plafonds (octets, pas caractères) ------------------

def test_post_data_cap_is_enforced_in_bytes_not_characters():
    """`OCULAR_MAX_POST_DATA_BYTES` est documenté en OCTETS. Appliqué en
    caractères, un corps de « é » consomme 2× le budget annoncé (4× avec des
    points de code sur 4 octets), multiplié par 5000 entrées."""
    cap, hooks = _attach()
    hooks["request"](_Req("https://e.test/", post_data="é" * 20000))
    kept = len(cap.network[0]["post_data"].encode("utf-8"))
    assert kept <= DOC_POST_DATA_BYTES, (
        f"corps conservé de {kept} octets pour un plafond annoncé à {DOC_POST_DATA_BYTES}"
    )
    assert cap.truncation().post_data_truncated == 1


def test_console_text_cap_is_enforced_in_bytes_not_characters():
    cap, hooks = _attach()
    hooks["console"](_Msg("é" * 200000))
    kept = len(cap.console[0]["text"].encode("utf-8"))
    assert kept <= DOC_CONSOLE_TEXT_BYTES, f"texte console conservé de {kept} octets"


def test_url_cap_is_enforced_in_bytes_at_capture_time():
    cap, hooks = _attach()
    hooks["request"](_Req("https://e.test/" + "é" * 200000))
    kept = len(cap.network[0]["url"].encode("utf-8"))
    assert kept <= DOC_URL_BYTES, f"URL conservée de {kept} octets"


# --- 6. les plafonds eux-mêmes ne sont pas retirables -----------------------

def test_entry_caps_cannot_be_raised_past_their_hard_ceiling(monkeypatch, warnings_of):
    """§2.10 affirme « l'exploitation peut baisser ces plafonds, pas les
    retirer » : mesuré, `=999999999999` était accepté tel quel, donc le plafond
    était supprimé de fait."""
    logged = warnings_of("ocular.wrapper")
    monkeypatch.setenv("OCULAR_MAX_NETWORK_ENTRIES", "999999999999")
    value = _max_network_entries()
    assert value < 999999999999, "plafond de fait supprimé par la configuration"
    assert any("OCULAR_MAX_NETWORK_ENTRIES" in m for m in logged), (
        "valeur hors bornes substituée en silence"
    )


@pytest.mark.parametrize("raw", ["0", "-3", "abc"])
def test_out_of_range_cap_values_are_logged_not_silently_substituted(monkeypatch, warnings_of, raw):
    """`0` valait 1 alors que la variable sœur `OCULAR_MAX_ARTIFACT_BYTES`
    documente « 0 = illimité » : un exploitant appliquant la convention voisine
    ne gardait qu'UNE entrée réseau, sans aucun signal."""
    logged = warnings_of("ocular.wrapper")
    monkeypatch.setenv("OCULAR_MAX_CONSOLE_ENTRIES", raw)
    _max_console_entries()
    assert any("OCULAR_MAX_CONSOLE_ENTRIES" in m for m in logged), (
        f"valeur {raw!r} substituée en silence"
    )


def test_internal_read_caps_have_a_ceiling_too(monkeypatch):
    from web.internal_http import _max_bytes
    monkeypatch.setenv("OCULAR_MAX_INTERNAL_JSON_BYTES", "999999999999")
    assert _max_bytes("OCULAR_MAX_INTERNAL_JSON_BYTES", 16 * 1024 * 1024) < 999999999999


def test_lowering_the_read_cap_under_the_source_budget_is_flagged(monkeypatch, warnings_of):
    """Le piège inverse : un plafond de LECTURE serré sous le budget de la
    source rend la fonction inaccessible en permanence, ce qui est exactement le
    déni de service que ces plafonds sont censés éviter."""
    from web.internal_http import _max_bytes
    logged = warnings_of("ocular.internal_http")
    monkeypatch.setenv("OCULAR_MAX_INTERNAL_JSON_BYTES", str(64 * 1024))
    _max_bytes("OCULAR_MAX_INTERNAL_JSON_BYTES", 16 * 1024 * 1024)
    assert any("SOUS le budget de la source" in m for m in logged)
