# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Le coût de l'analyse statique ne doit dépendre NI de la taille du document NI
de sa FORME — les deux sont choisies par la page, qui est hostile par définition.

Ce que le tour précédent avait verrouillé ne couvrait qu'UNE forme, `document.cookie;`
répété, mesurée linéaire *avant* correctif. Trois autres formes, toutes dictées par la
page, restaient quadratiques et n'étaient testées par rien — mesuré sur 2067ee7,
chemin complet (`analyze_html` + `extract_forms` + `extract_mailtos`) :

    forme `eval(`  :  16 Kio 332 ms · 32 Kio 1 392 ms · 64 Kio 5 648 ms · 128 Kio 27 295 ms
    forme `<input` : 128 Kio 52 608 ms
    forme `<form`  :  32 Kio 2 915 ms

soit ×4 par DOUBLEMENT de taille, et ZÉRO détection produite — donc sans rapport
avec le nombre de matches. Cause : ~11 motifs en `<tag[^>]*…` et plusieurs en
`X\\s*\\(\\s*([^)]+)\\)`, dont la classe négative n'a pas de borne : le moteur
consomme jusqu'à la fin du document puis rétrograde depuis CHAQUE position de
départ.

Ce fichier verrouille donc la PROPRIÉTÉ, pas les formes déjà vues :
  1. aucun motif du module n'a de quantificateur non borné — vérifié sur
     `PATTERNS` lui-même, donc sur les motifs FUTURS aussi ;
  2. le coût reste linéaire sur une batterie de formes DÉRIVÉES des motifs
     (donc pas choisies pour passer) et sur des formes exotiques que le
     correctif ne traite pas nommément ;
  3. la fenêtre d'analyse borne le coût ABSOLU, et le dit quand elle mord.
"""
import re
import time

import pytest

from engine.result import Truncation
from engine.static import (
    PATTERNS,
    HtmlScan,
    UnboundedPatternError,
    _compile_bounded,
    analysis_window,
    max_analyzed_html_chars,
    quantifier_bounds,
    scan_html,
)

# Comme dans tests/test_static_linear.py : les `eval(`, `<input`, `document.cookie`
# de ce fichier sont des chaînes d'octets INERTES (faux DOM), jamais exécutées.

LIVE_TIMEOUT_S = 5.0  # timeout réel de `web.internal_http.internal_get_json`


# --- 1. la propriété, vérifiée sur la SOURCE des motifs ------------------------

@pytest.mark.parametrize("pattern,description", [(p, d) for p, d, _ in PATTERNS])
def test_no_pattern_has_an_unbounded_quantifier(pattern, description):
    """Le vrai verrou : il porte sur `PATTERNS`, donc sur tout motif AJOUTÉ plus
    tard, et pas sur la liste des formes qu'on a pensé à mesurer."""
    bounds = quantifier_bounds(pattern)
    assert all(b is not None for b in bounds), (
        f"{description} : quantificateur non borné dans {pattern!r} — le coût par "
        f"position de départ redevient proportionnel à la taille du document"
    )


def test_every_regex_of_the_module_goes_through_the_guard():
    """Exhaustivité par construction : on relit le SOURCE du module et on exige
    que tout `re.compile` y passe par `_compile_bounded`. Sans ça, un extracteur
    ajouté à côté (comme l'étaient `_FORM_TAG_RE` & co., eux aussi quadratiques)
    rouvrirait le trou sans qu'aucun test ne le voie."""
    import engine.static as mod
    source = open(mod.__file__, encoding="utf-8").read()
    # On ne compte pas que `re.compile` : `re.search`/`match`/`findall`/`finditer`/
    # `sub` compilent aussi (via le cache du module) et contourneraient tout autant
    # la garde. La propriété porte donc sur TOUT usage du module `re`.
    usages = [m for m in re.finditer(r"\bre\.(\w+)\(", source)]
    guard = (source.index("def quantifier_bounds"), source.index("_COMPILED = ["))
    dehors = [m.group(0) for m in usages if not guard[0] < m.start() < guard[1]]
    assert not dehors, (
        f"usages du module `re` hors de la garde : {dehors}. Toute regex de ce "
        f"module doit passer par `_compile_bounded`, sans quoi elle balaye du "
        f"contenu hostile sans borne sur le travail par position de départ."
    )
    assert sum(1 for m in usages if m.group(1) == "compile") == 1


@pytest.mark.parametrize("bad", [
    r"eval\(([^)]+)\)",       # `+`
    r"<form[^>]*>",           # `*`
    r"a{3,}b",                # `{n,}`
    r"x[^y]+?z",              # paresseux : la borne haute reste absente
    r"(?:ab{0,4}){0,9}",      # imbrication
])
def test_the_guard_refuses_unbounded_patterns(bad):
    with pytest.raises(UnboundedPatternError):
        _compile_bounded(bad)


@pytest.mark.parametrize("ok,expected", [
    (r"eval\{0,3\}", []),            # `{0,3}` ÉCHAPPÉ = littéral, pas un quantificateur
    (r"a[*+]b", []),                 # `*`/`+` DANS une classe = littéraux
    (r"a\*b\+c", []),                # échappés
    (r"a{0,5}b?", [5, 1]),
    (r"(?:ab){0,4}", [4]),
    (r"x{3}", [3]),
])
def test_the_guard_reads_the_regex_and_not_a_lookalike(ok, expected):
    """Un `*` littéral, échappé ou dans une classe, n'est pas un quantificateur :
    la garde analyse la regex, elle ne cherche pas des caractères."""
    assert quantifier_bounds(ok) == expected
    _compile_bounded(ok)  # ne lève pas


# --- 2. le coût, sur des formes NON choisies par le correctif -----------------

def _literal_prefix(pattern: str) -> str:
    """Plus long préfixe LITTÉRAL d'un motif — sert à fabriquer une amorce qui
    fait entrer le moteur dans le motif sans jamais le satisfaire."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            if i + 1 < len(pattern) and pattern[i + 1] in ".+*?()[]{}|^$/":
                out.append(pattern[i + 1])
                i += 2
                continue
            break
        if c in "[](){}|*+?.^$":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _amorces() -> list[str]:
    """Amorces DÉRIVÉES des motifs eux-mêmes : la batterie suit la liste de
    motifs, elle n'est pas une sélection de cas qu'on a su corriger."""
    seen: list[str] = []
    for pattern, _, _ in PATTERNS:
        prefix = _literal_prefix(pattern)
        for variante in (prefix, prefix + "(", prefix + '="'):
            if len(prefix) >= 3 and variante not in seen:
                seen.append(variante)
    return seen


# Formes que le correctif ne traite PAS nommément : séparateurs exotiques,
# écriture multi-ligne, casse mélangée, unicode, imbrication, mélange de familles.
FORMES_EXOTIQUES = [
    ("tabulation", "eval\t("),
    ("tab-vertical", "eval\v("),
    ("saut-de-page", "eval\f("),
    ("multi-ligne", "eval\n\n("),
    ("retour-chariot", "innerHTML\r\n="),
    ("casse-melangee", "EvAl( DoCuMeNt.WrItE("),
    ("espace-insecable", "eval ("),
    ("imbrication", "eval(eval(eval(atob("),
    ("balise-nue", "<form"),
    ("attribut-ouvert", '<input type="'),
    ("guillemet-ouvert", 'onclick="'),
    ("unicode", "eval(éèê"),
    ("melange-de-familles", '<form action="eval(innerHTML=onclick="'),
]


def _cost_ms(doc: str) -> float:
    """Chemin COMPLET : les extracteurs balayent le même document hostile."""
    from engine.static import extract_forms, extract_mailtos
    start = time.perf_counter()
    scan_html(doc)
    extract_forms(doc)
    extract_mailtos(doc)
    return (time.perf_counter() - start) * 1000


def _doc(unit: str, kib: int) -> str:
    return unit * max(1, (kib * 1024) // len(unit))


@pytest.mark.parametrize("nom,unit", FORMES_EXOTIQUES)
def test_exotic_forms_are_linear_in_size(nom, unit):
    """×4 de taille : un coût quadratique est multiplié par ~16, un linéaire par
    ~4. Mesuré avant sur `<input` : 981 ms -> 52 608 ms de 16 à 128 Kio (×53,6)."""
    petit = _cost_ms(_doc(unit, 16))
    grand = _cost_ms(_doc(unit, 64))
    ratio = grand / max(petit, 1e-6)
    assert ratio < 8.0, (
        f"forme {nom!r} : ×{ratio:.1f} de coût pour ×4 de taille "
        f"({petit:.0f} ms -> {grand:.0f} ms) — le coût est resté quadratique"
    )


def test_every_pattern_derived_amorce_stays_under_the_live_timeout():
    """Chaque amorce dérivée d'un motif, à la TAILLE MAXIMALE que l'analyse
    accepte de balayer. C'est le pire cas atteignable, pas un échantillon : la
    fenêtre interdit d'aller au-delà. Mesuré ici avec une marge large parce que
    le seuil qui compte est opérationnel (5,0 s = 502 sur `/live`), pas une
    performance machine."""
    window = max_analyzed_html_chars()
    pires: list[tuple[float, str]] = []
    for amorce in _amorces():
        doc = amorce * max(1, window // len(amorce))
        pires.append((_cost_ms(doc), amorce))
    pires.sort(reverse=True)
    pire_ms, pire_amorce = pires[0]
    assert pire_ms < LIVE_TIMEOUT_S * 1000, (
        f"amorce {pire_amorce!r} : {pire_ms:.0f} ms au plafond de fenêtre "
        f"({window} caractères) — au-delà de {LIVE_TIMEOUT_S} s, chaque poll "
        f"/live rend 502 pour le restant de la session"
    )


def test_cost_stops_growing_past_the_analysis_window():
    """La borne de TAILLE est ce qui transforme « linéaire » en un plafond de
    millisecondes : au-delà de la fenêtre, agrandir le document ne coûte plus
    rien. Sans elle, « linéaire » reste sans plafond."""
    window = max_analyzed_html_chars()
    unit = "eval(eval(eval(atob("
    au_plafond = _cost_ms(unit * (window // len(unit)))
    huit_fois = _cost_ms(unit * (8 * window // len(unit)))
    assert huit_fois < au_plafond * 2.5, (
        f"×8 de document au-delà de la fenêtre coûte ×{huit_fois / au_plafond:.1f} "
        f"({au_plafond:.0f} ms -> {huit_fois:.0f} ms) : la fenêtre ne borne rien"
    )


# --- 3. la fenêtre DIT ce qu'elle a écarté ------------------------------------

def test_the_window_reports_what_it_did_not_look_at(monkeypatch):
    monkeypatch.setenv("OCULAR_MAX_ANALYZED_HTML_CHARS", "1000")
    doc = "x" * 2500
    scan = scan_html(doc)
    assert scan.chars_dropped == 1500
    fenetre, ecarte = analysis_window(doc)
    assert len(fenetre) == 1000 and ecarte == 1500


def test_a_document_that_fits_declares_itself_complete(monkeypatch):
    """Compteur à zéro = document analysé EN ENTIER. Un marqueur qui n'apparaît
    qu'en cas de coupe force le lecteur à distinguer « complet » de « ne sait pas »."""
    monkeypatch.setenv("OCULAR_MAX_ANALYZED_HTML_CHARS", "100000")
    assert scan_html("<script>eval(atob('ZG9j'))</script>").chars_dropped == 0


def test_the_marker_reaches_the_result_without_the_tier_wiring_it():
    """`build()` lit le marqueur DANS l'objet que le scanner rend : détections et
    marqueur voyagent ensemble, donc un tier ne peut pas transmettre les unes en
    perdant l'autre."""
    from engine.wrapper import ResultBuilder
    result, _ = ResultBuilder().build(
        job_id="j", profile="analysis", target="t", input_hash=None, verdict="benign",
        static_findings=HtmlScan([], 4242),
    )
    assert result.truncation.html_chars_dropped == 4242
    assert result.truncation != Truncation()


def test_findings_built_by_hand_declare_no_html_truncation():
    """Rétro-compatibilité : une liste nue (résultat composé sans balayage) ne
    peut rien avoir écarté — le compteur reste à zéro, pas « inconnu »."""
    from engine.wrapper import ResultBuilder
    result, _ = ResultBuilder().build(
        job_id="j", profile="analysis", target="t", input_hash=None, verdict="benign",
        static_findings=[],
    )
    assert result.truncation.html_chars_dropped == 0


def test_the_window_cap_can_be_lowered_but_not_removed(monkeypatch):
    for raw, attendu in (("0", 1), ("-5", 1), ("999999999999", 16 * 1024 * 1024),
                         ("pasunnombre", 512 * 1024), ("65536", 65536)):
        monkeypatch.setenv("OCULAR_MAX_ANALYZED_HTML_CHARS", raw)
        assert max_analyzed_html_chars() == attendu, f"valeur {raw!r}"


# --- 4. non-régression de CONTENU sur des documents réalistes -----------------

@pytest.mark.parametrize("html,rule", [
    ("<script>eval(atob('ZG9j'))</script>", "Dynamic code evaluation"),
    ('<form action="https://evil.tld/c" method="post"></form>', "External form action"),
    ('<input type="password" name="pass">', "Password input field"),
    ('<img class="a b c" data-x="1" src="https://cdn.tld/x.png">', "External image"),
    ('<iframe width="0" height="0" src="https://evil.tld/i"></iframe>', "Embedded iframe"),
    ("<script>document.write('<b>x</b>')</script>", "Direct DOM write"),
    ("<script>el.innerHTML = '<div>' + u + '</div>';</script>", "HTML injection"),
    ("<script>String.fromCharCode(104,105)</script>", "String construction"),
    ('<a onclick="go()">x</a>', "Event handler"),
    ("<script>fetch('https://evil.tld/c')</script>", "Fetch request"),
])
def test_ordinary_detections_still_fire(html, rule):
    """Les bornes sont calibrées sur une mesure de contenu réel ; ces cas
    ordinaires doivent rester détectés à l'identique."""
    assert rule in {f.rule for f in scan_html(html).findings}


def test_a_long_but_legitimate_attribute_run_still_matches():
    """Une balise chargée d'attributs avant celui qui compte : la classe bornée
    doit couvrir largement le réel (mesuré p99,9 = 269 caractères sur 7 404
    balises réelles)."""
    bourrage = " ".join(f'data-attr{i}="valeur-{i}"' for i in range(40))
    html = f'<img {bourrage} src="https://cdn.tld/pixel.png">'
    assert len(bourrage) > 800
    assert "External image" in {f.rule for f in scan_html(html).findings}
