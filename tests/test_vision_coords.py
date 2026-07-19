# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mapping px IMAGE (viewport screenshot Playwright) -> px ÉCRAN Xvfb (clic
xdotool). Cf. docs/superpowers/plans/2026-07-13-ocular-phase3d2b-turnstile-fix.md
Task B1 — cause racine n°1 du Turnstile qui rate sa cible : `vision.detect()`
renvoie des coordonnées relatives au screenshot (viewport), mais
`human_click_xdotool` clique en coordonnées écran absolues ; il manque
l'offset du chrome Firefox (barre d'URL/onglets) + position fenêtre, exposé
par `window.mozInnerScreenX/Y` (Gecko), et la conversion px CSS/device via
`devicePixelRatio` (le screenshot est en px *device*, mozInnerScreen en px
*CSS*)."""

from runner_recon.vision import image_to_screen


def test_image_to_screen_dpr1_is_simple_offset():
    # dpr=1 : px image == px CSS, donc juste une addition d'offset.
    assert image_to_screen((10, 20), moz_x=100, moz_y=50, dpr=1) == (110, 70)


def test_image_to_screen_dpr2_divides_by_dpr():
    # dpr=2 : le screenshot est 2x plus dense que les px CSS -> diviser avant
    # d'ajouter l'offset (lui-même déjà en px CSS).
    assert image_to_screen((100, 40), moz_x=0, moz_y=0, dpr=2) == (50, 20)


def test_image_to_screen_nonzero_offset_and_dpr_combined():
    assert image_to_screen((200, 80), moz_x=300, moz_y=150, dpr=2) == (400, 190)


def test_image_to_screen_rounds_to_nearest_int():
    # 15 / 2 = 7.5 -> round-half-to-even de Python arrondit 7.5 -> 8.
    x, y = image_to_screen((15, 15), moz_x=0, moz_y=0, dpr=2)
    assert isinstance(x, int) and isinstance(y, int)
    assert x == round(15 / 2)
    assert y == round(15 / 2)


def test_image_to_screen_dpr_falsy_defaults_to_one():
    # dpr=0/None (valeur JS foireuse ou absente) -> ne doit jamais diviser par
    # zéro ; comportement identique à dpr=1 (cf. `d = dpr or 1` du plan).
    assert image_to_screen((10, 20), moz_x=5, moz_y=5, dpr=0) == (15, 25)
    assert image_to_screen((10, 20), moz_x=5, moz_y=5, dpr=None) == (15, 25)
