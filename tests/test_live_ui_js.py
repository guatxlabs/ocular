# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests comportementaux (node) du panneau live côté client.

Deux harnais, deux niveaux :

  * `tests/poll_test.mjs` — la cadence seule (`web/ui/poll.js`), horloge
    INJECTÉE : jamais deux appels en vol, un échec ne rompt pas la boucle, le
    recul double et plafonne, un succès le remet à zéro. Aucune attente réelle,
    donc rien qui dépende de la charge de la machine.

  * `tests/interactive_live_test.mjs` — la VRAIE vue (`views/interactive.js`
    montée par `core.js`) sur un DOM minimal, face à un `/live` qui échoue puis
    revient : ce qui est vérifié est le TEXTE que l'analyste a sous les yeux —
    l'incident annoncé pendant qu'il dure, la reprise sans intervention, le
    marqueur d'un champ coupé que la vue n'affiche nulle part (`headers`), un
    compteur de troncature absent des modèles (`forms_dropped`), et l'analyse
    périmée dite comme telle.

  * `tests/detail_truncation_test.mjs` — la VRAIE vue détail, avec un résultat
    dont `title`, `final_url` et un champ INVENTÉ sont coupés : chaque coupe
    doit atteindre l'analyste parce que le champ est nommé dans
    `truncated_fields`, pas parce que quelqu'un a pensé à appeler le badge à cet
    endroit-là.

Ignorés si `node` est introuvable (CI minimale sans toolchain JS), comme
tests/test_filter_js.py.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

NODE = shutil.which("node")
REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [NODE, f"tests/{script}"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=120,
    )


@pytest.mark.skipif(NODE is None, reason="node introuvable — test JS ignoré")
def test_poll_loop_behaviour():
    result = _run("poll_test.mjs")
    assert result.returncode == 0, (
        f"poll_test.mjs a échoué (rc={result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "poll_test OK" in result.stdout


@pytest.mark.skipif(NODE is None, reason="node introuvable — test JS ignoré")
def test_live_panel_survives_a_failing_poll_and_says_so():
    result = _run("interactive_live_test.mjs")
    assert result.returncode == 0, (
        f"interactive_live_test.mjs a échoué (rc={result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "interactive_live_test OK" in result.stdout


@pytest.mark.skipif(NODE is None, reason="node introuvable — test JS ignoré")
def test_every_cut_field_reaches_the_analyst_in_the_detail_view():
    result = _run("detail_truncation_test.mjs")
    assert result.returncode == 0, (
        f"detail_truncation_test.mjs a échoué (rc={result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "detail_truncation_test OK" in result.stdout
