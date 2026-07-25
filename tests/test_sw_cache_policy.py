# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Politique de cache du service worker (web/ui/sw.js) — confidentialité côté
poste de l'analyste.

Le service worker écrit dans le Cache Storage du navigateur : tout ce qu'il y met
SURVIT à la fermeture de l'onglet et à la déconnexion. La liste des préfixes
sensibles a UNE SEULE source de vérité, `web.app._PROTECTED` (celle que le
middleware d'authentification applique) : ce test la lui prend et vérifie qu'AUCUN
de ces préfixes n'est cachable — plus le shell statique, qui doit l'être.

Le comportement réel du worker est exercé par tests/sw_test.mjs (node), qui
l'évalue avec des doublures de Cache Storage ; ignoré si `node` est absent.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from web.app import _PROTECTED

NODE = shutil.which("node")
REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(NODE is None, reason="node introuvable — test JS ignoré")
def test_service_worker_never_caches_protected_routes():
    result = subprocess.run(
        [NODE, "tests/sw_test.mjs", json.dumps(list(_PROTECTED))],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"sw_test.mjs a échoué (rc={result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "sw_test OK" in result.stdout
