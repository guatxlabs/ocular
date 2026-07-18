"""Test comportemental (node) des helpers purs de web/ui/triage.js.

Lance tests/triage_test.mjs via subprocess ; ignoré si `node` est introuvable
sur la machine d'exécution (CI minimal sans toolchain JS).
"""
import shutil
import subprocess
from pathlib import Path

import pytest

NODE = shutil.which("node")
REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(NODE is None, reason="node introuvable — test JS ignoré")
def test_triage_js_node_suite():
    result = subprocess.run(
        [NODE, "tests/triage_test.mjs"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"triage_test.mjs a échoué (rc={result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "triage_test OK" in result.stdout
