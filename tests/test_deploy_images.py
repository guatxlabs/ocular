"""Garde de build des 3 images de déploiement.

Ce test aurait attrapé :
  - P2 : `docker.io` (Debian récent) ne fournit QUE le daemon, pas le client
    `/usr/bin/docker` — le broker n'aurait donc pas pu lancer les runners.
    Ici on vérifie explicitement la présence du CLI `docker` dans l'image broker.
  - C1-adjacent : l'image web doit importer `web.app` ET `saved_store`
    (le tier /saved) — un COPY manquant casserait tout /saved.

Marqué `integration` : nécessite un daemon Docker. Exclu par défaut
(addopts = "-m 'not integration'").
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_ROOT = Path(__file__).resolve().parent.parent


def _docker() -> str:
    exe = shutil.which("docker")
    if exe is None:
        pytest.skip("docker CLI absent de l'hôte")
    return exe


def _build(dockerfile: str, tag: str) -> None:
    subprocess.run(
        [_docker(), "build", "-f", dockerfile, "-t", tag, "."],
        cwd=_ROOT,
        check=True,
        capture_output=True,
    )


def _run(tag: str, script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_docker(), "run", "--rm", "--entrypoint", "sh", tag, "-c", script],
        cwd=_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def test_web_image_imports_app_and_saved_store():
    tag = "ocular-web-guard:test"
    _build("deploy/Dockerfile.web", tag)
    try:
        # user 10002 non-root : on importe simplement, sans écrire de DB.
        _run(tag, "python -c 'import web.app; import saved_store'")
    finally:
        subprocess.run([_docker(), "rmi", "-f", tag], capture_output=True)


def test_broker_image_has_docker_cli_and_imports_main():
    tag = "ocular-broker-guard:test"
    _build("deploy/Dockerfile.broker", tag)
    try:
        # P2 : le client docker DOIT être présent (le broker lance les runners).
        cli = _run(tag, "which docker && docker --version")
        assert "/docker" in cli.stdout, cli.stdout
        _run(tag, "python -c 'import broker.main'")
    finally:
        subprocess.run([_docker(), "rmi", "-f", tag], capture_output=True)


def test_runner_image_builds():
    tag = "ocular-runner-guard:test"
    _build("runner_analysis/Dockerfile", tag)
    subprocess.run([_docker(), "rmi", "-f", tag], capture_output=True)
