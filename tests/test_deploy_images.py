"""Garde de build des 4 images de déploiement.

Ce test aurait attrapé :
  - P2 : `docker.io` (Debian récent) ne fournit QUE le daemon, pas le client
    `/usr/bin/docker` — le broker n'aurait donc pas pu lancer les runners.
    Ici on vérifie explicitement la présence du CLI `docker` dans l'image broker.
  - C1-adjacent : l'image web doit importer `web.app` ET `saved_store`
    (le tier /saved) — un COPY manquant casserait tout /saved.
  - Régression Dockerfile runner-recon : l'image doit être rebuildée à chaque
    changement de `runner_recon/capture.py` (ex. le fix de résilience — wrapper
    valide même si Camoufox meurt en cours de capture) ; ce test build à neuf
    et fait naviguer réellement le conteneur (`--url https://example.com`)
    pour vérifier que le binaire embarqué émet bien un wrapper `profile:capture`.

Marqué `integration` : nécessite un daemon Docker. Exclu par défaut
(addopts = "-m 'not integration'").
"""
from __future__ import annotations

import json
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


def test_runner_recon_image_builds_and_navigates():
    """4e image (recon) : rebuild à neuf (jamais de cache implicite d'une
    image obsolète) puis navigation réelle avec le profil sécurité de
    production (broker.launcher.build_docker_args, profil `capture`) — garde
    contre une régression Dockerfile qui empêcherait de rebuild
    `capture.py`/`vision.py`/`engine/` à jour dans l'image."""
    tag = "ocular-runner-recon-guard:test"
    _build("runner_recon/Dockerfile", tag)
    try:
        proc = subprocess.run(
            [
                _docker(), "run", "--rm",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "--security-opt", "seccomp=schemas/seccomp-recon.json",
                "--read-only",
                "--tmpfs", "/work:size=512m,mode=1777",
                "--tmpfs", "/tmp:size=64m,mode=1777",
                "--user", "10001:10001",
                "--memory", "4g",
                "--pids-limit", "512",
                tag,
                "--url", "https://example.com",
            ],
            cwd=_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        wrapper = json.loads(proc.stdout)
        assert wrapper["result"]["profile"] == "capture", wrapper["result"]
    finally:
        subprocess.run([_docker(), "rmi", "-f", tag], capture_output=True)
