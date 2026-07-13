"""Garde de build des 5 images de déploiement.

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
  - Régression Dockerfile runner-recon-vnc (5e image, phase 3b — gateway
    interactive) : l'image DÉRIVE de `ocular-runner-recon:latest` (ordre de
    build important, cf. Makefile::build-runner) ; ce test build à neuf et
    démarre le conteneur durci pour vérifier que le session_server répond
    (health), que noVNC sert bien son client web, et surtout que le
    clipboard est coupé à la source côté x11vnc — vérifié via
    `/proc/*/cmdline` (jamais `ps aux`, qui tronque la ligne de commande dans
    un conteneur minimal et donnerait un faux négatif).

Marqué `integration` : nécessite un daemon Docker. Exclu par défaut
(addopts = "-m 'not integration'").
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
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


def test_runner_recon_vnc_image_builds_and_smokes():
    """5e image (session interactif, phase 3b) : `runner_recon_vnc/Dockerfile`
    dérive de `ocular-runner-recon:latest` (FROM, cf. Makefile::build-runner
    qui build recon AVANT recon-vnc) — on (re)build d'abord l'image recon
    pour ne jamais dépendre d'un état de cache implicite, puis l'image vnc à
    neuf. Le conteneur est ensuite démarré avec le même durcissement que
    `broker/sessions.py::build_session_args` (cap-drop ALL, no-new-privileges,
    read-only, seccomp recon, user non-root, tmpfs /work+/tmp) ; `--network
    none` suffit ici (aucun test ne navigue réellement, seul le poll interne
    au conteneur via `docker exec` compte). On vérifie :
      - health : `GET localhost:8090/health` (session_server FastAPI) répond
        `{"ok": true}` ;
      - noVNC : `GET localhost:6080/vnc.html` (servi par websockify --web)
        répond 200 ;
      - clipboard-off : le process x11vnc tourne bien avec `-noclipboard`,
        lu depuis `/proc/*/cmdline` (PAS `ps aux`, qui tronque la commande
        dans une image minimale sans `procps` complet — faux négatif)."""
    _build("runner_recon/Dockerfile", "ocular-runner-recon:latest")

    tag = "ocular-runner-recon-vnc-guard:test"
    _build("runner_recon_vnc/Dockerfile", tag)
    name = "ocular-runner-recon-vnc-guard-container"
    subprocess.run([_docker(), "rm", "-f", name], capture_output=True)
    try:
        subprocess.run(
            [
                _docker(), "run", "-d",
                "--name", name,
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true",
                "--security-opt", "seccomp=schemas/seccomp-recon.json",
                "--read-only",
                "--tmpfs", "/work:size=512m,mode=1777",
                "--tmpfs", "/tmp:size=64m,mode=1777",
                "--user", "10001:10001",
                "--memory", "4g",
                "--pids-limit", "512",
                "--network", "none",
                tag,
            ],
            cwd=_ROOT,
            check=True,
            capture_output=True,
        )

        health_body = None
        for _ in range(30):
            probe = subprocess.run(
                [_docker(), "exec", name, "curl", "-fsS", "http://localhost:8090/health"],
                cwd=_ROOT,
                capture_output=True,
                text=True,
            )
            if probe.returncode == 0:
                health_body = probe.stdout
                break
            time.sleep(1)
        assert health_body is not None, "session_server /health injoignable après 30s"
        assert json.loads(health_body) == {"ok": True}, health_body

        novnc = subprocess.run(
            [
                _docker(), "exec", name, "curl", "-fsS", "-o", "/dev/null",
                "-w", "%{http_code}", "http://localhost:6080/vnc.html",
            ],
            cwd=_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        assert novnc.stdout.strip() == "200", novnc.stdout

        # clipboard-off : lecture directe de /proc/*/cmdline (les arguments
        # sont séparés par des NUL) plutôt que `ps aux`, qui tronque.
        proc_scan = subprocess.run(
            [
                _docker(), "exec", name, "sh", "-c",
                "for f in /proc/[0-9]*/cmdline; do tr '\\0' ' ' < \"$f\"; echo; done",
            ],
            cwd=_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        x11vnc_lines = [line for line in proc_scan.stdout.splitlines() if "x11vnc" in line]
        assert x11vnc_lines, proc_scan.stdout
        assert any("-noclipboard" in line for line in x11vnc_lines), proc_scan.stdout
    finally:
        subprocess.run([_docker(), "rm", "-f", name], capture_output=True)
        subprocess.run([_docker(), "rmi", "-f", tag], capture_output=True)
