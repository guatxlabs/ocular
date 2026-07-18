"""Preuve d'intégration de l'isolation réseau par session (design
2026-07-18) : deux sessions réelles vivent sur des réseaux docker DISJOINTS,
donc un conteneur de session compromis ne peut PAS joindre le :6080/:8090
d'un pair — alors que le conteneur web (ici une « sonde » qui en joue le
rôle, attachée par launch_session) joint les deux.

Marqué `integration` : nécessite le démon Docker + l'image de session.
Lancer via `make test-int`."""
import shutil
import subprocess
import time
import uuid

import pytest

import broker.sessions as sessions_mod
from broker.sessions import launch_session, stop_session

pytestmark = pytest.mark.integration

_SESSION_IMAGE = "ocular-runner-recon-vnc:latest"


def _docker() -> str:
    exe = shutil.which("docker")
    if exe is None:
        pytest.skip("docker CLI absent de l'hôte")
    return exe


def _require_image(docker: str) -> None:
    proc = subprocess.run([docker, "image", "inspect", _SESSION_IMAGE],
                          capture_output=True, check=False)
    if proc.returncode != 0:
        pytest.skip(f"image {_SESSION_IMAGE} absente (make build-runner)")


def _can_reach(docker: str, from_container: str, host: str, port: int) -> bool:
    """curl depuis `from_container` vers host:port. True si la connexion TCP
    aboutit (peu importe le code HTTP), False si DNS/connexion échoue."""
    proc = subprocess.run(
        [docker, "exec", from_container, "curl", "-s", "-m", "3", "-o", "/dev/null",
         f"http://{host}:{port}/"],
        capture_output=True, check=False,
    )
    # curl: 6=DNS introuvable, 7=connexion refusée, 28=timeout -> injoignable.
    return proc.returncode == 0


def _wait_reachable(docker: str, from_container: str, host: str, port: int,
                    timeout_s: float = 60.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _can_reach(docker, from_container, host, port):
            return True
        time.sleep(1.0)
    return False


def test_two_sessions_cannot_reach_each_other(monkeypatch):
    docker = _docker()
    _require_image(docker)

    suffix = uuid.uuid4().hex[:8]
    sid_a, sid_b = f"iso-a-{suffix}", f"iso-b-{suffix}"
    probe = f"ocular-web-probe-{suffix}"

    # La « sonde » joue le rôle du conteneur web : launch_session l'attachera
    # à chaque réseau de session via OCULAR_WEB_CONTAINER.
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", probe)

    subprocess.run(
        [docker, "run", "-d", "--name", probe, "--entrypoint", "sleep",
         _SESSION_IMAGE, "3600"],
        capture_output=True, check=False,
    )
    try:
        launch_session(sid_a)
        launch_session(sid_b)
        ca, cb = f"ocular-sess-{sid_a}", f"ocular-sess-{sid_b}"
        try:
            # 1) Contrôle POSITIF : la sonde (= le web) joint les DEUX sessions.
            #    Attente de disponibilité : websockify met quelques secondes.
            assert _wait_reachable(docker, probe, ca, 6080), \
                "la sonde (web) doit joindre la session A"
            assert _wait_reachable(docker, probe, cb, 6080), \
                "la sonde (web) doit joindre la session B"

            # 2) PROPRIÉTÉ DE SÉCURITÉ : A ne joint PAS B (réseaux disjoints).
            assert not _can_reach(docker, ca, cb, 6080), \
                "ISOLATION ROMPUE : la session A joint le :6080 de la session B"
            assert not _can_reach(docker, ca, cb, 8090), \
                "ISOLATION ROMPUE : la session A joint le :8090 de la session B"
            assert not _can_reach(docker, cb, ca, 6080), \
                "ISOLATION ROMPUE : la session B joint le :6080 de la session A"
        finally:
            stop_session(ca)
            stop_session(cb)
    finally:
        subprocess.run([docker, "rm", "-f", probe], capture_output=True, check=False)


def test_stop_session_removes_the_dedicated_network():
    docker = _docker()
    _require_image(docker)

    suffix = uuid.uuid4().hex[:8]
    sid = f"iso-net-{suffix}"
    net = sessions_mod._session_net(sid)
    try:
        launch_session(sid)
        listed = subprocess.run(
            [docker, "network", "ls", "--filter", f"name={net}", "--format", "{{.Name}}"],
            capture_output=True, check=False, text=True,
        )
        assert net in listed.stdout, "le réseau dédié doit exister après launch"
    finally:
        stop_session(f"ocular-sess-{sid}")

    listed = subprocess.run(
        [docker, "network", "ls", "--filter", f"name={net}", "--format", "{{.Name}}"],
        capture_output=True, check=False, text=True,
    )
    assert net not in listed.stdout, "le réseau dédié doit être supprimé au teardown"
