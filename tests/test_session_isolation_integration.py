# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
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


class ReachToolingError(RuntimeError):
    """L'outillage (`docker exec` ou `curl`) a échoué : la sonde n'a RIEN
    prouvé sur la joignabilité. Levée plutôt que retourner `False`, car un
    `False` ici serait interprété par les assertions négatives comme une preuve
    d'isolation — le test conclurait « isolé » sur un outillage cassé."""


# Seuls codes de sortie de curl qui prouvent l'injoignabilité :
#   6 = hôte/DNS introuvable, 7 = connexion refusée, 28 = timeout.
# Liste BLANCHE volontaire (et non liste noire {125,126,127}) pour deux raisons
# constatées empiriquement :
#   - `docker exec` sur un conteneur ARRÊTÉ ou ABSENT renvoie 1, pas 125 — une
#     liste noire laisserait donc passer ce cas en « isolé » ;
#   - un code inattendu signifiant que le TCP a ABOUTI (ex. curl 52, « empty
#     reply from server ») fabriquerait une fausse preuve d'isolation.
# Tout ce qui n'est ni 0 ni un code réseau fait donc HURLER le test.
_CURL_UNREACHABLE_CODES = frozenset({6, 7, 28})


def _classify_reach(returncode: int, stderr: str) -> bool:
    """Traduit le code de sortie de `docker exec … curl` en verdict de
    joignabilité. `True` = joignable, `False` = injoignable (preuve valide),
    `ReachToolingError` = on ne sait pas, l'outillage est cassé."""
    if returncode == 0:
        return True
    if returncode in _CURL_UNREACHABLE_CODES:
        return False
    raise ReachToolingError(
        f"outillage cassé, la joignabilité n'est PAS prouvée : "
        f"`docker exec … curl` a renvoyé rc={returncode} "
        f"(attendu 0=joignable ou {sorted(_CURL_UNREACHABLE_CODES)}=injoignable) ; "
        f"stderr={stderr.strip()!r}"
    )


def _can_reach(docker: str, from_container: str, host: str, port: int) -> bool:
    """curl depuis `from_container` vers host:port. True si la connexion TCP
    aboutit (peu importe le code HTTP), False si DNS/connexion échoue. Lève
    `ReachToolingError` si l'échec vient de l'outillage (curl absent de
    l'image, conteneur arrêté, démon Docker en vrac) — cf. `_classify_reach`."""
    proc = subprocess.run(
        [docker, "exec", from_container, "curl", "-s", "-m", "3", "-o", "/dev/null",
         f"http://{host}:{port}/"],
        capture_output=True, check=False, text=True,
    )
    return _classify_reach(proc.returncode, proc.stderr or "")


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
    # Noms déterministes : calculés AVANT tout lancement pour que le `finally`
    # d'arrêt couvre aussi un échec de launch_session.
    ca, cb = f"ocular-sess-{sid_a}", f"ocular-sess-{sid_b}"
    probe = f"ocular-web-probe-{suffix}"

    # La « sonde » joue le rôle du conteneur web : launch_session l'attachera
    # à chaque réseau de session via OCULAR_WEB_CONTAINER.
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", probe)

    # Durcissement IDENTIQUE au service `web` du compose (read_only, cap_drop
    # ALL, no-new-privileges, user 10002:10002) : sans ça, le contrôle POSITIF
    # ne prouverait pas que `docker network connect` fonctionne contre un
    # conteneur durci comme le web réellement déployé — seulement contre un
    # conteneur permissif. Le tmpfs /tmp est le pendant du `tmpfs: ["/tmp"]`
    # du compose, requis pour démarrer avec un rootfs read-only.
    run = subprocess.run(
        [docker, "run", "-d", "--name", probe,
         "--read-only", "--tmpfs", "/tmp",
         "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
         "--user", "10002:10002",
         "--entrypoint", "sleep", _SESSION_IMAGE, "3600"],
        capture_output=True, check=False, text=True,
    )
    try:
        # Échec de démarrage de la sonde => sans cette vérification, le test ne
        # tombe qu'après ~60 s d'attente sur « la sonde doit joindre la session A »,
        # ce qui pointe le diagnostic vers l'isolation réseau alors que le vrai
        # problème est le `docker run` ci-dessus. On le constate tout de suite,
        # avec le stderr du run dans le message.
        state = subprocess.run(
            [docker, "inspect", "-f", "{{.State.Running}}", probe],
            capture_output=True, check=False, text=True,
        )
        assert state.stdout.strip() == "true", (
            f"la sonde {probe} n'a pas démarré (docker run rc={run.returncode}) ; "
            f"run stderr={run.stderr.strip()!r} ; inspect={state.stdout.strip()!r} "
            f"stderr={state.stderr.strip()!r}"
        )
        try:
            launch_session(sid_a)
            launch_session(sid_b)

            # 1) Contrôle POSITIF : la sonde (= le web) joint les DEUX sessions.
            #    Attente de disponibilité : websockify met quelques secondes.
            assert _wait_reachable(docker, probe, ca, 6080), \
                "la sonde (web) doit joindre la session A"
            assert _wait_reachable(docker, probe, cb, 6080), \
                "la sonde (web) doit joindre la session B"
            assert _wait_reachable(docker, probe, ca, 8090), \
                "la sonde (web) doit joindre le :8090 de la session A " \
                "(sinon l'assertion négative sur 8090 serait vacue)"

            # 2) PROPRIÉTÉ DE SÉCURITÉ : A ne joint PAS B (réseaux disjoints).
            assert not _can_reach(docker, ca, cb, 6080), \
                "ISOLATION ROMPUE : la session A joint le :6080 de la session B"
            assert not _can_reach(docker, ca, cb, 8090), \
                "ISOLATION ROMPUE : la session A joint le :8090 de la session B"
            assert not _can_reach(docker, cb, ca, 6080), \
                "ISOLATION ROMPUE : la session B joint le :6080 de la session A"
        finally:
            stop_session(sid_a)
            stop_session(sid_b)
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
        stop_session(sid)

    listed = subprocess.run(
        [docker, "network", "ls", "--filter", f"name={net}", "--format", "{{.Name}}"],
        capture_output=True, check=False, text=True,
    )
    assert net not in listed.stdout, "le réseau dédié doit être supprimé au teardown"
