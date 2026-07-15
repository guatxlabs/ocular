"""Intégration réelle du câblage de l'egress guard dans `runner_recon/capture.py`
(Phase 3g, Task G2) : preuve que le trafic navigateur d'un conteneur
`ocular-runner-recon` réel passe RÉELLEMENT par `engine.egress_guard.
EgressGuard` — pas seulement un câblage cosmétique.

Suit le pattern des autres tests d'intégration (`tests/test_runner_scripted_
integration.py`, `tests/test_deploy_images.py`) : marqueur `integration`, CLI
docker requis (skip sinon), rebuild INCONDITIONNEL de l'image runner (jamais
de cache implicite d'une image obsolète qui masquerait la régression que ce
test doit justement détecter), nettoyage réseau/conteneurs en `finally`.

Stratégie retenue (navigation DIRECTE vers la fixture interne, pas un
`fetch()` déclenché depuis une page tierce) : une piste initialement
envisagée — livrer une page "attaquante" en `data:` URI (pour contourner le
fait que `is_ip_allowed`, source unique de vérité IP réutilisée par le
garde, rejette catégoriquement TOUTE IP privée RFC1918, y compris celle
d'une simple page fixture "publique-simulée" sur un réseau docker perso) —
se heurte à un bug PRÉEXISTANT, sans rapport avec cette tâche, dans
`engine/urlnorm.py::normalize_url` (`if "://" not in url: url = "https://" +
url` — une URI `data:` ne contient jamais `"://"`, elle est donc préfixée à
tort et `urlsplit` explose sur le port). `engine/` est hors périmètre de
cette tâche (G2 ne touche que capture.py/session_server.py/ocular_settings.py)
: ce bug n'est PAS corrigé ici, juste contourné en évitant les URI `data:`
comme cible top-level — cf. rapport de tâche pour le signaler.

La preuve retenue est donc plus simple et tout aussi probante : la cible
top-level ELLE-MÊME est la fixture interne (comme `test_runner_scripted_
integration.py` le fait déjà pour une fixture publique-simulée, sans le
garde). Le mécanisme de blocage du garde (résolution+pinning IP au CONNECT/
requête HTTP absolue, indépendant de la façon dont Firefox a décidé
d'émettre la requête — navigation directe, redirection suivie, ou `fetch()`
JS) est identique dans tous les cas : bloquer une navigation directe vers
une IP privée est une preuve tout aussi valide que bloquer un `fetch()` post-
chargement.

Trois tests :
  1. `test_egress_guard_blocks_navigation_to_internal_target` : le garde est
     ACTIF (défaut, `OCULAR_EGRESS_GUARD` non positionné) -> la navigation
     vers une fixture "secrète" sur un réseau docker privé est bloquée —
     jamais le marqueur secret dans le DOM capturé.
  2. `test_egress_guard_disabled_control_leaks_internal_target` : CONTRÔLE
     NÉGATIF indispensable (`OCULAR_EGRESS_GUARD=0`, garde désactivé) sur
     EXACTEMENT la même fixture/réseau -> le marqueur secret DOIT apparaître.
     Sans ce contrôle, un test 1 qui passe pourrait aussi bien s'expliquer
     par une isolation réseau docker incidente (rien à voir avec le garde)
     que par le garde lui-même — ce contrôle prouve que la fixture EST
     atteignable au niveau réseau, et que seul le garde (quand actif) change
     l'issue. Si Camoufox ignorait silencieusement l'option `proxy` (câblage
     cosmétique), les tests 1 ET 2 laisseraient fuiter le secret -> le test 1
     échouerait franchement (pas de triche possible).
  3. `test_egress_guard_allows_legitimate_public_capture` : le garde est
     ACTIF (défaut) et la cible est un VRAI site public (`https://example.
     com`, réseau docker par défaut avec accès internet — même pattern que
     `tests/test_deploy_images.py::test_runner_recon_image_builds_and_
     navigates`) -> la capture aboutit normalement (DOM avec le contenu réel
     de la page) : le garde ne casse pas la capture légitime.
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_ROOT = Path(__file__).resolve().parent.parent
_IMAGE = "ocular-runner-recon:latest"

_SECRET_MARKER = "OCULAR-EGRESS-GUARD-SECRET-MARKER-3g"

# Fixture "secrète" : simule une ressource strictement interne (ex. un
# service backend privé, ou le service de metadata cloud) — sert
# `_SECRET_MARKER` en clair sur `/secret`. Une navigation qui réussit à
# l'atteindre révélerait ce marqueur dans le DOM capturé.
_SECRET_FIXTURE_SCRIPT = r'''
import http.server
import socketserver

MARKER = "OCULAR-EGRESS-GUARD-SECRET-MARKER-3g"
HTML = ("<!doctype html><html><body><p>" + MARKER + "</p></body></html>").encode()

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(HTML)

    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", 9000), H) as httpd:
    httpd.serve_forever()
'''


def _docker() -> str:
    exe = shutil.which("docker")
    if exe is None:
        pytest.skip("docker CLI absent de l'hôte")
    return exe


def _rebuild_runner_image() -> None:
    """Rebuild INCONDITIONNEL (pas de check `image inspect` -> skip) : ce
    test valide justement que le câblage egress guard AJOUTÉ dans
    `runner_recon/capture.py` est bien présent dans l'image testée — un
    reuse d'image obsolète masquerait silencieusement une régression."""
    docker = _docker()
    subprocess.run(
        [docker, "build", "-f", "runner_recon/Dockerfile", "-t", _IMAGE, "."],
        cwd=_ROOT,
        check=True,
        capture_output=True,
        timeout=900,
    )


def _wait_fixture_ready(docker: str, fixture_name: str) -> None:
    probe = "import urllib.request; urllib.request.urlopen('http://localhost:9000/secret', timeout=1)"
    for _ in range(30):
        r = subprocess.run(
            [docker, "exec", fixture_name, "python3", "-c", probe],
            capture_output=True,
        )
        if r.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("fixture secrète injoignable après 30s")


def _setup_secret_fixture(docker: str, suffix: str) -> tuple[str, str]:
    net = f"ocular-egress-test-net-{suffix}"
    fixture_name = f"ocular-egress-test-secret-{suffix}"
    subprocess.run([docker, "network", "create", net], check=True, capture_output=True)
    subprocess.run(
        [
            docker, "run", "-d", "--rm",
            "--name", fixture_name,
            "--network", net,
            "python:3.11-slim", "python3", "-c", _SECRET_FIXTURE_SCRIPT,
        ],
        check=True,
        capture_output=True,
    )
    _wait_fixture_ready(docker, fixture_name)
    return net, fixture_name


def _teardown_secret_fixture(docker: str, net: str, fixture_name: str) -> None:
    subprocess.run([docker, "rm", "-f", fixture_name], capture_output=True)
    subprocess.run([docker, "network", "rm", net], capture_output=True)


def _run_capture_url(
    docker: str, network: str, image: str, url: str, extra_env: list[str] | None = None
) -> dict:
    cmd = [docker, "run", "--rm", "--network", network]
    for kv in extra_env or []:
        cmd += ["-e", kv]
    cmd += [
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--security-opt", "seccomp=schemas/seccomp-recon.json",
        "--read-only",
        "--tmpfs", "/work:size=512m,mode=1777",
        "--tmpfs", "/tmp:size=64m,mode=1777",
        "--user", "10001:10001",
        "--memory", "4g",
        "--pids-limit", "512",
        image,
        "--url", url,
    ]
    proc = subprocess.run(
        cmd, cwd=_ROOT, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-4000:]
    return json.loads(proc.stdout)


def _dom_text(wrapper: dict) -> str:
    ref = wrapper["result"]["artifacts"].get("dom_html_ref")
    if not ref:
        return ""
    return base64.b64decode(wrapper["blobs"][ref]).decode("utf-8", "replace")


def test_egress_guard_blocks_navigation_to_internal_target():
    """Le garde est ACTIF (défaut) : naviguer directement vers la fixture
    secrète, sur un réseau docker privé, ne doit JAMAIS révéler
    `_SECRET_MARKER` — preuve que le trafic Camoufox passe réellement par le
    garde (résolution+pinning IP, `is_ip_allowed` rejette l'IP RFC1918 de la
    fixture)."""
    docker = _docker()
    _rebuild_runner_image()

    suffix = uuid.uuid4().hex[:8]
    net, fixture_name = _setup_secret_fixture(docker, suffix)
    try:
        wrapper = _run_capture_url(docker, net, _IMAGE, f"http://{fixture_name}:9000/secret")

        dom_text = _dom_text(wrapper)
        assert _SECRET_MARKER not in dom_text, dom_text

        # La cible n'a jamais été servie avec succès : soit aucune entrée
        # réseau du tout (goto a levé avant qu'une réponse arrive), soit une
        # entrée présente mais jamais avec le statut 200 du VRAI serveur
        # fixture (le garde répond lui-même en 403 sans jamais s'y connecter,
        # cf. engine/egress_guard.py::_handle_absolute_http).
        target_reqs = [n for n in wrapper["result"]["network"] if f"{fixture_name}:9000" in n["url"]]
        assert all(n.get("status") != 200 for n in target_reqs), target_reqs
    finally:
        _teardown_secret_fixture(docker, net, fixture_name)


def test_egress_guard_disabled_control_leaks_internal_target():
    """CONTRÔLE NÉGATIF (cf. docstring module) : EXACTEMENT la même fixture
    et le même réseau que le test précédent, mais `OCULAR_EGRESS_GUARD=0` —
    la navigation DOIT réussir et révéler `_SECRET_MARKER`. Ceci prouve que
    la fixture est réellement atteignable réseau (le blocage du test
    précédent n'est pas un artefact d'isolation docker incidente) et donc
    que c'est bien le garde, actif par défaut, qui bloque — pas autre
    chose. Si le câblage `proxy=` était cosmétique (ignoré par Camoufox), ce
    test contrôle passerait EXACTEMENT PAREIL que le test 1 (fuite dans les
    deux cas), ce qui ferait échouer le test 1 (pas de triche possible)."""
    docker = _docker()
    _rebuild_runner_image()

    suffix = uuid.uuid4().hex[:8]
    net, fixture_name = _setup_secret_fixture(docker, suffix)
    try:
        wrapper = _run_capture_url(
            docker, net, _IMAGE, f"http://{fixture_name}:9000/secret",
            extra_env=["OCULAR_EGRESS_GUARD=0"],
        )

        dom_text = _dom_text(wrapper)
        assert _SECRET_MARKER in dom_text, dom_text

        target_reqs = [n for n in wrapper["result"]["network"] if f"{fixture_name}:9000" in n["url"]]
        assert any(n.get("status") == 200 for n in target_reqs), target_reqs
    finally:
        _teardown_secret_fixture(docker, net, fixture_name)


def test_egress_guard_allows_legitimate_public_capture():
    """Le garde est ACTIF (défaut, réseau docker PAR DÉFAUT — accès
    internet, même pattern que `tests/test_deploy_images.py::
    test_runner_recon_image_builds_and_navigates`) : une capture d'un VRAI
    site public doit aboutir normalement (DOM avec le contenu réel) — le
    garde ne casse pas la capture légitime."""
    docker = _docker()
    _rebuild_runner_image()

    proc = subprocess.run(
        [
            docker, "run", "--rm",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--security-opt", "seccomp=schemas/seccomp-recon.json",
            "--read-only",
            "--tmpfs", "/work:size=512m,mode=1777",
            "--tmpfs", "/tmp:size=64m,mode=1777",
            "--user", "10001:10001",
            "--memory", "4g",
            "--pids-limit", "512",
            _IMAGE,
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
    assert "Example Domain" in wrapper["result"]["dom"]["title"], wrapper["result"]["dom"]

    dom_text = _dom_text(wrapper)
    assert "Example Domain" in dom_text, dom_text[:2000]
