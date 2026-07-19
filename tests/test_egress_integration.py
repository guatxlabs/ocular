# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
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


# =====================================================================
# Audit 3g — C1 (WebRTC off) + I2 (blocage sur redirection interne réelle)
# =====================================================================
#
# Ces tests ont besoin d'une page "attaquante" qui, elle, DOIT charger à
# travers le garde ACTIF (sinon on ne peut pas tester ce que fait son script/
# sa redirection). Or `is_ip_allowed` (source unique) rejette TOUTE IP privée
# RFC1918 -> une fixture sur un réseau docker par défaut (172.x) serait bloquée
# comme n'importe quelle cible interne. Astuce "publique-simulée" : on crée le
# réseau docker de la fixture d'entrée sur un sous-réseau CLASSÉ GLOBAL par
# `ipaddress.is_global` (ex. 9.9.0.0/16) — la fixture y obtient une IP que le
# garde considère routable publiquement et laisse donc passer, tout en restant
# un conteneur local joignable. (203.0.113.0/24 et les autres plages "doc"
# RFC5737 ne conviennent PAS : `is_global` les classe non-globales.)

_GLOBAL_SUBNET = "9.9.0.0/16"  # classé is_global=True -> fixture "publique-simulée"

_HARDENING_ARGS = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges:true",
    "--security-opt", "seccomp=schemas/seccomp-recon.json",
    "--read-only",
    "--tmpfs", "/work:size=512m,mode=1777",
    "--tmpfs", "/tmp:size=64m,mode=1777",
    "--user", "10001:10001",
    "--memory", "4g",
    "--pids-limit", "512",
]

# Page-sonde WebRTC : à l'analyse du DOM, son script inline écrit
# `typeof RTCPeerConnection` dans #rtc. WebRTC désactivé (pref
# media.peerconnection.enabled=false) -> `RTCPeerConnection` indisponible ->
# le DOM capturé contient `RTC_TYPEOF=undefined`. Sert sur le port 8000.
_WEBRTC_PROBE_SCRIPT = r'''
import http.server
import socketserver

HTML = b"""<!doctype html><html><body>
<script>
  var d = document.createElement('div');
  d.id = 'rtc';
  d.textContent = 'RTC_TYPEOF=' + (typeof RTCPeerConnection);
  document.body.appendChild(d);
</script>
</body></html>"""

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(HTML)

    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", 8000), H) as httpd:
    httpd.serve_forever()
'''

# Fixture d'entrée "publique-simulée" : répond 302 vers l'URL interne fournie
# par l'env `SECRET_URL` (une IP RFC1918/link-local). Le navigateur, après le
# 302, émet un NOUVEAU CONNECT/GET vers cette IP interne -> re-vérifié par le
# garde (chemin redirection, distinct de la navigation directe). Port 8000.
_REDIRECT_ENTRY_SCRIPT = r'''
import http.server
import os
import socketserver

TARGET = os.environ["SECRET_URL"]

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", TARGET)
        self.end_headers()

    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", 8000), H) as httpd:
    httpd.serve_forever()
'''


def _wait_tcp_ready(docker: str, name: str, port: int) -> None:
    probe = (
        f"import socket,sys; s=socket.create_connection(('127.0.0.1',{port}),1); s.close()"
    )
    for _ in range(30):
        r = subprocess.run(
            [docker, "exec", name, "python3", "-c", probe], capture_output=True
        )
        if r.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError(f"fixture {name}:{port} injoignable après 30s")


def _container_ip(docker: str, name: str) -> str:
    r = subprocess.run(
        [docker, "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
        capture_output=True, text=True, check=True,
    )
    ip = r.stdout.strip()
    assert ip, f"pas d'IP pour {name}"
    return ip


def test_egress_guard_disables_webrtc_rtcpeerconnection_undefined():
    """C1 (audit 3g) : le garde egress est un proxy TCP ; WebRTC (ICE/STUN)
    sortirait en UDP DIRECT hors du garde. On désactive WebRTC via la pref
    Firefox `media.peerconnection.enabled=false`. PREUVE empirique : capturer
    une page-sonde (chargée à travers le garde ACTIF, via une IP "publique-
    simulée") dont le script écrit `typeof RTCPeerConnection` -> le DOM
    capturé DOIT montrer `RTC_TYPEOF=undefined` (constructeur indisponible ->
    vecteur UDP fermé)."""
    docker = _docker()
    _rebuild_runner_image()

    suffix = uuid.uuid4().hex[:8]
    net = f"ocular-egress-webrtc-net-{suffix}"
    probe_name = f"ocular-egress-webrtc-probe-{suffix}"
    subprocess.run(
        [docker, "network", "create", "--subnet", _GLOBAL_SUBNET, net],
        check=True, capture_output=True,
    )
    try:
        subprocess.run(
            [
                docker, "run", "-d", "--rm", "--name", probe_name, "--network", net,
                "python:3.11-slim", "python3", "-c", _WEBRTC_PROBE_SCRIPT,
            ],
            check=True, capture_output=True,
        )
        try:
            _wait_tcp_ready(docker, probe_name, 8000)
            # Garde ACTIF (défaut) : la sonde est en 9.9.x (is_global=True) ->
            # passe le garde et charge normalement.
            wrapper = _run_capture_url(docker, net, _IMAGE, f"http://{probe_name}:8000/")
            dom_text = _dom_text(wrapper)
            assert "RTC_TYPEOF=undefined" in dom_text, dom_text
            assert "RTC_TYPEOF=function" not in dom_text, dom_text
            assert "RTC_TYPEOF=object" not in dom_text, dom_text
        finally:
            subprocess.run([docker, "rm", "-f", probe_name], capture_output=True)
    finally:
        subprocess.run([docker, "network", "rm", net], capture_output=True)


def _run_capture_url_two_nets(
    docker: str, pubnet: str, privnet: str, url: str, extra_env: list[str] | None = None
) -> tuple[dict, str]:
    """Runner attaché à DEUX réseaux (create + network connect + start -a) :
    le pubnet "publique-simulé" (entrée joignable via le garde) ET le privnet
    interne (cible réelle vers laquelle la fixture d'entrée redirige — pour
    que le contrôle garde-OFF puisse réellement l'atteindre, prouvant que
    seul le garde, quand actif, la bloque). Retourne (wrapper, stderr) :
    stderr porte le log `egress blocked host=...` du garde."""
    name = f"ocular-egress-2net-runner-{uuid.uuid4().hex[:8]}"
    # PAS de `-i` : le runner lit stdin (`_read_stdin_payload`) — un stdin
    # OUVERT (interactif) bloquerait `sys.stdin.read()` indéfiniment en
    # attente d'EOF (le mode `--url` du chemin 3a ne recevrait jamais la main).
    # Sans `-i`, stdin est fermé -> lecture vide immédiate -> chemin `--url`.
    create = [docker, "create", "--name", name, "--network", pubnet]
    for kv in extra_env or []:
        create += ["-e", kv]
    create += _HARDENING_ARGS + [_IMAGE, "--url", url]
    subprocess.run(create, cwd=_ROOT, check=True, capture_output=True)
    try:
        subprocess.run([docker, "network", "connect", privnet, name], check=True, capture_output=True)
        proc = subprocess.run(
            [docker, "start", "-a", name],
            cwd=_ROOT, capture_output=True, text=True, timeout=120,
        )
        assert proc.returncode == 0, proc.stderr[-4000:]
        return json.loads(proc.stdout), proc.stderr
    finally:
        subprocess.run([docker, "rm", "-f", name], capture_output=True)


def _setup_redirect_topology(docker: str, suffix: str) -> tuple[str, str, str, str]:
    """pubnet (global-classé) + privnet (172.x) ; fixture secrète sur privnet,
    fixture d'entrée sur pubnet qui redirige (302) vers l'IP privée de la
    secrète. Retourne (pubnet, privnet, entry_name, secret_name)."""
    pubnet = f"ocular-egress-redir-pub-{suffix}"
    privnet = f"ocular-egress-redir-priv-{suffix}"
    entry_name = f"ocular-egress-redir-entry-{suffix}"
    secret_name = f"ocular-egress-redir-secret-{suffix}"

    subprocess.run([docker, "network", "create", "--subnet", _GLOBAL_SUBNET, pubnet],
                   check=True, capture_output=True)
    subprocess.run([docker, "network", "create", privnet], check=True, capture_output=True)

    subprocess.run(
        [
            docker, "run", "-d", "--rm", "--name", secret_name, "--network", privnet,
            "python:3.11-slim", "python3", "-c", _SECRET_FIXTURE_SCRIPT,
        ],
        check=True, capture_output=True,
    )
    _wait_tcp_ready(docker, secret_name, 9000)
    secret_ip = _container_ip(docker, secret_name)  # 172.x (RFC1918 -> interne)

    subprocess.run(
        [
            docker, "run", "-d", "--rm", "--name", entry_name, "--network", pubnet,
            "-e", f"SECRET_URL=http://{secret_ip}:9000/secret",
            "python:3.11-slim", "python3", "-c", _REDIRECT_ENTRY_SCRIPT,
        ],
        check=True, capture_output=True,
    )
    _wait_tcp_ready(docker, entry_name, 8000)
    return pubnet, privnet, entry_name, secret_name


def _teardown_redirect_topology(docker, pubnet, privnet, entry_name, secret_name) -> None:
    subprocess.run([docker, "rm", "-f", entry_name], capture_output=True)
    subprocess.run([docker, "rm", "-f", secret_name], capture_output=True)
    subprocess.run([docker, "network", "rm", pubnet], capture_output=True)
    subprocess.run([docker, "network", "rm", privnet], capture_output=True)


def test_egress_guard_blocks_redirect_to_internal_target():
    """I2 (audit 3g) : chemin REDIRECTION (pas seulement navigation directe).
    Une page d'entrée "publique-simulée" (chargée à travers le garde ACTIF)
    répond 302 vers l'IP RFC1918 réelle d'une fixture secrète. Le navigateur
    ré-émet la requête vers cette IP interne -> le garde re-vérifie ce NOUVEAU
    CONNECT/GET et le bloque. Le runner est branché AUSSI sur le réseau privé
    (la route existe réellement) : le blocage vient donc du garde, pas d'une
    absence de route. `_SECRET_MARKER` ne doit JAMAIS apparaître, et le garde
    doit avoir loggé `egress blocked host=<ip-interne>`."""
    docker = _docker()
    _rebuild_runner_image()

    suffix = uuid.uuid4().hex[:8]
    pubnet, privnet, entry_name, secret_name = _setup_redirect_topology(docker, suffix)
    try:
        secret_ip = _container_ip(docker, secret_name)
        wrapper, stderr = _run_capture_url_two_nets(
            docker, pubnet, privnet, f"http://{entry_name}:8000/"
        )

        dom_text = _dom_text(wrapper)
        assert _SECRET_MARKER not in dom_text, dom_text
        # preuve directe côté garde : il a bien intercepté et bloqué la
        # requête post-redirection vers l'IP interne.
        assert f"egress blocked host={secret_ip}" in stderr, stderr[-4000:]

        secret_reqs = [n for n in wrapper["result"]["network"] if f"{secret_ip}:9000" in n["url"]]
        assert all(n.get("status") != 200 for n in secret_reqs), secret_reqs
    finally:
        _teardown_redirect_topology(docker, pubnet, privnet, entry_name, secret_name)


def test_egress_guard_disabled_control_redirect_reaches_internal_target():
    """CONTRÔLE NÉGATIF du chemin redirection (`OCULAR_EGRESS_GUARD=0`) :
    EXACTEMENT la même topologie, garde désactivé -> le 302 est suivi
    jusqu'à la fixture interne (route réellement présente via le privnet) et
    `_SECRET_MARKER` DOIT apparaître. Prouve que la fixture interne EST
    atteignable et que seul le garde (actif par défaut) la bloque — le test
    précédent ne peut donc pas passer par un artefact d'isolation docker."""
    docker = _docker()
    _rebuild_runner_image()

    suffix = uuid.uuid4().hex[:8]
    pubnet, privnet, entry_name, secret_name = _setup_redirect_topology(docker, suffix)
    try:
        wrapper, _stderr = _run_capture_url_two_nets(
            docker, pubnet, privnet, f"http://{entry_name}:8000/",
            extra_env=["OCULAR_EGRESS_GUARD=0"],
        )
        dom_text = _dom_text(wrapper)
        assert _SECRET_MARKER in dom_text, dom_text
    finally:
        _teardown_redirect_topology(docker, pubnet, privnet, entry_name, secret_name)
