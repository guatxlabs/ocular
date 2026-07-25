# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Intégration réelle du mode scripté (3c) : `runner_recon.capture.main()`
rejoue un job `{"url": ..., "steps": [...]}` reçu sur **stdin**, contre une
page fixture servie par un conteneur dédié sur un réseau docker privé, et le
résultat doit révéler l'appel réseau POST-clic (preuve que l'interaction a
bien été rejouée, pas juste la navigation initiale).

Suit le pattern des autres tests d'intégration (`tests/test_deploy_images.py`)
: marqueur `integration`, CLI docker requis (skip sinon), build à la demande
de l'image runner si absente, nettoyage réseau/conteneurs en `finally`.

Note d'architecture couverte par CE test : `capture_scripted` ne re-SSRF-
valide PAS l'URL top-level (cf. docstring dans runner_recon/capture.py) — la
fixture tourne sur un réseau docker privé (IP/hostname non routable
publiquement), ce qui n'est atteignable QUE parce que ce choix est fait :
si `capture_scripted` re-validait `url` avec `engine.ssrf.validate_capture_url`,
la résolution du hostname fixture (adresse privée RFC1918 du réseau docker
dédié) serait rejetée à tort.
"""
from __future__ import annotations

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

# Page fixture : le bouton #go ne fait un fetch('/beacon') qu'APRES le clic
# (jamais au chargement) — la seule façon de faire apparaître /beacon dans la
# trace réseau est donc de rejouer le clic, pas seulement de naviguer.
# Le fetch met à jour le DOM (div#done) une fois résolu : le step `wait` sur
# ce sélecteur attend le résultat réel plutôt qu'un délai fixe arbitraire
# (plus robuste qu'un `wait` en millisecondes face à la latence réseau/DNS
# variable observée empiriquement dans ce genre d'environnement conteneurisé).
_FIXTURE_SCRIPT = r'''
import http.server
import socketserver

HTML = b"""<!doctype html><html><body>
<button id="go" onclick="fetch('/beacon?x=1').then(function(){
  var d = document.createElement('div'); d.id = 'done'; d.textContent = 'done';
  document.body.appendChild(d);
}).catch(function(e){
  var d = document.createElement('div'); d.id = 'done'; d.textContent = 'error: ' + String(e);
  document.body.appendChild(d);
})">go</button>
</body></html>"""

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *a):
        pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("0.0.0.0", 8000), H) as httpd:
    httpd.serve_forever()
'''


def _docker() -> str:
    exe = shutil.which("docker")
    if exe is None:
        pytest.skip("docker CLI absent de l'hôte")
    return exe


def _ensure_runner_image() -> None:
    docker = _docker()
    inspect = subprocess.run(
        [docker, "image", "inspect", _IMAGE], capture_output=True
    )
    if inspect.returncode == 0:
        return
    subprocess.run(
        [docker, "build", "-f", "runner_recon/Dockerfile", "-t", _IMAGE, "."],
        cwd=_ROOT,
        check=True,
        capture_output=True,
        timeout=900,
    )


def _wait_fixture_ready(docker: str, fixture_name: str) -> None:
    probe = ["import urllib.request; urllib.request.urlopen('http://localhost:8000/', timeout=1)"]
    for _ in range(30):
        r = subprocess.run(
            [docker, "exec", fixture_name, "python3", "-c", probe[0]],
            capture_output=True,
        )
        if r.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError("page fixture injoignable après 30s")


def test_scripted_run_captures_post_click_call():
    docker = _docker()
    _ensure_runner_image()

    suffix = uuid.uuid4().hex[:8]
    net = f"ocular-scripted-test-net-{suffix}"
    fixture_name = f"ocular-scripted-test-fixture-{suffix}"

    subprocess.run([docker, "network", "create", net], check=True, capture_output=True)
    try:
        subprocess.run(
            [
                docker, "run", "-d", "--rm",
                "--name", fixture_name,
                "--network", net,
                "python:3.11-slim", "python3", "-c", _FIXTURE_SCRIPT,
            ],
            check=True,
            capture_output=True,
        )
        try:
            _wait_fixture_ready(docker, fixture_name)

            payload = json.dumps({
                "url": f"http://{fixture_name}:8000/",
                "steps": [
                    {"click": "#go"},
                    {"wait": {"selector": "#done"}},
                    {"capture": "apres"},
                ],
            })

            proc = subprocess.run(
                [
                    docker, "run", "-i", "--rm",
                    "--network", net,
                    # La fixture tourne sur un réseau docker privé (IP RFC1918) :
                    # l'egress guard (3g, ON par défaut) la bloquerait à raison.
                    # On le désactive ICI car la cible est une fixture de test
                    # interne, pas un scénario SSRF réel.
                    "-e", "OCULAR_EGRESS_GUARD=0",
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
                ],
                cwd=_ROOT,
                input=payload,
                capture_output=True,
                text=True,
                timeout=120,
            )
            assert proc.returncode == 0, proc.stderr[-4000:]
            wrapper = json.loads(proc.stdout)
            result = wrapper["result"]

            # (a) un screenshot labellisé 'apres' existe
            apres_shots = [s for s in result["screenshots"] if s["phase"] == "apres"]
            assert apres_shots, result["screenshots"]
            apres_ref = apres_shots[0]["image_ref"]
            assert apres_ref in wrapper["blobs"]

            # (b) la trace réseau contient une requête vers /beacon
            # (preuve de l'exécution post-clic, pas juste la navigation initiale)
            beacon_reqs = [n for n in result["network"] if "/beacon" in n["url"]]
            assert beacon_reqs, result["network"]

            # (c) dynamic_steps cohérent : le click ok:true, le capture porte
            # le screenshot_ref de 'apres'
            click_entry = next(
                s for s in result["dynamic_steps"] if s["action"] == '{"click": "#go"}'
            )
            assert click_entry["ok"] is True

            capture_entry = next(
                s for s in result["dynamic_steps"] if s["action"] == '{"capture": "apres"}'
            )
            assert capture_entry["ok"] is True
            assert capture_entry["screenshot_ref"] == apres_ref
        finally:
            subprocess.run([docker, "rm", "-f", fixture_name], capture_output=True)
    finally:
        subprocess.run([docker, "network", "rm", net], capture_output=True)
