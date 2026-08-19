# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Smoke e2e de l'UI : les vues principales se chargent VRAIMENT dans un navigateur.

CE QUE ÇA ATTRAPE, ET QUE RIEN D'AUTRE N'ATTRAPE — `tests/test_ui_smoke.py`
(unitaire, `TestClient`) prouve que les fichiers sont SERVIS en 200 avec le bon
type MIME ; `tests/*_test.mjs` prouvent que des fonctions isolées calculent
juste sur un DOM simulé. Aucun des deux n'exécute l'application : un module ES
qui n'importe plus, un `export` renommé d'un côté seulement, une CSP qui bloque
le module noVNC, une vue qui lève au premier rendu — tout cela passe au vert.
Ce test-ci charge les routes dans Camoufox et échoue sur la moindre exception
JS non rattrapée.

BORNES (feuille de route) :
  - headless, dans le conteneur `ocular-runner-recon` (Camoufox + le
    `playwright==1.49.1` ÉPINGLÉ avec lui) — rien à installer sur l'hôte ;
  - réseau INTERNE : le conteneur de navigation partage la pile réseau du
    frontal `gateway` (`--network container:…`) et vise `http://127.0.0.1:8000`.
    Aucun port publié n'est requis, aucune cible tierce n'est jointe, et
    l'origine `127.0.0.1` est un contexte sécurisé — donc `crypto.subtle`
    (`api.js::sha256Hex`, dédup avant soumission) fonctionne comme en
    déploiement derrière TLS ;
  - aucun résidu : le conteneur de navigation part avec `--rm` ET un
    `docker rm -f` en `finally` (un dépassement de délai tue le CLI, pas le
    conteneur) ; les conteneurs/réseaux de session créés par le test sont
    comparés à un instantané pris AVANT, attendus disparus, et balayés de
    force si le teardown asynchrone n'a pas fait son office.

POURQUOI HORS DE LA MATRICE CI — les runners GitHub n'ont pas de navigateur, et
ce test exige EN PLUS une pile Ocular levée (`make up`) donc un démon Docker
avec le socket : c'est un contrôle d'opérateur, pas de CI. D'où la cible dédiée
`make smoke-ui`, à l'image de `make test-int`.

DOUBLE MARQUAGE `integration` + `smoke_ui`, à ne pas « simplifier » : c'est
`integration` qui garantit l'exclusion de `pytest -m "not integration"`, y
compris quand ce filtre est passé EXPLICITEMENT en ligne de commande (la suite
dockerisée le fait : `deploy/Dockerfile.test`). Un `-m` en argument l'emporte
sur celui d'`addopts` — se reposer sur `addopts` seul laisserait donc ce test
s'exécuter dans l'image de test unitaire, qui n'a ni Docker ni navigateur. Le
second marqueur, lui, permet à `make test-int` de l'exclure
(`-m "integration and not smoke_ui"`) : le smoke reste OPT-IN.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke_ui]

_ROOT = Path(__file__).resolve().parent.parent
_DRIVER = _ROOT / "tests" / "smoke_ui" / "driver.py"
_IMAGE = "ocular-runner-recon:latest"
_JSON_PREFIX = "OCULAR_SMOKE_JSON:"

# Nom de projet compose FIGÉ dans `deploy/docker-compose.yml` (`name: ocular`) :
# c'est lui qui étiquette les conteneurs, donc ce par quoi on retrouve le
# frontal sans deviner un nom généré.
_COMPOSE_PROJECT = "ocular"

# Préfixes posés par `broker/sessions.py` (_CONTAINER_PREFIX / _NET_PREFIX).
_SESS_CONTAINER_PREFIX = "ocular-sess-"
_SESS_NET_PREFIX = "ocular-sess-net-"

# Le teardown de session est ASYNCHRONE (cf. AGENTS.md §5 : attendre ~25 s
# avant de conclure à une fuite). 60 s laissent la marge sans masquer une vraie
# fuite — au-delà, le résidu est réel et le test le dit.
_TEARDOWN_GRACE_S = 60.0


# --- pré-requis : tout absent => skip PROPRE, jamais une erreur de collecte ---


def _docker() -> str:
    exe = shutil.which("docker")
    if exe is None:
        pytest.skip("docker CLI absent de l'hôte")
    return exe


def _out(*args: str) -> str:
    proc = subprocess.run([_docker(), *args], cwd=_ROOT, capture_output=True,
                          text=True, check=False)
    return proc.stdout if proc.returncode == 0 else ""


def _require_image() -> None:
    proc = subprocess.run([_docker(), "image", "inspect", _IMAGE],
                          cwd=_ROOT, capture_output=True, check=False)
    if proc.returncode != 0:
        pytest.skip(f"image {_IMAGE} absente — lancer `make build-runner`")


def _gateway_container() -> str:
    """Identifiant du frontal `gateway` en cours d'exécution.

    On passe par les ÉTIQUETTES compose et non par un nom : `container_name`
    n'est figé que pour le `web` (le broker doit pouvoir le nommer) ; celui du
    frontal est généré par compose et changerait avec le nom de projet."""
    cid = _out("ps", "--quiet", "--filter", "status=running",
               "--filter", f"label=com.docker.compose.project={_COMPOSE_PROJECT}",
               "--filter", "label=com.docker.compose.service=gateway").strip()
    if not cid:
        pytest.skip("pile Ocular non levée (frontal `gateway` absent) — lancer `make up`")
    return cid.splitlines()[0]


def _token() -> str:
    """Jeton Bearer de la pile sous test.

    `deploy/.env` est LU, jamais sourcé : le sourcer exporterait aussi
    `REDIS_URL` dans le shell de pytest, ce qui fait rougir la suite sur du
    code sain (AGENTS.md §5). Seule cette clé est extraite."""
    tok = os.environ.get("OCULAR_TOKEN", "").strip()
    if tok:
        return tok
    env_file = _ROOT / "deploy" / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line.startswith("OCULAR_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    pytest.skip("jeton introuvable — exporter OCULAR_TOKEN ou le poser dans deploy/.env")
    raise AssertionError("unreachable")  # pragma: no cover


# --- inventaire des résidus de session --------------------------------------


def _session_containers() -> set[str]:
    # `--filter name=` est un filtre SOUS-CHAÎNE : on re-filtre sur le PRÉFIXE,
    # comme le fait `broker/sessions.py` et comme la cible `make down`.
    return {n for n in _out("ps", "-a", "--format", "{{.Names}}").split()
            if n.startswith(_SESS_CONTAINER_PREFIX)}


def _session_networks() -> set[str]:
    return {n for n in _out("network", "ls", "--format", "{{.Name}}").split()
            if n.startswith(_SESS_NET_PREFIX)}


def _sweep(containers: set[str], networks: set[str]) -> None:
    """Filet de dernier recours : ne retire QUE ce que le test a fait naître
    (delta), jamais une session d'un opérateur qui travaillait à côté."""
    for name in containers:
        subprocess.run([_docker(), "rm", "-f", name], cwd=_ROOT, capture_output=True, check=False)
    for name in networks:
        subprocess.run([_docker(), "network", "rm", name], cwd=_ROOT,
                       capture_output=True, check=False)


# --- exécution du pilote -----------------------------------------------------


def _run_driver(extra_args: list[str], timeout_s: int) -> dict:
    """Lance le pilote dans un conteneur jetable et rend son verdict JSON."""
    _require_image()
    gateway = _gateway_container()
    token = _token()
    assert _DRIVER.is_file(), f"pilote introuvable : {_DRIVER}"

    name = f"ocular-smoke-ui-{uuid.uuid4().hex[:8]}"
    cmd = [
        _docker(), "run", "--rm", "-i", "--name", name,
        # Partage de la pile réseau du frontal : l'UI est atteinte en
        # 127.0.0.1:8000, sans port publié et sans quitter le réseau interne.
        "--network", f"container:{gateway}",
        "--entrypoint", "python3",
        # Même durcissement que le tier capture en production
        # (broker/launcher.py::build_docker_args) : si le smoke tourne sous un
        # profil plus permissif, il ne prouve rien du navigateur réellement
        # déployé. `/work` doit être inscriptible : HOME/TMPDIR y pointent et
        # Camoufox y écrit son profil (cf. runner_recon/Dockerfile).
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--security-opt", "seccomp=schemas/seccomp-recon.json",
        "--read-only",
        "--tmpfs", "/work:size=512m,mode=1777",
        "--tmpfs", "/tmp:size=64m,mode=1777",
        "--user", "10001:10001",
        "--memory", "2g",
        "--pids-limit", "512",
        # engine/ vit dans /app (WORKDIR de l'image) ; le pilote est monté
        # ailleurs, donc /app n'est pas sur sys.path sans cette variable.
        "-e", "PYTHONPATH=/app",
        "-v", f"{_DRIVER}:/smoke/driver.py:ro",
        _IMAGE, "/smoke/driver.py",
        "--base-url", "http://127.0.0.1:8000",
        "--token-stdin",
        *extra_args,
    ]
    try:
        proc = subprocess.run(cmd, cwd=_ROOT, input=token + "\n", capture_output=True,
                              text=True, check=False, timeout=timeout_s)
        stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) \
            else (exc.stdout or "")
        stderr = (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) \
            else (exc.stderr or "")
        pytest.fail(f"pilote non terminé en {timeout_s}s\nstderr:\n{stderr[-4000:]}")
    finally:
        # `--rm` ne suffit PAS : un dépassement de délai tue le CLI docker, pas
        # le conteneur, qui continuerait à tenir un Camoufox et la pile réseau
        # du frontal. Idempotent quand `--rm` a déjà fait le travail.
        subprocess.run([_docker(), "rm", "-f", name], cwd=_ROOT,
                       capture_output=True, check=False)

    verdict = _verdict(stdout)
    if verdict is None:
        pytest.fail(
            f"le pilote n'a émis aucune ligne `{_JSON_PREFIX}` (rc={rc})\n"
            f"stdout:\n{stdout[-2000:]}\nstderr:\n{stderr[-4000:]}"
        )
    verdict["_rc"] = rc
    verdict["_stderr"] = stderr
    return verdict


def _verdict(stdout: str) -> dict | None:
    """Dernière ligne préfixée du pilote -> dict. On CHERCHE le préfixe au lieu
    de parser tout stdout : ni Camoufox ni le driver Playwright ne promettent
    un stdout silencieux, et un message parasite d'une dépendance ne doit pas
    faire passer un smoke réussi pour un échec de parsing."""
    for line in reversed(stdout.splitlines()):
        if line.startswith(_JSON_PREFIX):
            try:
                return json.loads(line[len(_JSON_PREFIX):])
            except json.JSONDecodeError:
                return None
    return None


def _assert_clean(verdict: dict) -> None:
    """Assertions communes : verdict positif ET zéro `pageerror`.

    Les deux sont contrôlés SÉPARÉMENT bien que le pilote pose déjà `ok=False`
    s'il a vu une erreur de page : un jour où `ok` changerait de sens, cette
    ligne-ci continuerait de mordre. « Zéro pageerror » est une assertion, pas
    une intention."""
    assert not verdict.get("page_errors"), (
        "exception(s) JS non rattrapée(s) dans l'UI :\n"
        + json.dumps(verdict.get("page_errors"), indent=2, ensure_ascii=False)
    )
    assert verdict.get("ok"), (
        f"smoke en échec [{verdict.get('kind')}] en phase {verdict.get('phase')!r} : "
        f"{verdict.get('error')}\n"
        f"étapes atteintes :\n"
        + json.dumps(verdict.get("steps", []), indent=2, ensure_ascii=False)
        + f"\nstderr du pilote :\n{verdict.get('_stderr', '')[-4000:]}"
    )


# --- les tests ---------------------------------------------------------------


def test_smoke_ui_main_views():
    """Login (pose du jeton) -> jobs -> submit -> détail/verdict -> interactif.

    Un seul navigateur pour toute la chaîne, à dessein : c'est ce qui permet
    d'exiger que le jeton posé au login survive à quatre rechargements complets
    de document, et que le job soumis réapparaisse dans la liste locale."""
    verdict = _run_driver([], timeout_s=420)
    _assert_clean(verdict)

    # Le marqueur de chaque vue doit avoir été RELEVÉ, pas seulement « pas
    # d'erreur » : un pilote qui sortirait tôt sans lever d'exception passerait
    # sinon au vert.
    phases = {s["phase"] for s in verdict.get("steps", [])}
    for expected in ("login", "jobs", "submit", "detail", "jobs-après-soumission",
                     "interactive"):
        assert expected in phases, (
            f"vue `{expected}` jamais atteinte ; phases vues : {sorted(phases)}"
        )
    assert verdict.get("job_id"), "aucun job_id — la soumission n'a pas abouti"


def test_smoke_ui_interactive_session_novnc():
    """Ouvre une VRAIE session interactive, attend le canvas noVNC + la
    connexion du flux, la referme, et vérifie qu'il ne reste RIEN.

    Séparé du test précédent parce qu'il coûte un conteneur de session
    (`mem_limit` 4 g) et un sous-réseau du pool docker — sur une machine
    contrainte, on veut pouvoir lancer l'un sans l'autre (`-k`)."""
    before_c, before_n = _session_containers(), _session_networks()
    created_c: set[str] = set()
    created_n: set[str] = set()
    try:
        verdict = _run_driver(["--with-session"], timeout_s=600)
        _assert_clean(verdict)

        phases = {s["phase"] for s in verdict.get("steps", [])}
        assert "interactive-session" in phases, (
            f"session interactive jamais ouverte ; phases : {sorted(phases)}"
        )
        steps = {s["step"] for s in verdict.get("steps", [])}
        assert "canvas noVNC présent" in steps, "le canvas noVNC n'a pas été observé"
        assert "flux VNC connecté" in steps, (
            "canvas présent mais flux jamais connecté — le `<canvas>` est créé "
            "par le constructeur RFB AVANT toute connexion, donc seul le statut "
            "`connecté` prouve la poignée de main WebSocket de bout en bout"
        )

        # AUCUN RÉSIDU. Le teardown est asynchrone : on laisse le temps au
        # broker, puis on constate. Un résidu au-delà de la grâce est un vrai
        # défaut — on le dit, après l'avoir nettoyé.
        deadline = time.time() + _TEARDOWN_GRACE_S
        while time.time() < deadline:
            created_c = _session_containers() - before_c
            created_n = _session_networks() - before_n
            if not created_c and not created_n:
                break
            time.sleep(2.0)
        assert not created_c and not created_n, (
            f"résidu de session après {_TEARDOWN_GRACE_S:.0f}s : "
            f"conteneurs={sorted(created_c)} réseaux={sorted(created_n)}"
        )
    finally:
        # Y COMPRIS EN CAS D'ÉCHEC : une session laissée vivante immobilise un
        # conteneur ~4 Go et un sous-réseau (le pool docker par défaut n'en
        # offre qu'une trentaine) jusqu'à son TTL.
        _sweep(_session_containers() - before_c, _session_networks() - before_n)
