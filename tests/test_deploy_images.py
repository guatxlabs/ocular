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

Les tests qui construisent/lancent des conteneurs sont marqués `integration`
au cas par cas (nécessitent un daemon Docker, exclus par défaut via
`addopts = "-m 'not integration'"`). Les gardes ci-dessous sur le Makefile/
README (phase 3c) sont volontairement **non-integration** : elles n'ont pas
besoin de Docker et confirment, sans lancer de build, que le tier dynamique
scripté (3c) ne fait QUE réutiliser `ocular-runner-recon` (aucune 6e image).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest

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


@pytest.mark.integration
def test_web_image_imports_app_and_saved_store():
    tag = "ocular-web-guard:test"
    _build("deploy/Dockerfile.web", tag)
    try:
        # user 10002 non-root : on importe simplement, sans écrire de DB.
        _run(tag, "python -c 'import web.app; import saved_store'")
    finally:
        subprocess.run([_docker(), "rmi", "-f", tag], capture_output=True)


@pytest.mark.integration
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


@pytest.mark.integration
def test_runner_image_builds():
    tag = "ocular-runner-guard:test"
    _build("runner_analysis/Dockerfile", tag)
    subprocess.run([_docker(), "rmi", "-f", tag], capture_output=True)


@pytest.mark.integration
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


@pytest.mark.integration
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


def test_makefile_has_script_target():
    """3c : `make script URL=... STEPS=...` doit exister et soumettre le job
    scripté via POST /jobs (même mécanisme/jeton que `analyze`)."""
    makefile = (_ROOT / "Makefile").read_text()
    assert "\nscript:" in makefile
    assert "/jobs" in makefile
    assert "STEPS" in makefile


def test_readme_documents_3c():
    """3c doit être documenté (usage, DSL, garanties de sécurité)."""
    readme = (_ROOT / "README.md").read_text().lower()
    assert "scripté" in readme
    assert "steps" in readme
    assert "make script" in readme


_WEB_CONTAINER_EXPR = "${OCULAR_WEB_CONTAINER:-ocular-web}"


def _compose_service_block(service: str) -> str:
    """Bloc texte d'un service de `deploy/docker-compose.yml`.

    Parsing TEXTE volontaire : `yaml` n'est pas une dépendance de test du
    projet (aucun `import yaml` dans la suite, aucun requirements), on
    n'en introduit pas une pour une garde de déploiement.
    """
    compose = (_ROOT / "deploy" / "docker-compose.yml").read_text()
    assert f"\n  {service}:" in compose, f"service `{service}` absent du compose"
    after = compose.split(f"\n  {service}:", 1)[1]
    lines = []
    for line in after.splitlines():
        # Fin du bloc : première ligne non vide indentée de <= 2 espaces
        # (service suivant ou section top-level `volumes:`/`networks:`).
        if line.strip() and not line.startswith("    "):
            break
        lines.append(line)
    return "\n".join(lines)


def test_compose_web_container_name_is_single_source_of_truth():
    """Le `container_name` du web ET la variable `OCULAR_WEB_CONTAINER` passée
    au broker doivent dériver de la MÊME expression interpolée.

    MODE DE PANNE PRÉVENU — ne pas « simplifier » ce test : si quelqu'un
    re-fige `container_name: ocular-web` en dur (ou change un seul des deux
    côtés), un opérateur qui surcharge `OCULAR_WEB_CONTAINER` dans
    `deploy/.env` obtient un broker qui attache aux réseaux per-session un
    conteneur qui n'existe PAS : `docker network connect` échoue et TOUTES
    les sessions interactives deviennent injoignables depuis le web. Rien
    d'autre dans la suite n'attraperait cette divergence.
    """
    web = _compose_service_block("web")
    broker = _compose_service_block("broker")

    web_names = [
        line.split(":", 1)[1].strip().strip('"').strip("'")
        for line in web.splitlines()
        if line.strip().startswith("container_name:")
    ]
    assert len(web_names) == 1, f"container_name web attendu une seule fois : {web_names}"
    assert web_names[0] == _WEB_CONTAINER_EXPR, (
        "le container_name du web doit rester l'expression interpolée "
        f"{_WEB_CONTAINER_EXPR}, pas une valeur en dur : {web_names[0]!r}"
    )

    broker_vars = [
        line.split(":", 1)[1].strip().strip('"').strip("'")
        for line in broker.splitlines()
        if line.strip().startswith("OCULAR_WEB_CONTAINER:")
    ]
    assert len(broker_vars) == 1, f"OCULAR_WEB_CONTAINER broker attendu une fois : {broker_vars}"
    assert broker_vars[0] == _WEB_CONTAINER_EXPR, (
        "le broker doit lire la MÊME expression que le container_name du web : "
        f"{broker_vars[0]!r}"
    )
    assert web_names[0] == broker_vars[0], (web_names, broker_vars)


def test_build_runner_still_builds_exactly_three_images():
    """3c réutilise `ocular-runner-recon` (le conteneur `capture` 3a) : il ne
    doit PAS y avoir de 6e image. `build-runner` construit toujours les 3
    images runner (analysis, recon, recon-vnc) ; web/broker sont construites
    par `deploy/docker-compose.yml` — total 5 images inchangé depuis 3b."""
    makefile = (_ROOT / "Makefile").read_text()
    build_runner_block = makefile.split("build-runner:", 1)[1].split("\nup:", 1)[0]
    assert build_runner_block.count("docker build") == 3
    for image in (
        "ocular-runner-analysis",
        "ocular-runner-recon",
        "ocular-runner-recon-vnc",
    ):
        assert image in build_runner_block


# --- Durcissement du déploiement (audit sécurité 2026-07-18) -----------------
# Ces gardes sont NON-integration : elles lisent le compose, sans Docker.

_HARDENED_SERVICES = ("web", "broker", "redis")


@pytest.mark.parametrize("service", _HARDENED_SERVICES)
def test_compose_service_is_hardened(service):
    """Les TROIS services du plan de contrôle gardent les 4 flags de durcissement.

    MODE DE PANNE PRÉVENU : avant l'audit, seul le `web` était durci — le
    `broker`, qui est pourtant le SEUL à monter `/var/run/docker.sock`,
    tournait root / rootfs inscriptible / toutes capabilities, et `redis`
    idem. Une régression silencieuse d'un de ces flags rouvrirait les étapes
    intermédiaires d'une RCE (implant persistant, SUID, abus de capability)
    sur le tier le plus sensible de la stack.
    """
    block = _compose_service_block(service)
    assert "read_only: true" in block, f"{service} : read_only manquant"
    assert 'cap_drop: ["ALL"]' in block, f"{service} : cap_drop ALL manquant"
    assert 'security_opt: ["no-new-privileges:true"]' in block, (
        f"{service} : no-new-privileges manquant"
    )
    user_lines = [ln.strip() for ln in block.splitlines() if ln.strip().startswith("user:")]
    assert len(user_lines) == 1, f"{service} : `user:` attendu une fois, vu {user_lines}"
    uid = user_lines[0].split(":", 1)[1].strip().strip('"').strip("'").split(":")[0]
    assert uid.isdigit() and uid != "0", f"{service} : doit tourner non-root, vu {user_lines[0]!r}"


def test_compose_broker_docker_gid_is_parameterised():
    """Le broker est non-root : son accès au socket Docker passe par `group_add`.

    MODE DE PANNE PRÉVENU — ne pas figer ce GID : le socket est
    `root:docker` avec un GID SPÉCIFIQUE À L'HÔTE (965 sur la machine de
    dev, 999 sur un Debian/Ubuntu standard). Un GID en dur casserait l'accès
    Docker — donc TOUTES les sessions interactives — sur la plupart des hôtes.
    """
    block = _compose_service_block("broker")
    assert "group_add:" in block, "broker : group_add requis pour l'accès au socket Docker"
    assert "${OCULAR_DOCKER_GID:-" in block, (
        "le GID du socket doit rester interpolé depuis l'environnement, jamais en dur"
    )
    # Le broker écrit hors /artifacts uniquement dans /tmp : le CLI docker doit y
    # être pointé, sinon il vise $HOME/.docker sur un rootfs gelé.
    assert 'DOCKER_CONFIG: "/tmp/.docker"' in block, "broker : DOCKER_CONFIG doit viser le tmpfs"
    assert 'OCULAR_ARTIFACTS_DIR: "/artifacts"' in block, (
        "sans cette variable, artifacts_dir() retombe sur un chemin relatif "
        "(/app/artifacts) non inscriptible sous read_only: true"
    )


def test_compose_redis_tmpfs_carries_writable_mode():
    """Le tmpfs /data de redis DOIT porter mode=1777.

    MODE DE PANNE PRÉVENU (reproduit live avant d'écrire ce test) : redis
    tourne en uid 999, or un tmpfs Docker par défaut est root:root 0755. Sans
    le mode, le premier point de sauvegarde échoue en EACCES et redis bascule
    en `stop-writes-on-bgsave-error` -> `MISCONF`, TOUT write refusé. La stack
    ne tombe pas au démarrage mais quelques minutes après : régression
    particulièrement traître.
    """
    block = _compose_service_block("redis")
    assert "/data:mode=1777" in block, "redis : tmpfs /data doit être inscriptible par uid 999"


def test_compose_api_binds_loopback_by_default():
    """L'API ne doit pas être publiée sur 0.0.0.0 par défaut.

    `ports: ["8000:8000"]` écoutait implicitement sur toutes les interfaces :
    /sessions et le proxy noVNC étaient joignables depuis n'importe quel poste
    du LAN, derrière un unique Bearer statique sans rotation ni rate-limit.
    """
    block = _compose_service_block("web")
    assert "${OCULAR_BIND:-127.0.0.1}:8000:8000" in block, (
        "le bind par défaut doit rester la loopback ; exposer doit rester un acte "
        "explicite de l'opérateur (OCULAR_BIND=0.0.0.0)"
    )


def test_compose_redis_url_degrades_to_no_auth_when_password_empty():
    """`requirepass` optionnel, sans branche — et surtout sans casser le défaut.

    Vide -> `redis-server --requirepass ""` (auth désactivée côté serveur) et
    `redis://:@redis:6379`, que redis-py parse en password=None (aucun AUTH
    envoyé). Les deux extrémités doivent lire la MÊME variable, sinon poser un
    mot de passe authentifie un côté et pas l'autre -> stack morte.
    """
    expected = "redis://:${OCULAR_REDIS_PASSWORD:-}@redis:6379"
    for service in ("web", "broker"):
        block = _compose_service_block(service)
        urls = [
            line.split(":", 1)[1].strip().strip('"').strip("'")
            for line in block.splitlines()
            if line.strip().startswith("REDIS_URL:")
        ]
        assert urls == [expected], f"{service} : REDIS_URL attendu {expected!r}, vu {urls}"
    redis_block = _compose_service_block("redis")
    assert '"--requirepass", "${OCULAR_REDIS_PASSWORD:-}"' in redis_block, (
        "redis doit lire la MÊME variable que l'URL des clients"
    )
