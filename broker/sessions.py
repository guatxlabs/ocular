from __future__ import annotations

import subprocess

from broker.launcher import (
    CAPTURE_MEMORY,
    CAPTURE_PIDS_LIMIT,
    RECON_SECCOMP,
    egress_policy_env,
    base_hardening,
)
from bus.queue import RESULT_PREFIX
from ocular_logging import get_logger
from ocular_settings import session_screen, web_container

log = get_logger("broker.sessions")

# Plafonds de blocage des commandes conteneur. SANS eux, un démon bloqué
# (containerd coincé, disque plein, suppression « Removal In Progress ») fige
# l'appel INDÉFINIMENT : reaper figé, sweeper figé, ou — le pire — la boucle
# principale du broker figée via `process_session_cmd -> launch_session`, plus
# aucun job ni commande traité, alors que le processus reste « vivant » pour
# toute sonde de liveness. Un dépassement est traité comme n'importe quel autre
# échec best-effort (log + on continue) : c'est le contrat du module.
_TIMEOUT_NET = 15.0     # network create/connect/disconnect/rm/ls, ps
_TIMEOUT_CONTAINER = 30.0  # run/kill/rm : peuvent légitimement prendre du temps
_TIMEOUT_RETURNCODE = 124  # convention `timeout(1)` : commande interrompue

_SESSION_IMAGE = "ocular-runner-recon-vnc:latest"
_CONTAINER_PREFIX = "ocular-sess-"
_NET_PREFIX = "ocular-sess-net-"


def _run(args: list[str], timeout: float, **kwargs):
    """`subprocess.run` best-effort BORNÉ DANS LE TEMPS. Un dépassement ne
    remonte JAMAIS d'exception : il est converti en un résultat en échec
    (`returncode=124`), que les appelants traitent déjà comme tel — aucun
    d'entre eux ne doit pouvoir bloquer sa boucle sur un démon coincé."""
    try:
        return subprocess.run(args, capture_output=True, check=False, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        log.warning("commande conteneur expirée timeout=%ss cmd=%s", timeout, " ".join(args[:3]))
        empty = "" if kwargs.get("text") else b""
        return type("P", (), {"returncode": _TIMEOUT_RETURNCODE, "stdout": empty, "stderr": empty})()


def _session_name(session_id: str) -> str:
    return f"{_CONTAINER_PREFIX}{session_id}"


def _session_net(session_id: str) -> str:
    """Réseau docker DÉDIÉ à une session (miroir de `_session_name`). Chaque
    session vit sur son propre réseau bridge : deux sessions n'ont donc aucune
    route l'une vers l'autre (un conteneur compromis ne peut plus joindre le
    :6080/:8090 d'un pair). Le web y est attaché dynamiquement par le broker."""
    return f"{_NET_PREFIX}{session_id}"


def build_session_args(
    session_id: str, secret: str = "", image: str = _SESSION_IMAGE
) -> list[str]:
    """docker run **détaché** (`-d`, jamais `--rm -i` : le conteneur est
    persistant, son cycle de vie géré explicitement via `stop_session`) pour
    une session interactive (noVNC). Réseau **dédié à la session**
    (`ocular-sess-net-{id}`) ON (egress Internet nécessaire au recon) mais
    **aucun port hôte publié** (`-p`) :
    le web/broker parlent au conteneur via le réseau Docker interne
    uniquement — jamais docker.sock, jamais `--network host`, jamais
    `--privileged`. Durcissement (cap-drop/no-new-privileges/read-only/user)
    réutilisé de `launcher.base_hardening` (DRY, cf. audit phase 3a)."""
    return [
        "docker", "run", "-d",
        *base_hardening(_session_name(session_id), rm=False),
        "--network", _session_net(session_id),
        "--security-opt", f"seccomp={RECON_SECCOMP}",
        "--tmpfs", "/work:size=512m,mode=1777",
        "--tmpfs", "/tmp:size=64m,mode=1777",
        "--memory", CAPTURE_MEMORY,
        "--pids-limit", CAPTURE_PIDS_LIMIT,
        # Secret de session à la frontière conteneur (défense-en-profondeur
        # F1/F2) : le session_server exige ce secret sur /goto,/load,/capture.
        # SEUL le web le connaît ; jamais publié, jamais loggé. Fail-closed côté
        # conteneur (secret absent/vide => 403).
        "-e", f"OCULAR_SESSION_SECRET={secret}",
        # Résolution Xvfb configurable (non hardcodée) : le broker lit son propre
        # OCULAR_SESSION_SCREEN (validé par regex) et le passe au conteneur, où
        # entrypoint_vnc.sh l'utilise pour `Xvfb -screen`.
        "-e", f"OCULAR_SESSION_SCREEN={session_screen()}",
        # Politique egress (garde + mode strict) propagée au session_server.
        *egress_policy_env(),
        image,
    ]


def launch_session(session_id: str, secret: str = "") -> str:
    """Lance un conteneur de session détaché sur son réseau DÉDIÉ et y attache
    le conteneur web, puis retourne le nom du conteneur
    (`ocular-sess-{session_id}`). Seul le broker (jamais le web) exécute ceci.

    Ordre CONTRAIGNANT (garantie anti-race) : réseau créé -> conteneur lancé
    dessus -> web attaché. `process_session_cmd` n'écrit au registre qu'APRÈS
    le retour d'ici, donc quand le web commence son poll de santé il est déjà
    sur le réseau et résout `ocular-sess-{id}` par DNS Docker.

    Tout est best-effort : le nom est toujours retourné, même si une commande
    échoue — c'est le poll de santé aval qui décide de l'état réel."""
    name = _session_name(session_id)
    net = _session_net(session_id)
    log.info("session launch session_id=%s net=%s", session_id, net)  # jamais le secret

    created = _run(["docker", "network", "create", net], _TIMEOUT_NET)
    if created.returncode != 0:
        stderr = created.stderr.decode(errors="replace")
        if "already exists" not in stderr:
            # Warning DISTINCTIF : la cause la plus probable est l'épuisement du
            # pool d'adresses Docker (cf. docs/DEPLOY-SECURITY.md, élargir
            # default-address-pools). Sans ce log, l'échec serait opaque.
            log.warning(
                "session network create failed session_id=%s net=%s stderr=%s "
                "(pool d'adresses Docker épuisé ? cf. default-address-pools)",
                session_id, net, stderr[:200],
            )

    proc = _run(build_session_args(session_id, secret=secret), _TIMEOUT_CONTAINER)
    if proc.returncode != 0:
        log.warning(
            "session launch failed session_id=%s returncode=%s stderr=%s",
            session_id, proc.returncode, proc.stderr.decode(errors="replace")[:200],
        )

    web = web_container()
    conn = _run(["docker", "network", "connect", net, web], _TIMEOUT_NET)
    if conn.returncode != 0:
        log.warning(
            "session network connect failed session_id=%s net=%s web=%s stderr=%s",
            session_id, net, web, conn.stderr.decode(errors="replace")[:200],
        )
    return name


def stop_session(container: str) -> None:
    """Arrête et supprime un conteneur de session PUIS libère son réseau dédié
    (détache le web, supprime le réseau). Best-effort (`check=False`) : robuste
    au TOCTOU (conteneur/réseau déjà disparu — `reap` peut appeler ceci sur un
    fantôme sans lever).

    L'ORDRE est contraignant : Docker refuse de supprimer un réseau encore
    utilisé, donc le conteneur part d'abord."""
    _run(["docker", "kill", container], _TIMEOUT_CONTAINER)
    _run(["docker", "rm", "-f", container], _TIMEOUT_CONTAINER)

    if not container.startswith(_CONTAINER_PREFIX):
        return  # nom inattendu : ne jamais dériver/supprimer un réseau au hasard
    session_id = container[len(_CONTAINER_PREFIX):]
    net = _session_net(session_id)
    _run(["docker", "network", "disconnect", "-f", net, web_container()], _TIMEOUT_NET)
    _run(["docker", "network", "rm", net], _TIMEOUT_NET)


def _sweep_orphan_networks(registry) -> int:
    """Supprime les réseaux `ocular-sess-net-*` qui ne correspondent à AUCUNE
    session vivante — résidus d'un crash broker, d'un `compose down`, ou d'un
    `network rm` qui avait échoué (conteneur pas encore parti). Un réseau
    orphelin est inerte mais consomme un sous-réseau du pool d'adresses Docker,
    qui est une ressource FINIE : sans ce balayage, les lancements finiraient
    par échouer. Best-effort."""
    proc = _run(
        ["docker", "network", "ls", "--filter", f"name={_NET_PREFIX}", "--format", "{{.Name}}"],
        _TIMEOUT_NET, text=True,
    )
    if proc.returncode != 0:
        return 0
    removed = 0
    web = web_container()
    for name in proc.stdout.split():
        if not name.startswith(_NET_PREFIX):
            continue  # garde-fou : le filtre `name=` est un substring
        session_id = name[len(_NET_PREFIX):]
        if registry.get(session_id) is not None:
            continue  # session vivante : on ne touche pas à son réseau
        _run(["docker", "network", "disconnect", "-f", name, web], _TIMEOUT_NET)
        _run(["docker", "network", "rm", name], _TIMEOUT_NET)
        removed += 1
    if removed:
        log.info("session orphan networks swept count=%d", removed)
    return removed


def sweep_orphans(registry) -> int:
    """Supprime les conteneurs de session `ocular-sess-*` qui ne correspondent
    à AUCUNE session vivante du registre — orphelins laissés par un crash du
    broker OU par `docker compose down` (les conteneurs de session sont lancés
    hors-compose via `docker run`, donc JAMAIS retirés par `compose down`).
    Balaie ENSUITE les réseaux dédiés `ocular-sess-net-*` restés sans session
    vivante, qui consommeraient un sous-réseau du pool d'adresses Docker.
    Appelé au démarrage du broker ET périodiquement (`_sweeper_loop`, cf.
    `sweep_interval()`) : tout conteneur (ou réseau) sans session vivante est
    forcément un résidu -> on le supprime. Best-effort
    (`check=False`) : une absence de Docker ou une erreur transitoire renvoie 0
    sans lever. Retourne le nombre de **conteneurs** supprimés (le compte des
    réseaux part dans un log dédié)."""
    proc = _run(
        ["docker", "ps", "-a", "--filter", f"name={_CONTAINER_PREFIX}", "--format", "{{.Names}}"],
        _TIMEOUT_NET, text=True,
    )
    removed = 0
    # Un `docker ps` en échec neutralise le balayage CONTENEURS uniquement : pas
    # de `return` anticipé ici, sinon le balayage RÉSEAU (indépendant, et dont le
    # `docker network ls` aurait pu réussir) sauterait lui aussi : le rattrapage
    # au prochain cycle du sweeper ne doit pas être la seule chance de libérer un
    # sous-réseau du pool d'adresses Docker.
    if proc.returncode == 0:
        for name in proc.stdout.split():
            if not name.startswith(_CONTAINER_PREFIX):
                continue  # garde-fou : le filtre `name=` est un substring
            session_id = name[len(_CONTAINER_PREFIX):]
            if registry.get(session_id) is None:
                stop_session(name)
                removed += 1
        if removed:
            log.info("session orphans swept count=%d", removed)
    # Les conteneurs orphelins sont partis -> leurs réseaux peuvent être libérés
    # (ordre contraignant, comme dans stop_session).
    _sweep_orphan_networks(registry)
    return removed


_GLOB_META = "\\*?[]"


def _escape_glob(value: str) -> str:
    """Neutralise les métacaractères de glob Redis (`\\ * ? [ ]`) pour qu'une
    valeur interpolée dans un motif `SCAN MATCH` ne matche QU'elle-même.
    L'antislash passe en premier : l'échapper après aurait ré-échappé les
    antislashs posés par les autres remplacements."""
    for ch in _GLOB_META:
        value = value.replace(ch, "\\" + ch)
    return value


def purge_session_results(client, session_id: str) -> int:
    """Supprime de Redis les captures interactives ÉPHÉMÈRES d'une session
    (`ocular:result:sesscap-{sid}-*`). Une capture non nommée n'est jamais
    persistée en SQLite → à la fermeture/expiration de la session elle doit
    disparaître (exigence : « ne sauvegarde que si un nom est donné »). Les
    captures SAUVEGARDÉES sont déjà copiées en SQLite par POST /saved, donc
    purger le résultat Redis reste sûr. Best-effort (aucune exception propagée).
    Retourne le nombre de clés supprimées."""
    # `scan_iter(match=...)` prend un GLOB Redis : `*`, `?`, `[...]` et `\` y
    # sont des MÉTACARACTÈRES. Interpolé brut, un session_id hostile élargissait
    # le motif (`sesscap-*-*`) et purgeait les captures éphémères de TOUTES les
    # sessions actives. Le web filtre déjà le format en amont ; ce verrou-ci est
    # INDÉPENDANT (le broker ne doit jamais dépendre de l'hygiène de l'appelant).
    pattern = f"{RESULT_PREFIX}sesscap-{_escape_glob(session_id)}-*"
    removed = 0
    try:
        for key in client.scan_iter(match=pattern, count=100):
            client.delete(key)
            removed += 1
    except Exception as exc:  # noqa: BLE001 - purge best-effort, ne bloque jamais le teardown
        log.warning("purge session results failed session_id=%s err=%s", session_id, str(exc)[:200])
    if removed:
        log.info("session results purged session_id=%s count=%d", session_id, removed)
    return removed


def reap(registry, now_epoch: float, ttl: float, idle: float, disconnect_grace=None) -> int:
    """Détruit les sessions expirées (TTL absolu, inactivité, ou — si
    `disconnect_grace` fourni — fermeture brutale du navigateur au-delà de la
    grâce) : pour chaque id retourné par `registry.expired`, stoppe le
    conteneur par son nom **déterministe** `ocular-sess-{id}` (dérivé du
    session_id, jamais via `registry.get` qui peut renvoyer None sur une
    course entre l'expiration et le reap — le conteneur existe toujours
    indépendamment de l'état du registre) puis retire la session du registre.
    Retourne le nombre de sessions réellement traitées."""
    count = 0
    for session_id in registry.expired(now_epoch, ttl, idle, disconnect_grace=disconnect_grace):
        stop_session(_session_name(session_id))
        purge_session_results(registry.client, session_id)  # captures éphémères non nommées
        registry.delete(session_id)
        count += 1
    return count
