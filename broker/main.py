from __future__ import annotations

import json
import threading
import time as _time
from datetime import datetime, timezone

import redis

from broker.gc import collect
from broker.launcher import run_job
from broker.sessions import launch_session, purge_session_results, reap, stop_session, sweep_orphans
from bus.queue import RedisJobQueue
from bus.sessions import SessionCmdQueue, SessionRegistry
from ocular_logging import get_logger
from ocular_settings import (
    artifacts_dir,
    gc_interval,
    job_ttl,
    reaper_interval,
    redis_url,
    result_ttl,
    session_disconnect_grace,
    session_idle,
    session_ttl,
    sweep_interval,
)

log = get_logger("broker")

# Repli d'intervalle utilisé si l'accesseur lui-même explosait (défense en
# profondeur : les accesseurs de `ocular_settings` ne lèvent plus, cf. la règle
# en tête de ce module-là). Jamais 0 : `sleep(0)` = boucle folle à 100 % CPU.
_FALLBACK_INTERVAL = 60

# Cadence de la boucle des commandes de session. Le RYTHME réel vient du
# `blpop(timeout=1)` BLOQUANT de `dequeue_cmd` — pas de ce sleep, qui n'existe
# que pour respecter l'invariant de `_daemon_loop` (jamais `sleep(0)`, qui
# ferait une boucle folle à 100 % CPU si `dequeue_cmd` rendait la main
# instantanément, ce qui est le cas des doubles de test). 50 ms est invisible
# face aux ~0,6-3 s de `launch_session`.
_SESSION_CMD_INTERVAL = 0.05


def error_result(job_id: str, exc: Exception) -> str:
    """Résultat JSON TOUJOURS valide pour un job échoué (le message d'exception
    peut contenir des guillemets/newlines venant de stderr Docker). `status`
    à "error" pour que l'UI distingue un échec réel d'un verdict "unknown"."""
    return json.dumps({"job_id": job_id, "status": "error", "error": str(exc)[:200]})


def process_one(queue: RedisJobQueue, job) -> None:
    """Une itération de la boucle : traite un job et stocke son résultat
    (ou l'erreur). Extrait de run_forever() pour être testable sans mocker
    une boucle infinie."""
    log.info("job start job_id=%s", job.job_id)
    # Rafraîchit la fenêtre d'acceptation au moment où le job DÉMARRE réellement :
    # sous une file profonde de jobs scriptés (broker mono-thread), le marqueur
    # posé au submit pouvait expirer avant le démarrage -> GET /jobs renverrait
    # un faux « unknown » terminal alors que le job va aboutir (audit L2).
    try:
        queue.mark_accepted(job.job_id, job_ttl())
    except Exception:  # noqa: BLE001 - best-effort, ne bloque pas le traitement
        pass
    try:
        result_json = run_job(job)
    except Exception as exc:  # le job échoue proprement, le broker survit
        log.error("job failed job_id=%s err=%s", job.job_id, str(exc)[:200])
        result_json = error_result(job.job_id, exc)
    else:
        log.info("job done job_id=%s", job.job_id)
    queue.set_result(job.job_id, result_json, ttl=result_ttl())


def process_session_cmd(cmd: dict, registry: SessionRegistry) -> None:
    """Une itération de la boucle session-cmds : `launch` démarre le
    conteneur (seul le broker a accès à Docker) et écrit l'entrée registre
    (container/kind/target/token/owner — le token comme le propriétaire
    viennent tels quels de la commande, le token n'est jamais loggé) ; `stop`
    détruit le conteneur par son nom déterministe et retire l'entrée. Extrait
    de `run_forever()` pour être testable sans mocker une boucle infinie ni
    Docker."""
    action = cmd.get("action")
    session_id = cmd.get("session_id")
    if not session_id:
        log.warning("session cmd sans session_id ignorée action=%s", action)
        return
    if action == "launch":
        # secret conteneur (défense-en-profondeur F1/F2) : threadé de la cmd
        # jusqu'à `docker run -e OCULAR_SESSION_SECRET=…` ET stocké au registre
        # pour que le web signe ses appels internes. Jamais loggé.
        secret = cmd.get("secret", "")
        # RÉSERVATION AVANT LANCEMENT (anti-race avec `_sweeper_loop`) : l'entrée
        # registre est écrite d'ABORD, avec un `container` vide. Sans elle, la
        # fenêtre de `launch_session` (~0,6-3 s : network create + docker run +
        # network connect) laissait un conteneur visible de `docker ps -a` mais
        # ABSENT du registre — le sweeper concurrent appliquait « pas au registre
        # => résidu » et DÉTRUISAIT une session saine qui venait de démarrer
        # (variante pire : un sweep entre `network create` et `docker run`
        # supprimait le réseau et le run échouait en « network not found »).
        # Le `container` vide est significatif : `web._wait_session_ready` exige
        # un container non vide, donc il continue d'attendre le remplissage.
        registry.create(
            session_id,
            container="",
            kind="recon-vnc",
            target=cmd.get("target", ""),
            token=cmd.get("token", ""),
            secret=secret,
            # Propriétaire résolu côté web (`resolve_identity`) et threadé tel
            # quel : le broker ne voit aucune requête HTTP, il ne peut pas le
            # recalculer. Une commande sans `owner` (jamais produite par le web
            # actuel) donne une session sans propriétaire, que le web refuse
            # ensuite aux non-admins — fail-closed.
            owner=cmd.get("owner", ""),
            now_iso=datetime.now(timezone.utc).isoformat(),
        )
        try:
            container = launch_session(session_id, secret=secret)
        except Exception:
            # pas de fantôme pending au registre : il protégerait indéfiniment
            # du balayage un réseau/conteneur qui n'aboutira jamais.
            registry.delete(session_id)
            raise
        registry.set_container(session_id, container)
        log.info("session cmd launch session_id=%s container=%s", session_id, container)
    elif action == "stop":
        stop_session(session_id)
        purge_session_results(registry.client, session_id)  # captures éphémères non nommées
        registry.delete(session_id)
        log.info("session cmd stop session_id=%s", session_id)
    else:
        log.warning("session cmd action inconnue session_id=%s action=%s", session_id, action)


def _daemon_loop(work, interval_fn, error_label: str, stop_event=None) -> None:
    """Corps COMMUN des boucles démon (reaper / GC / sweeper), qui répétaient
    toutes trois la même structure : « tant que pas d'arrêt demandé : travaille,
    absorbe et journalise l'exception, dors ».

    `work` et `interval_fn` sont des callables SANS argument : les boucles
    appelantes capturent leurs dépendances dans une lambda, ce qui préserve la
    résolution des globales AU MOMENT DE L'APPEL (les tests monkeypatchent
    `main_mod.reap`, `main_mod.gc_interval`, … : une référence capturée à
    l'import les manquerait).

    `error_label` garde les journaux DISTINCTS d'une boucle à l'autre : une
    ligne « erreur » indifférenciée rendrait indiscernable une panne Docker du
    sweeper d'une panne Redis du reaper, exactement au moment où on en a besoin.

    Invariants que les tests existants verrouillent, à ne pas simplifier :
    - le travail est RETENTÉ à chaque tour malgré une exception à CHAQUE tour
      (jamais de `return` dans l'`except` : le broker resterait « vivant » pour
      une sonde de liveness alors que plus rien n'est reapé/collecté/balayé) ;
    - la LECTURE D'INTERVALLE est DANS le `try` : placée après l'`except`, une
      valeur d'env malformée (`OCULAR_REAPER_INTERVAL=60s`) levait hors de toute
      garde et tuait le thread démon SANS UN SEUL LOG ;
    - repli sur `_FALLBACK_INTERVAL`, jamais 0 (`sleep(0)` = 100 % CPU)."""
    while stop_event is None or not stop_event.is_set():
        try:
            work()
            interval = interval_fn()
        except Exception as exc:  # la boucle survit à une erreur transitoire
            log.error("%s err=%s", error_label, str(exc)[:200])
            interval = _FALLBACK_INTERVAL
        if stop_event is not None:
            if stop_event.wait(interval):
                break
        else:
            _time.sleep(interval)


def _reaper_loop(registry, stop_event=None) -> None:
    """Boucle du reaper de sessions : appelle `reap` à intervalle régulier
    (`reaper_interval()`). `stop_event` permet un arrêt propre en test (une
    seule itération) ; en production (`stop_event=None`) tourne indéfiniment
    dans un thread démon. Les erreurs de `reap` sont capturées pour que le
    reaper survive à un incident Redis/Docker transitoire."""
    _daemon_loop(
        lambda: reap(
            registry, _time.time(), session_ttl(), session_idle(), session_disconnect_grace()
        ),
        lambda: reaper_interval(),
        "reaper error",
        stop_event=stop_event,
    )


def _start_reaper(client) -> threading.Thread:
    """Démarre le reaper de sessions dans un thread démon (n'empêche jamais
    l'arrêt du process broker). Réutilise le client Redis déjà créé par
    `run_forever` (pas de connexion supplémentaire)."""
    reg = SessionRegistry(client)
    t = threading.Thread(target=_reaper_loop, args=(reg,), daemon=True, name="ocular-reaper")
    t.start()
    return t


def _gc_loop(client, stop_event=None) -> None:
    """Boucle de garbage-collection des artefacts : appelle `collect` à
    intervalle régulier (`gc_interval()`). `stop_event` permet un arrêt
    propre en test (une seule itération) ; en production (`stop_event=None`)
    tourne indéfiniment dans un thread démon. Les erreurs de `collect` sont
    capturées pour que le GC survive à un incident Redis/disque transitoire
    (les artefacts s'accumuleraient sinon jusqu'au prochain redémarrage)."""
    _daemon_loop(
        lambda: collect(artifacts_dir(), client),
        lambda: gc_interval(),
        "gc error",
        stop_event=stop_event,
    )


def _start_gc(client) -> threading.Thread:
    """Démarre le GC des artefacts dans un thread démon (n'empêche jamais
    l'arrêt du process broker). Réutilise le client Redis déjà créé par
    `run_forever` (pas de connexion supplémentaire)."""
    t = threading.Thread(target=_gc_loop, args=(client,), daemon=True, name="ocular-gc")
    t.start()
    return t


def _sweeper_loop(registry, stop_event=None) -> None:
    """Boucle de balayage des orphelins : appelle `sweep_orphans` à intervalle
    régulier (`sweep_interval()`). L'appel au démarrage de `run_forever` ne
    couvre QUE les résidus d'un crash précédent ; un orphelin apparu EN COURS
    de vie (teardown partiellement échoué, conteneur tué hors flux) survivrait
    sinon jusqu'au prochain redémarrage du broker, en gardant un sous-réseau du
    pool d'adresses Docker — ressource FINIE. `stop_event` permet un arrêt
    propre en test (une seule itération) ; en production (`stop_event=None`)
    tourne indéfiniment dans un thread démon. Les erreurs de `sweep_orphans`
    sont capturées pour que le balayage survive à un incident Docker/Redis
    transitoire."""
    _daemon_loop(
        lambda: sweep_orphans(registry),
        lambda: sweep_interval(),
        "orphan sweep error",
        stop_event=stop_event,
    )


def _start_sweeper(client) -> threading.Thread:
    """Démarre le balayage des orphelins dans un thread démon (n'empêche jamais
    l'arrêt du process broker). Réutilise le client Redis déjà créé par
    `run_forever` (pas de connexion supplémentaire)."""
    reg = SessionRegistry(client)
    t = threading.Thread(target=_sweeper_loop, args=(reg,), daemon=True, name="ocular-sweeper")
    t.start()
    return t


def _consume_session_cmd(cmd_queue: SessionCmdQueue, registry: SessionRegistry) -> None:
    """UN tour de la boucle des commandes de session : dépile (bloquant ~1 s)
    puis traite. Les deux gardes viennent TELS QUELS de l'ancienne boucle
    unique de `run_forever` et doivent le rester :

    - le DÉPILAGE est gardé séparément du traitement, parce que `json.loads`
      a lieu dans `dequeue_cmd` : une commande corrompue levait sinon jusqu'au
      `while True` et ARRÊTAIT le broker. L'élément fautif est déjà consommé
      par `blpop` (pas de boucle infinie dessus) et il est journalisé SANS son
      contenu brut, qui peut porter un token de session ou le secret conteneur ;
    - le TRAITEMENT est gardé pour que le broker SURVIVE à une commande en
      échec (Docker qui hoquette sur `launch_session`, Redis en vrac).

    Extrait de `run_forever` pour pouvoir tourner dans son propre thread démon :
    `process_one` est synchrone et lent (jusqu'à 90 s pour une capture, 180 s
    pour un job scripté), et tant que les deux files partageaient la même
    boucle, une commande de session déposée pendant un job attendait la fin de
    ce job — au-delà du plafond `OCULAR_SESSION_READY_TIMEOUT` (30 s) que
    `web.create_session` accorde à la disponibilité. Le client recevait alors
    504 pendant que le broker lançait le conteneur malgré tout : un session_id
    vivant perdu, donc un conteneur (~4 g) et un sous-réseau du pool Docker
    retenus jusqu'à ce que le `stop` compensatoire soit lui-même dépilé."""
    try:
        cmd = cmd_queue.dequeue_cmd(timeout=1)
    except Exception as exc:  # noqa: BLE001 - commande illisible : on l'abandonne
        log.error("commande de session illisible ignorée err=%s", type(exc).__name__)
        return
    if cmd is None:
        return
    try:
        process_session_cmd(cmd, registry)
    except Exception as exc:  # le broker survit à une commande en échec
        log.error("session cmd failed cmd=%s err=%s", cmd.get("action"), str(exc)[:200])


def _session_cmd_loop(cmd_queue, registry, stop_event=None) -> None:
    """Boucle de consommation des commandes de session (`launch`/`stop`),
    désormais INDÉPENDANTE de la boucle des jobs. Même corps commun que le
    reaper/GC/sweeper (`_daemon_loop`) : elle survit à une erreur imprévue,
    relit son intervalle à chaque tour et ne dort jamais 0."""
    _daemon_loop(
        lambda: _consume_session_cmd(cmd_queue, registry),
        lambda: _SESSION_CMD_INTERVAL,
        "session cmd loop error",
        stop_event=stop_event,
    )


def _start_session_cmds(client) -> threading.Thread:
    """Démarre la consommation des commandes de session dans un thread démon
    (n'empêche jamais l'arrêt du process broker). Réutilise le client Redis
    déjà créé par `run_forever` (pas de connexion supplémentaire).

    UN SEUL thread, délibérément : les commandes de session restent donc
    sérialisées ENTRE ELLES, exactement comme avant, et le broker ne lance
    jamais deux conteneurs de session à la fois. Le plafond de sessions
    concurrentes (`OCULAR_MAX_SESSIONS`) reste appliqué côté web, où il a le
    contexte HTTP pour répondre 429 ; un sémaphore ici ne bornerait rien de
    plus (le parallélisme introduit est de 1) et ne ferait que réintroduire de
    l'attente dans le chemin qu'on vient de libérer."""
    cmd_queue = SessionCmdQueue(client)
    registry = SessionRegistry(client)
    t = threading.Thread(
        target=_session_cmd_loop,
        args=(cmd_queue, registry),
        daemon=True,
        name="ocular-session-cmds",
    )
    t.start()
    return t


def run_forever() -> None:
    # Client Redis PARTAGÉ par la boucle de jobs et les 4 threads démon. C'est
    # sûr : `redis.Redis` sert chaque commande via un `ConnectionPool` verrouillé
    # (une connexion est prise puis rendue par appel) et n'est déclaré non
    # thread-safe QUE construit avec `single_connection_client=True`, ce qui
    # n'est pas le cas ici. Les pipelines WATCH de `SessionRegistry`
    # (`_hset_if_alive`) prennent eux aussi leur propre connexion, par appel.
    client = redis.Redis.from_url(redis_url())
    queue = RedisJobQueue(client)
    registry = SessionRegistry(client)
    # Balayage des conteneurs de session orphelins AVANT de servir : nettoie les
    # résidus d'un crash précédent ou d'un `compose down` (conteneurs lancés
    # hors-compose). Best-effort — ne bloque jamais le démarrage.
    try:
        sweep_orphans(registry)
    except Exception as exc:  # noqa: BLE001 - le démarrage ne dépend pas du sweep
        log.error("startup orphan sweep error err=%s", str(exc)[:200])
    _start_reaper(client)
    _start_gc(client)
    # …puis EN CONTINU : un orphelin peut aussi naître en cours de vie (teardown
    # partiel), et il retiendrait un sous-réseau du pool Docker jusqu'au prochain
    # redémarrage si le balayage restait cantonné au démarrage.
    _start_sweeper(client)
    # …et les commandes de session dans LEUR PROPRE thread. Elles partageaient
    # cette boucle-ci, dont chaque tour traite un job de façon SYNCHRONE et
    # LENTE (`process_one` : docker run du runner + chargement + capture,
    # jusqu'à 90 s en capture et 180 s en scripté). Des timeouts de dépilage
    # courts n'y changeaient rien — ce n'est pas le dépilage qui bloquait, mais
    # le traitement entre deux dépilages — et `web.create_session` abandonnait
    # au bout d'`OCULAR_SESSION_READY_TIMEOUT` (30 s) en renvoyant 504, alors
    # que le broker finissait par lancer le conteneur : session_id vivant perdu
    # côté client, conteneur ~4 g + sous-réseau Docker retenus entre-temps.
    _start_session_cmds(client)
    while True:
        # Le DÉPILAGE est gardé : la désérialisation (pydantic `Job`)
        # a lieu dans `dequeue`, hors du `try` de traitement ci-dessous. Un seul
        # élément corrompu en file (champ requis manquant, contenu non-JSON)
        # remontait donc jusqu'au `while True` et ARRÊTAIT le process broker —
        # emportant les 3 threads démon (reaper/gc/sweeper) avec lui. L'élément
        # fautif est déjà consommé par `blpop` : on le journalise SANS son
        # contenu brut (qui peut porter un token/secret) et on reboucle.
        try:
            job = queue.dequeue(timeout=1)
        except Exception as exc:  # noqa: BLE001 - élément illisible : on l'abandonne
            log.error("job illisible ignoré err=%s", type(exc).__name__)
            continue
        if job is not None:
            try:
                process_one(queue, job)
            except Exception as exc:  # le broker SURVIT à une erreur de traitement
                # Symétrie avec le chemin session-cmd ci-dessous : sans ce garde,
                # une erreur (ex. Redis qui hoquette dans set_result, job déjà
                # blpop'é) remonterait jusqu'au `while True` et TUERAIT le broker
                # (threads reaper/gc morts, job perdu sans résultat). Best-effort
                # de marquer le job en erreur pour ne pas laisser un fantôme.
                log.error("job processing failed job_id=%s err=%s", job.job_id, str(exc)[:200])
                try:
                    queue.set_result(job.job_id, error_result(job.job_id, exc))
                except Exception:  # noqa: BLE001 - Redis encore en vrac : on abandonne ce job proprement
                    pass


if __name__ == "__main__":
    run_forever()
