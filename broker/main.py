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
    (container/kind/target/token — le token vient tel quel de la commande,
    jamais loggé) ; `stop` détruit le conteneur par son nom déterministe et
    retire l'entrée. Extrait de `run_forever()` pour être testable sans
    mocker une boucle infinie ni Docker."""
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


def _reaper_loop(registry, stop_event=None) -> None:
    """Boucle du reaper de sessions : appelle `reap` à intervalle régulier
    (`reaper_interval()`). `stop_event` permet un arrêt propre en test (une
    seule itération) ; en production (`stop_event=None`) tourne indéfiniment
    dans un thread démon. Les erreurs de `reap` sont capturées pour que le
    reaper survive à un incident Redis/Docker transitoire."""
    while stop_event is None or not stop_event.is_set():
        try:
            reap(registry, _time.time(), session_ttl(), session_idle(), session_disconnect_grace())
            # La LECTURE D'INTERVALLE est dans le `try` : appelée après le
            # `except`, une valeur d'env malformée (`OCULAR_REAPER_INTERVAL=60s`) levait
            # hors de toute garde et tuait le thread démon SANS UN SEUL LOG.
            interval = reaper_interval()
        except Exception as exc:  # le reaper survit à une erreur transitoire
            log.error("reaper error err=%s", str(exc)[:200])
            interval = _FALLBACK_INTERVAL
        if stop_event is not None:
            if stop_event.wait(interval):
                break
        else:
            _time.sleep(interval)


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
    while stop_event is None or not stop_event.is_set():
        try:
            collect(artifacts_dir(), client)
            # La LECTURE D'INTERVALLE est dans le `try` : appelée après le
            # `except`, une valeur d'env malformée (`OCULAR_GC_INTERVAL=60s`) levait
            # hors de toute garde et tuait le thread démon SANS UN SEUL LOG.
            interval = gc_interval()
        except Exception as exc:  # le GC survit à une erreur transitoire
            log.error("gc error err=%s", str(exc)[:200])
            interval = _FALLBACK_INTERVAL
        if stop_event is not None:
            if stop_event.wait(interval):
                break
        else:
            _time.sleep(interval)


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
    while stop_event is None or not stop_event.is_set():
        try:
            sweep_orphans(registry)
            # La LECTURE D'INTERVALLE est dans le `try` : appelée après le
            # `except`, une valeur d'env malformée (`OCULAR_SWEEP_INTERVAL=60s`) levait
            # hors de toute garde et tuait le thread démon SANS UN SEUL LOG.
            interval = sweep_interval()
        except Exception as exc:  # le sweeper survit à une erreur transitoire
            log.error("orphan sweep error err=%s", str(exc)[:200])
            interval = _FALLBACK_INTERVAL
        if stop_event is not None:
            if stop_event.wait(interval):
                break
        else:
            _time.sleep(interval)


def _start_sweeper(client) -> threading.Thread:
    """Démarre le balayage des orphelins dans un thread démon (n'empêche jamais
    l'arrêt du process broker). Réutilise le client Redis déjà créé par
    `run_forever` (pas de connexion supplémentaire)."""
    reg = SessionRegistry(client)
    t = threading.Thread(target=_sweeper_loop, args=(reg,), daemon=True, name="ocular-sweeper")
    t.start()
    return t


def run_forever() -> None:
    client = redis.Redis.from_url(redis_url())
    queue = RedisJobQueue(client)
    cmd_queue = SessionCmdQueue(client)
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
    while True:
        # Timeouts courts (au lieu d'un unique blpop bloquant longtemps sur
        # `ocular:jobs`) pour que la file de commandes de session ne soit
        # jamais affamée par un flux de jobs (et inversement) : chaque tour
        # attend au plus ~2s au total avant de reboucler.
        # Le DÉPILAGE lui-même est gardé : la désérialisation (pydantic `Job`)
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
        # Même garde côté commandes de session : `json.loads` a lieu dans
        # `dequeue_cmd`, hors du `try` de traitement (cf. commentaire ci-dessus).
        try:
            cmd = cmd_queue.dequeue_cmd(timeout=1)
        except Exception as exc:  # noqa: BLE001 - commande illisible : on l'abandonne
            log.error("commande de session illisible ignorée err=%s", type(exc).__name__)
            continue
        if cmd is not None:
            try:
                process_session_cmd(cmd, registry)
            except Exception as exc:  # le broker survit à une commande en échec
                log.error("session cmd failed cmd=%s err=%s", cmd.get("action"), str(exc)[:200])


if __name__ == "__main__":
    run_forever()
