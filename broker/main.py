from __future__ import annotations

import json
import threading
import time as _time
from datetime import datetime, timezone

import redis

from broker.launcher import run_job
from broker.sessions import launch_session, reap, stop_session
from bus.queue import RedisJobQueue
from bus.sessions import SessionCmdQueue, SessionRegistry
from ocular_logging import get_logger
from ocular_settings import (
    reaper_interval,
    redis_url,
    result_ttl,
    session_idle,
    session_ttl,
)

log = get_logger("broker")


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
        container = launch_session(session_id)
        registry.create(
            session_id,
            container=container,
            kind="recon-vnc",
            target=cmd.get("target", ""),
            token=cmd.get("token", ""),
            now_iso=datetime.now(timezone.utc).isoformat(),
        )
        log.info("session cmd launch session_id=%s container=%s", session_id, container)
    elif action == "stop":
        stop_session(f"ocular-sess-{session_id}")
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
            reap(registry, _time.time(), session_ttl(), session_idle())
        except Exception as exc:  # le reaper survit à une erreur transitoire
            log.error("reaper error err=%s", str(exc)[:200])
        if stop_event is not None:
            if stop_event.wait(reaper_interval()):
                break
        else:
            _time.sleep(reaper_interval())


def _start_reaper(client) -> threading.Thread:
    """Démarre le reaper de sessions dans un thread démon (n'empêche jamais
    l'arrêt du process broker). Réutilise le client Redis déjà créé par
    `run_forever` (pas de connexion supplémentaire)."""
    reg = SessionRegistry(client)
    t = threading.Thread(target=_reaper_loop, args=(reg,), daemon=True, name="ocular-reaper")
    t.start()
    return t


def run_forever() -> None:
    client = redis.Redis.from_url(redis_url())
    queue = RedisJobQueue(client)
    cmd_queue = SessionCmdQueue(client)
    registry = SessionRegistry(client)
    _start_reaper(client)
    while True:
        # Timeouts courts (au lieu d'un unique blpop bloquant longtemps sur
        # `ocular:jobs`) pour que la file de commandes de session ne soit
        # jamais affamée par un flux de jobs (et inversement) : chaque tour
        # attend au plus ~2s au total avant de reboucler.
        job = queue.dequeue(timeout=1)
        if job is not None:
            process_one(queue, job)
        cmd = cmd_queue.dequeue_cmd(timeout=1)
        if cmd is not None:
            try:
                process_session_cmd(cmd, registry)
            except Exception as exc:  # le broker survit à une commande en échec
                log.error("session cmd failed cmd=%s err=%s", cmd.get("action"), str(exc)[:200])


if __name__ == "__main__":
    run_forever()
