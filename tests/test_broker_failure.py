import json
import logging

import fakeredis

from broker import main
from bus.queue import Job, RedisJobQueue


def test_error_result_has_status_error():
    d = json.loads(main.error_result("j", RuntimeError('boom "q"\nx')))
    assert d["job_id"] == "j" and d["status"] == "error" and "boom" in d["error"]


def test_process_one_stores_error_result_on_job_failure(monkeypatch):
    r = fakeredis.FakeStrictRedis()
    q = RedisJobQueue(r)
    job = Job(job_id="jf", profile="analysis", html="x")

    def boom(_job):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(main, "run_job", boom)

    main.process_one(q, job)

    stored = json.loads(q.get_result("jf"))
    assert stored["status"] == "error" and "kaboom" in stored["error"]


def test_process_one_stores_ok_result_on_success(monkeypatch):
    r = fakeredis.FakeStrictRedis()
    q = RedisJobQueue(r)
    job = Job(job_id="jok", profile="analysis", html="x")

    monkeypatch.setattr(main, "run_job", lambda _job: '{"job_id": "jok", "verdict": "benign"}')

    main.process_one(q, job)

    stored = json.loads(q.get_result("jok"))
    assert stored["verdict"] == "benign"


# --- Défaut B : un élément malformé en file TUAIT le broker ------------------
# Dans `run_forever`, `queue.dequeue()` et `cmd_queue.dequeue_cmd()` étaient
# HORS de tout `try`. La désérialisation (pydantic `Job`, `json.loads`) levait
# donc jusqu'au `while True` -> le PROCESS broker s'arrêtait, et les 3 threads
# démon (reaper/gc/sweeper) mouraient avec lui. Un seul élément corrompu en
# file suffisait à faire tomber tout le service.


class _StopLoop(BaseException):
    """Sentinelle : sort de la boucle infinie de `run_forever` en test.

    Hérite de **BaseException**, pas d'`Exception` : `run_forever` garde
    désormais chaque étape derrière un `except Exception`, qui avalerait une
    sentinelle ordinaire et ferait tourner le test à l'infini."""


def _drive_run_forever(monkeypatch, seed, on_job=None, on_cmd=None):
    """Lance `run_forever` sur une fakeredis pré-seedée, threads démon
    neutralisés, et rend la main quand `_StopLoop` remonte. Retourne la liste
    des éléments réellement TRAITÉS par le broker."""
    r = fakeredis.FakeStrictRedis()
    for key, raw in seed:
        r.rpush(key, raw)

    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(lambda _url: r))
    for name in ("_start_reaper", "_start_gc", "_start_sweeper"):
        monkeypatch.setattr(main, name, lambda _client: None)
    monkeypatch.setattr(main, "sweep_orphans", lambda _reg: 0)

    processed = []

    def fake_process_one(_queue, job):
        processed.append(job.job_id)
        if on_job:
            on_job()
        raise _StopLoop

    def fake_process_session_cmd(cmd, _registry):
        processed.append(cmd.get("session_id"))
        if on_cmd:
            on_cmd()
        raise _StopLoop

    monkeypatch.setattr(main, "process_one", fake_process_one)
    monkeypatch.setattr(main, "process_session_cmd", fake_process_session_cmd)

    try:
        main.run_forever()
    except _StopLoop:
        pass
    return processed


def test_job_with_missing_required_field_does_not_kill_the_broker(monkeypatch):
    processed = _drive_run_forever(monkeypatch, [
        ("ocular:jobs", b'{"job_id": "malforme"}'),          # `profile` manquant
        ("ocular:jobs", b'{"job_id": "bon", "profile": "analysis", "html": "x"}'),
    ])
    assert processed == ["bon"], (
        "RÉGRESSION défaut B : un job sans champ requis doit être ignoré, "
        "pas tuer la boucle broker"
    )


def test_non_json_job_does_not_kill_the_broker(monkeypatch):
    processed = _drive_run_forever(monkeypatch, [
        ("ocular:jobs", b"ceci n'est pas du json"),
        ("ocular:jobs", b'{"job_id": "bon", "profile": "analysis", "html": "x"}'),
    ])
    assert processed == ["bon"]


def test_truncated_session_cmd_does_not_kill_the_broker(monkeypatch):
    processed = _drive_run_forever(monkeypatch, [
        ("ocular:session-cmds", b'{"action": "launch", "session_id"'),   # JSON tronqué
        ("ocular:session-cmds", b'{"action": "launch", "session_id": "s-bon"}'),
    ])
    assert processed == ["s-bon"], (
        "RÉGRESSION défaut B : une commande de session tronquée doit être "
        "ignorée, pas tuer la boucle broker"
    )


def test_malformed_item_is_not_reprocessed_in_a_loop(monkeypatch):
    """L'élément fautif est déjà consommé par `blpop` : le `continue` ne peut
    pas boucler à l'infini dessus (la file est vidée du malformé)."""
    r = fakeredis.FakeStrictRedis()
    r.rpush("ocular:jobs", b"pas du json")
    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(lambda _url: r))
    for name in ("_start_reaper", "_start_gc", "_start_sweeper"):
        monkeypatch.setattr(main, name, lambda _client: None)
    monkeypatch.setattr(main, "sweep_orphans", lambda _reg: 0)

    calls = {"n": 0}
    real_dequeue = main.RedisJobQueue.dequeue

    def counting_dequeue(self, timeout=0):
        calls["n"] += 1
        if calls["n"] > 3:
            raise _StopLoop
        return real_dequeue(self, timeout=timeout)

    monkeypatch.setattr(main.RedisJobQueue, "dequeue", counting_dequeue)
    try:
        main.run_forever()
    except _StopLoop:
        pass
    assert r.llen("ocular:jobs") == 0


def test_malformed_item_is_not_logged_verbatim(monkeypatch, caplog):
    """Le contenu brut peut porter un secret (token de session, secret
    conteneur) : il ne doit JAMAIS partir dans les logs."""
    secret = "tok-ultra-secret-ne-doit-pas-fuiter"
    with caplog.at_level(logging.DEBUG):
        _drive_run_forever(monkeypatch, [
            ("ocular:session-cmds", ('{"action": "launch", "secret": "%s"' % secret).encode()),
            ("ocular:session-cmds", b'{"action": "launch", "session_id": "s-bon"}'),
        ])
    assert all(secret not in r.getMessage() for r in caplog.records)
