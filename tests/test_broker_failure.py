# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import logging
import threading

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
    for name in ("_start_reaper", "_start_gc", "_start_sweeper", "_start_session_cmds"):
        monkeypatch.setattr(main, name, lambda _client: None)
    monkeypatch.setattr(main, "sweep_orphans", lambda _reg: 0)

    processed = []

    def fake_process_one(_queue, job):
        processed.append(job.job_id)
        if on_job:
            on_job()
        raise _StopLoop

    monkeypatch.setattr(main, "process_one", fake_process_one)

    try:
        main.run_forever()
    except _StopLoop:
        pass
    return processed


def _drive_session_cmds(monkeypatch, seed, turns=2, on_cmd=None):
    """Pendant de `_drive_run_forever` pour la file des commandes de session,
    qui a désormais SON PROPRE thread démon (`_start_session_cmds`) : on pilote
    directement `_consume_session_cmd`, tour par tour, sans thread — c'est là
    que vivent les deux gardes (dépilage illisible / traitement en échec)
    autrefois inscrits dans la boucle unique de `run_forever`.

    Retourne la liste des commandes réellement TRAITÉES."""
    r = fakeredis.FakeStrictRedis()
    for key, raw in seed:
        r.rpush(key, raw)

    cmd_queue = main.SessionCmdQueue(r)
    registry = main.SessionRegistry(r)

    processed = []

    def fake_process_session_cmd(cmd, _registry):
        processed.append(cmd.get("session_id"))
        if on_cmd:
            on_cmd()

    monkeypatch.setattr(main, "process_session_cmd", fake_process_session_cmd)

    for _ in range(turns):
        main._consume_session_cmd(cmd_queue, registry)
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
    processed = _drive_session_cmds(monkeypatch, [
        ("ocular:session-cmds", b'{"action": "launch", "session_id"'),   # JSON tronqué
        ("ocular:session-cmds", b'{"action": "launch", "session_id": "s-bon"}'),
    ])
    assert processed == ["s-bon"], (
        "RÉGRESSION défaut B : une commande de session tronquée doit être "
        "ignorée, pas tuer la boucle des commandes de session"
    )


def test_failing_session_cmd_does_not_kill_the_loop(monkeypatch):
    """Garde de TRAITEMENT (distinct du garde de dépilage ci-dessus) : une
    commande qui explose (Docker en vrac) ne doit pas tuer le thread — la
    suivante est encore servie."""
    r = fakeredis.FakeStrictRedis()
    r.rpush("ocular:session-cmds", b'{"action": "launch", "session_id": "s-boom"}')
    r.rpush("ocular:session-cmds", b'{"action": "launch", "session_id": "s-bon"}')
    cmd_queue, registry = main.SessionCmdQueue(r), main.SessionRegistry(r)

    seen = []

    def flaky(cmd, _registry):
        seen.append(cmd.get("session_id"))
        if cmd.get("session_id") == "s-boom":
            raise RuntimeError("docker en vrac")

    monkeypatch.setattr(main, "process_session_cmd", flaky)
    main._consume_session_cmd(cmd_queue, registry)
    main._consume_session_cmd(cmd_queue, registry)

    assert seen == ["s-boom", "s-bon"]


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


# --- Défaut D : les commandes de session étaient AFFAMÉES par un job long ----
# `run_forever` alternait, dans UNE seule boucle : dépiler un job -> le traiter
# (`process_one`, SYNCHRONE et LENT : docker run du runner + chargement de page
# + capture, jusqu'à 90 s pour une capture et 180 s pour un job scripté) ->
# dépiler une commande de session -> la traiter. Le commentaire en place
# affirmait que les timeouts de dépilage courts (1 s) suffisaient à éviter
# l'affamement : c'est faux, ce n'est pas le DÉPILAGE qui bloque, c'est le
# TRAITEMENT du job entre les deux dépilages.
# Conséquence mesurée sur la stack : POST /sessions renvoyait 504 « session non
# prête » au bout des 30 s de `OCULAR_SESSION_READY_TIMEOUT` alors que le broker
# lançait le conteneur ~67 s plus tard — le client perd un session_id vivant.


def test_session_cmd_is_processed_while_a_job_is_running(monkeypatch):
    """Découplage : une commande de session déposée PENDANT le traitement d'un
    job doit être traitée sans attendre la fin de ce job.

    Mord sur la structure de `run_forever` : tant que les deux files sont
    servies par la même boucle, `process_session_cmd` ne peut pas être appelé
    avant le retour de `process_one`, et l'attente ci-dessous expire."""
    r = fakeredis.FakeStrictRedis()
    r.rpush("ocular:jobs", b'{"job_id": "lent", "profile": "analysis", "html": "x"}')
    monkeypatch.setattr(main.redis.Redis, "from_url", staticmethod(lambda _url: r))
    # Les 3 démons historiques sont neutralisés : ce test ne parle QUE du
    # couplage jobs / commandes de session.
    for name in ("_start_reaper", "_start_gc", "_start_sweeper"):
        monkeypatch.setattr(main, name, lambda _client: None)
    monkeypatch.setattr(main, "sweep_orphans", lambda _reg: 0)

    job_running = threading.Event()
    cmd_processed = threading.Event()
    release_job = threading.Event()

    def slow_process_one(_queue, _job):
        job_running.set()
        release_job.wait(15)
        raise _StopLoop  # BaseException : termine proprement la boucle de jobs

    def fake_process_session_cmd(_cmd, _registry):
        cmd_processed.set()
        raise _StopLoop  # idem pour le thread des commandes de session

    monkeypatch.setattr(main, "process_one", slow_process_one)
    monkeypatch.setattr(main, "process_session_cmd", fake_process_session_cmd)

    # `_StopLoop` remonte VOLONTAIREMENT hors des threads (c'est ce qui les
    # termine). Sans ce filtre, pytest le remonterait en
    # PytestUnhandledThreadExceptionWarning à chaque exécution.
    real_hook = threading.excepthook
    monkeypatch.setattr(
        threading,
        "excepthook",
        lambda args: None if args.exc_type is _StopLoop else real_hook(args),
    )

    broker = threading.Thread(target=main.run_forever, daemon=True)
    broker.start()
    try:
        assert job_running.wait(10), "le job de test n'a jamais démarré"
        # La commande n'est enfilée qu'UNE FOIS le job en cours de traitement :
        # elle ne peut donc pas avoir été servie « avant » par chance.
        r.rpush("ocular:session-cmds", b'{"action": "launch", "session_id": "s-pendant"}')
        served = cmd_processed.wait(5)
    finally:
        release_job.set()
        broker.join(timeout=10)

    assert served, (
        "RÉGRESSION défaut D : la commande de session est restée affamée "
        "derrière un job en cours de traitement (POST /sessions -> 504 alors "
        "que le conteneur finit par être lancé)"
    )


def test_malformed_item_is_not_logged_verbatim(monkeypatch, caplog):
    """Le contenu brut peut porter un secret (token de session, secret
    conteneur) : il ne doit JAMAIS partir dans les logs."""
    secret = "tok-ultra-secret-ne-doit-pas-fuiter"
    with caplog.at_level(logging.DEBUG):
        _drive_session_cmds(monkeypatch, [
            ("ocular:session-cmds", ('{"action": "launch", "secret": "%s"' % secret).encode()),
            ("ocular:session-cmds", b'{"action": "launch", "session_id": "s-bon"}'),
        ])
    assert all(secret not in r.getMessage() for r in caplog.records)
