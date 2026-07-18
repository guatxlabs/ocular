import logging

import fakeredis

from broker.sessions import build_session_args, launch_session, reap, stop_session
import broker.sessions as sessions_mod


def _fake_redis(keys=None):
    """Vraie fakeredis pré-seedée (audit qualité 3m : plus de faux client maison)."""
    r = fakeredis.FakeStrictRedis()
    for k in keys or []:
        r.set(k, b"1")
    return r


def _keys(r):
    return {k.decode() if isinstance(k, bytes) else k for k in r.keys()}


def test_build_session_args_is_detached_not_interactive_rm():
    a = build_session_args("s1")
    assert "-d" in a
    assert "--rm" not in a
    assert "-i" not in a


def test_build_session_args_names_container_and_network():
    a = build_session_args("s1")
    assert "--name" in a and "ocular-sess-s1" in a
    # réseau DÉDIÉ à la session (isolation conteneur-à-conteneur) — plus
    # jamais le réseau partagé `ocular-sessions`.
    assert "--network" in a and "ocular-sess-net-s1" in a
    assert "ocular-sessions" not in a


def test_session_net_mirrors_session_name():
    from broker.sessions import _session_net, _session_name
    assert _session_name("abc") == "ocular-sess-abc"
    assert _session_net("abc") == "ocular-sess-net-abc"


def test_build_session_args_uses_recon_vnc_image_by_default():
    a = build_session_args("s1")
    assert "ocular-runner-recon-vnc:latest" in a


def test_build_session_args_accepts_image_override():
    a = build_session_args("s1", image="ocular-runner-recon-vnc:custom")
    assert "ocular-runner-recon-vnc:custom" in a
    assert "ocular-runner-recon-vnc:latest" not in a


def test_build_session_args_fully_hardened():
    a = build_session_args("s1")
    j = " ".join(a)
    assert "--cap-drop" in a and "ALL" in a
    assert "no-new-privileges" in j
    assert "--read-only" in a
    assert "--user" in a and "10001:10001" in a
    assert "seccomp=" in j and "unconfined" not in j
    assert "--memory" in a and "4g" in a
    assert "--pids-limit" in a and "512" in a
    assert a.count("--tmpfs") == 2
    tmpfs_values = [a[i + 1] for i, v in enumerate(a) if v == "--tmpfs"]
    assert any(v.startswith("/work:") for v in tmpfs_values)
    assert any(v.startswith("/tmp:") for v in tmpfs_values)


def test_build_session_args_never_publishes_a_port():
    a = build_session_args("s1")
    assert "-p" not in a and "--publish" not in a


def test_build_session_args_passes_session_secret_env():
    a = build_session_args("s1", secret="my-sess-secret")
    # le secret est injecté dans le conteneur via -e (frontière conteneur)
    assert "-e" in a
    assert "OCULAR_SESSION_SECRET=my-sess-secret" in a


def test_launch_session_threads_secret_to_docker_run(monkeypatch):
    # launch_session émet 3 commandes (network create / run / network connect) :
    # on isole celle du `docker run` pour asserter sur le secret.
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)

    launch_session("s1", secret="threaded-secret")

    run_args = next(a for a in calls if a[:3] == ["docker", "run", "-d"])
    assert "OCULAR_SESSION_SECRET=threaded-secret" in run_args


def test_build_session_args_never_touches_docker_socket_or_host_net_or_privileged():
    j = " ".join(build_session_args("s1"))
    a = build_session_args("s1")
    assert "docker.sock" not in j
    assert not ("--network" in a and "host" in a)
    assert "--privileged" not in a


def test_launch_session_runs_docker_and_returns_container_name(monkeypatch):
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"deadbeef\n", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)

    container = launch_session("s1")

    assert container == "ocular-sess-s1"
    assert any(a[:3] == ["docker", "run", "-d"] for a in calls)


def test_stop_session_kills_then_removes(monkeypatch):
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)

    stop_session("ocular-sess-s1")

    assert calls[0] == ["docker", "kill", "ocular-sess-s1"]
    assert calls[1] == ["docker", "rm", "-f", "ocular-sess-s1"]


def test_stop_session_is_best_effort_check_false(monkeypatch):
    seen_check = []

    def fake_run(args, capture_output=None, check=None):
        seen_check.append(check)
        return type("P", (), {"returncode": 1, "stdout": b"", "stderr": b"no such container"})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)

    stop_session("ocular-sess-ghost")  # ne doit pas lever malgré returncode 1

    # 4 commandes depuis le teardown réseau (kill, rm -f, network disconnect,
    # network rm) : TOUTES best-effort, aucune ne doit lever sur returncode 1.
    assert seen_check == [False, False, False, False]


class _FakeRegistry:
    """`get` renvoie toujours None : simule la course où le conteneur a
    expiré mais l'entrée registre a déjà disparu (ou n'a jamais reflété le
    conteneur) — `reap` doit rester robuste et stopper par nom déterministe
    sans jamais consulter `get`."""

    def __init__(self, expired_ids, redis_keys=None):
        self._expired_ids = expired_ids
        self.deleted = []
        self._r = _fake_redis(redis_keys)
        self.client = self._r  # cf. SessionRegistry.client (prod appelle registry.client)

    def expired(self, now_epoch, ttl, idle, disconnect_grace=None):
        return self._expired_ids

    def get(self, session_id):
        return None

    def delete(self, session_id):
        self.deleted.append(session_id)


def test_reap_stops_by_deterministic_name_and_deletes_each_expired_session(monkeypatch):
    stopped = []
    monkeypatch.setattr(sessions_mod, "stop_session", lambda c: stopped.append(c))

    registry = _FakeRegistry(expired_ids=["s1", "s2"])

    count = reap(registry, now_epoch=1000.0, ttl=3600, idle=600)

    assert count == 2
    assert stopped == ["ocular-sess-s1", "ocular-sess-s2"]
    assert registry.deleted == ["s1", "s2"]


def test_reap_stops_even_when_registry_get_returns_none(monkeypatch):
    """Le coeur du fix : `reap` ne doit JAMAIS dépendre de `registry.get`
    (peut renvoyer None sur une course) pour retrouver le conteneur à
    stopper — le nom est dérivé directement du session_id."""
    stopped = []
    monkeypatch.setattr(sessions_mod, "stop_session", lambda c: stopped.append(c))

    registry = _FakeRegistry(expired_ids=["ghost"])
    assert registry.get("ghost") is None  # confirme la course simulée

    count = reap(registry, now_epoch=1000.0, ttl=3600, idle=600)

    assert count == 1
    assert stopped == ["ocular-sess-ghost"]
    assert registry.deleted == ["ghost"]


def test_reap_returns_zero_when_nothing_expired(monkeypatch):
    stopped = []
    monkeypatch.setattr(sessions_mod, "stop_session", lambda c: stopped.append(c))

    registry = _FakeRegistry(expired_ids=[])

    count = reap(registry, now_epoch=1000.0, ttl=3600, idle=600)

    assert count == 0
    assert stopped == []
    assert registry.deleted == []


# --- Phase 3j : purge des captures interactives éphémères -------------------
from broker.sessions import purge_session_results  # noqa: E402


def test_purge_session_results_removes_only_that_sessions_sesscap_keys():
    r = _fake_redis([
        "ocular:result:sesscap-s1-aaaa",
        "ocular:result:sesscap-s1-bbbb",
        "ocular:result:sesscap-s2-cccc",   # autre session -> conservée
        "ocular:result:job-normal",        # job normal -> conservé
    ])
    removed = purge_session_results(r, "s1")
    assert removed == 2
    assert _keys(r) == {"ocular:result:sesscap-s2-cccc", "ocular:result:job-normal"}


def test_purge_session_results_best_effort_on_error(monkeypatch):
    r = _fake_redis(["ocular:result:sesscap-s1-x"])

    def _boom(*a, **k):
        raise RuntimeError("redis down")

    monkeypatch.setattr(r, "scan_iter", _boom)
    assert purge_session_results(r, "s1") == 0  # ne lève jamais


def test_reap_purges_session_results(monkeypatch):
    monkeypatch.setattr(sessions_mod, "stop_session", lambda c: None)
    registry = _FakeRegistry(
        expired_ids=["s1"],
        redis_keys=["ocular:result:sesscap-s1-xyz", "ocular:result:sesscap-s2-keep"],
    )
    reap(registry, now_epoch=1000.0, ttl=3600, idle=600)
    assert _keys(registry._r) == {"ocular:result:sesscap-s2-keep"}  # s1 purgée, s2 intacte


# --- Phase 3k : résolution Xvfb configurable (non hardcodée) -----------------

def test_build_session_args_passes_session_screen_env(monkeypatch):
    monkeypatch.setenv("OCULAR_SESSION_SCREEN", "1600x900")
    a = build_session_args("s1")
    assert "OCULAR_SESSION_SCREEN=1600x900" in a


def test_session_screen_default_and_validation(monkeypatch):
    from ocular_settings import session_screen
    monkeypatch.delenv("OCULAR_SESSION_SCREEN", raising=False)
    assert session_screen() == "1920x1080"                 # défaut
    monkeypatch.setenv("OCULAR_SESSION_SCREEN", "2560x1440")
    assert session_screen() == "2560x1440"                 # valeur valide
    monkeypatch.setenv("OCULAR_SESSION_SCREEN", "; rm -rf /")  # injection -> défaut
    assert session_screen() == "1920x1080"


# --- Isolation réseau par session : orchestration du lancement ---------------

def test_launch_session_creates_net_runs_then_connects_web(monkeypatch):
    # L'ORDRE est la garantie anti-race : le web est attaché AVANT que
    # process_session_cmd n'expose la session au registre.
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "ocular-web")

    name = launch_session("s1", secret="sec")

    assert name == "ocular-sess-s1"
    assert calls[0] == ["docker", "network", "create", "ocular-sess-net-s1"]
    assert calls[1][:3] == ["docker", "run", "-d"]
    assert calls[2] == ["docker", "network", "connect", "ocular-sess-net-s1", "ocular-web"]


def test_launch_session_survives_network_connect_failure(monkeypatch):
    # Si le web n'est pas joignable, on logue mais on ne lève pas : le poll
    # de santé côté web décidera (504 -> teardown), pas d'exception ici.
    def fake_run(args, capture_output=None, check=None):
        rc = 1 if args[:3] == ["docker", "network", "connect"] else 0
        return type("P", (), {"returncode": rc, "stdout": b"", "stderr": b"no such container"})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    assert launch_session("s1") == "ocular-sess-s1"


def test_launch_session_survives_network_create_failure(monkeypatch):
    # Pool d'adresses Docker épuisé : on logue un warning distinctif, on ne lève pas.
    def fake_run(args, capture_output=None, check=None):
        rc = 1 if args[:3] == ["docker", "network", "create"] else 0
        return type("P", (), {"returncode": rc, "stdout": b"", "stderr": b"could not find an available predefined subnet"})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    assert launch_session("s1") == "ocular-sess-s1"


def test_launch_session_survives_docker_run_failure(monkeypatch):
    # 3e chemin best-effort : un `docker run` en échec ne doit pas lever non
    # plus — le nom est toujours retourné, le poll de santé côté web décidera.
    def fake_run(args, capture_output=None, check=None):
        rc = 1 if args[:3] == ["docker", "run", "-d"] else 0
        return type("P", (), {"returncode": rc, "stdout": b"", "stderr": b"boom"})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    assert launch_session("s1") == "ocular-sess-s1"


def _create_fails_with(stderr: bytes):
    """fake subprocess.run où SEUL `docker network create` échoue, avec le
    stderr fourni (les deux autres commandes best-effort réussissent, donc
    tout warning capturé provient forcément du chemin `network create`)."""
    def fake_run(args, capture_output=None, check=None):
        rc = 1 if args[:3] == ["docker", "network", "create"] else 0
        return type("P", (), {"returncode": rc, "stdout": b"", "stderr": stderr})()
    return fake_run


def test_launch_session_network_create_warning_only_when_not_already_exists(monkeypatch, caplog):
    """Exigence explicite du plan : PAS de warning quand le réseau existe déjà
    (relance idempotente d'une session), MAIS un warning distinctif quand
    l'échec est réel (pool d'adresses Docker épuisé). Cette double face garde
    la comparaison de sous-chaîne sur un message Docker non contractuel : la
    supprimer ferait passer chaque relance pour une erreur.

    Capture : le logger est `ocular.broker.sessions` (get_logger préfixe
    `ocular.`) et `propagate` reste à True, donc caplog le voit dès qu'on
    abaisse le niveau sur ce logger précis."""
    logger_name = sessions_mod.log.name
    assert logger_name == "ocular.broker.sessions"  # préfixe posé par get_logger

    # Face 1 : réseau déjà présent -> silence complet.
    monkeypatch.setattr(sessions_mod.subprocess, "run",
                        _create_fails_with(b"Error response from daemon: network with name ocular-sess-net-s1 already exists"))
    with caplog.at_level(logging.WARNING, logger=logger_name):
        assert launch_session("s1") == "ocular-sess-s1"
    assert not [r for r in caplog.records if "network create failed" in r.getMessage()]

    caplog.clear()

    # Face 2 : pool d'adresses épuisé -> warning émis ET distinctif.
    monkeypatch.setattr(sessions_mod.subprocess, "run",
                        _create_fails_with(b"could not find an available predefined subnet"))
    with caplog.at_level(logging.WARNING, logger=logger_name):
        assert launch_session("s1") == "ocular-sess-s1"
    warnings = [r.getMessage() for r in caplog.records
                if r.levelno == logging.WARNING and "network create failed" in r.getMessage()]
    assert len(warnings) == 1
    # message distinctif : il oriente vers le pool d'adresses Docker
    assert "pool d'adresses" in warnings[0]
    assert "default-address-pools" in warnings[0]
    assert "could not find an available predefined subnet" in warnings[0]


def test_stop_session_removes_container_then_network(monkeypatch):
    # ORDRE CONTRAIGNANT : Docker refuse `network rm` tant qu'un conteneur y
    # est attaché -> le conteneur doit partir AVANT.
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "ocular-web")

    stop_session("ocular-sess-s1")

    assert calls[0] == ["docker", "kill", "ocular-sess-s1"]
    assert calls[1] == ["docker", "rm", "-f", "ocular-sess-s1"]
    assert calls[2] == ["docker", "network", "disconnect", "-f", "ocular-sess-net-s1", "ocular-web"]
    assert calls[3] == ["docker", "network", "rm", "ocular-sess-net-s1"]


def test_stop_session_ignores_container_without_session_prefix(monkeypatch):
    # Nom inattendu -> on ne dérive aucun réseau (pas de `network rm` sauvage).
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    stop_session("un-autre-conteneur")
    assert len(calls) == 2  # kill + rm, et RIEN de plus (sinon l'assert suivant est vacue)
    assert all("network" not in a for a in calls)


class _FakeReg:
    """Registre minimal : seules les sessions listées sont 'vivantes'."""
    def __init__(self, alive):
        self._alive = set(alive)

    def get(self, session_id):
        return {"session_id": session_id} if session_id in self._alive else None


def test_sweep_orphans_removes_orphan_networks_only(monkeypatch):
    from broker.sessions import sweep_orphans
    calls = []

    def fake_run(args, capture_output=None, check=None, text=None):
        calls.append(args)
        if args[:2] == ["docker", "ps"]:
            return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if args[:3] == ["docker", "network", "ls"]:
            # un réseau orphelin (s-dead) + un réseau de session vivante (s-live)
            return type("P", (), {"returncode": 0,
                                  "stdout": "ocular-sess-net-s-dead\nocular-sess-net-s-live\n",
                                  "stderr": ""})()
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "ocular-web")

    sweep_orphans(_FakeReg(alive={"s-live"}))

    assert ["docker", "network", "rm", "ocular-sess-net-s-dead"] in calls
    assert ["docker", "network", "rm", "ocular-sess-net-s-live"] not in calls
    assert ["docker", "network", "disconnect", "-f", "ocular-sess-net-s-dead", "ocular-web"] in calls


def test_sweep_orphans_network_substring_guard(monkeypatch):
    # `--filter name=` est un filtre SUBSTRING : un réseau au nom voisin ne
    # doit pas être supprimé.
    from broker.sessions import sweep_orphans
    calls = []

    def fake_run(args, capture_output=None, check=None, text=None):
        calls.append(args)
        if args[:2] == ["docker", "ps"]:
            return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if args[:3] == ["docker", "network", "ls"]:
            return type("P", (), {"returncode": 0,
                                  "stdout": "prefixe-ocular-sess-net-x\n", "stderr": ""})()
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    sweep_orphans(_FakeReg(alive=set()))
    assert all(a[:3] != ["docker", "network", "rm"] for a in calls)
