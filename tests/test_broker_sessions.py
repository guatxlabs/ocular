from broker.sessions import build_session_args, launch_session, reap, stop_session
import broker.sessions as sessions_mod


def test_build_session_args_is_detached_not_interactive_rm():
    a = build_session_args("s1")
    assert "-d" in a
    assert "--rm" not in a
    assert "-i" not in a


def test_build_session_args_names_container_and_network():
    a = build_session_args("s1")
    assert "--name" in a and "ocular-sess-s1" in a
    assert "--network" in a and "ocular-sessions" in a


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
    calls = {}

    def fake_run(args, capture_output=None, check=None):
        calls["args"] = args
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)

    launch_session("s1", secret="threaded-secret")

    assert "OCULAR_SESSION_SECRET=threaded-secret" in calls["args"]


def test_build_session_args_never_touches_docker_socket_or_host_net_or_privileged():
    j = " ".join(build_session_args("s1"))
    a = build_session_args("s1")
    assert "docker.sock" not in j
    assert not ("--network" in a and "host" in a)
    assert "--privileged" not in a


def test_launch_session_runs_docker_and_returns_container_name(monkeypatch):
    calls = {}

    def fake_run(args, capture_output=None, check=None):
        calls["args"] = args
        return type("P", (), {"returncode": 0, "stdout": b"deadbeef\n", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)

    container = launch_session("s1")

    assert container == "ocular-sess-s1"
    assert calls["args"][:3] == ["docker", "run", "-d"]


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

    assert seen_check == [False, False]


class _FakeRegistry:
    """`get` renvoie toujours None : simule la course où le conteneur a
    expiré mais l'entrée registre a déjà disparu (ou n'a jamais reflété le
    conteneur) — `reap` doit rester robuste et stopper par nom déterministe
    sans jamais consulter `get`."""

    def __init__(self, expired_ids):
        self._expired_ids = expired_ids
        self.deleted = []

    def expired(self, now_epoch, ttl, idle):
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
