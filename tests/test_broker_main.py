import json

import broker.main as main_mod
from broker.main import (
    _gc_loop,
    _reaper_loop,
    _start_gc,
    _start_reaper,
    _start_sweeper,
    _sweeper_loop,
    error_result,
)


class _FakeStopEvent:
    """Simule un `threading.Event` sans dépendre du temps réel : ne bascule
    qu'après `n_iterations` appels à `wait()` -> la boucle testée effectue
    EXACTEMENT `n_iterations` tours, quel que soit l'intervalle configuré.

    Le paramètre est essentiel (défaut F) : avec un événement qui bascule dès
    le premier `wait()`, les tests « la boucle survit à une exception » ne
    prouvaient que « ne lève pas au premier tour ». Une implémentation où le
    reaper, le GC et le sweeper ABANDONNENT définitivement à la première erreur
    transitoire (`except ...: return`) les satisfaisait tous."""

    def __init__(self, n_iterations: int = 1) -> None:
        self._remaining = n_iterations
        self._set = False

    def is_set(self) -> bool:
        return self._set

    def wait(self, timeout: float) -> bool:
        self._remaining -= 1
        if self._remaining <= 0:
            self._set = True
        return self._set


def test_error_result_is_valid_json_even_with_special_chars():
    s = error_result("job-x", RuntimeError('runner a échoué: err "quote"\nline\\back'))
    d = json.loads(s)  # ne doit PAS lever
    assert d["job_id"] == "job-x"
    assert "runner a échoué" in d["error"]


def test_error_result_truncates_long_messages():
    s = error_result("job-y", RuntimeError("x" * 500))
    d = json.loads(s)
    assert len(d["error"]) <= 200


def test_reaper_loop_calls_reap_once_with_stop_event(monkeypatch):
    calls = []
    stop_event = _FakeStopEvent()

    def fake_reap(registry, now, ttl, idle, disconnect_grace):
        calls.append((registry, now, ttl, idle, disconnect_grace))

    monkeypatch.setattr(main_mod, "reap", fake_reap)
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)
    monkeypatch.setattr(main_mod, "_time", type("T", (), {"time": staticmethod(lambda: 42.0)})())

    registry = object()
    _reaper_loop(registry, stop_event=stop_event)  # une seule itération puis sort via wait()

    assert len(calls) == 1
    assert calls[0] == (registry, 42.0, 1800, 600, 45)


def test_reaper_loop_survives_reap_exception(monkeypatch):
    def boom(registry, now, ttl, idle, disconnect_grace):
        raise RuntimeError("redis down")

    monkeypatch.setattr(main_mod, "reap", boom)
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)

    stop_event = _FakeStopEvent()

    _reaper_loop(object(), stop_event=stop_event)  # ne doit PAS lever, malgré l'exception


def test_start_reaper_starts_a_daemon_thread(monkeypatch):
    started = {}

    def fake_reaper_loop(registry, stop_event=None):
        started["registry"] = registry
        started["called"] = True

    monkeypatch.setattr(main_mod, "_reaper_loop", fake_reaper_loop)
    monkeypatch.setattr(main_mod, "SessionRegistry", lambda client: ("registry-for", client))

    client = object()
    t = _start_reaper(client)
    t.join(timeout=2)

    assert t.daemon is True
    assert t.name == "ocular-reaper"
    assert started["called"] is True
    assert started["registry"] == ("registry-for", client)


def test_gc_loop_calls_collect_once_with_stop_event(monkeypatch):
    calls = []
    stop_event = _FakeStopEvent()

    def fake_collect(artifacts_dir, client):
        calls.append((artifacts_dir, client))

    monkeypatch.setattr(main_mod, "collect", fake_collect)
    monkeypatch.setattr(main_mod, "artifacts_dir", lambda: "/some/artifacts")
    monkeypatch.setattr(main_mod, "gc_interval", lambda: 600)

    client = object()
    _gc_loop(client, stop_event=stop_event)  # une seule itération puis sort via wait()

    assert calls == [("/some/artifacts", client)]


def test_gc_loop_survives_collect_exception(monkeypatch):
    def boom(artifacts_dir, client):
        raise RuntimeError("disk down")

    monkeypatch.setattr(main_mod, "collect", boom)
    monkeypatch.setattr(main_mod, "artifacts_dir", lambda: "/some/artifacts")
    monkeypatch.setattr(main_mod, "gc_interval", lambda: 600)

    stop_event = _FakeStopEvent()

    _gc_loop(object(), stop_event=stop_event)  # ne doit PAS lever, malgré l'exception


def test_start_gc_starts_a_daemon_thread(monkeypatch):
    started = {}

    def fake_gc_loop(client, stop_event=None):
        started["client"] = client
        started["called"] = True

    monkeypatch.setattr(main_mod, "_gc_loop", fake_gc_loop)

    client = object()
    t = _start_gc(client)
    t.join(timeout=2)

    assert t.daemon is True
    assert t.name == "ocular-gc"
    assert started["called"] is True
    assert started["client"] is client


# --- Balayage PÉRIODIQUE des orphelins (conteneurs + réseaux de session) -----
# Sans boucle, un résidu apparu en cours de vie (teardown partiellement échoué,
# conteneur tué hors flux) survivrait jusqu'au prochain redémarrage du broker,
# en consommant le pool d'adresses Docker (ressource FINIE).

def test_sweeper_loop_calls_sweep_orphans_once_with_stop_event(monkeypatch):
    calls = []
    stop_event = _FakeStopEvent()

    def fake_sweep(registry):
        calls.append(registry)
        return 0

    monkeypatch.setattr(main_mod, "sweep_orphans", fake_sweep)
    monkeypatch.setattr(main_mod, "sweep_interval", lambda: 600)

    registry = object()
    _sweeper_loop(registry, stop_event=stop_event)  # une itération puis sort via wait()

    assert calls == [registry]


def test_sweeper_loop_survives_sweep_exception(monkeypatch):
    def boom(registry):
        raise RuntimeError("docker down")

    monkeypatch.setattr(main_mod, "sweep_orphans", boom)
    monkeypatch.setattr(main_mod, "sweep_interval", lambda: 600)

    stop_event = _FakeStopEvent()

    _sweeper_loop(object(), stop_event=stop_event)  # ne doit PAS lever, malgré l'exception


def test_start_sweeper_starts_a_daemon_thread(monkeypatch):
    started = {}

    def fake_sweeper_loop(registry, stop_event=None):
        started["registry"] = registry
        started["called"] = True

    monkeypatch.setattr(main_mod, "_sweeper_loop", fake_sweeper_loop)
    monkeypatch.setattr(main_mod, "SessionRegistry", lambda client: ("registry-for", client))

    client = object()
    t = _start_sweeper(client)
    t.join(timeout=2)

    assert t.daemon is True
    assert t.name == "ocular-sweeper"
    assert started["called"] is True
    assert started["registry"] == ("registry-for", client)


# --- Défaut C : l'accesseur d'intervalle était appelé HORS du `try` ----------
# `_time.sleep(reaper_interval())` était placé APRÈS le `except` : une valeur
# d'env malformée (`OCULAR_REAPER_INTERVAL=60s`) levait donc en dehors de toute
# garde -> le thread démon mourait SANS UN SEUL LOG, le broker continuait de
# servir, et plus aucune session n'était jamais reapée (fuite illimitée de
# conteneurs ~4 Go). Défense en profondeur : la lecture d'intervalle passe DANS
# le `try`, en plus du durcissement des accesseurs (cf. tests/test_settings.py).

import pytest

_LOOPS = [
    ("_reaper_loop", "reap", "reaper_interval", "OCULAR_REAPER_INTERVAL"),
    ("_gc_loop", "collect", "gc_interval", "OCULAR_GC_INTERVAL"),
    ("_sweeper_loop", "sweep_orphans", "sweep_interval", "OCULAR_SWEEP_INTERVAL"),
]


@pytest.mark.parametrize("loop,work,interval_fn,env", _LOOPS)
@pytest.mark.parametrize("bad", ["60s", "abc", "", "-1", "0"])
def test_daemon_loop_survives_a_malformed_interval_env(monkeypatch, loop, work, interval_fn, env, bad):
    """Le thread démon doit SURVIVRE à une valeur d'intervalle malformée, et
    avoir fait son travail au moins une fois."""
    monkeypatch.setenv(env, bad)
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)

    calls = []
    monkeypatch.setattr(main_mod, work, lambda *a, **k: calls.append(1))

    getattr(main_mod, loop)(object(), stop_event=_FakeStopEvent())  # ne doit PAS lever
    assert calls, f"{loop} n'a pas fait son travail avec {env}={bad!r}"


@pytest.mark.parametrize("loop,work,interval_fn,env", _LOOPS)
def test_daemon_loop_survives_an_exploding_interval_accessor(monkeypatch, loop, work, interval_fn, env):
    """Défense en profondeur : même si l'accesseur d'intervalle lui-même
    explosait, la boucle ne doit pas laisser l'exception tuer le thread."""
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)
    monkeypatch.setattr(main_mod, work, lambda *a, **k: None)

    def boom():
        raise ValueError("accesseur cassé")

    monkeypatch.setattr(main_mod, interval_fn, boom)

    getattr(main_mod, loop)(object(), stop_event=_FakeStopEvent())  # ne doit PAS lever


@pytest.mark.parametrize("loop,work,interval_fn,env", _LOOPS)
def test_daemon_loop_never_sleeps_zero(monkeypatch, loop, work, interval_fn, env):
    """`interval=0` -> `sleep(0)` -> boucle folle à 100 % CPU martelant
    Docker/Redis. L'attente demandée doit toujours être >= 1 s."""
    monkeypatch.setenv(env, "0")
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)
    monkeypatch.setattr(main_mod, work, lambda *a, **k: None)

    waited = []

    class _RecordingStopEvent(_FakeStopEvent):
        def wait(self, timeout):
            waited.append(timeout)
            return super().wait(timeout)

    getattr(main_mod, loop)(object(), stop_event=_RecordingStopEvent())
    assert waited and all(w >= 1 for w in waited), f"attente non bornée : {waited}"


# --- Défaut F : prouver que les boucles CONTINUENT DE TOURNER ----------------
# Une erreur transitoire (Redis qui redémarre, démon conteneur indisponible)
# doit être absorbée tour après tour : si un thread démon abandonnait à la
# première, plus aucune session ne serait jamais reapée, aucun artefact
# collecté, aucun orphelin balayé — le broker restant « vivant » pour toute
# sonde de liveness. Les tests ci-dessous imposent N tours ET des exceptions à
# CHAQUE tour ; ils échouent sur une implémentation qui `return` dans l'`except`.

_N_ITERATIONS = 4


@pytest.mark.parametrize("loop,work,interval_fn,env", _LOOPS)
def test_daemon_loop_keeps_working_despite_an_exception_every_iteration(
    monkeypatch, loop, work, interval_fn, env
):
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)

    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise RuntimeError("panne transitoire")

    monkeypatch.setattr(main_mod, work, boom)

    stop_event = _FakeStopEvent(_N_ITERATIONS)
    getattr(main_mod, loop)(object(), stop_event=stop_event)  # ne doit PAS lever

    assert len(calls) == _N_ITERATIONS, (
        f"{loop} a abandonné après {len(calls)} tour(s) : le travail doit être "
        f"retenté à chaque itération malgré l'exception"
    )
    assert stop_event.is_set()  # la boucle est bien sortie par l'événement d'arrêt


@pytest.mark.parametrize("loop,work,interval_fn,env", _LOOPS)
def test_daemon_loop_recovers_after_a_transient_exception(
    monkeypatch, loop, work, interval_fn, env
):
    """Cas réaliste : la panne cesse. Le tour suivant doit RÉUSSIR — ce qui
    n'arrive que si la boucle a survécu au tour en échec."""
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)

    outcomes = []

    def flaky(*a, **k):
        if not outcomes:
            outcomes.append("boom")
            raise RuntimeError("panne transitoire")
        outcomes.append("ok")

    monkeypatch.setattr(main_mod, work, flaky)

    getattr(main_mod, loop)(object(), stop_event=_FakeStopEvent(3))

    assert outcomes == ["boom", "ok", "ok"], f"{loop} n'a pas repris après la panne"


@pytest.mark.parametrize("loop,work,interval_fn,env", _LOOPS)
def test_daemon_loop_keeps_working_despite_an_exploding_interval_accessor(
    monkeypatch, loop, work, interval_fn, env
):
    """Même exigence quand c'est l'accesseur d'intervalle qui explose à chaque
    tour : la boucle retombe sur l'intervalle de repli et continue."""
    monkeypatch.setattr(main_mod, "session_ttl", lambda: 1800)
    monkeypatch.setattr(main_mod, "session_idle", lambda: 600)
    monkeypatch.setattr(main_mod, "session_disconnect_grace", lambda: 45)

    calls = []
    monkeypatch.setattr(main_mod, work, lambda *a, **k: calls.append(1))

    def boom():
        raise ValueError("accesseur cassé")

    monkeypatch.setattr(main_mod, interval_fn, boom)

    getattr(main_mod, loop)(object(), stop_event=_FakeStopEvent(_N_ITERATIONS))

    assert len(calls) == _N_ITERATIONS
