import ocular_settings as s


def test_defaults(monkeypatch):
    # REDIS_URL (SANS préfixe) doit figurer ici : `redis_url()` le lit en repli
    # de OCULAR_REDIS_URL, et c'est le nom que pose deploy/docker-compose.yml.
    # Sans cet effacement, le test échouait pour quiconque avait sourcé
    # deploy/.env dans son shell — une suite ROUGE sur du code SAIN, qui envoie
    # chercher une régression inexistante (vécu pendant l'audit du 2026-07-18).
    for v in [
        "OCULAR_REDIS_URL",
        "REDIS_URL",
        "OCULAR_JOB_MEMORY",
        "OCULAR_RESULT_TTL",
        "OCULAR_MAX_HTML_BYTES",
    ]:
        monkeypatch.delenv(v, raising=False)
    assert s.redis_url() == "redis://localhost:6379"
    assert s.job_memory() == "2g"
    assert s.result_ttl() == 86400
    assert s.max_html_bytes() == 5_000_000


def test_env_override(monkeypatch):
    monkeypatch.setenv("OCULAR_RESULT_TTL", "120")
    monkeypatch.setenv("OCULAR_JOB_MEMORY", "1g")
    assert s.result_ttl() == 120
    assert s.job_memory() == "1g"


# --- Phase 3k : mode strict egress (fail-closed en réseau sensible) ----------

def test_require_egress_guard_default_off(monkeypatch):
    monkeypatch.delenv("OCULAR_REQUIRE_EGRESS_GUARD", raising=False)
    assert s.require_egress_guard() is False


def test_require_egress_guard_on(monkeypatch):
    for v in ("1", "true", "yes", "on"):
        monkeypatch.setenv("OCULAR_REQUIRE_EGRESS_GUARD", v)
        assert s.require_egress_guard() is True
    for v in ("0", "false", "", "off"):
        monkeypatch.setenv("OCULAR_REQUIRE_EGRESS_GUARD", v)
        assert s.require_egress_guard() is False


# --- Isolation réseau par session : conteneur web attaché/détaché ------------

def test_web_container_default(monkeypatch):
    monkeypatch.delenv("OCULAR_WEB_CONTAINER", raising=False)
    from ocular_settings import web_container
    assert web_container() == "ocular-web"


def test_web_container_env_override(monkeypatch):
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "mon-web")
    from ocular_settings import web_container
    assert web_container() == "mon-web"


def test_web_container_blank_falls_back_to_default(monkeypatch):
    # une valeur vide/espaces ne doit pas produire un nom de conteneur vide
    # (docker network connect échouerait de façon opaque).
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "   ")
    from ocular_settings import web_container
    assert web_container() == "ocular-web"


# --- Balayage périodique des orphelins ---------------------------------------

def test_sweep_interval_default(monkeypatch):
    # 600 s : les résidus n'apparaissent qu'en cas d'anomalie — un balayage
    # toutes les 10 min suffit sans marteler le démon Docker.
    monkeypatch.delenv("OCULAR_SWEEP_INTERVAL", raising=False)
    assert s.sweep_interval() == 600


def test_sweep_interval_env_override(monkeypatch):
    monkeypatch.setenv("OCULAR_SWEEP_INTERVAL", "30")
    assert s.sweep_interval() == 30


# --- Défaut C : une valeur d'env malformée tuait un thread démon en silence ---
# 13 accesseurs sur 14 faisaient un `int()`/`float()` NU. `OCULAR_REAPER_INTERVAL=60s`
# -> ValueError. Or l'accesseur d'intervalle était appelé HORS du `try` des
# boucles démon : le thread mourait SANS UN SEUL LOG, le broker continuait de
# servir, et plus aucune session n'était jamais reapée (fuite illimitée de
# conteneurs ~4 Go chacun). `interval=0` -> `sleep(0)` -> boucle folle à 100 %
# CPU martelant Docker/Redis. `interval=-1` -> ValueError.
# RÈGLE : un accesseur numérique ne lève JAMAIS ; il retombe sur son défaut et
# applique un plancher.

import pytest

# (accesseur, variable d'env, défaut, plancher)
_NUMERIC_ACCESSORS = [
    ("job_pids", "OCULAR_JOB_PIDS", 256, 1),
    ("job_timeout", "OCULAR_JOB_TIMEOUT", 60, 1),
    ("render_timeout_ms", "OCULAR_RENDER_TIMEOUT_MS", 15000, 1),
    ("result_ttl", "OCULAR_RESULT_TTL", 86400, 1),
    ("job_ttl", "OCULAR_JOB_TTL", 1800, 1),
    ("max_html_bytes", "OCULAR_MAX_HTML_BYTES", 5_000_000, 1),
    ("session_ttl", "OCULAR_SESSION_TTL", 1800, 1),
    ("session_idle", "OCULAR_SESSION_IDLE", 600, 1),
    ("reaper_interval", "OCULAR_REAPER_INTERVAL", 60, 1),
    ("gc_interval", "OCULAR_GC_INTERVAL", 600, 1),
    ("sweep_interval", "OCULAR_SWEEP_INTERVAL", 600, 1),
    ("session_disconnect_grace", "OCULAR_SESSION_DISCONNECT_GRACE", 45, 0),
    ("session_ready_timeout", "OCULAR_SESSION_READY_TIMEOUT", 30, 1),
    ("max_sessions", "OCULAR_MAX_SESSIONS", 25, 0),
]


@pytest.mark.parametrize("name,env,default,floor", _NUMERIC_ACCESSORS)
@pytest.mark.parametrize("bad", ["abc", "60s", "", "  ", "1.2.3", "None"])
def test_numeric_accessor_falls_back_to_default_on_garbage(monkeypatch, name, env, default, floor, bad):
    monkeypatch.setenv(env, bad)
    assert getattr(s, name)() == default, (
        f"RÉGRESSION défaut C : {name}() doit retomber sur son défaut sur {bad!r}, jamais lever"
    )


@pytest.mark.parametrize("name,env,default,floor", _NUMERIC_ACCESSORS)
def test_numeric_accessor_clamps_to_floor(monkeypatch, name, env, default, floor):
    """`-5` et `0` ne doivent NI lever NI produire une valeur absurde : sur un
    intervalle de boucle, 0 signifie `sleep(0)` -> boucle folle à 100 % CPU."""
    for raw in ("-5", "-1", "0"):
        monkeypatch.setenv(env, raw)
        val = getattr(s, name)()
        assert val >= floor, f"RÉGRESSION défaut C : {name}()={val} sous le plancher {floor}"


@pytest.mark.parametrize("name,env,default,floor", _NUMERIC_ACCESSORS)
def test_numeric_accessor_still_honours_a_valid_override(monkeypatch, name, env, default, floor):
    monkeypatch.setenv(env, "7")
    assert getattr(s, name)() == 7


@pytest.mark.parametrize("name,env,default,floor", _NUMERIC_ACCESSORS)
def test_numeric_accessor_default_when_unset(monkeypatch, name, env, default, floor):
    monkeypatch.delenv(env, raising=False)
    assert getattr(s, name)() == default


def test_loop_intervals_are_never_zero(monkeypatch):
    """Verrou explicite anti-boucle-folle : un intervalle de boucle démon ne
    peut JAMAIS valoir 0 (sleep(0) = 100 % CPU à marteler Docker/Redis)."""
    for env, fn in (("OCULAR_REAPER_INTERVAL", s.reaper_interval),
                    ("OCULAR_GC_INTERVAL", s.gc_interval),
                    ("OCULAR_SWEEP_INTERVAL", s.sweep_interval)):
        for raw in ("0", "-1", "abc", ""):
            monkeypatch.setenv(env, raw)
            assert fn() >= 1
