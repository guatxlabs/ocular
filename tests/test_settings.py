import ocular_settings as s


def test_defaults(monkeypatch):
    for v in ["OCULAR_REDIS_URL", "OCULAR_JOB_MEMORY", "OCULAR_RESULT_TTL", "OCULAR_MAX_HTML_BYTES"]:
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
