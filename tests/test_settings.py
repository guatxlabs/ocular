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
