import json

import pytest

import broker.launcher as launcher_mod
from broker.launcher import _proxy_env, build_docker_args, run_job
from bus.queue import Job


def test_capture_args_network_on_hardened_no_socket():
    a = build_docker_args(Job(job_id="j", profile="capture", url="https://example.com"))
    j = " ".join(a)
    assert "--network" not in a or "none" not in a          # réseau ON (pas de --network none)
    assert "--cap-drop" in a and "ALL" in a
    assert "--rm" in a and "no-new-privileges" in j
    assert "docker.sock" not in j and "--privileged" not in a
    assert "ocular-runner-recon:latest" in a and "--url" in a and "https://example.com" in a


def test_capture_args_full_hardening():
    a = build_docker_args(Job(job_id="j", profile="capture", url="https://example.com"))
    assert "--read-only" in a
    assert "--user" in a and "10001:10001" in a
    assert "--pids-limit" in a and "512" in a
    assert "--memory" in a and "4g" in a
    assert a.count("--tmpfs") == 2
    tmpfs_values = [a[i + 1] for i, v in enumerate(a) if v == "--tmpfs"]
    assert any(v.startswith("/work:") for v in tmpfs_values)
    assert any(v.startswith("/tmp:") for v in tmpfs_values)
    assert "schemas/seccomp-recon.json" in " ".join(a)


def test_analysis_still_network_none():
    a = build_docker_args(Job(job_id="j", profile="analysis", html="x"))
    assert "--network" in a and "none" in a


def test_proxy_env_adds_flags_when_set(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.local:8080")
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("https_proxy", raising=False)
    out = _proxy_env()
    assert out == ["-e", "HTTP_PROXY=http://proxy.local:8080"]


def test_proxy_env_empty_when_unset(monkeypatch):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(k, raising=False)
    assert _proxy_env() == []


class _FakeCompletedProcess:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_run_job_analysis_passes_html_stdin_and_60s_timeout(monkeypatch, tmp_path):
    calls = {}

    def fake_run(args, input=None, capture_output=None, timeout=None):
        calls["args"] = args
        calls["input"] = input
        calls["timeout"] = timeout
        wrapper = json.dumps({"result": {"ok": True}, "blobs": {}})
        return _FakeCompletedProcess(returncode=0, stdout=wrapper.encode())

    monkeypatch.setattr(launcher_mod, "_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(launcher_mod.subprocess, "run", fake_run)

    run_job(Job(job_id="j1", profile="analysis", html="<html></html>"))

    assert calls["input"] == b"<html></html>"
    assert calls["timeout"] == 60


def test_run_job_capture_no_stdin_90s_timeout_and_url_arg(monkeypatch, tmp_path):
    calls = {}

    def fake_run(args, input=None, capture_output=None, timeout=None):
        calls["args"] = args
        calls["input"] = input
        calls["timeout"] = timeout
        wrapper = json.dumps({"result": {"ok": True}, "blobs": {}})
        return _FakeCompletedProcess(returncode=0, stdout=wrapper.encode())

    monkeypatch.setattr(launcher_mod, "_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(launcher_mod.subprocess, "run", fake_run)

    run_job(Job(job_id="j2", profile="capture", url="https://example.com"))

    assert calls["input"] is None
    assert calls["timeout"] == 90
    assert "--url" in calls["args"]


def test_run_job_nonzero_returncode_raises_runtime_error(monkeypatch, tmp_path):
    def fake_run(args, input=None, capture_output=None, timeout=None):
        return _FakeCompletedProcess(returncode=1, stdout=b"", stderr=b"boom")

    monkeypatch.setattr(launcher_mod, "_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(launcher_mod.subprocess, "run", fake_run)

    with pytest.raises(RuntimeError):
        run_job(Job(job_id="j3", profile="analysis", html="x"))
