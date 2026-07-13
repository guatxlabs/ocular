import json

from broker.launcher import build_docker_args, scripted_stdin
from bus.queue import Job


def test_scripted_capture_job_uses_dash_i_and_stdin_payload():
    job = Job(job_id="j", profile="capture", url="https://example.com",
              steps=[{"click": "#a"}, {"capture": "final"}])
    args = build_docker_args(job)
    assert "-i" in args

    joined = " ".join(args)
    # les steps/sélecteurs ne fuitent JAMAIS dans les args docker (donc
    # absents de `docker inspect`) : ils passent uniquement par stdin.
    assert "#a" not in joined
    assert "click" not in joined

    payload = scripted_stdin(job)
    assert json.loads(payload) == {
        "url": "https://example.com",
        "steps": [{"click": "#a"}, {"capture": "final"}],
    }

    # durcissement 3a préservé (réutilisé, pas dupliqué)
    assert "--rm" in args
    assert "--cap-drop" in args and "ALL" in args
    assert "--security-opt" in args
    assert "no-new-privileges:true" in args


def test_capture_job_without_steps_has_no_dash_i_and_unchanged_args():
    job = Job(job_id="j", profile="capture", url="https://example.com")
    args = build_docker_args(job)
    assert "-i" not in args
    # chemin 3a strictement inchangé : url reste passée en argument (fallback)
    assert "--url" in args and "https://example.com" in args


def test_capture_job_with_empty_steps_list_is_treated_as_no_steps():
    job = Job(job_id="j", profile="capture", url="https://example.com", steps=[])
    args = build_docker_args(job)
    assert "-i" not in args


def test_analysis_job_unchanged_still_has_dash_i_and_no_scripted_payload():
    args = build_docker_args(Job(job_id="j", profile="analysis", html="<h1>x</h1>"))
    assert "-i" in args
    assert "--network" in args and "none" in args


def test_run_job_capture_scripted_passes_stdin_and_no_url_arg_leak(monkeypatch, tmp_path):
    import broker.launcher as launcher_mod

    calls = {}

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout=b"", stderr=b""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(args, input=None, capture_output=None, timeout=None):
        calls["args"] = args
        calls["input"] = input
        calls["timeout"] = timeout
        wrapper = json.dumps({"result": {"ok": True}, "blobs": {}})
        return _FakeCompletedProcess(returncode=0, stdout=wrapper.encode())

    monkeypatch.setattr(launcher_mod, "_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(launcher_mod.subprocess, "run", fake_run)

    job = Job(job_id="j4", profile="capture", url="https://example.com",
              steps=[{"click": "#a"}, {"capture": "final"}])
    launcher_mod.run_job(job)

    assert calls["input"] is not None
    payload = json.loads(calls["input"])
    assert payload == {"url": "https://example.com",
                        "steps": [{"click": "#a"}, {"capture": "final"}]}
    assert calls["timeout"] == 90
    assert "-i" in calls["args"]


def test_run_job_capture_without_steps_still_no_stdin(monkeypatch, tmp_path):
    import broker.launcher as launcher_mod

    calls = {}

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout=b"", stderr=b""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(args, input=None, capture_output=None, timeout=None):
        calls["input"] = input
        wrapper = json.dumps({"result": {"ok": True}, "blobs": {}})
        return _FakeCompletedProcess(returncode=0, stdout=wrapper.encode())

    monkeypatch.setattr(launcher_mod, "_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(launcher_mod.subprocess, "run", fake_run)

    launcher_mod.run_job(Job(job_id="j5", profile="capture", url="https://example.com"))
    assert calls["input"] is None


def test_run_job_analysis_stdin_unchanged(monkeypatch, tmp_path):
    import broker.launcher as launcher_mod

    calls = {}

    class _FakeCompletedProcess:
        def __init__(self, returncode=0, stdout=b"", stderr=b""):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr

    def fake_run(args, input=None, capture_output=None, timeout=None):
        calls["input"] = input
        wrapper = json.dumps({"result": {"ok": True}, "blobs": {}})
        return _FakeCompletedProcess(returncode=0, stdout=wrapper.encode())

    monkeypatch.setattr(launcher_mod, "_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.setattr(launcher_mod.subprocess, "run", fake_run)

    launcher_mod.run_job(Job(job_id="j6", profile="analysis", html="<html></html>"))
    assert calls["input"] == b"<html></html>"
