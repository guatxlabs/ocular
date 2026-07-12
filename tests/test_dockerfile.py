from pathlib import Path


def test_dockerfile_runs_as_nonroot_and_has_no_curl_bash_docker():
    df = Path("runner_analysis/Dockerfile").read_text()
    assert "USER 10001" in df, "le runner doit tourner non-root"
    assert "get.docker.com" not in df, "le runner ne doit PAS contenir le CLI docker"


def test_seccomp_profile_is_not_unconfined():
    import json
    prof = json.loads(Path("schemas/seccomp-analysis.json").read_text())
    assert prof.get("defaultAction") in {"SCMP_ACT_ERRNO", "SCMP_ACT_KILL"}
