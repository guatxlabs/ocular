from broker.launcher import build_docker_args
from bus.queue import Job


def test_capture_args_network_on_hardened_no_socket():
    a = build_docker_args(Job(job_id="j", profile="capture", url="https://example.com"))
    j = " ".join(a)
    assert "--network" not in a or "none" not in a          # réseau ON (pas de --network none)
    assert "--cap-drop" in a and "ALL" in a
    assert "--rm" in a and "no-new-privileges" in j
    assert "docker.sock" not in j and "--privileged" not in a
    assert "ocular-runner-recon:latest" in a and "--url" in a and "https://example.com" in a


def test_analysis_still_network_none():
    a = build_docker_args(Job(job_id="j", profile="analysis", html="x"))
    assert "--network" in a and "none" in a
