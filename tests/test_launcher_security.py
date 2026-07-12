import json
import pytest
from broker.launcher import build_docker_args, run_analysis_job
from bus.queue import Job


def test_analysis_container_has_all_hardening_flags():
    args = build_docker_args(Job(job_id="j1", profile="analysis", html="<h1>x</h1>"))
    joined = " ".join(args)
    assert "--network" in args and "none" in args
    assert "--cap-drop" in args and "ALL" in args
    assert "no-new-privileges" in joined
    assert "seccomp=" in joined and "unconfined" not in joined
    assert "--read-only" in args
    assert "--rm" in args
    assert "--user" in args and "10001:10001" in args
    assert "--pids-limit" in args


def test_html_is_not_written_to_host_disk_path():
    # le HTML transite par stdin (pas de -v montant un fichier hôte contenant le HTML)
    args = build_docker_args(Job(job_id="j1", profile="analysis", html="<h1>x</h1>"))
    assert not any(a.startswith("/") and a.endswith(".html") for a in args)


@pytest.mark.integration
def test_runner_has_no_network_egress():
    # HTML tentant un fetch externe : la requête ne doit jamais aboutir (network=none)
    html = '<script>fetch("http://example.com/steal").catch(()=>{})</script>'
    out = run_analysis_job(Job(job_id="net-test", profile="analysis", html=html))
    result = json.loads(out)
    # la requête peut être *tentée* (listée) mais ne peut jamais avoir de status (pas de réseau)
    external = [n for n in result["network"] if "example.com" in n["url"]]
    assert all(n.get("status") is None for n in external)
