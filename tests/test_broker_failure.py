import json

import fakeredis

from broker import main
from bus.queue import Job, RedisJobQueue


def test_error_result_has_status_error():
    d = json.loads(main.error_result("j", RuntimeError('boom "q"\nx')))
    assert d["job_id"] == "j" and d["status"] == "error" and "boom" in d["error"]


def test_process_one_stores_error_result_on_job_failure(monkeypatch):
    r = fakeredis.FakeStrictRedis()
    q = RedisJobQueue(r)
    job = Job(job_id="jf", profile="analysis", html="x")

    def boom(_job):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(main, "run_analysis_job", boom)

    main.process_one(q, job)

    stored = json.loads(q.get_result("jf"))
    assert stored["status"] == "error" and "kaboom" in stored["error"]


def test_process_one_stores_ok_result_on_success(monkeypatch):
    r = fakeredis.FakeStrictRedis()
    q = RedisJobQueue(r)
    job = Job(job_id="jok", profile="analysis", html="x")

    monkeypatch.setattr(main, "run_analysis_job", lambda _job: '{"job_id": "jok", "verdict": "benign"}')

    main.process_one(q, job)

    stored = json.loads(q.get_result("jok"))
    assert stored["verdict"] == "benign"
