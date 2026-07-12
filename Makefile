.PHONY: build-runner up down analyze test test-int gc clean
build-runner:
	docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .
up: build-runner
	docker compose -f deploy/docker-compose.yml up -d --build
down:
	docker compose -f deploy/docker-compose.yml down
analyze: build-runner
	@test -n "$(FILE)" || (echo "usage: make analyze FILE=suspect.html"; exit 1)
	. .venv/bin/activate && python -c "from broker.launcher import run_analysis_job; from bus.queue import Job; import sys; print(run_analysis_job(Job(job_id='cli', profile='analysis', html=open('$(FILE)').read())))"
test:
	. .venv/bin/activate && pytest -q
test-int:
	. .venv/bin/activate && pytest -m integration -q
gc:
	docker compose -f deploy/docker-compose.yml exec -T broker python -m broker.gc
clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null; true
	rm -rf .coverage *.egg-info artifacts *.db *.db-* 2>/dev/null; true
