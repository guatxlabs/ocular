.PHONY: build-runner up down analyze test test-int gc clean
build-runner:
	docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .
	docker build -f runner_recon/Dockerfile -t ocular-runner-recon:latest .
up: build-runner
	docker compose -f deploy/docker-compose.yml up -d --build
down:
	docker compose -f deploy/docker-compose.yml down
analyze: build-runner
	@if [ -n "$(URL)" ]; then . .venv/bin/activate && python -c "from broker.launcher import run_job; from bus.queue import Job; print(run_job(Job(job_id='cli', profile='capture', url='$(URL)')))"; \
	elif [ -n "$(FILE)" ]; then . .venv/bin/activate && python -c "from broker.launcher import run_job; from bus.queue import Job; print(run_job(Job(job_id='cli', profile='analysis', html=open('$(FILE)').read())))"; \
	else echo "usage: make analyze FILE=x.html | URL=https://…"; exit 1; fi
test:
	. .venv/bin/activate && pytest -q
test-int:
	. .venv/bin/activate && pytest -m integration -q
gc:
	docker compose -f deploy/docker-compose.yml exec -T broker python -m broker.gc
clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null; true
	rm -rf .coverage *.egg-info artifacts *.db *.db-* 2>/dev/null; true
