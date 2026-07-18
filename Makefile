.PHONY: build-runner up down analyze script test test-int calibrate gc clean
build-runner:
	docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .
	docker build -f runner_recon/Dockerfile -t ocular-runner-recon:latest .
	docker build -f runner_recon_vnc/Dockerfile -t ocular-runner-recon-vnc:latest .
up: build-runner
	docker compose -f deploy/docker-compose.yml up -d --build
down:
	docker compose -f deploy/docker-compose.yml down
	@# Les conteneurs de session (ocular-sess-*) sont lancés hors-compose par le
	@# broker (docker run) : `compose down` ne les retire pas -> nettoyage explicite
	@# (sinon orphelins + réseau de session non supprimable).
	-@ids=$$(docker ps -aq --filter name=ocular-sess-); if [ -n "$$ids" ]; then docker rm -f $$ids; fi
	@# Idem pour les réseaux DÉDIÉS par session (ocular-sess-net-*), créés hors
	@# compose par le broker. APRÈS les conteneurs : un réseau encore attaché à
	@# un conteneur n'est pas supprimable.
	-@ids=$$(docker network ls -q --filter name=ocular-sess-net-); if [ -n "$$ids" ]; then docker network rm $$ids; fi
analyze: build-runner
	@if [ -n "$(URL)" ]; then . .venv/bin/activate && python -c "from broker.launcher import run_job; from bus.queue import Job; print(run_job(Job(job_id='cli', profile='capture', url='$(URL)')))"; \
	elif [ -n "$(FILE)" ]; then . .venv/bin/activate && python -c "from broker.launcher import run_job; from bus.queue import Job; print(run_job(Job(job_id='cli', profile='analysis', html=open('$(FILE)').read())))"; \
	else echo "usage: make analyze FILE=x.html | URL=https://…"; exit 1; fi
# Tier dynamique scripté (3c) : rejoue une séquence d'actions (fill/click/wait…)
# après le chargement de la page, pour révéler les appels post-interaction
# (phishing multi-étapes, beacon au clic). STEPS pointe vers un fichier JSON
# contenant la liste de steps du DSL (cf. README « Tier dynamique scripté »).
# Même mécanisme/auth que la route API : POST /jobs, Authorization: Bearer
# $(OCULAR_TOKEN). La cible ne parle jamais au broker directement (contrairement
# à `analyze`) — la validation stricte (engine.steps.validate_steps) et le SSRF
# sur url/goto sont appliqués côté serveur ; réponse 422 si les steps sont
# invalides.
# usage: make script URL=https://exemple-suspect.tld STEPS=chemin/vers/steps.json
#        [OCULAR_API=http://localhost:8000] OCULAR_TOKEN=<jeton-fort>
script:
	@if [ -z "$(URL)" ] || [ -z "$(STEPS)" ]; then \
		echo "usage: make script URL=https://... STEPS=chemin/vers/steps.json"; exit 1; \
	fi
	@BODY=$$(python3 -c "import json,sys; print(json.dumps({'profile':'capture','url':sys.argv[1],'steps':json.load(open(sys.argv[2]))}))" "$(URL)" "$(STEPS)") && \
	curl -sS -X POST "$${OCULAR_API:-http://localhost:8000}/jobs" \
	  -H "Authorization: Bearer $(OCULAR_TOKEN)" \
	  -H "Content-Type: application/json" \
	  -d "$$BODY"
# Tests unitaires EN CONTENEUR (canonique, sans venv natif) : build l'image de
# test puis exécute pytest -m "not integration" dedans.
test:
	docker build -f deploy/Dockerfile.test -t ocular-test:latest .
	docker run --rm ocular-test:latest
# Variante locale (venv) pour un cycle rapide en dev, si tu préfères.
test-local:
	. .venv/bin/activate && pytest -m "not integration" -q
# Tests d'INTÉGRATION : restent sur l'hôte (ils orchestrent Docker : build/run
# d'images, pas de docker-in-docker). Nécessitent le CLI docker + le venv.
test-int:
	. .venv/bin/activate && pytest -m integration -q
# Calibration HORS-LIGNE des poids de triage (lecture seule de la base saved,
# aucun réseau). Tourne dans un conteneur jetable -> aucun résidu host. L'image
# de test embarque déjà numpy (deploy/Dockerfile.test) : pas d'install à la volée.
# DB= chemin de la base saved ; OUT= fichier de poids proposé ; DATE= suffixe version.
calibrate:
	docker build -f deploy/Dockerfile.test -t ocular-test:latest .
	docker run --rm -v "$(CURDIR):/app" -w /app ocular-test:latest \
		python -m tools.calibrate_triage --db $(DB) --out $(OUT) --date $(DATE)
gc:
	docker compose -f deploy/docker-compose.yml exec -T broker python -m broker.gc
clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null; true
	rm -rf .coverage *.egg-info artifacts *.db *.db-* 2>/dev/null; true
