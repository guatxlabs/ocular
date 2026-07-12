FROM mcr.microsoft.com/playwright/python:v1.41.0-jammy@sha256:6db13504e3915a9d9fee8638432c8036216bfda087ea36dd86608db83e3eb560

WORKDIR /app
# playwright==1.41.0 pinné pour matcher les binaires navigateurs déjà présents
# dans l'image de base (chromium-1097) : le tag v1.41.0-jammy fournit les
# navigateurs mais PAS le paquet pip playwright lui-même.
RUN pip install --no-cache-dir pydantic>=2.6 playwright==1.41.0
COPY engine/ ./engine/
COPY runner_analysis/ ./runner_analysis/

# Utilisateur non privilégié
RUN useradd -u 10001 -m runner

# Le conteneur tourne avec --read-only + --tmpfs /work:...  (seul répertoire
# inscriptible à l'exécution). Chromium a besoin d'un HOME/TMPDIR inscriptible
# pour son profil utilisateur et ses fichiers de verrouillage : on les fait
# pointer vers /work plutôt que /home/runner (en lecture seule à l'exécution).
ENV HOME=/work
ENV TMPDIR=/work
# /work est le SEUL point d'écriture au runtime (HOME/TMPDIR de Chromium). Le runtime DOIT
# monter --tmpfs /work:size=...,mode=1777 (cf. broker/launcher.py) : sans ce flag, /work reste
# root:root en lecture seule et Chromium échoue silencieusement.
RUN mkdir -p /work

USER 10001

ENTRYPOINT ["python", "-m", "runner_analysis.render"]
