# Ocular

Moteur unifié de capture + analyse web durci (recon anti-bot + analyse HTML hostile).

Voir `docs/superpowers/specs/` pour le design.

## Utiliser

### En local (CLI, sans docker compose)

```sh
make analyze FILE=suspect.html
```

Construit l'image `ocular-runner-analysis` si besoin, lance l'analyse dans le conteneur durci
(`--network none`, seccomp, `--read-only`, utilisateur non-root) et affiche le résultat JSON.

### Via l'API (web + broker + redis, avec docker compose)

```sh
OCULAR_TOKEN=<jeton-fort> make up
curl -X POST http://localhost:8000/jobs \
  -H "Authorization: Bearer $OCULAR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"profile": "analysis", "html": "<html>...</html>"}'
curl http://localhost:8000/jobs/<job_id> \
  -H "Authorization: Bearer $OCULAR_TOKEN"
```

Toutes les routes exigent `Authorization: Bearer $OCULAR_TOKEN` ; sans `OCULAR_TOKEN` configuré
côté serveur, l'API répond `503` (fail-closed), jamais un accès sans auth.

### Via l'UI

```sh
OCULAR_TOKEN=<jeton-fort> make up
```

Puis ouvrir `http://localhost:8000` — connexion avec le jeton, soumission de job, suivi des
jobs, détail (captures, DOM) en PWA installable.

## Déployer

Sur un VPS :

1. Créer `deploy/.env` (copie de `deploy/.env.example`) avec au minimum `OCULAR_TOKEN=<jeton-fort>`.
2. `make up` — construit automatiquement l'image runner (`build-runner` en dépendance) puis
   démarre `redis`, `web` et `broker` via `docker compose`.
3. `make down` pour arrêter ; `make gc` pour nettoyer les artefacts orphelins (fichiers du
   volume `ocular-artifacts` dont plus aucun résultat Redis ne référence le ref).

Le tier `web` n'a jamais accès à `docker.sock` (seul `broker` y accède) et lit les artefacts en
lecture seule depuis le volume partagé `ocular-artifacts`. Il est recommandé de mettre un
reverse-proxy (Caddy) avec TLS + une couche d'authentification supplémentaire devant `web` avant
toute exposition publique.
