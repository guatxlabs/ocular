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

### Analyser une URL (recon live)

```sh
make analyze URL=https://exemple-suspect.tld
```

Construit `ocular-runner-analysis` **et** `ocular-runner-recon` si besoin, puis lance une
capture live (profil `capture` : Camoufox anti-detect + Xvfb, résolution auto du Turnstile
Cloudflare via vision) dans le conteneur durci — `--cap-drop ALL`, seccomp dédié, `--read-only`,
utilisateur non-root — et affiche le résultat JSON (verdict statique calculé sur le DOM capturé).

**⚠️ Avertissement — exposition IP.** Contrairement au profil `analysis` (`--network none`),
le profil `capture` a le réseau **activé** : le conteneur `ocular-runner-recon` effectue une
vraie requête sortante vers l'URL cible, ce qui expose l'IP de la machine qui exécute Ocular à
la cible (et à tout service tiers qu'elle charge). Pour analyser une cible sans révéler son IP
réelle (recon offensive, cible potentiellement hostile ou surveillée), faire transiter ce trafic
par un VPN ou Tor via les variables `HTTP_PROXY`/`HTTPS_PROXY`, lues et transmises au conteneur
par `broker/launcher.py` :

```sh
HTTPS_PROXY=socks5h://127.0.0.1:9050 make analyze URL=https://exemple-suspect.tld
```

Une garde SSRF (`engine/ssrf.py`) bloque en amont les URL dont l'hôte résout vers une IP privée
(RFC1918), loopback, link-local ou le service de metadata cloud (`169.254.169.254`) — best-effort
au moment du submit, pas une protection complète contre le DNS-rebinding (cf. docstring du
module).

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

### Interactif (navigation manuelle)

Pour les cas où l'analyse automatique (profils `analysis`/`capture`) ne suffit pas — cible qui
détecte l'automatisation, formulaire à remplir à la main, navigation multi-étapes — Ocular
propose une session interactive : un conteneur Camoufox headed persistant, piloté à la souris/
clavier depuis le navigateur de l'analyste via un client noVNC embarqué dans l'UI.

**Modèle de sécurité — pixels-only.** L'analyste ne parle jamais directement au conteneur
cible :

- **Rendu pixels uniquement**, via la gateway web : le navigateur de l'analyste ouvre un
  WebSocket vers `web` (`/sessions/{id}/ws`, auth par sous-protocole — le jeton capability ne
  transite jamais dans l'URL ni les logs), qui relaie le flux RFB/noVNC depuis le conteneur de
  session sur le réseau Docker interne `ocular-sessions`. Aucun DOM, aucun cookie, aucun
  fichier téléchargé côté cible n'atteint jamais la machine de l'analyste — seulement une image.
- **Presse-papiers coupé à la source** : le serveur VNC du conteneur tourne avec
  `x11vnc -noclipboard -nosetclipboard` (`runner_recon_vnc/entrypoint_vnc.sh`) — aucun texte ne
  peut transiter entre le presse-papiers de l'analyste et la session, quel que soit le client
  noVNC utilisé côté navigateur.
- **Aucun port hôte publié** : le conteneur de session (`ocular-runner-recon-vnc`) est lancé par
  le broker sans `-p`/`--publish` (`broker/sessions.py::build_session_args`) ; `session_server`
  (8090) et websockify/noVNC (6080) écoutent sur `0.0.0.0` uniquement parce qu'il n'y a rien à
  publier vers l'hôte — l'isolation vient de l'absence de mapping combinée au réseau interne
  `ocular-sessions`, jamais d'un bind localhost. Le serveur VNC brut (5900) n'écoute lui QUE sur
  `localhost` à l'intérieur du conteneur ; seul websockify (même conteneur) y accède.
- **Conteneur éphémère + reaper** : chaque session a une durée de vie bornée — TTL absolu
  (`OCULAR_SESSION_TTL`, 1800 s par défaut) et timeout d'inactivité (`OCULAR_SESSION_IDLE`,
  600 s), contrôlés par un reaper qui tourne dans le broker (thread démon, intervalle
  `OCULAR_REAPER_INTERVAL`, 60 s) et détruit (`docker kill` + `docker rm -f`) tout conteneur
  expiré, même orphelin (nom déterministe `ocular-sess-{id}`, pas de dépendance au registre).

**⚠️ Avertissement — IP exposée et contenu rendu côté conteneur.** Comme le profil `capture`, une
session interactive fait naviguer réellement Camoufox vers l'URL cible (ou rend le HTML fourni) :
l'IP de la machine qui exécute Ocular est exposée à la cible (utiliser `HTTPS_PROXY`/Tor si
nécessaire, cf. section précédente). Le contenu potentiellement hostile de la cible (JS, popups,
téléchargements déclenchés automatiquement) s'exécute et se rend **dans le conteneur durci**
(`--cap-drop ALL`, seccomp recon, `--read-only`, non-root) — jamais sur la machine de l'analyste,
qui ne reçoit que des pixels.

**Ouvrir une session :**

```sh
curl -X POST http://localhost:8000/sessions \
  -H "Authorization: Bearer $OCULAR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://exemple-suspect.tld"}'
# -> {"session_id": "sess-…", "token": "…"}  -- token capability WS, à usage unique
```

Le client noVNC de l'UI se connecte ensuite à `/sessions/{session_id}/ws` avec ce jeton comme
sous-protocole WebSocket. Plus simple : ouvrir `#/interactive` dans l'UI (`http://localhost:8000`
une fois connecté avec `$OCULAR_TOKEN`), qui gère la création de session et l'affichage noVNC
sans manipuler l'API directement.

### Portabilité authentification & secrets

Ocular n'impose **aucun** fournisseur d'identité ni gestionnaire de secrets — c'est un choix
délibéré de portabilité :

- **Authentification** : toutes les routes protégées (`/jobs*`, `/saved*`, `/sessions*`)
  exigent un simple jeton `Authorization: Bearer $OCULAR_TOKEN` vérifié côté serveur
  (`web/app.py`). Ce jeton opaque fonctionne aussi bien seul (déploiement mono-utilisateur) que
  derrière **n'importe quel** reverse-proxy ou couche SSO en amont (Authentik, Authelia, OIDC
  générique, LDAP, Basic Auth Caddy/Nginx…) — Ocular ne connaît ni ne dépend d'un fournisseur en
  particulier ; le proxy n'a qu'à transmettre ou fixer l'en-tête `Authorization`.
- **Secrets** : `OCULAR_TOKEN`, `OCULAR_ADMIN_TOKEN` (et tout autre secret) sont lus depuis des
  variables d'environnement (`deploy/.env`, cf. `deploy/.env.example`). N'importe quel
  gestionnaire de secrets capable d'injecter des variables d'environnement au démarrage du
  conteneur (Vault, SOPS, `docker compose --env-file`, secrets Kubernetes, gestionnaire du
  VPS…) fonctionne sans modification — **aucun n'est requis** : un simple fichier `.env` local
  suffit pour un déploiement mono-VPS.

## Déployer

Sur un VPS :

1. Créer `deploy/.env` (copie de `deploy/.env.example`) avec au minimum `OCULAR_TOKEN=<jeton-fort>`.
2. `make up` — construit automatiquement l'image runner (`build-runner` en dépendance) puis
   démarre `redis`, `web` et `broker` via `docker compose`.
3. `make down` pour arrêter ; `make gc` pour nettoyer les artefacts orphelins (fichiers du
   volume `ocular-artifacts` dont plus aucun résultat Redis ne référence le ref). `make gc`
   s'exécute dans le conteneur `broker` (via `docker compose exec`, qui a accès au bon Redis
   et au volume partagé) — la stack doit être démarrée (`make up`) au préalable.

Le tier `web` n'a jamais accès à `docker.sock` (seul `broker` y accède) et lit les artefacts en
lecture seule depuis le volume partagé `ocular-artifacts`. Il est recommandé de mettre un
reverse-proxy (Caddy) avec TLS + une couche d'authentification supplémentaire devant `web` avant
toute exposition publique.
