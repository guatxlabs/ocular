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

**Auto-résolution Turnstile.** Repose sur un rendu headed réel dans le Xvfb du conteneur
(`runner_recon/vision.py` + `xdotool`) : template matching sur le screenshot pour localiser la
case, puis clic **OS** (X11 réel, pas `page.mouse`) pour franchir la vérification `isTrusted`
d'un widget interactif. Le widget se chargeant dans une iframe async, `solve_turnstile`
(`runner_recon/capture.py`) retente la détection ~6 fois sur ~4s avant de conclure à l'absence de
Turnstile. Les coordonnées de clic sont mappées du repère **image** (viewport du screenshot,
ce que renvoie `vision.detect()`) au repère **écran** (ce qu'attend `xdotool`) via
`window.mozInnerScreenX/Y` (offset du chrome Firefox, API Gecko) et `devicePixelRatio`
(`vision.image_to_screen`) — sans cet offset le clic tombe à côté de la case. Après le clic,
une nouvelle détection vérifie que la case a bien disparu avant de marquer `turnstile_solved`
(jamais un `True` optimiste non vérifié). **Limite connue** : le mapping, la boucle de retry et
la logique de vérification sont couverts par des tests unitaires (page/vision mockées, cf.
`tests/test_vision_coords.py` et `tests/test_capture_logic.py`) et par le smoke d'intégration
docker sur une page sans Turnstile (`tests/test_deploy_images.py::test_runner_recon_image_builds_and_navigates`),
mais la résolution effective d'un **vrai** challenge Cloudflare n'a pas pu être validée en bout
en bout dans cet environnement — à confirmer contre une cible réelle.

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

### Tier dynamique scripté (3c)

Le profil `capture` seul ne voit que ce qui se charge **au chargement de la page**. Or beaucoup de
comportements hostiles ne se déclenchent qu'**après une interaction** : formulaire de phishing
multi-étapes (identifiants → OTP → redirection), balise de tracking posée uniquement au clic
(« beacon »), contenu qui ne s'affiche qu'après un `scroll` ou la fermeture d'un consentement. Le
tier scripté rejoue une **séquence d'actions déclarative** dans le même conteneur `capture`
(`ocular-runner-recon`, aucune image supplémentaire) pendant que le trafic réseau est capturé, pour
révéler ces appels post-interaction en un run éphémère et jetable.

**Le DSL.** Une liste de *steps*, chacun un objet à une seule clé parmi les verbes en allowlist
`goto`, `fill`, `click`, `wait`, `press`, `capture`, `scroll` :

```json
[
  {"click": "#accept-cookies"},
  {"fill": {"sel": "#email", "value": "victime@exemple.tld"}},
  {"click": "#submit"},
  {"wait": 1000},
  {"capture": "apres-soumission"}
]
```

`goto` navigue vers une nouvelle URL (revalidée SSRF), `fill` remplit un champ (`{sel, value}`),
`click`/`wait`(ms ou `{selector}`)/`press` (touche en allowlist) pilotent l'interaction, `scroll`
déplace la page (`"top"`/`"bottom"`/pixels), `capture` prend un screenshot labellisé. Un `capture`
final est **ajouté automatiquement** si la séquence ne s'y termine pas déjà, pour toujours obtenir
un état de fin. Bornes strictes : ≤ 50 steps, sélecteur ≤ 500 caractères, valeur `fill` ≤ 2000,
`wait` ≤ 30000 ms, `scroll` ≤ 100000 px, label ≤ 64 caractères — tout dépassement ou verbe hors
allowlist est rejeté avant exécution.

**Garanties de sécurité.**

- **Aucun JS arbitraire, aucun `eval`** : les verbes sont une allowlist stricte validée par
  `engine.steps.validate_steps` (source unique, importée à la fois par le web et par le runner —
  pas de seconde implémentation qui pourrait diverger) ; sélecteurs et valeurs passent par l'**API
  locator** Playwright (`page.locator`, `page.fill`), jamais interpolés dans du code exécuté.
- **Steps transmis par stdin, jamais par argument ni variable d'environnement** : le broker écrit
  `{"url": ..., "steps": [...]}` sur l'entrée standard du conteneur (`docker run --rm -i`) — les
  steps (et donc les valeurs saisies) sont **absents de `docker inspect`** et des arguments de
  commande visibles par les autres processus de l'hôte.
- **Valeurs `fill` redigées** : toute valeur de champ est remplacée par `"***"` dans le journal
  d'actions renvoyé au client et dans les logs — jamais de mot de passe/identifiant en clair
  stocké ou affiché après l'exécution.
- **SSRF sur l'URL initiale ET chaque `goto`** : `engine.ssrf.validate_capture_url` s'applique à
  l'URL de départ comme à toute navigation demandée en cours de séquence (mêmes règles que le
  profil `capture` — IP privées/loopback/link-local/metadata cloud bloquées en amont).
- **Même durcissement conteneur que le profil `capture` 3a**, réutilisé tel quel (pas de
  duplication) : `--cap-drop ALL`, seccomp dédié, `--read-only`, non-root, réseau activé
  uniquement pour joindre la cible (mêmes avertissements IP/proxy que ci-dessus).

**Utilisation.**

```sh
cat > steps.json <<'EOF'
[{"click": "#accept-cookies"}, {"fill": {"sel": "#email", "value": "test@exemple.tld"}},
 {"click": "#submit"}, {"wait": 1000}, {"capture": "apres-soumission"}]
EOF
OCULAR_TOKEN=<jeton-fort> make script URL=https://exemple-suspect.tld STEPS=steps.json
```

`make script` lit le fichier `STEPS`, construit `{"profile":"capture","url":$URL,"steps":<contenu>}`
et le soumet à `POST /jobs` — même mécanisme et même jeton `Authorization: Bearer $OCULAR_TOKEN` que
la section « Via l'API » ci-dessus. Steps invalides (verbe inconnu, borne dépassée, SSRF sur un
`goto`) → `422` avec le motif de rejet. Le résultat expose le **journal d'actions** (`dynamic_steps` :
action, succès, durée, erreur éventuelle — valeurs déjà redigées) et la **galerie de captures
labellisées**, aussi bien depuis l'API que depuis le formulaire scripté de l'UI (`http://localhost:8000`,
onglet capture — champ « script » au format JSON ci-dessus).

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
  session, sur le réseau Docker **dédié à cette session** (`ocular-sess-net-{id}`, créé au
  lancement et détruit au teardown ; le `web` y est attaché dynamiquement pour le seul besoin
  du proxy). Aucun DOM, aucun cookie, aucun
  fichier téléchargé côté cible n'atteint jamais la machine de l'analyste — seulement une image.
- **Presse-papiers coupé à la source** : le serveur VNC du conteneur tourne avec
  `x11vnc -noclipboard -nosetclipboard` (`runner_recon_vnc/entrypoint_vnc.sh`) — aucun texte ne
  peut transiter entre le presse-papiers de l'analyste et la session, quel que soit le client
  noVNC utilisé côté navigateur.
- **Aucun port hôte publié** : le conteneur de session (`ocular-runner-recon-vnc`) est lancé par
  le broker sans `-p`/`--publish` (`broker/sessions.py::build_session_args`) ; `session_server`
  (8090) et websockify/noVNC (6080) écoutent sur `0.0.0.0` uniquement parce qu'il n'y a rien à
  publier vers l'hôte — l'isolation vient de l'absence de mapping combinée au réseau interne
  **dédié à la session**, jamais d'un bind localhost. Le serveur VNC brut (5900) n'écoute lui QUE sur
  `localhost` à l'intérieur du conteneur ; seul websockify (même conteneur) y accède.
- **Isolation inter-sessions** : chaque session obtient son **propre** réseau docker
  (`ocular-sess-net-{id}`), créé par le broker au lancement et supprimé au teardown. Deux
  sessions sont donc sur des réseaux **disjoints** : une session compromise ne peut pas joindre
  le `:6080` (websockify, sans auth propre) ni le `:8090` d'un pair — elle ne le voit tout
  simplement pas. Seul le `web` est attaché à chaque réseau de session (nécessaire au proxy) ;
  le broker, lui, n'y est attaché à aucun. Prouvé par
  `tests/test_session_isolation_integration.py`.
- **Conteneur éphémère + reaper** : chaque session a une durée de vie bornée — TTL absolu
  (`OCULAR_SESSION_TTL`, 1800 s par défaut) et timeout d'inactivité (`OCULAR_SESSION_IDLE`,
  600 s), contrôlés par un reaper qui tourne dans le broker (thread démon, intervalle
  `OCULAR_REAPER_INTERVAL`, 60 s) et détruit (`docker kill` + `docker rm -f`) tout conteneur
  expiré, même orphelin (nom déterministe `ocular-sess-{id}`, pas de dépendance au registre).
- **Balayage des orphelins** : au démarrage du broker *et* périodiquement (thread démon,
  intervalle `OCULAR_SWEEP_INTERVAL`, 600 s), les conteneurs `ocular-sess-*` et les réseaux
  `ocular-sess-net-*` sans session vivante au registre sont supprimés. Sans ce passage
  périodique, un résidu né en cours de vie (teardown partiellement échoué, conteneur tué hors
  flux) retiendrait un sous-réseau du pool d'adresses Docker — ressource finie — jusqu'au
  prochain redémarrage du broker.

**⚠️ Avertissement — IP exposée et contenu rendu côté conteneur.** Comme le profil `capture`, une
session interactive fait naviguer réellement Camoufox vers l'URL cible (ou rend le HTML fourni) :
l'IP de la machine qui exécute Ocular est exposée à la cible (utiliser `HTTPS_PROXY`/Tor si
nécessaire, cf. section précédente). Le contenu potentiellement hostile de la cible (JS, popups,
téléchargements déclenchés automatiquement) s'exécute et se rend **dans le conteneur durci**
(`--cap-drop ALL`, seccomp recon, `--read-only`, non-root) — jamais sur la machine de l'analyste,
qui ne reçoit que des pixels.

**Ouvrir une session — la création est ASYNCHRONE (202) :**

```sh
curl -X POST http://localhost:8000/sessions \
  -H "Authorization: Bearer $OCULAR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://exemple-suspect.tld"}'
# HTTP 202 Accepted (réponse en < 1 s)
# -> {"session_id": "sess-…", "token": "…"}  -- token capability WS, à usage unique
```

> **202 ne veut PAS dire « prête ».** La session est *acceptée* ; son conteneur met encore ~7-9 s
> à démarrer. Il faut ensuite **sonder** sa disponibilité (ci-dessous) avant de brancher le
> WebSocket noVNC ou de capturer.

Cette route était autrefois **synchrone** : elle attendait la disponibilité (jusqu'à
`OCULAR_SESSION_READY_TIMEOUT`, 30 s) avant de répondre. Un client qui abandonnait pendant
l'attente — timeout, `Ctrl-C`, proxy amont, onglet fermé — n'apprenait **jamais** son
`session_id` alors que la session était déjà créée : elle immobilisait un conteneur (~4 Go) et un
sous-réseau du pool docker jusqu'à son TTL, **sans que personne ne puisse la supprimer**. Le
client reçoit désormais l'identifiant immédiatement et peut donc toujours nettoyer.

**Sonder la disponibilité :** `GET /sessions/{session_id}`

```sh
curl http://localhost:8000/sessions/sess-… -H "Authorization: Bearer $OCULAR_TOKEN"
# -> {"session_id":"sess-…","state":"starting","ready":false,
#     "kind":"recon-vnc","target":"https://exemple-suspect.tld/","created_at":…,"last_activity":…}
```

| `state` | signification |
| --- | --- |
| `pending` | l'entrée registre existe, le conteneur n'est **pas encore lancé** |
| `starting` | conteneur lancé, son `session_server` ne répond pas encore `/health` |
| `ready` | prête : WebSocket noVNC et `/capture` utilisables |

`ready` (booléen) est le dérivé `state == "ready"` : s'arrêter dessus plutôt que sur une liste
d'états intermédiaires codée en dur, pour survivre à l'ajout d'un état.

La réponse ne contient **jamais** le token capability WS ni le secret de frontière conteneur
(même filtrage que `GET /sessions`) ; `owner` n'est rendu qu'à un admin. Comme toutes les routes
de session, elle rend **404** aussi bien pour une session inconnue que pour celle d'un autre
analyste (indistinguables à dessein : pas d'oracle d'existence) — l'admin passe outre.

**Nettoyage — la contrepartie du 202.** Si la disponibilité n'arrive pas dans un délai
raisonnable, ou si le sondage échoue, le client **doit** appeler `DELETE /sessions/{session_id}`.
Un 404 pendant le sondage signale que le serveur a lui-même renoncé et détruit la session (filet
de sécurité conservé du contrat synchrone) : c'est un échec terminal, pas un état d'attente.

Le client noVNC de l'UI se connecte ensuite à `/sessions/{session_id}/ws` avec ce jeton comme
sous-protocole WebSocket. Plus simple : ouvrir `#/interactive` dans l'UI (`http://localhost:8000`
une fois connecté avec `$OCULAR_TOKEN`), qui gère la création de session, le sondage (avec
progression visible), le nettoyage en cas d'échec et l'affichage noVNC sans manipuler l'API
directement.

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

#### Identité IdP (forward-auth) — optionnel

Pour tracer **qui** analyse/tranche (verdict analyste, provenance des sauvegardes), Ocular peut
dériver l'identité de l'utilisateur depuis les en-têtes injectés par un reverse-proxy
authentifié — compatible **n'importe quel** IdP (Keycloak, Authentik, Authelia, oauth2-proxy,
LDAP fronté par un proxy…), sans verrouillage.

- **Désactivé par défaut.** L'en-tête d'identité n'est lu que si `OCULAR_TRUST_FORWARD_AUTH=1`.
  Sans cette variable, seul le `Bearer $OCULAR_TOKEN` authentifie (comportement inchangé).
- Variables : `OCULAR_TRUST_FORWARD_AUTH` (opt-in), `OCULAR_FORWARD_USER_HEADER`
  (défaut `X-Forwarded-User`), `OCULAR_FORWARD_EMAIL_HEADER` (défaut `X-Forwarded-Email`).
- Quand activé, une requête proxifiée porteuse de l'en-tête d'identité est autorisée
  automatiquement (l'analyste derrière l'IdP n'a **aucun jeton à coller**) ; l'identité alimente
  `saved_by` et le verdict analyste. `GET /auth/whoami` renvoie l'identité de l'appelant.
- **IP cliente dans la piste d'audit** (même opt-in) : le frontal `gateway` détient le port
  publié et relaie en **L4**, donc le pair TCP vu par `web` est toujours le gateway. Quand
  `OCULAR_TRUST_FORWARD_AUTH=1`, la ligne d'audit `session create` prend l'IP dans
  `OCULAR_FORWARD_FOR_HEADER` (défaut `X-Forwarded-For`), **élément le plus à gauche** (le client
  d'origine ; la liste est construite par ajout successif). Sans l'opt-in, l'en-tête est ignoré
  et l'IP du pair est journalisée : une IP de frontal, honnête et connue, vaut mieux qu'une IP
  choisie par le client. Le gateway étant du L4, il transmet l'en-tête **inchangé** — c'est bien
  le reverse-proxy amont qui doit le poser et stripper les copies clientes.
- **Rôle admin via groupe IdP** (opt-in, nécessite aussi `OCULAR_TRUST_FORWARD_AUTH=1`) :
  définir `OCULAR_ADMIN_GROUP=<nom-de-groupe>` accorde le rôle admin (`DELETE /saved`) à tout
  appelant dont l'en-tête de groupes (`OCULAR_FORWARD_GROUPS_HEADER`, défaut `X-Forwarded-Groups`,
  liste séparée par des virgules) **contient exactement** ce groupe (comparaison sensible à la
  casse, sans espaces parasites — un `OCULAR_ADMIN_GROUP=" admins"` ne matchera pas `admins`).
  `X-Admin-Token` reste un fallback valable en parallèle. Vide (défaut) → admin uniquement via
  `X-Admin-Token`. `GET /auth/whoami` expose `groups` et `is_admin` (l'UI masque les contrôles
  admin aux non-admins — mais le backend reste la vraie garde).

> ⚠️ **IMPÉRATIF de sécurité.** N'activez `OCULAR_TRUST_FORWARD_AUTH` **que** derrière un
> reverse-proxy qui **authentifie ET supprime (strip) toute copie des en-têtes de confiance
> venant du client** — au minimum `X-Forwarded-User` **ET `X-Forwarded-Groups`** (et les en-têtes
> d'email/de groupes/d'IP que vous configurez, cf. `X-Forwarded-For` ci-dessus : non strippé, il
> laisse un client empoisonner l'IP de la piste d'audit). Sinon, un client peut usurper `X-Forwarded-User: x`
> ou, si `OCULAR_ADMIN_GROUP` est activé, `X-Forwarded-Groups: <groupe-admin>` et **escalader en
> admin**. Recommandations : (1) gardez `OCULAR_TOKEN`/`OCULAR_ADMIN_TOKEN` définis même en mode
> forward-auth (filet) ; (2) le conteneur `web` n'est **jamais** joignable en direct, seul le
> proxy l'atteint ; (3) le proxy doit **écraser** ces en-têtes, pas seulement les ajouter.

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

## Sécurité

Ocular **charge et exécute du contenu web hostile** : c'est sa fonction. Le confinement
(séparation des privilèges, conteneurs éphémères durcis, isolation réseau par session, garde
SSRF avec épinglage d'IP) est décrit dans [`SECURITY.md`](SECURITY.md), qui documente aussi
les **limites connues et assumées** — dont le fait que le `broker` monte le socket Docker.

Pour signaler une vulnérabilité : **ne pas ouvrir d'issue publique**, voir
[`SECURITY.md`](SECURITY.md).

Prérequis de déploiement (règles `DOCKER-USER`, `default-address-pools`) :
[`docs/DEPLOY-SECURITY.md`](docs/DEPLOY-SECURITY.md).

## Contribuer

La convention d'opération du dépôt — discipline git, actions gatées, pièges vérifiés — est
dans [`AGENTS.md`](AGENTS.md). Elle s'applique aux sessions humaines comme aux agents.

Avant toute proposition de fusion : `make test` et `make test-int` verts, plus une
vérification live de ce qui a changé.

## Licence

**GNU Affero General Public License v3.0 ou ultérieure** (AGPL-3.0-or-later), pour le
code propre au projet.

L'AGPL ajoute à la GPL une obligation qui compte pour un outil comme celui-ci : si vous
**exposez une version modifiée en service réseau**, vous devez en proposer le source
correspondant à ses utilisateurs — pas seulement à ceux à qui vous distribuez un binaire.
C'est délibéré : Ocular est fait pour tourner en service.

    Copyright (C) 2026 guatx

    Ce programme est un logiciel libre : vous pouvez le redistribuer et/ou le
    modifier selon les termes de la GNU Affero General Public License telle que
    publiée par la Free Software Foundation, soit la version 3 de la licence,
    soit (à votre choix) toute version ultérieure.

    Ce programme est distribué dans l'espoir qu'il sera utile, mais SANS AUCUNE
    GARANTIE, sans même la garantie implicite de QUALITÉ MARCHANDE ou
    D'ADÉQUATION À UN USAGE PARTICULIER. Voir la GNU Affero General Public
    License pour plus de détails.

    Vous devriez avoir reçu une copie de la GNU Affero General Public License
    avec ce programme. Si ce n'est pas le cas, voir <https://www.gnu.org/licenses/>.

Texte intégral : [`COPYING`](COPYING).

Les composants tiers embarqués (noVNC sous MPL-2.0, pako sous MIT) restent sous **leur
propre licence** — voir [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
