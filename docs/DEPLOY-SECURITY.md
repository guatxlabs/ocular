# Ocular — Déploiement sûr & modèle de menace réseau

Ocular **rend des pages web potentiellement hostiles** dans un navigateur (Camoufox/Firefox) à l'intérieur de conteneurs éphémères. Déployé **dans un réseau client / entreprise / production**, il ne doit **jamais** devenir un pivot : une page hostile (ou un processus compromis via une faille du moteur de rendu) ne doit pas pouvoir atteindre les services internes (metadata cloud `169.254.169.254`, RFC1918 `10/8`·`172.16/12`·`192.168/16`, loopback, CGNAT `100.64/10`, ULA IPv6), ni les autres conteneurs, ni l'hôte.

Ce document distingue **ce qu'Ocular garantit dans son code** de **ce qui reste à la charge de l'opérateur** (couche réseau/L3) — synthèse de trois audits adversariaux (2026, complétude du garde egress · isolation conteneurs/réseau · egress hors-navigateur).

---

## 1. Ce qu'Ocular garantit dans le code (vérifié + testé)

**Garde egress applicatif** (`engine/egress_guard.py`) sur les deux tiers réseau-ON (capture batch, session interactive) :
- le navigateur est **forcé via un proxy local** (`127.0.0.1`) — Playwright `proxy=`.
- chaque connexion : résolution DNS → **épinglage de l'IP** → connexion à l'IP validée, **jamais de re-résolution** (défait le DNS-rebinding) → sinon `403`.
- **chaque redirection** est re-validée indépendamment ; le garde ne suit jamais les redirections lui-même.
- `is_global` + **rejet multicast** (`engine/ssrf.py`) : bloque metadata/RFC1918/loopback/link-local/CGNAT/ULA/réservé/multicast (IPv4 et IPv6).
- **fail-closed sur échec** : si le garde ne démarre pas, le navigateur n'est **pas** lancé en direct.

**Prefs navigateur durcies** (`engine/browser_prefs.py`, source unique partagée par les deux tiers) — ferment les canaux egress **hors du proxy TCP** :
- **WebRTC**, **QUIC/HTTP-3**, **WebTransport** désactivés (canaux UDP directs).
- **loopback forcé à travers le proxy** (`allow_hijacking_localhost`, `no_proxies_on=""`) → une page hostile ne peut plus atteindre `session_server:8090` / `x11vnc:5900` en local (le garde les 403).
- **résolution DNS spéculative coupée** (dns-prefetch, predictor, speculative-connect) → pas de canal DNS vers le resolver interne hors garde.
- DoH/TRR figé OFF ; télémétrie/update/Safe-Browsing/captive-portal/Normandy/push OFF (hygiène egress + anti-detect).

**Séparation de privilèges & durcissement conteneur :**
- `web` (FastAPI) **sans `docker.sock`** ; **seul le `broker`** parle à Docker.
- runners **éphémères**, `--cap-drop ALL`, `no-new-privileges`, **non-root**, **rootfs read-only**, tmpfs, `--pids-limit`, `--memory`.
- **seccomp = allowlist deny-défaut** (jamais `unconfined`) : `ptrace`/`bpf`/`unshare`/`setns`/`mount`/`keyctl`/`pivot_root`/`process_vm_*`/`userfaultfd`/`init_module` **bloqués**.
- profil **analyse HTML = `--network none`** (isolation réseau totale).
- **aucun port hôte publié** par les conteneurs de session (pas de `-p`) ; seul `web` publie `8000`.
- auth Bearer fail-closed + temps-constant ; proxy WebSocket qui valide le token **avant** `accept()` (token hors URL) ; secret par session à la frontière conteneur ; store d'artefacts **content-addressed** (anti-empoisonnement).

**Mode strict egress** (`OCULAR_REQUIRE_EGRESS_GUARD=1`) : le runner **REFUSE de démarrer** (fail-closed) si le garde est désactivé, au lieu de lancer un navigateur à egress direct. Un garde désactivé émet toujours un **WARNING bruyant**.

---

## 2. Résiduels à la charge de l'opérateur (couche réseau — INDISPENSABLE en réseau sensible)

Le garde egress agit **dans le navigateur**. Il ne contraint **pas** le trafic au niveau réseau. Les points suivants **ne peuvent pas** être fermés par le seul code d'Ocular — ils exigent des contrôles L3 au déploiement. **En réseau entreprise/prod, ils sont obligatoires.**

### 2.1 Filtrage egress L3 (CRITIQUE)
Un processus qui **échappe au bac à sable Firefox**, ou une dépendance compromise, peut ouvrir des **sockets bruts** (le seccomp autorise `socket`/`connect`, nécessaires au navigateur) et joindre directement metadata/RFC1918 — **sans passer par le garde**. De plus, le conteneur de **capture batch** tourne sur le **bridge Docker par défaut** et les conteneurs de **session** sur un réseau `ocular-sessions` **non `internal`**.

**À faire (choisir au moins un) :**
- Règles `DOCKER-USER` (iptables/nftables) **DROP** en sortie des réseaux runner vers `169.254.0.0/16`, `10/8`, `172.16/12`, `192.168/16`, `127/8`, `100.64/10`, `fc00::/7`, `fe80::/10`, multicast — **sauf** le strict nécessaire.
  ```
  iptables -I DOCKER-USER -s <subnet_runners> -d 169.254.0.0/16 -j DROP
  iptables -I DOCKER-USER -s <subnet_runners> -d 10.0.0.0/8      -j DROP
  iptables -I DOCKER-USER -s <subnet_runners> -d 172.16.0.0/12   -j DROP
  iptables -I DOCKER-USER -s <subnet_runners> -d 192.168.0.0/16  -j DROP
  ```
- **ou** réseau `internal: true` + un unique **conteneur egress-proxy** (le garde en sidecar) détenant la seule interface externe → chokepoint L3.
- **ou** exécuter les runners dans un namespace réseau sans route vers l'interne.

### 2.2 Egress DNS (HIGH)
Le garde résout **chaque** nom demandé (même ceux qu'il va bloquer) via le resolver du conteneur → une page hostile peut **exfiltrer par requêtes DNS** (`<données>.exfil.attaquant.com`) et sonder des noms internes, **même si le CONNECT TCP est ensuite refusé**.
**À faire :** restreindre le `:53` sortant à un resolver contrôlé (loguant/allowlistant), ou `--dns <resolver_contrôlé>` sur les runners. Non fermable en Python seul.

### 2.3 Isolation inter-sessions & VNC (HIGH)
Le serveur VNC (`x11vnc`) n'a **pas de mot de passe** et `websockify` écoute sur `0.0.0.0:6080` **dans le conteneur** ; tous les conteneurs de session partagent `ocular-sessions` **sans isolation mutuelle**. Le proxy `web` valide bien le token — mais un **conteneur de session compromis** pourrait scanner le sous-réseau et se connecter **directement** au `:6080` d'une autre session (vue + **injection clavier/souris** dans le Camoufox d'un autre analyste), en contournant `web`.
**À faire :** isoler les conteneurs de session entre eux au L3 (un réseau par session, ou pare-feu session↔session). **Suivi code recommandé** : mot de passe VNC par session (dérivé du secret de session).

### 2.4 Redis (MEDIUM)
Redis n'a **pas d'authentification** (aujourd'hui protégé par la seule topologie : Redis n'est pas sur `ocular-sessions`). **À faire :** poser `requirepass`/ACL et mettre le secret dans `REDIS_URL` (défense en profondeur des tokens/secrets au repos).

### 2.5 Co-tenance plan de contrôle (MEDIUM)
`web` (et actuellement le `broker`) sont joignables depuis `ocular-sessions`. `web` est protégé par l'auth Bearer, mais toute future faille pré-auth deviendrait un pivot. **À faire :** pare-feu session→`web:8000` ; ne pas exposer d'API du plan de contrôle au réseau de session au-delà du strict proxy.

### 2.6 Chaîne d'approvisionnement (MEDIUM)
Binaire Camoufox téléchargé au **build** sans vérification de checksum ; dépendances pip majoritairement non épinglées. **À faire :** épingler les versions + hashes, vérifier un checksum du binaire Camoufox. (Aucun téléchargement au **runtime** — vérifié.)

### 2.7 Option LLM d'explication (`POST /jobs/{id}/explain`) — OFF par défaut
Désarmée sauf `OCULAR_LLM_ENABLED=1` + `OCULAR_LLM_BASE_URL`. L'appel sortant (depuis `web`) passe par la garde egress (`validate_capture_url`/`resolve_allowed_ip`) et est **épinglé sur l'IP résolue** (anti DNS-rebinding, vérif TLS préservée) ; le résumé envoyé au LLM est une **whitelist** (verdict/triage/findings — jamais le HTML brut/artefacts). **Contraintes opérateur du pinning :** l'appel LLM **ne suit aucune redirection** et **ignore les proxies d'environnement** (`http_proxy`/`https_proxy`) — nécessaire pour que le pin tienne. Donc : un endpoint LLM qui répond par un 3xx, ou qui n'est joignable qu'à travers un proxy sortant, **ne fonctionnera pas** ; pointer `OCULAR_LLM_BASE_URL` directement sur l'hôte final. Un hôte interne (Ollama LAN) exige `OCULAR_LLM_ALLOW_INTERNAL=1` (lève le blocage RFC1918 **pour cet hôte seulement**).

---

## 3. Checklist de déploiement en réseau sensible

- [ ] `OCULAR_REQUIRE_EGRESS_GUARD=1` (refus fail-closed si garde off).
- [ ] Filtrage **egress L3** (DOCKER-USER DROP metadata+RFC1918, ou réseau `internal` + egress-proxy) — §2.1.
- [ ] **DNS** sortant restreint à un resolver contrôlé — §2.2.
- [ ] **Isolation inter-sessions** (réseau par session / pare-feu) — §2.3.
- [ ] **Redis** avec `requirepass` — §2.4.
- [ ] `web` **jamais exposé en direct** : derrière un reverse-proxy authentifié qui strippe les en-têtes d'identité clients ; garder `OCULAR_TOKEN` comme filet ; pare-feu session→web — §2.5.
- [ ] Dépendances **épinglées** + checksum Camoufox — §2.6.
- [ ] Ne **jamais** poser `OCULAR_EGRESS_GUARD=0` en prod (réservé à l'analyse d'une cible interne de confiance en environnement isolé).
- [ ] Superviser les logs : tout `egress guard DÉSACTIVÉ` ou `egress blocked host=…` doit alerter.

---

## 4. Posture

La séparation de privilèges et le bac à sable process d'Ocular sont **solides** (pas d'injection de commande, seccomp strict, non-root, éphémère, analyse `--network none`). Le garde egress est **bien implémenté comme filtre HTTP/CONNECT** (anti-rebinding, blocage metadata/interne, canaux UDP fermés côté navigateur). **La couche à durcir au déploiement est le réseau L3** (§2) : c'est là, et non dans le code applicatif, que se joue la garantie « Ocular n'est pas un pivot » une fois posé dans un vrai réseau.
