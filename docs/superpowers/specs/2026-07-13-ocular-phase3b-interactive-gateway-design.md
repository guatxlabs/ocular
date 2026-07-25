# Ocular — Phase 3b : Gateway noVNC interactif durci — Design

- **Date** : 2026-07-13
- **Statut** : Approuvé (design), prêt pour plan
- **Base** : moteur mergé (analysis + capture + sauvegardes). Ajoute le **tier interactif** : l'analyste navigue à la main (URL live OU HTML hostile) via une passerelle **pixels-only**, le contenu malveillant ne touche jamais son navigateur. 3c (dynamique scripté) = suivant.

---

## 1. But & modèle de menace
Besoin SOC : cliquer manuellement dans un phishing multi-étapes / passer un captcha que la vision rate / capter les appels d'un site vivant. C'est **l'inverse exact de l'ancien bug** (noVNC en iframe sur l'origine analyste + pont clipboard + cert conteneur accepté par l'hôte). Le contenu est **hostile ET interactif ET réseau ON** → durcissement maximal.

## 2. Décisions figées
| # | Décision |
|---|---|
| B1 | Modèle **session** (conteneur persistant), distinct des jobs éphémères. Cibles : `{url}` (capture) OU `{html}` (analyse hostile). |
| B2 | Conteneur = **Camoufox headed + Xvfb + x11vnc + websockify + noVNC + serveur de session** persistant. Réseau ON (capter les appels), durci (non-root, cap-drop, seccomp-recon, --rm, limites), **JAMAIS** docker.sock/host-net. |
| B3 | **Clipboard coupé à la source** : `x11vnc -noclipboard -nosetclipboard` → aucun canal presse-papier, indépendamment du proxy. |
| B4 | VNC/noVNC du conteneur sur un **réseau docker interne** (`ocular-sessions`), **aucun port hôte**. Seul le **web** (sur ce réseau) l'atteint. |
| B5 | Le **web relaie** le websocket noVNC sur **son TLS + auth** ; l'analyste charge noVNC depuis l'**origine web** (pixels-only), jamais l'origine malveillante. |
| B6 | **Éphémère** : TTL + timeout d'inactivité → un reaper détruit ; `DELETE /sessions/{id}` explicite. |
| B7 | **Bouton Capturer** → snapshot → `OcularResult` (coule dans sauvegardes/résultats). |

## 3. Architecture

```
analyste ──WS(TLS,auth)──▶ [ web (gateway) ] ──WS interne──▶ [ conteneur session ]
  noVNC.js (origine web)     proxy pixels-only              Camoufox+Xvfb+x11vnc(noclip)
  POST/DELETE /sessions      (réseau ocular-sessions)        +websockify+noVNC+session_server
                                    │
                              [ broker ] ──docker──▶ lance/détruit le conteneur session
                              registre sessions (Redis) + reaper TTL/idle
```

### 3.1 Conteneur session (`runner_recon_vnc/`)
Dérivé de `runner_recon` + `x11vnc websockify novnc`. Entrypoint : Xvfb :99 → `x11vnc -display :99 -forever -shared -rfbport 5900 -noclipboard -nosetclipboard -localhost` → `websockify --web=/usr/share/novnc 6080 localhost:5900` → `exec python -m runner_recon_vnc.session_server`.
- `session_server.py` (FastAPI, in-container, port interne) : au démarrage lance Camoufox headed (garde le contexte vivant, arme la capture réseau via `engine.wrapper.NetworkCapture`) ; endpoints internes `POST /goto {url}`, `POST /load {html}`, `POST /capture` (→ wrapper `OcularResult` base64, comme capture.py), `GET /health`. **Écoute sur localhost du conteneur uniquement** ; noVNC (websockify:6080) est le seul point atteint par le web.
- Réseau ON (le contenu hostile peut appeler l'extérieur — c'est le but ; warning IP+hostile).

### 3.2 Broker — gestion des sessions
- `launch_session(session_id, target) -> None` : `docker run -d` (détaché, PAS `--rm -i`) sur le réseau `ocular-sessions`, `--name ocular-sess-{id}`, durci (non-root, cap-drop ALL, seccomp-recon, read-only+tmpfs, mem/pids, no docker.sock/host-net), **aucun `-p`** (pas de port hôte). Après démarrage, appelle le `session_server` du conteneur (`/goto` ou `/load`) via le réseau interne (le broker est-il sur `ocular-sessions` ? — non : le broker lance, le WEB parle au conteneur. Le premier `goto/load` est déclenché par le web au moment du POST /sessions, cf. 3.3). En fait : le broker lance juste le conteneur ; le **web** fait le `goto/load` + le proxy + le capture (le web est sur `ocular-sessions`).
- `stop_session(session_id)` : `docker kill/rm ocular-sess-{id}`.
- **Registre** : Redis `ocular:session:{id}` = `{container, target_kind, created_at, last_activity}` avec TTL. **Reaper** (thread/loop du broker) : toutes N s, détruit les conteneurs dont le TTL/idle est dépassé (et les entrées Redis).

### 3.3 Web — gateway
- `POST /sessions {url|html}` (auth) : valide (SSRF si url), demande au broker `launch_session`, attend le health du `session_server`, déclenche `goto/load`, enregistre la session (Redis), renvoie `{session_id}` (+ un **token de session** capability pour le WS). Warning IP/hostile.
- `WS /sessions/{id}/ws` : le web **proxy** le websocket entre l'analyste et `ws://ocular-sess-{id}:6080/websockify` (réseau interne). **Auth du WS** : Bearer via sous-protocole `Sec-WebSocket-Protocol` OU token de session capability (validé Redis) — car un WebSocket navigateur ne pose pas d'en-tête `Authorization`. Relaie les octets bruts (RFB) dans les deux sens. Met à jour `last_activity`.
- `POST /sessions/{id}/capture` (auth) : appelle le `session_server`/capture → wrapper → stocke artefacts + résultat léger (comme un job) → renvoie le résultat. `input_kind` = url/html selon la cible.
- `DELETE /sessions/{id}` (auth) : `stop_session` + purge Redis. `GET /sessions` : liste.
- Le web reste **sans Docker** (il parle réseau au conteneur + Redis ; le broker seul lance/détruit via socket).

### 3.4 UI — vue interactive
- noVNC client **embarqué localement** (`web/ui/vendor/novnc/` bundlé, servi par le web ; pas de CDN → CSP-compatible). Vue `interactive` : `POST /sessions` → connecte le canvas noVNC au `WS /sessions/{id}/ws` (via le token de session) → **pixels**. Boutons **Capturer** (→ `/capture`, affiche le résultat) et **Fermer** (→ `DELETE`). Bandeau **warning** (IP exposée, contenu hostile rendu dans le conteneur, pas ici).
- **CSP** : ajouter `connect-src 'self'` (WS same-origin) — le noVNC WS va vers l'origine web. Vérifier que la CSP autorise le WS same-origin (`connect-src 'self'` couvre ws/wss same-origin).

## 4. Sécurité (delta, purple team)
| Risque | Défense |
|---|---|
| Contenu malveillant s'exécute chez l'analyste | Rendu **uniquement** dans le conteneur ; analyste = **pixels** via noVNC depuis l'origine web |
| Pont presse-papier (l'ancien trou) | `x11vnc -noclipboard -nosetclipboard` → **aucun** canal clipboard |
| Accès direct au VNC du conteneur | VNC sur **réseau interne**, `-localhost`, aucun port hôte ; seul le web proxifie |
| Pollution de confiance TLS | TLS **du web** (le proxy), jamais un cert conteneur |
| WS non authentifié (session d'un autre) | Auth du WS (sous-protocole/capability token validé Redis) ; le token de session est lié au créateur |
| Escape conteneur (hostile+réseau+interaction) | non-root, cap-drop ALL, seccomp-recon (non-unconfined), read-only+tmpfs, mem/pids, pas de docker.sock/host-net, éphémère |
| Conteneurs orphelins / fuite de ressources | Reaper TTL + idle ; `DELETE` explicite ; `docker kill/rm` |
| SSRF (cible url) | `validate_capture_url` réutilisé au `POST /sessions` |
| IP exposée / contenu hostile réseau-ON | warning explicite (log + UI) ; proxy opt-in (`HTTP_PROXY`) hérité |
| DOM hostile capturé servi inline | le `/capture` produit un `OcularResult` (screenshots pixels + refs) servi avec les protections existantes (nosniff, DOM attachment) |

> **Différé (documenté)** : SSRF DNS-rebinding (egress filter runner) ; le HTML hostile en réseau-ON peut beaconer (inhérent à « capter les appels » — c'est le but, contenu par l'isolation conteneur).

## 5. Tests
- **Unit** : `build_session_args` (détaché, réseau interne, durci, pas de docker.sock/host-net, pas de `-p`) ; registre session Redis (create/get/touch/expire) ; reaper (session expirée → à détruire) ; auth WS (token invalide → refus) ; validation POST /sessions (url SSRF → 400, ni url ni html → 422) ; le `session_server` build_result (capture) réutilise `engine.wrapper`.
- **Intégration** : image `runner_recon_vnc` **build** ; démarrage → `session_server` health OK, noVNC (websockify) répond, `x11vnc` a bien `-noclipboard` (inspection du process/args) ; `POST /goto` + `/capture` → wrapper `OcularResult` valide.
- **e2e (revue finale)** : `POST /sessions {url}` → conteneur lancé sur réseau interne (pas de port hôte, `docker port` vide) → WS proxy transmet des octets RFB → `/capture` produit un résultat → `DELETE` détruit → reaper nettoie une session abandonnée. **Vérif clipboard OFF** : le process x11vnc n'a aucun bridge clipboard.

## 6. Ordre de livraison (une branche, SDD)
1. Image `runner_recon_vnc` (recon + x11vnc noclipboard + websockify + noVNC) + `session_server.py` (Camoufox persistant, /goto,/load,/capture,/health via `engine.wrapper`) + **build réel** (health + noVNC + clipboard-off vérifiés).
2. Registre session Redis (`bus/sessions.py` : create/get/touch/list/delete + TTL) + tests.
3. Broker : `launch_session`/`stop_session` (détaché, réseau interne, durci, pas de docker.sock/host-net/-p) + **reaper** TTL/idle + tests unit (args).
4. Réseau `ocular-sessions` (compose) : web + sessions le rejoignent ; web sans Docker.
5. Web : `POST /sessions` (valide+SSRF, launch, goto/load, token session) + `DELETE`/`GET` + auth ; tests.
6. Web : `WS /sessions/{id}/ws` proxy noVNC (auth WS, relais octets, touch last_activity) + tests (proxy/auth).
7. Web : `POST /sessions/{id}/capture` (→ session_server → wrapper → stocke → résultat) + tests.
8. UI : noVNC embarqué (`web/ui/vendor/novnc`) + vue interactive (connexion WS, Capturer, Fermer, warning) + CSP `connect-src 'self'` ; smoke + vérif navigateur.
9. Ops : Makefile (build image vnc), guard `test_deploy_images` (5e image), README (interactif + sécu).
10. **Audit indépendant** (3 auditeurs) + **e2e réel** (session live, clipboard-off, réseau interne, reaper) + merge.

## 7. Défauts assumés
Session TTL 30 min, idle 10 min, reaper toutes 60 s. Résolution noVNC 1280x720. noVNC embarqué (pas de CDN). Camoufox pour capture ET analyse (set_content pour HTML). WS auth = token de session capability (à défaut du sous-protocole si friction).
