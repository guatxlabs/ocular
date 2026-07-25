# Ocular — Isolation réseau par session interactive — Design

- **Date** : 2026-07-18 · **Statut** : Approuvé (design), prêt pour plan.
- **Origine** : audit sécu holistique 2026-07-18 (résiduel « VNC-passwd par session »). Ferme le dernier résiduel connu du tier interactif.

## 1. Problème

Tous les conteneurs de session interactive **et** le web partagent le réseau docker `ocular-sessions`. `websockify`/`x11vnc` (port conteneur `6080`) n'a **pas d'authentification propre**. Les trois couches existantes protègent de l'**externe** mais pas du **conteneur-à-conteneur** :

1. auth du proxy WS côté web (token capability validé **avant** `accept()`),
2. `X-Session-Secret` sur les endpoints de contrôle (`/goto`, `/load`, `/capture`),
3. isolation réseau `ocular-sessions` (aucun port hôte publié).

**Résiduel** : un conteneur de session **compromis** peut joindre directement le `:6080` (ou `:8090`) d'un **pair** sur le même réseau et détourner son navigateur.

**Écarté : le VNC-passwd.** L'auth VNC est DES limitée à 8 caractères — cassable. Ce serait une **fausse sécurité**. Le vrai correctif est l'isolation réseau.

## 2. Décisions figées (validées)

| # | Décision |
|---|----------|
| N1 | **Un réseau bridge par session**, `ocular-sess-net-{session_id}` (miroir du conteneur `ocular-sess-{session_id}`). Chaque réseau ne contient que `{conteneur de session, web}`. |
| N2 | **Secure-by-default, sans flag** : toute session est isolée. Le chemin « réseau partagé » disparaît. |
| N3 | **Le broker attache dynamiquement le web** au réseau de chaque session (`docker network connect`), et l'en détache au teardown. Le web garde sa résolution **par DNS Docker** — donc **aucun changement de logique côté web**. |
| N4 | **PAS `--internal`** : la session a besoin d'egress recon. La garde egress applicative reste le filtre (inchangée). |
| N5 | **Tout le cycle de vie réseau est encapsulé dans `broker/sessions.py`** (`launch_session`/`stop_session`/`sweep_orphans`). `process_session_cmd`, `reap`, `bus/sessions.py`, `web/app.py` : **inchangés**. |
| N6 | **Pas de port hôte publié** — le principe actuel est préservé (l'alternative « ports sur `127.0.0.1`» a été écartée : elle déplace la surface vers l'hôte au lieu de la fermer). |

## 3. Architecture

```
AVANT                                  APRÈS
┌─ réseau ocular-sessions ─────┐       ┌─ ocular-sess-net-A ─┐  ┌─ ocular-sess-net-B ─┐
│  web   sessA   sessB   ...   │       │   web ── sessA      │  │   web ── sessB      │
│         ↕ sessA peut         │       └─────────────────────┘  └─────────────────────┘
│           joindre sessB:6080 │        sessA et sessB sont sur des réseaux DISJOINTS
└──────────────────────────────┘        -> aucune route entre elles
```
Le web est attaché aux **deux** réseaux (plus `default` pour Redis) ; les sessions ne se voient pas.

### 3.1 Ordre au lancement (dans `launch_session`)
1. `docker network create ocular-sess-net-{id}` — best-effort (si existe déjà → ignoré).
2. `docker run --network ocular-sess-net-{id} …` — le conteneur naît **directement** sur son réseau isolé.
3. `docker network connect ocular-sess-net-{id} <web>` — best-effort + warning si échec.
4. Retour de `launch_session`, **puis** `process_session_cmd` fait `registry.create(...)`.

**Pas de race** : le web est attaché **avant** que le registre expose la session. Quand `_wait_session_ready` démarre son poll, il résout `ocular-sess-{id}` par DNS Docker exactement comme aujourd'hui.

### 3.2 Ordre au teardown (dans `stop_session`)
1. `docker kill` + `docker rm -f` le conteneur — **libère le réseau**.
2. `docker network disconnect -f ocular-sess-net-{id} <web>` — best-effort.
3. `docker network rm ocular-sess-net-{id}` — best-effort.

L'ordre est contraignant : Docker refuse de supprimer un réseau encore utilisé. Tout est `check=False` (robuste au TOCTOU : conteneur/réseau déjà disparu), cohérent avec l'existant.

### 3.3 Identification du conteneur web
- `deploy/docker-compose.yml` : `container_name: ocular-web` sur le service web (nom déterministe ; sinon Docker génère `<projet>-web-1`).
- `ocular_settings.py` : `web_container()` lisant `OCULAR_WEB_CONTAINER` (défaut `ocular-web`), fourni au broker par le compose (`OCULAR_WEB_CONTAINER: "${OCULAR_WEB_CONTAINER:-ocular-web}"`).

### 3.4 Changements précis
- `broker/sessions.py` :
  - nouveau helper `_session_net(session_id) -> "ocular-sess-net-{id}"` (miroir de `_session_name`) ;
  - constante `_SESSION_NETWORK = "ocular-sessions"` **supprimée** ;
  - `build_session_args` : `--network` = `_session_net(session_id)` ;
  - `launch_session` : `network create` avant le run, `network connect <net> <web>` après. Signature et retour **inchangés** ;
  - `stop_session(container)` : dérive l'id du nom de conteneur → `disconnect -f` + `network rm` après le `rm -f`. Signature **inchangée** ;
  - `sweep_orphans(registry)` : après les conteneurs orphelins, balaie les **réseaux** `ocular-sess-net-*` sans session vivante (`docker network ls --filter name=ocular-sess-net- --format {{.Name}}` → pour chacun sans `registry.get(id)` : `disconnect -f` puis `network rm`). Garde-fou substring identique à celui des conteneurs ;
  - logs : `net=ocular-sess-net-{id}` (jamais de secret).
- `ocular_settings.py` : accessor `web_container()`.
- `deploy/docker-compose.yml` : `container_name: ocular-web` + `OCULAR_WEB_CONTAINER` sur le broker.
- Le réseau `ocular-sessions` **devient vestigial** (plus aucune session dessus). Laissé déclaré (web+broker y restent, inoffensif) pour ne rien casser ; suppression possible ultérieurement.

## 4. Robustesse & cas d'échec

- **Redémarrage du web** : recréé sans ses interfaces per-session → les sessions en cours deviennent injoignables → poll/WS échouent → le reaper les nettoie (idle/déconnexion). Acceptable (déjà le cas aujourd'hui : une session ne survit pas au redémarrage du plan de contrôle). Les réseaux laissés sont balayés au prochain démarrage broker.
- **Redémarrage/crash du broker, `compose down`** : `sweep_orphans` (déjà appelé au démarrage) nettoie désormais **conteneurs ET réseaux** orphelins. Ferme la fuite de réseaux.
- **Échec de `network connect <web>`** (web absent/pas prêt) : warning, `launch_session` retourne quand même → `_wait_session_ready` timeout → 504 → `stop` enqueue nettoie conteneur + réseau. Fail-safe, pas de fuite.
- **Échec de `network rm`** (TOCTOU, conteneur pas encore parti) : best-effort + filet `sweep_orphans`. Un réseau orphelin sans conteneur est inerte.
- **Pool de sous-réseaux Docker — prérequis de déploiement, pas une simple note.** Chaque réseau bridge consomme un sous-réseau du pool d'adresses local. Le pool **par défaut** de Docker (`default-address-pools` : base `172.17.0.0/12`, size `16`) ne fournit qu'une **poignée de réseaux `/16`** (ordre de grandeur : ~16, dont `docker0` et les réseaux compose). `OCULAR_MAX_SESSIONS` valant **25** par défaut, une charge soutenue **peut épuiser le pool** — `docker network create` échouerait alors, et la session partirait en 504 (fail-safe, mais dégradé).
  **Conséquence, à traiter dans l'implémentation** : (a) documenter dans `DEPLOY-SECURITY.md` l'élargissement du pool, ex. `{"default-address-pools":[{"base":"172.16.0.0/12","size":24},{"base":"10.200.0.0/16","size":24}]}` dans `/etc/docker/daemon.json` (des `/24` donnent des centaines de réseaux) ; (b) `launch_session` **logue explicitement** un warning distinctif si `network create` échoue, pour que l'épuisement du pool soit diagnosticable et non silencieux.
- **Concurrence** : plusieurs `launch` simultanés créent chacun leur réseau et attachent le web ; `docker network connect` est sûr en concurrence. Rien à sérialiser.

## 5. Tests

**Unitaires (sans Docker, espion sur `subprocess.run` — pattern existant `tests/test_broker_sessions.py`)**
1. `build_session_args("s1")` utilise `--network ocular-sess-net-s1` (**met à jour** l'assertion existante `test_broker_sessions.py:29` qui attend `ocular-sessions`).
2. `launch_session` émet la séquence **ordonnée** `network create` → `docker run` → `network connect <net> <web>` (l'ordre EST la garantie anti-race).
3. `launch_session` retourne le nom du conteneur et **ne lève pas** si `network connect` échoue.
4. `stop_session("ocular-sess-s1")` émet `kill` → `rm -f` → `network disconnect -f` → `network rm` **dans cet ordre**.
5. `sweep_orphans` supprime un réseau sans session vivante, **épargne** celui d'une session vivante, et applique le garde-fou substring.
6. `web_container()` : défaut `ocular-web` + surcharge `OCULAR_WEB_CONTAINER`.
7. `launch_session` logue un warning **distinctif** quand `network create` échoue (diagnostic de l'épuisement du pool d'adresses, cf. §4).

**Intégration (marqué `integration`, Docker requis) — preuve de la propriété sécu**

7. Lancer **deux** sessions réelles ; depuis le conteneur A, tenter de joindre `:6080` et `:8090` du conteneur B → **doit échouer** (nom non résolvable / connexion refusée) ; le **web joint les deux**. C'est le scénario exact de l'audit — sans ce test, la propriété n'est pas prouvée.

**Non-régression** : la suite existante (create/capture/live/ws/reaper, `test_reaper_e2e`, `test_web_sessions`) reste verte **sans modification** — signal que l'encapsulation dans les 3 fonctions launcher n'a rien cassé.

**Validation finale** : `make test` (Dockerisé) + `make test-int` pour le test d'intégration, puis vérification e2e réelle (session interactive : noVNC s'affiche, capture fonctionne).

## 6. Ce qui n'est PAS fait (YAGNI)

- Pas de VNC-passwd (fausse sécurité, cf. §1).
- Pas de flag d'activation (secure-by-default, décision N2).
- Le nom du réseau n'est **pas** stocké au registre (dérivable de l'id).
- Suppression du réseau `ocular-sessions` du compose : différée (vestigial mais inoffensif).
- Pas de pool de réseaux pré-créés (complexité d'allocation sans gain).
