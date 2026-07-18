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
Un processus qui **échappe au bac à sable Firefox**, ou une dépendance compromise, peut ouvrir des **sockets bruts** (le seccomp autorise `socket`/`connect`, nécessaires au navigateur) et joindre directement metadata/RFC1918 — **sans passer par le garde**. De plus, le conteneur de **capture batch** tourne sur le **bridge Docker par défaut**, et chaque conteneur de **session** tourne sur un réseau docker **dédié, éphémère et non `internal`** (`ocular-sess-net-{id}`, créé au lancement de la session et détruit à son teardown).

**⚠️ Conséquence directe sur l'écriture des règles.** Le sous-réseau d'un réseau de session est **alloué dynamiquement** par le pool d'adresses de Docker et le bridge hôte porte un nom volatil (`br-<hash>`) : **il n'existe aucun sous-réseau ni aucune interface stable à épingler pour le tier interactif**. Une règle écrite contre le sous-réseau d'un réseau nommé (l'ancien `ocular-sessions`) ou contre un `br-…` observé un jour donné **cesse silencieusement de couvrir les sessions** — le contrôle CRITIQUE dégénère alors en no-op, précisément sur la surface qui rend des pages hostiles.

Le périmètre stable, c'est **la ou les bases de `default-address-pools`** que vous fixez en §2.3 : tout réseau de session est, par construction, alloué **à l'intérieur** de ces bases. **Écrivez les règles contre les bases du pool, jamais contre un sous-réseau de réseau nommé.**

**À faire (choisir au moins un) :**
- Règles `DOCKER-USER` (iptables/nftables) **DROP** en sortie **des bases du pool d'adresses Docker** (`default-address-pools`, cf. §2.3) vers `169.254.0.0/16`, `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`, `fe80::/10`, multicast, et — en réseau IPv6/DNS64/NAT64 — le préfixe NAT64 `64:ff9b::/96` (+ `64:ff9b:1::/48`) qui traduit vers l'IPv4 interne. *(Le garde applicatif rejette déjà ces formes NAT64/IPv4-embedding depuis 2026-07-18 ; la règle L3 reste la défense en profondeur pour un canal hors-garde.)*

  > **`127.0.0.0/8` n'a rien à faire ici.** Le loopback n'est **jamais** forwardé : un
  > paquet à destination de `127/8` ne traverse pas `FORWARD`, donc pas `DOCKER-USER`.
  > Une ligne `-d 127.0.0.0/8` y est **inopérante** — la poser donne l'illusion d'une
  > protection qui n'existe pas. Le loopback du conteneur est déjà traité côté code
  > (prefs navigateur, §1) ; le loopback de l'**hôte** est protégé par `route_localnet=0`
  > (défaut) et par l'absence de port publié (§1), pas par `DOCKER-USER`.

  #### Trois règles de rédaction, à respecter dans cet ordre
  1. **Les exceptions se posent en `RETURN`, JAMAIS en `ACCEPT`.** Un `-j ACCEPT` dans
     `DOCKER-USER` **termine la traversée de `FORWARD`** : la chaîne
     `DOCKER-ISOLATION-STAGE-1/2`, qui est parcourue **après** `DOCKER-USER`, n'est
     alors plus jamais atteinte pour ce flux. C'est elle — et non les DROP ci-dessous —
     qui assure l'isolation session↔session, session→`broker`, session→`redis`. Un seul
     `ACCEPT` mal placé **rouvre silencieusement le pivot déclaré fermé en §2.3/§2.5**,
     sans qu'aucun test ni aucun log ne le signale. `RETURN` rend simplement la main à
     `FORWARD`, où `DOCKER-ISOLATION` continue de faire son travail.
  2. **`-I` insère en TÊTE de chaîne** : les règles s'installent dans l'**ordre inverse**
     du listing. L'ordre *voulu* dans la chaîne est **exceptions `RETURN` d'abord, DROP
     ensuite** — donc on tape les **DROP d'abord** et les **`RETURN` en dernier**.
     N'utilisez **pas** `-A` : Docker termine `DOCKER-USER` par un `-j RETURN`, une règle
     appendue atterrirait **après** lui et serait morte.
  3. **Une base ne se couvre pas elle-même sans exception intra-base.** Le conteneur
     `web` est attaché à **chaque** réseau de session (nécessaire au proxy noVNC
     `web`→`session:6080` et au pilotage `web`→`session:8090`, cf. §2.5) : `web` et
     session **partagent le sous-réseau de la session**, donc la même base de pool. Un
     `-s <base> -d <supra-réseau contenant la base>` matche ce trafic légitime et le
     **DROP** — la session interactive meurt (de façon intermittente : seulement pour
     les sessions allouées dans la base concernée). Ces règles n'étant **pas** à état,
     le trafic **retour** session→`web` est cassé de la même façon.

  Avec le pool d'exemple de §2.3 (`172.16.0.0/12` et `10.200.0.0/16`) :
  ```sh
  # --- 1) DROP (tapés en premier => finiront EN BAS de la chaîne) --------------
  # Base 1 du pool : 172.16.0.0/12  (couvre TOUT réseau de session qui y sera alloué)
  iptables -I DOCKER-USER -s 172.16.0.0/12 -d 169.254.0.0/16 -j DROP
  iptables -I DOCKER-USER -s 172.16.0.0/12 -d 10.0.0.0/8     -j DROP
  # NOTE: ligne ci-dessous INTÉGRALEMENT NEUTRALISÉE par l'exception intra-base
  # `-s 172.16.0.0/12 -d 172.16.0.0/12 -j RETURN` posée plus bas (même 5-tuple,
  # placée EN TÊTE de chaîne) : l'intra-base 172.16/12 N'EST PAS bloqué, et ne
  # doit pas l'être (web<->session). Conservée parce qu'elle redevient VIVE et
  # nécessaire dès que vous RESSERREZ la base (p.ex. base=172.20.0.0/14) : elle
  # couvre alors le reste de 172.16/12, qui n'est plus exempté par le RETURN.
  iptables -I DOCKER-USER -s 172.16.0.0/12 -d 172.16.0.0/12  -j DROP
  iptables -I DOCKER-USER -s 172.16.0.0/12 -d 192.168.0.0/16 -j DROP
  iptables -I DOCKER-USER -s 172.16.0.0/12 -d 100.64.0.0/10  -j DROP
  iptables -I DOCKER-USER -s 172.16.0.0/12 -d 224.0.0.0/4    -j DROP
  # Base 2 du pool : 10.200.0.0/16
  iptables -I DOCKER-USER -s 10.200.0.0/16 -d 169.254.0.0/16 -j DROP
  iptables -I DOCKER-USER -s 10.200.0.0/16 -d 10.0.0.0/8     -j DROP
  iptables -I DOCKER-USER -s 10.200.0.0/16 -d 172.16.0.0/12  -j DROP
  iptables -I DOCKER-USER -s 10.200.0.0/16 -d 192.168.0.0/16 -j DROP
  iptables -I DOCKER-USER -s 10.200.0.0/16 -d 100.64.0.0/10  -j DROP
  iptables -I DOCKER-USER -s 10.200.0.0/16 -d 224.0.0.0/4    -j DROP

  # --- 2) EXCEPTIONS intra-base (tapées en DERNIER => atterrissent EN TÊTE) ----
  # Trafic INTRA-pool (web <-> session sur le réseau dédié) — REQUIS, sinon le
  # proxy noVNC (:6080) et le pilotage de session (:8090) sont coupés.
  # RETURN (jamais ACCEPT) : rend la main à FORWARD, où DOCKER-ISOLATION-STAGE-1/2
  # continue d'isoler les réseaux de session entre eux.
  iptables -I DOCKER-USER -s 172.16.0.0/12 -d 172.16.0.0/12 -j RETURN
  iptables -I DOCKER-USER -s 10.200.0.0/16 -d 10.200.0.0/16 -j RETURN
  ```
  Vérifiez l'ordre obtenu avec `iptables -L DOCKER-USER -n --line-numbers` : les deux
  `RETURN` doivent apparaître **avant** les `DROP`.

  **Ce que ces exceptions n'affaiblissent pas.** Un `RETURN` intra-base laisse repartir
  le paquet dans `FORWARD`, où `DOCKER-ISOLATION-STAGE-1` le renvoie vers `STAGE-2` dès
  que le bridge d'**entrée** et celui de **sortie** diffèrent, et `STAGE-2` le **DROP**
  si la sortie est un bridge Docker. Conséquence : session A → session B, session →
  `broker`, session → `redis` restent bloqués (bridges disjoints) ; seul le trafic
  **sur le même bridge** — c'est-à-dire `web`↔sa session — passe. **L'isolation
  inter-sessions vient des bridges disjoints + `DOCKER-ISOLATION`, pas de ces DROP.**

  **Contrainte d'adressage à respecter.** L'exception intra-base exempte *toute* la
  base : elle n'est sûre que si la base du pool est **découpée dans de l'espace
  d'adressage qui n'héberge aucun service interne réel**. Ne réutilisez pas un préfixe
  de votre LAN comme base de pool — sinon une session pourrait joindre ce LAN via
  l'exception (le paquet sortirait par une interface non-Docker, donc hors du filet
  `DOCKER-ISOLATION`).

  **Si vous n'avez PAS personnalisé `default-address-pools`**, le pool **intégré** de
  Docker est `172.17.0.0/16` … `172.31.0.0/16` **plus `192.168.0.0/16` découpé en `/20`**
  (~31 réseaux **au mieux** — la capacité réellement allouable peut être bien moindre,
  cf. §2.3). Il faut alors couvrir **les deux** portions — un `-s` dérivé de la seule
  plage `172.x` **raterait entièrement `192.168.0.0/16`**, c'est-à-dire le no-op
  silencieux que toute cette section vise à éliminer :
  ```sh
  BASES=$(for i in $(seq 17 31); do echo 172.$i.0.0/16; done
          for j in $(seq 0 16 240); do echo 192.168.$j.0/20; done)
  for B in $BASES; do   # DROP d'abord
    for D in 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 224.0.0.0/4; do
      iptables -I DOCKER-USER -s "$B" -d "$D" -j DROP
    done
  done
  for B in $BASES; do   # puis les exceptions intra-base => en tête de chaîne
    iptables -I DOCKER-USER -s "$B" -d "$B" -j RETURN
  done
  ```
  Les exceptions portent ici sur chaque **base exacte** (`/16` ou `/20`), pas sur les
  agrégats `172.16.0.0/12` / `192.168.0.0/16` : n'exemptez **jamais** un agrégat plus
  large que le pool, il contiendrait votre LAN. C'est verbeux et fragile — d'où le
  prérequis ci-dessous.

  #### ⚠️ `DOCKER-USER` ne couvre PAS l'hôte lui-même — la surface `INPUT`

  Tout ce qui précède filtre la chaîne **`FORWARD`**. Or un conteneur de session joint
  l'hôte à l'**IP de passerelle de son propre bridge** (p.ex. `10.200.5.1`) : ce trafic
  est destiné à une adresse **locale de l'hôte**, donc **délivré localement** — il
  traverse la chaîne **`INPUT`** et **jamais `FORWARD`**. **Aucune règle `DOCKER-USER`
  ne peut le filtrer** : `DOCKER-USER` est une branche de `FORWARD`.

  **Conséquence, même avec §2.1 parfaitement appliquée :** tout service de l'hôte bindé
  sur `0.0.0.0` (Grafana, `node_exporter`, agent de supervision, runner CI, resolver
  local, socket d'admin…) **reste joignable depuis une session**, via l'IP de passerelle
  du bridge. La protection `127.0.0.0/8` documentée plus haut (`route_localnet=0`,
  aucun port publié) est exacte mais **ne couvre que le loopback** : elle **n'empêche
  pas** d'atteindre l'hôte sur son IP de passerelle. Ne la lisez pas comme une
  couverture complète de l'hôte.

  Le mécanisme ci-dessus est **validé empiriquement** (2026-07-18, netns jetable) :
  un `ctr → 10.200.5.1:9999` incrémente le compteur `INPUT` (4 paquets) et laisse
  `FORWARD` **et** `DOCKER-USER` à **0**. La prémisse de tout ce paragraphe est donc exacte.

  **À faire — fermer `INPUT` depuis les bridges de conteneurs :**
  ```sh
  # -I insère en TÊTE : on tape les DROP d'abord, les exceptions ENSUITE.
  # docker0 est OBLIGATOIRE, pas optionnel : `br+` ne le matche pas (voir ci-dessous).
  iptables -I INPUT -i br+     -j DROP
  iptables -I INPUT -i docker0 -j DROP

  # Exception conntrack — REQUISE, sinon vous cassez l'UI web d'Ocular (voir ci-dessous).
  iptables -I INPUT -i br+     -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -I INPUT -i docker0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ```
  Vérifiez l'ordre obtenu avec `iptables -vnL INPUT --line-numbers` : les deux `ACCEPT`
  conntrack doivent apparaître **avant** les deux `DROP`.

  > **🔴 L'exception conntrack n'est PAS facultative — sans elle la règle casse Ocular.**
  > Mesuré en netns jetable (2026-07-18). `-I INPUT` insère en **position 1**, donc
  > **avant** le `-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT` que la plupart
  > des distributions posent en tête d'`INPUT` : le DROP prend la main sur ce filet et
  > jette **tout le trafic retour** des connexions initiées par l'**hôte** vers un
  > conteneur. Ce trafic retour est délivré localement, donc il traverse `INPUT` en
  > entrant par le bridge — exactement comme le flux qu'on veut bloquer.
  >
  > Concrètement, avec le seul `-i br+ -j DROP` : `hôte → conteneur:8080` **casse**, et
  > surtout **`web` publie `8000:8000`** (cf. `deploy/docker-compose.yml`) — un
  > `curl http://127.0.0.1:8000` depuis l'hôte part en `OUTPUT`, est DNATé vers le
  > conteneur, et la **réponse** rentre par le bridge → `INPUT` → **DROP**. Reproduit :
  > l'UI web d'Ocular devient injoignable pour l'opérateur (timeout, pas d'erreur claire).
  > Avec l'exception conntrack : UI **OK**, et `conteneur → service hôte` reste **BLOQUÉ**
  > (il est en état `NEW`, donc non couvert par l'exception). **La garantie est intacte,
  > seul le faux positif disparaît.**

  Précisions **indispensables** avant de coller ça :
  - **Ici `ACCEPT` est correct — et ce n'est pas une entorse à la règle n°1.**
    L'interdiction du `-j ACCEPT` porte sur **`DOCKER-USER`**, où un `ACCEPT` termine la
    traversée de `FORWARD` et court-circuite `DOCKER-ISOLATION-STAGE-1/2`. La chaîne
    **`INPUT` n'a pas d'équivalent en aval** à préserver : `RETURN` y rendrait la main à
    la politique par défaut d'`INPUT`, ce qui n'est pas ce qu'on veut pour une exception.
    **`RETURN` dans `DOCKER-USER`, `ACCEPT` dans `INPUT`** — les deux chaînes ne se
    raisonnent pas pareil.
  - **`br+` ne matche PAS `docker0` — c'est un trou, pas un détail de confort.** Vérifié
    en netns : avec le seul `-i br+ -j DROP`, un conteneur attaché à `docker0` **joint
    toujours** le service hôte sur l'IP de passerelle. Or le tier **capture batch**
    d'Ocular tourne précisément sur le **bridge par défaut** `docker0` (§2.1, 1er §).
    Omettre `-i docker0`, c'est laisser hors couverture le tier qui rend des pages
    hostiles. Les deux lignes `docker0` ci-dessus sont **obligatoires**.
  - **`br+` matche *tout* bridge nommé `br…`**, y compris des bridges non-Docker de
    l'hôte (libvirt `br0`, ponts de VM…). Sur un hôte qui en héberge, visez les
    interfaces réellement concernées plutôt que le joker — le DROP y couperait aussi le
    **DHCP** (`udp/67`) et le DNS que ces VM prennent sur l'hôte.
  - **Cette règle ne casse ni le proxy noVNC ni le pilotage de session — vérifié.**
    `web`→`session:6080`/`:8090` est du trafic **conteneur↔conteneur** : la destination
    n'est pas une adresse locale de l'hôte, donc le paquet n'est **jamais** délivré
    localement et ne traverse **pas** `INPUT`. Mesuré en netns : `web`→`session:6080`
    reste **OK** avec le DROP seul comme avec l'exception conntrack. Idem `web`↔`redis`.
  - **L'ICMP echo conteneur→passerelle est bloqué** par la règle (c'est voulu). Les
    erreurs ICMP utiles au **PMTU** restent acceptées : elles sont en état `RELATED`,
    donc couvertes par l'exception conntrack.

  > **⚠️ Exception DNS `:53` — nécessaire BEAUCOUP moins souvent qu'on ne le croit.**
  > **Mesuré (2026-07-18) : en configuration Docker par défaut, elle n'est PAS
  > nécessaire, et l'ajouter par précaution élargit la surface pour rien.**
  >
  > Sur un réseau *user-defined* (donc tout réseau de session), le conteneur interroge le
  > resolver embarqué **`127.0.0.11`**, qui vit dans **son propre** namespace : ce trafic
  > ne traverse aucun bridge et n'est pas concerné par `INPUT`. La question est donc
  > uniquement : **d'où part la requête amont ?** Vérifié expérimentalement en
  > blackholant l'IP de passerelle **depuis le netns du conteneur lui-même**
  > (`ip route add blackhole <gw>/32`) : la résolution externe **continue de fonctionner**.
  > La requête amont ne part donc **pas** du conteneur — c'est `dockerd` qui la relaie
  > **depuis le namespace de l'hôte**. Le `/etc/resolv.conf` du conteneur l'annonce
  > explicitement : `# ExtServers: [host(192.168.1.1)]` — le marqueur **`host(...)`**
  > signifie « interrogé depuis l'hôte ».
  >
  > **Le critère exact, à lire dans le conteneur :**
  > ```sh
  > docker run --rm --network <votre_reseau> debian:bookworm-slim grep ExtServers /etc/resolv.conf
  > ```
  > - `ExtServers: [host(...)]` → relais **depuis l'hôte**, hors `INPUT` → **ne posez PAS
  >   l'exception `:53`**. (Contrôlé : c'est le cas en configuration Docker par défaut.)
  > - `ExtServers: [<ip nue>]` où l'IP est la **passerelle du bridge** ou une **IP de
  >   l'hôte** → la requête part **du conteneur** vers `INPUT` → **l'exception `:53` est
  >   requise**, sinon toute la résolution casse (échecs opaques : timeouts, pas d'erreur
  >   réseau claire). C'est le cas typique de `--dns <ip_passerelle>`, ou d'un resolver
  >   contrôlé de §2.2 hébergé sur l'hôte. Vérifié : forcer `--dns <passerelle>` produit
  >   bien une entrée **sans** marqueur `host(...)`.
  >
  > Si et seulement si vous êtes dans le second cas, ajoutez (après les DROP, donc
  > tapées en dernier pour atterrir en tête) :
  > ```sh
  > iptables -I INPUT -i br+ -p udp --dport 53 -j ACCEPT
  > iptables -I INPUT -i br+ -p tcp --dport 53 -j ACCEPT   # TCP : réponses tronquées
  > ```
  > Vérifié en netns : sans exception, `udp/53` vers la passerelle est bloqué ; avec,
  > `udp/53` et `tcp/53` passent tandis que `tcp/9999` reste bloqué. Une exception `:53`
  > reste bien plus étroite que l'exposition totale de l'hôte — mais **ne la posez pas
  > "au cas où"** : en configuration par défaut elle n'ouvre du port 53 vers l'hôte que
  > pour rien.

  **Si vous ne posez PAS cette règle, actez-le comme RÉSIDUEL CONNU :** *« une session
  compromise peut joindre tout service de l'hôte bindé sur `0.0.0.0` via l'IP de
  passerelle de son bridge ; §2.1 (`DOCKER-USER`) ne l'en empêche pas. »* La contre-mesure
  minimale sans règle `INPUT` est de **ne rien binder sur `0.0.0.0`** sur cet hôte
  (binder les services d'exploitation sur `127.0.0.1` ou sur une interface d'admin
  dédiée) — ce qui suppose de l'auditer, pas de le supposer.

  #### ⚠️ Ces exemples sont IPv4 UNIQUEMENT

  Tous les blocs ci-dessus utilisent **`iptables`**, donc ne filtrent **que l'IPv4** —
  alors que la liste des destinations à bloquer mentionne `fc00::/7`, `fe80::/10`, le
  multicast IPv6 et le préfixe NAT64 `64:ff9b::/96`. **Un opérateur qui copie-colle ces
  recettes sur un hôte où IPv6 est activé côté Docker obtient une couverture IPv4 seule**,
  sans le moindre avertissement — et l'IPv6 devient le chemin de contournement du
  contrôle CRITIQUE.

  **À faire — si IPv6 est activé sur le démon Docker** (`"ipv6": true`, `ip6tables`,
  ou fonctionnalités `experimental`) : **répliquer les mêmes règles via `ip6tables` sur
  `DOCKER-USER`**, avec :
  - pour `-s`, les **bases IPv6 de votre pool** — `default-address-pools` accepte aussi
    des bases IPv6 (p.ex. `{"base":"fd00:ocu::/48","size":64}`) ; **la règle de §2.3
    vaut à l'identique en IPv6** : déclarez-les explicitement, c'est le seul périmètre
    stable ;
  - pour `-d`, les destinations IPv6 déjà listées : `fc00::/7`, `fe80::/10`,
    `ff00::/8` (multicast), `64:ff9b::/96` et `64:ff9b:1::/48` (NAT64) ;
  - **la même logique `RETURN` intra-base** — exception `-s <base v6> -d <base v6> -j
    RETURN` posée **en tête**, **jamais `ACCEPT`** (règle de rédaction n°1 ci-dessus :
    un `ACCEPT` court-circuiterait `DOCKER-ISOLATION` exactement de la même manière
    en IPv6).

  La surface **`INPUT`** décrite juste au-dessus vaut elle aussi en IPv6 : l'équivalent
  `ip6tables -I INPUT -i br+ -j DROP` **et `-i docker0`**, **avec la même exception
  conntrack `ESTABLISHED,RELATED` en tête**, est nécessaire pour fermer l'accès à l'hôte
  via l'**IP de passerelle IPv6** du bridge. ⚠️ **Non validé empiriquement** : la
  campagne de tests du 2026-07-18 a porté sur **IPv4 uniquement**. Le raisonnement est le
  même (l'IP de passerelle IPv6 est une adresse locale de l'hôte, donc livraison locale
  → `INPUT`), mais **traitez-le comme non vérifié** et mesurez-le sur votre hôte avant de
  vous appuyer dessus. En IPv6 il faut en outre **conserver `ipv6-icmp`** (NDP :
  sollicitations/annonces de voisin sont en état `NEW` et ne sont **pas** couvertes par
  l'exception conntrack — un DROP nu casserait la résolution d'adresse L2, ce qu'IPv4
  n'a pas comme problème puisque l'ARP ne traverse pas `iptables`).

  Si vous n'avez **pas** besoin d'IPv6 pour les conteneurs, le plus simple et le plus sûr
  reste de **le laisser désactivé** côté démon Docker — il n'y a alors pas de second jeu
  de règles à maintenir en cohérence.

  **En pratique, appliquer §2.1 fait de « fixer explicitement `default-address-pools`
  (§2.3) » un PRÉREQUIS**, pas une option : sans bases déclarées, vous n'avez aucune
  valeur stable et étroite à mettre derrière `-s`/`-d`.
- **ou** réseau `internal: true` + un unique **conteneur egress-proxy** (le garde en sidecar) détenant la seule interface externe → chokepoint L3.
- **ou** exécuter les runners dans un namespace réseau sans route vers l'interne.

**Lien §2.1 ↔ §2.3 : le pool que vous fixez en §2.3 EST le périmètre des règles ci-dessus.** Les deux réglages ne sont pas indépendants — modifier `default-address-pools` sans réécrire les `-s`/`-d` de `DOCKER-USER` remet le tier interactif hors périmètre, **et** invalide les exceptions intra-base (proxy noVNC coupé).

### 2.2 Egress DNS (HIGH)
Le garde résout **chaque** nom demandé (même ceux qu'il va bloquer) via le resolver du conteneur → une page hostile peut **exfiltrer par requêtes DNS** (`<données>.exfil.attaquant.com`) et sonder des noms internes, **même si le CONNECT TCP est ensuite refusé**.
**À faire :** restreindre le `:53` sortant à un resolver contrôlé (loguant/allowlistant), ou `--dns <resolver_contrôlé>` sur les runners. Non fermable en Python seul.

### 2.3 Isolation inter-sessions & VNC — ✅ FERMÉ DANS LE CODE (2026-07-18)
Chaque session interactive vit désormais sur son **propre réseau docker**
(`ocular-sess-net-{id}`), auquel le broker attache dynamiquement le conteneur
web. Deux sessions sont sur des réseaux **disjoints** : un conteneur de session
compromis ne peut plus joindre le `:6080` (websockify, sans auth propre) ni le
`:8090` d'un pair. Prouvé par `tests/test_session_isolation_integration.py`.

**PRÉREQUIS DE DÉPLOIEMENT — pool d'adresses Docker.** Chaque session consomme
un sous-réseau du pool d'adresses local. Le pool **intégré** de Docker (celui
qui s'applique quand `default-address-pools` n'est pas déclaré) est
`172.17.0.0/16` … `172.31.0.0/16` **plus `192.168.0.0/16` découpé en `/20`** —
soit **~31 réseaux** répartis sur **deux plages disjointes**.

**⚠️ Ce « ~31 » est un plafond théorique, pas la capacité réelle.** Docker
**écarte à l'allocation** tout `/20` du pool intégré qui **chevauche une route
déjà présente sur l'hôte** (observé : `192.168.0.0/20` sauté sur une machine
dont le LAN est en `192.168`). La capacité effective dépend donc du **plan
d'adressage de l'hôte** : sur un **LAN plat `192.168.0.0/16`**, la **totalité**
de la portion `192.168` est écartée et le pool intégré retombe à
**15 réseaux** (`172.17`…`172.31`) — soit **moins que `OCULAR_MAX_SESSIONS=25`**.
La note de dimensionnement « 25 sessions tiennent dans le pool par défaut » est
alors **fausse** : fixer explicitement `default-address-pools` devient
nécessaire **bien avant** 25 sessions. Vérifiez le nombre réel de réseaux
allouables sur **votre** hôte plutôt que de vous fier au plafond théorique.

Avec `OCULAR_MAX_SESSIONS` à 25, une charge soutenue peut **épuiser le pool**
(`docker network create` échoue, la session part en 504 — fail-safe mais
dégradé, et le broker logue `session network create failed … pool d'adresses
Docker épuisé ?`).

**À faire** : déclarer explicitement le pool dans `/etc/docker/daemon.json`,
par ex.
```json
{"default-address-pools":[{"base":"172.16.0.0/12","size":24},
                          {"base":"10.200.0.0/16","size":24}]}
```
(des `/24` donnent des centaines de réseaux). Redémarrer le démon Docker après
modification. Choisissez des bases dans de l'espace d'adressage **non utilisé
par votre réseau interne** (cf. la contrainte d'adressage de §2.1).

Abaisser `OCULAR_MAX_SESSIONS` est une réponse à la **tenue en charge**
uniquement : cela réduit la consommation de sous-réseaux, mais **ne définit
aucun périmètre L3** — ce n'est donc **pas** une alternative à la déclaration du
pool dès lors que §2.1 est appliquée.

**⚠️ Ce pool est aussi le périmètre du filtrage L3 de §2.1.** Les réseaux de
session étant éphémères et alloués dynamiquement, il n'y a **pas** de
sous-réseau stable à épingler : les bases que vous déclarez ici sont ce contre
quoi les règles `DOCKER-USER` doivent être écrites (`-s <base du pool>`, plus
l'exception intra-base `-s <base> -d <base> -j RETURN`). **Déclarer
`default-address-pools` est donc un PRÉREQUIS de §2.1**, pas une option de
confort. **À faire :** après toute modification de `default-address-pools`,
réécrire les règles de §2.1 — sinon les sessions sortent silencieusement du
périmètre du contrôle CRITIQUE, et l'exception qui maintient le proxy noVNC en
vie ne correspond plus à rien.

### 2.4 Redis (MEDIUM)
Redis n'a **pas d'authentification** (aujourd'hui protégé par la seule topologie : Redis n'est sur **aucun réseau de session** — il vit sur le réseau `default` du compose, et les sessions vivent chacune sur leur propre réseau dédié). **À faire :** poser `requirepass`/ACL et mettre le secret dans `REDIS_URL` (défense en profondeur des tokens/secrets au repos).

### 2.5 Co-tenance plan de contrôle (MEDIUM)
Depuis l'isolation réseau par session (2026-07-18), le résiduel se réduit au **seul `web`** :
- le **`broker`** n'est attaché à **aucun** réseau de session — il se contente de créer le réseau, d'y lancer le conteneur et d'y attacher le `web` via le socket Docker. Un conteneur de session compromis **ne peut donc plus le joindre du tout** : il sort du périmètre de risque de cette section.
- le **`web`** reste attaché à chaque réseau de session — c'est **nécessaire** au proxy interactif (relais RFB/noVNC vers `:6080`, pilotage `:8090`). Il est donc joignable depuis une session, protégé par l'auth Bearer ; toute future faille pré-auth deviendrait un pivot.

**À faire :** pare-feu session→`web:8000` ; ne pas exposer d'API du plan de contrôle au réseau de session au-delà du strict proxy.

### 2.6 Chaîne d'approvisionnement (MEDIUM)
Binaire Camoufox téléchargé au **build** sans vérification de checksum ; dépendances pip majoritairement non épinglées. **À faire :** épingler les versions + hashes, vérifier un checksum du binaire Camoufox. (Aucun téléchargement au **runtime** — vérifié.)

### 2.7 Option LLM d'explication (`POST /jobs/{id}/explain`) — OFF par défaut
Désarmée sauf `OCULAR_LLM_ENABLED=1` + `OCULAR_LLM_BASE_URL`. L'appel sortant (depuis `web`) passe par la garde egress (`validate_capture_url`/`resolve_allowed_ip`) et est **épinglé sur l'IP résolue** (anti DNS-rebinding, vérif TLS préservée) ; le résumé envoyé au LLM est une **whitelist** (verdict/triage/findings — jamais le HTML brut/artefacts). **Contraintes opérateur du pinning :** l'appel LLM **ne suit aucune redirection** et **ignore les proxies d'environnement** (`http_proxy`/`https_proxy`) — nécessaire pour que le pin tienne. Donc : un endpoint LLM qui répond par un 3xx, ou qui n'est joignable qu'à travers un proxy sortant, **ne fonctionnera pas** ; pointer `OCULAR_LLM_BASE_URL` directement sur l'hôte final. Un hôte interne (Ollama LAN) exige `OCULAR_LLM_ALLOW_INTERNAL=1` (lève le blocage RFC1918 **pour cet hôte seulement**).

---

## 3. Checklist de déploiement en réseau sensible

- [ ] `OCULAR_REQUIRE_EGRESS_GUARD=1` (refus fail-closed si garde off).
- [ ] Filtrage **egress L3** (DOCKER-USER DROP metadata+RFC1918, ou réseau `internal` + egress-proxy) — §2.1.
- [ ] Si §2.1 appliquée : **exception intra-base en `RETURN`** posée **en tête** de `DOCKER-USER` pour chaque base du pool (sinon proxy noVNC/pilotage coupés), et **aucun `-j ACCEPT`** dans `DOCKER-USER` (il court-circuiterait `DOCKER-ISOLATION`) — §2.1.
- [ ] **Surface `INPUT`** : `iptables -I INPUT -i br+ -j DROP` (+ `-i docker0`, + exception `:53` si les conteneurs résolvent via la passerelle) — `DOCKER-USER` **ne filtre pas** l'accès à l'hôte par l'IP de passerelle du bridge. Si non posée, **acter le résiduel** et vérifier qu'aucun service d'hôte n'est bindé sur `0.0.0.0` — §2.1.
- [ ] **IPv6** : soit **désactivé** côté démon Docker, soit **mêmes règles répliquées en `ip6tables`** (`DOCKER-USER` + `INPUT`, bases IPv6 du pool, exception intra-base en `RETURN`) — les recettes IPv4 seules laissent l'IPv6 ouvert — §2.1.
- [ ] **DNS** sortant restreint à un resolver contrôlé — §2.2.
- ~~**Isolation inter-sessions** (réseau par session / pare-feu)~~ — ✅ fermé dans le code (réseau docker par session), §2.3.
- [ ] **Pool d'adresses Docker** déclaré explicitement (`default-address-pools`) — **prérequis** de §2.1, et le seul périmètre L3 stable ; `OCULAR_MAX_SESSIONS` ne règle que la tenue en charge — §2.3.
- [ ] **Redis** avec `requirepass` — §2.4.
- [ ] `web` **jamais exposé en direct** : derrière un reverse-proxy authentifié qui strippe les en-têtes d'identité clients ; garder `OCULAR_TOKEN` comme filet ; pare-feu session→web — §2.5.
- [ ] Dépendances **épinglées** + checksum Camoufox — §2.6.
- [ ] Ne **jamais** poser `OCULAR_EGRESS_GUARD=0` en prod (réservé à l'analyse d'une cible interne de confiance en environnement isolé).
- [ ] Superviser les logs : tout `egress guard DÉSACTIVÉ` ou `egress blocked host=…` doit alerter.

---

## 4. Posture

La séparation de privilèges et le bac à sable process d'Ocular sont **solides** (pas d'injection de commande, seccomp strict, non-root, éphémère, analyse `--network none`). Le garde egress est **bien implémenté comme filtre HTTP/CONNECT** (anti-rebinding, blocage metadata/interne, canaux UDP fermés côté navigateur). **La couche à durcir au déploiement est le réseau L3** (§2) : c'est là, et non dans le code applicatif, que se joue la garantie « Ocular n'est pas un pivot » une fois posé dans un vrai réseau.
