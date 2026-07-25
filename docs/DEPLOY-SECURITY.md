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
  > surtout **le frontal `gateway` publie `8000:8000`** (cf. `deploy/docker-compose.yml`) — un
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

### 2.4 Redis (MEDIUM) — ⚠️ partiellement fermé (2026-07-18)
Redis n'a **toujours pas d'authentification PAR DÉFAUT** (protégé par la topologie : il n'est sur **aucun réseau de session** — il vit sur le réseau `default` du compose, et les sessions vivent chacune sur leur propre réseau dédié). Le conteneur est en revanche désormais **durci** (§2.8).

**Le mécanisme d'auth est câblé et testé, il ne reste qu'à poser le secret.** Une seule variable arme les deux extrémités d'un coup :

```bash
# dans deploy/.env (non versionné)
OCULAR_REDIS_PASSWORD=$(openssl rand -base64 32)
docker compose -f deploy/docker-compose.yml up -d
```

Le serveur reçoit `--requirepass "$OCULAR_REDIS_PASSWORD"` et `web`/`broker` lisent `redis://:${OCULAR_REDIS_PASSWORD:-}@redis:6379` — **la même variable**, donc les deux côtés ne peuvent pas diverger. Variable **vide** = comportement historique exact : `requirepass ""` désactive l'auth côté serveur, et `redis://:@redis:6379` est parsée par redis-py en `password=None` (aucun `AUTH` envoyé). **Vérifié live dans les deux sens** (sans mot de passe : `PING` → `PONG` ; avec : `PING` → `NOAUTH Authentication required`, et une session interactive complète passe de bout en bout).

**Résiduel assumé :** le défaut reste « pas d'auth » pour ne pas casser les déploiements existants au `docker compose up`. En réseau sensible, **poser la variable** — c'est une commande, sans édition du compose.

### 2.5 Co-tenance plan de contrôle (MEDIUM)
Depuis l'isolation réseau par session (2026-07-18), le résiduel se réduit au **seul `web`** :
- le **`broker`** n'est attaché à **aucun** réseau de session — il se contente de créer le réseau, d'y lancer le conteneur et d'y attacher le `web` via le socket Docker. Un conteneur de session compromis **ne peut donc plus le joindre du tout** : il sort du périmètre de risque de cette section.
- le **`web`** reste attaché à chaque réseau de session — c'est **nécessaire** au proxy interactif (relais RFB/noVNC vers `:6080`, pilotage `:8090`). Il est donc joignable depuis une session, protégé par l'auth Bearer ; toute future faille pré-auth deviendrait un pivot.

**À faire :** pare-feu session→`web:8000` ; ne pas exposer d'API du plan de contrôle au réseau de session au-delà du strict proxy.

### 2.6 Chaîne d'approvisionnement (MEDIUM)
Binaire Camoufox téléchargé au **build** sans vérification de checksum ; dépendances pip majoritairement non épinglées (bornes `>=`, plancher seulement). (Aucun téléchargement au **runtime** — vérifié.)

**État actuel (partiellement adressé) :**

- **Checksum Camoufox — hook opt-in fail-loud livré.** `runner_recon/Dockerfile` calcule après `camoufox fetch` un sha256 agrégé reproductible de l'arborescence fetchée et l'**affiche toujours**. Le build-arg `CAMOUFOX_EXPECTED_SHA256` (vide par défaut) l'active :
  - **fourni** → vérification ; tout écart **fait échouer le build** (`exit 1`, jamais `|| true`) ;
  - **vide** → build non bloqué mais **AVERTISSEMENT** explicite « binaire NON VÉRIFIÉ » (jamais silencieux).
  - *Procédure d'épinglage :* faire un build de référence, relever la ligne `camoufox: sha256 arborescence fetchée = <hash>`, l'auditer, puis rebuild avec `--build-arg CAMOUFOX_EXPECTED_SHA256=<hash>` (idéalement en CI). `runner_recon_vnc` réutilise cette couche (image `FROM` recon) — un seul point à épingler.

- **Base du runner d'analyse épinglée par digest.** `runner_analysis/Dockerfile` est `FROM
  mcr.microsoft.com/playwright/python:vX.Y.Z-jammy@sha256:…`. Le digest garantit l'immuabilité,
  mais il **ne bouge jamais tout seul** : Dependabot propose une montée de *tag*, pas de digest sur
  un tag figé. *Procédure de re-bump (à faire à chaque correctif de sécurité de la base) :*
  1. relever le nouveau digest — `docker buildx imagetools inspect mcr.microsoft.com/playwright/python:<tag>` ;
  2. remplacer `@sha256:…` dans `runner_analysis/Dockerfile` ;
  3. si le **tag** change aussi, aligner la version `playwright==` du Dockerfile sur celle de la
     base (les binaires navigateurs de l'image doivent correspondre à la version du paquet) ;
  4. `make test` puis `make test-int` (le test d'image build et fait naviguer réellement le
     conteneur sous durcissement complet) avant de déployer.

**Reste À faire (opérateur) :** épingler les dépendances pip avec **hashes** via un lockfile (`pip-compile --generate-hashes` de pip-tools, ou `uv lock`) et installer avec `pip install --require-hashes`. Non introduit par défaut pour ne pas ajouter silencieusement un outil de résolution au build (cf. TODO dans `pyproject.toml`).

### 2.7 Option LLM d'explication (`POST /jobs/{id}/explain`) — OFF par défaut
Désarmée sauf `OCULAR_LLM_ENABLED=1` + `OCULAR_LLM_BASE_URL`. L'appel sortant (depuis `web`) passe par la garde egress (`validate_capture_url`/`resolve_allowed_ip`) et est **épinglé sur l'IP résolue** (anti DNS-rebinding, vérif TLS préservée) ; le résumé envoyé au LLM est une **whitelist** (verdict/triage/findings — jamais le HTML brut/artefacts). **Contraintes opérateur du pinning :** l'appel LLM **ne suit aucune redirection** et **ignore les proxies d'environnement** (`http_proxy`/`https_proxy`) — nécessaire pour que le pin tienne. Donc : un endpoint LLM qui répond par un 3xx, ou qui n'est joignable qu'à travers un proxy sortant, **ne fonctionnera pas** ; pointer `OCULAR_LLM_BASE_URL` directement sur l'hôte final. Un hôte interne (Ollama LAN) exige `OCULAR_LLM_ALLOW_INTERNAL=1` (lève le blocage RFC1918 **pour cet hôte seulement**).

### 2.8 Durcissement des conteneurs du plan de contrôle — ✅ FERMÉ DANS LE CODE (2026-07-18)

**Constat d'audit.** Seul le `web` était durci. Le **`broker` n'avait aucun** des quatre flags — il tournait **root**, rootfs inscriptible, **toutes capabilities** — **alors que c'est lui, et lui seul, qui monte `/var/run/docker.sock`**. `redis` non plus. La posture était donc inversée : le tier le plus privilégié était le moins contraint.

**Ce qui est appliqué dans `deploy/docker-compose.yml`** — les trois services (`web`, `broker`, `redis`) portent désormais :

| | `read_only` | `tmpfs` | `cap_drop: ALL` | `no-new-privileges` | `user:` non-root |
|---|---|---|---|---|---|
| `web` | ✅ | `/tmp` | ✅ | ✅ | `10002:10002` |
| `broker` | ✅ | `/tmp` | ✅ | ✅ | `10002:10002` + `group_add` |
| `redis` | ✅ | `/data:mode=1777` | ✅ | ✅ | `999:999` |

**⚠️ Ce que ça ne fait PAS — à lire avant de cocher quoi que ce soit.** Quiconque atteint le socket Docker peut lancer `docker run -v /:/host --privileged` et devenir **root sur l'hôte**. Ces flags **ne ferment pas** ce chemin : seul le retrait du socket le fermerait, et le broker ne peut pas fonctionner sans. Ils ferment les **étapes intermédiaires** d'une RCE dans le broker — implant persistant sur le rootfs, escalade via binaire SUID, abus de capability — et suppriment l'incohérence de posture. **Le socket Docker monté reste le risque structurel n°1 de la stack** ; le vrai correctif serait un proxy de socket filtrant (type `docker-socket-proxy`) restreignant les verbes autorisés, non fait à ce jour.

**GID du socket Docker — action opérateur REQUISE.** Le broker étant non-root, il obtient l'accès au socket (`srw-rw---- root:docker`) via `group_add`. Ce GID est **spécifique à l'hôte** — un GID en dur casserait l'accès Docker, donc toutes les sessions interactives, sur la plupart des machines. Il est donc paramétré, avec `999` (Debian/Ubuntu standard) pour défaut :

```bash
stat -c '%g' /var/run/docker.sock      # ex. 965
echo "OCULAR_DOCKER_GID=965" >> deploy/.env
```

En cas de mauvaise valeur, **l'échec est bruyant et sans risque de sécurité** : le broker perd le socket et les sessions échouent — il ne repasse pas root.

**Note `redis` — changement de comportement assumé.** Redis n'a jamais eu de volume : sa RDB s'écrivait sur le rootfs du conteneur (perdue à chaque recréation, conservée sur simple `restart`). Elle vit désormais sur un **tmpfs**, donc **en RAM** : les sessions ne survivent plus à un `restart` du conteneur redis. C'est délibéré — Redis porte les **secrets de session en clair**, qui n'ont pas à toucher le disque. Le `mode=1777` du tmpfs est **obligatoire** (redis tourne en uid 999, un tmpfs Docker est root:root 0755 par défaut) : sans lui, la première sauvegarde échoue et redis bascule en `MISCONF`, **refusant tout write** quelques minutes après le démarrage. Gardé par `tests/test_deploy_images.py`.

### 2.9 Exposition réseau de l'API — ✅ DÉFAUT SÛR (2026-07-18)

`ports: ["8000:8000"]` écoutait implicitement sur `0.0.0.0` : **toute l'API** (`/sessions`, proxy noVNC) était joignable depuis n'importe quel poste du LAN, protégée par un **unique Bearer statique**, sans rotation ni rate-limit — en contradiction directe avec le modèle du §1, qui suppose un reverse-proxy authentifiant en amont.

Le bind par défaut est désormais la **loopback** : `${OCULAR_BIND:-127.0.0.1}:8000:8000`. Exposer reste possible mais devient un **acte explicite** :

```bash
OCULAR_BIND=0.0.0.0   # dans deploy/.env — UNIQUEMENT derrière un reverse-proxy authentifiant
```

**Résiduel inchangé :** le Bearer statique reste sans rotation ni rate-limit. La loopback ne remplace pas le reverse-proxy du §2.5 — elle évite juste que l'omission de celui-ci expose l'API à tout le LAN.

**Où vit ce port (2026-07-18, correctif `rc=52`).** La publication a été **déplacée du `web` vers un frontal TCP dédié `gateway`** (nginx `stream`, `deploy/gateway.conf`) ; le `web` ne publie plus **aucun** port. Ce n'est pas cosmétique : le broker attache/détache le `web` d'un réseau **par session** (`docker network connect`), et Docker **reprogramme la publication de ports d'un conteneur à chaque changement de ses réseaux** — il tue et respawn le `docker-proxy`, **coupant toute connexion en vol** (`curl rc=52`, zéro octet de réponse). `POST /sessions` tenant sa connexion ~8-10 s pendant `_wait_session_ready`, il se faisait décapiter par son **propre** lancement de session (~4 échecs sur 6 mesurés), alors que la session **était créée** → `session_id` perdu et fuite jusqu'au TTL (un conteneur ~4 g et un sous-réseau du pool immobilisés). Le frontal n'étant **jamais** re-câblé, son `docker-proxy` n'est jamais reprogrammé. La propriété de bind loopback ci-dessus est **inchangée**, simplement portée par `gateway`. Gardé par `tests/test_deploy_images.py::test_compose_web_publishes_no_port` et `::test_compose_gateway_never_joins_a_dynamic_network`. **À jour 2026-07-19** : `POST /sessions` ne tient plus sa connexion pendant le démarrage — il répond **202** en < 1 s et le client sonde `GET /sessions/{id}` (cf. README). La fenêtre de décapitation décrite ci-dessus n'existe donc plus côté requête, et un `session_id` n'est plus perdable : le client le détient avant tout démarrage de conteneur. Le frontal `gateway` reste **indispensable** pour autant — le proxy noVNC `/sessions/{id}/ws` est, lui, une connexion **longue** que la reprogrammation de ports décapiterait tout autant.

**Conséquence à connaître :** l'API voit désormais l'IP du frontal comme IP cliente (le log `session create ... client_ip=`). En déploiement nominal — derrière le reverse-proxy authentifiant du §2.5 — cette IP était **déjà** celle du proxy amont ; la perte d'information ne concerne donc que l'accès direct en loopback.

### 2.10 Plafonds de taille du résultat (anti-OOM) — ✅ FERMÉ DANS LE CODE

Tout ce qui compose un `OcularResult` est dicté par la **page analysée**, donc par l'attaquant, et traverse ensuite le broker (`mem_limit 1g`), Redis **sur tmpfs — donc la RAM de l'hôte** (§2.8) puis SQLite. Les plafonds sont des **choix d'exploitation** : réglables, avec un défaut sûr.

Trois familles, parce que **borner la cardinalité ne borne rien** : une page n'a pas besoin d'émettre beaucoup d'entrées, il lui suffit d'en émettre **une seule énorme** (un `console.log` de 20 Mio produisait un résultat de 20,0 Mio qui s'annonçait *complet*).

**(a) Cardinalité** — combien d'éléments sont conservés.

| Variable | Défaut | Ce qui se passe au dépassement |
|---|---|---|
| `OCULAR_MAX_NETWORK_ENTRIES` | `5000` | Entrées réseau **suivantes rejetées** (tier batch : on garde les premières, la chaîne de chargement initiale documente la page). Tier **interactif** : fenêtre **glissante**, on garde les plus RÉCENTES — la capture y est armée une fois pour toute la session et l'analyste pilote la page pour déclencher l'exfiltration, qui arrive donc en fin de session. Compté dans `truncation.network_dropped`. |
| `OCULAR_MAX_CONSOLE_ENTRIES` | `5000` | Idem -> `truncation.console_dropped`. |
| `OCULAR_MAX_FINDINGS` | `5000` | Détections statiques **suivantes rejetées** -> `truncation.findings_dropped`. Appliqué **là où la liste est produite et mise en mémo** (`_analyze_dom`), pas seulement à la réponse : appliqué à la réponse seule, il bornait ce que l'analyste voit sans borner ce que le conteneur RETIENT (mesuré, DOM hostile de 512 Kio : 32 768 détections produites, 5 000 rendues, **32 768 retenues** dans le mémo de session, qui survit tant que le DOM ne change pas). |

**(b) Taille de chaque champ, en OCTETS UTF-8** — appliqués à l'insertion (`NetworkCapture`) *et* dans `ResultBuilder.build`, par un **point de coupe unique** (`_clip_field`) qui coupe **et** nomme le champ coupé dans le même appel.

L'unité est l'octet et non le caractère : un plafond en caractères laisse passer 2 à 4× le budget annoncé selon l'encodage. Le chemin rapide de la coupe se trompait d'ailleurs de sens — il concluait « sous le cap en caractères, donc sous le cap en octets », alors qu'un caractère vaut de 1 à 4 octets. Mesuré aux défauts publiés précédents : un `post_data` de 8 000 « é » (16 000 octets) était conservé **entier** pour un plafond annoncé à 8 192 — ×2,0 — et rendu avec « non coupé », donc même pas compté.

**Les valeurs ci-dessous sont calibrées sur une distribution MESURÉE**, pas sur une intuition. 34 335 URL réellement émises par 1 437 pages réelles : p50 = 39 o, p99 = 110 o, p99,9 = 126 o, p99,99 = 9 639 o, max = 12 703 o — toute la queue est faite d'URI `data:` (images inline, que Playwright rapporte **entières** dans `request.url`). À 4 096 o, 8 de ces URL réelles étaient coupées ; à 16 384 o, zéro. Les anciens défauts coupaient 5 contenus légitimes sur 10 mesurés (redirect SAML, URI `data:`, `id_token` OIDC chargé de groupes AD, trace de pile SPA, dump JSON d'API en console).

**Contre-mesure sur un corpus plus large** (24 009 fichiers HTML réels, 23 644 pages porteuses d'au moins une URL, 1 531 962 URL, mêmes attributs) : p50 = 45 o, p95 = 89 o, p99 = 113 o, p99,9 = 139 o, p99,99 = 210 o, **max = 242 002 o**. Le corps de la distribution concorde, la **queue non** : à 16 384 o, **110** de ces 1 531 962 URL sont coupées, et **99 le sont encore à 32 768 o** (0,0065 %). « Zéro coupée » est une propriété du corpus qui l'a mesuré, pas du plafond : la queue est faite d'URI `data:` dont la taille est celle de l'image inline, donc **aucun plafond par entrée ne la vide**. C'est ce qui justifie le budget **cumulé** ci-dessous plutôt qu'un plafond par entrée toujours plus haut.

| Variable | Défaut | Champ borné |
|---|---|---|
| `OCULAR_MAX_ARTIFACT_BYTES` | `33554432` (32 Mio) | Screenshot hors-cap **ignoré** (un PNG tronqué serait invalide) ; DOM **tronqué**. Seule variable de cette page à accepter `0` = illimité (cf. l'avertissement plus bas). |
| `OCULAR_MAX_POST_DATA_BYTES` | `32768` (32 Kio) | `network[].post_data`. Borné par `POST_DATA_MAX_CHARS` (65536), le plafond du modèle. |
| `OCULAR_MAX_URL_BYTES` | `32768` (32 Kio) | `network[].url`. ~2× la plus grande URL réelle connue (16 030 o, une image inline). |
| `OCULAR_MAX_HEADERS_BYTES` | `8192` (8 Kio) | `network[].headers`, budget **global** du dict (clés + valeurs). **Inchangé faute de mesure** : aucun producteur ne remplit ce champ aujourd'hui, donc aucune distribution réelle n'est observable. |
| `OCULAR_MAX_CONSOLE_TEXT_BYTES` | `32768` (32 Kio) | `console[].text`. Dimensionné sur 2 observations d'**exécution** (trace de pile SPA ~9,6 Kio, dump JSON d'API ~17,4 Kio) : la sortie console n'est pas bornée par la taille du source, donc compter les appels `console.*` du code ne donne qu'une borne basse. Extrapolation à partir de 2 points, dite comme telle. |
| `OCULAR_MAX_TITLE_BYTES` | `32768` (32 Kio) | `dom.title` et `dom.final_url` (`document.title = 'x'.repeat(1e7)`) ; `final_url` suit la distribution des URL ci-dessus. |

**(b ter) Budget CUMULÉ du tampon de session** — parce qu'un plafond **par entrée** ne borne jamais leur **somme**.

| Variable | Défaut | Ce qui se passe au dépassement |
|---|---|---|
| `OCULAR_MAX_CAPTURE_BUFFER_BYTES` | `33554432` (32 Mio) **par tampon** (réseau et console en ont chacun un) | Des entrées **entières** sortent du tampon : les plus **anciennes** en tier interactif (`keep="last"`, la preuve tardive est celle qu'on cherche), la **nouvelle** en tier batch (`keep="first"`). Compté dans `truncation.network_dropped` / `console_dropped`, comme le plafond de cardinalité. Borne haute `134217728` (128 Mio). |

Ce que ça coûtait de ne pas l'avoir, **mesuré** par le haut-de-marque **noyau** (`ru_maxrss`, tampons remplis via les vrais listeners de `NetworkCapture.attach`, 5 000 requêtes + 5 000 messages console au plafond, **trois exécutions par ligne**) :

| Configuration | Texte retenu | `ru_maxrss` |
|---|---|---|
| plafonds par entrée à `4096`/`8192`/`8192` (avant leur relèvement) | 97,7 Mio | 31 -> 153 Mio |
| plafonds par entrée à `32768` (les actuels), **sans** budget cumulé | 468,8 Mio | 31 -> 503-505 Mio |
| plafonds par entrée à `32768`, **avec** budget cumulé (défaut) | 63,9 Mio | 31 -> 96-97 Mio |

Relever les plafonds par entrée pour ne plus couper de contenu légitime avait donc multiplié par **4,8** la mémoire que la page dicte au conteneur de session — qui tourne à `--memory 2g` **partagé avec Camoufox** — et ce coût n'avait pas été mesuré. Le budget cumulé le ramène **sous** le point de départ **sans rendre le plafond par entrée à 4 Kio** : les deux régressions se referment ensemble. Le tampon vit toute la **session** (le délestage du résultat, lui, n'a lieu qu'au `/capture`), c'est donc bien là qu'il fallait borner.

Calibration du défaut, sur le **sous-ensemble requête** du corpus réel (`src`/`srcset`/`poster`/`data`, `href` d'un `<link>`, `action` d'un `<form>` — un `<a href>` est une **navigation**, pas une requête, et le compter surestimerait le tampon) : **266 142 URL de requête sur 23 137 pages réelles**, p50 = 180 o par page, p99 = 1 340 o, p99,9 = 1 630 o, **max = 6 205 374 o.** (87 requêtes, dont des URI `data:` de 242 002 o). 32 Mio = **5,4×** la page réelle la plus lourde du corpus, et **aucune** page réelle n'atteint le plafond de cardinalité (max mesuré : 87 requêtes). Ce corpus ne mesure **pas** le texte console (il n'est pas lisible dans le HTML source) : côté console, c'est une **borne d'exploitation**, pas une calibration — et c'est dit comme tel.

Toute coupe de (b) est comptée dans `truncation.text_truncated` — nombre de **champs** coupés, pas d'entrées — **et nommée sur l'entrée elle-même** dans `truncated_fields` (`url`, `post_data`, `headers`, `text`, `title`, `final_url`). Le compteur global répond à « ce résultat est-il complet ? » ; il ne désigne aucune ligne. `post_data_truncated` reste servi pour les payloads déjà stockés, mais il est désormais **dérivé** de `truncated_fields`, réconcilié dans les deux sens par le modèle. L'UI affiche un badge « ✂ coupé » sur la ligne réseau et la ligne console concernées.

**(b bis) Fenêtre d'analyse statique** — le balayage de `engine.static` ne regarde pas plus de `OCULAR_MAX_ANALYZED_HTML_CHARS` caractères (défaut **524 288**). L'unité est le **caractère** et non l'octet, parce que ce budget borne un coût **CPU** (le moteur d'expressions régulières balaye les caractères d'une chaîne déjà en mémoire), pas une empreinte mémoire — annoncer des octets ici serait annoncer la mauvaise grandeur. Ce qui n'a pas été regardé est compté dans `truncation.html_chars_dropped` : ce n'est ni de la preuve absente ni un champ coupé, c'est une zone du document où **aucune détection n'a été cherchée**, et sans ce compteur un verdict « benign » sur un document partiellement analysé serait indiscernable d'un verdict « benign » sur un document lu en entier.

**Ce que cette fenêtre COÛTE, mesuré.** Le corpus qui a calibré les motifs (`engine/static.py`, 1 437 fichiers dont 10 échantillons malveillants) ne contient **aucun** document assez gros pour que la fenêtre morde : il ne dit donc rien du prix de la fenêtre. Mesure faite sur la population qui la dépasse réellement (24 009 fichiers HTML réels de la machine de mesure ; balayage complet vs balayage fenêtré, à détections comparées) :

- **100 fichiers sur 24 009 dépassent la fenêtre** — 0,42 %, taux confirmé indépendamment ;
- sur ces 100, **7 perdent des détections**. Pire cas : `trace_viewer_full.html` (`/usr/lib/go/src/internal/trace/traceviewer/static/`), **31 détections vues sur 376 réelles — 91,8 % perdues** ; puis −28, −27, −27 sur des documentations Clang/OpenVDB ;
- un fichier passe de **4 détections à ZÉRO** (`/usr/share/doc/cmake/html/genindex.html`) : le verdict est calculé sur ce que l'analyse a **vu**, donc un document dont toutes les détections vivent au-delà de la fenêtre est rendu « benign ».

**Ce que l'analyste doit faire quand le bandeau apparaît.** `truncation.html_chars_dropped > 0` (bandeau « … caractères de page non analysés ») veut dire que le **verdict porte sur un préfixe du document**, pas sur le document. Un « benign » n'y est pas un acquittement. Deux issues : rejouer l'analyse avec `OCULAR_MAX_ANALYZED_HTML_CHARS` relevé (borne haute `16 777 216` ; le coût CPU croît linéairement avec la fenêtre, cf. le plafond en millisecondes ci-dessous), ou récupérer l'artefact DOM et l'analyser hors fenêtre. Sans bandeau, la question ne se pose pas : le document a été balayé en entier.

Cette fenêtre est ce qui donne un **plafond en millisecondes** ; les motifs à quantificateurs bornés (garantis par `_compile_bounded`, qui refuse à l'import tout motif non borné) donnent la linéarité, la fenêtre donne la valeur absolue. Mesuré sur la machine de développement, chemin complet, sur une batterie de 65 formes hostiles **dérivées des motifs eux-mêmes**, chacune répétée jusqu'au plafond : pire cas **572 à 784 ms selon la charge de la machine** (deux exécutions), contre 5,0 s de timeout de lecture interne. La même batterie à 4 Mio donne le même ordre de grandeur (704 ms) — au-delà de la fenêtre, agrandir le document ne coûte plus rien. Ces chiffres sont une **mesure sur une machine**, pas une garantie universelle : `tests/test_static_bounded.py` les rejoue à chaque exécution de la suite et échoue si le pire cas franchit 5,0 s. Coût sur contenu légitime inchangé (1 437 fichiers réels, A/B entrelacé : −0,4 %), détections **identiques** (même empreinte SHA-256 sur 2 386 détections).

**(c) Budget MESURÉ du résultat sérialisé** — parce que (a) et (b) bornent le *texte*, pas le *JSON*. `json.dumps` échappe un octet de contrôle en `\u00XX`, soit **×6**. Aucune arithmétique de plafonds ne tient cette promesse ; une mesure suivie d'un délestage, si.

Le pré-élagage qui précède ce délestage doit lui-même **mesurer le coût sérialisé, champ par champ**. Compté sur le texte brut et en ignorant `headers`, il laissait passer un résultat très au-dessus du plafond, et la garde anti-OOM matérialisait alors le JSON complet pour le découvrir. Mesuré par le haut-de-marque **noyau** (`ru_maxrss` — un échantillonneur en Python est affamé par le GIL pendant `json.dumps`, ce qui masque précisément le pic recherché) : sur un résultat dont la masse est dans les en-têtes, surcoût propre à la garde **1 416 Mio -> 32 Mio**, dans un conteneur à `--memory 2g` partagé avec Chromium.

| Variable | Défaut | Ce qui se passe au dépassement |
|---|---|---|
| `OCULAR_MAX_RESULT_JSON_BYTES` | `33554432` (32 Mio) | `build()` **mesure** le résultat sérialisé et délester **toutes** ses listes de volume variable — celles que le MODÈLE déclare délestables, pas une liste écrite à la main — jusqu'à repasser sous le plafond, en comptant tout dans `truncation`. |
| `OCULAR_MAX_INTERNAL_CAPTURE_BYTES` | `134217728` (128 Mio) | Réponse `/capture` du `session_server` **refusée** -> `502`. Doit rester au-dessus du pire cas, qui est **borné par construction** : budget du résultat + part des blobs = 33 554 432 + 89 478 488 = **123 032 920 o. (117,3 Mio)**, plus l'enveloppe JSON (deux réfs `sha256:` et les accolades). Mesuré par dichotomie sur le plus grand résultat que le délestage **ne touche pas** : 33 436 468 o. de résultat -> payload **122 915 349 o. (117,22 Mio)**, soit **10,78 Mio de marge**. |
| `OCULAR_MAX_LIVE_JSON_BYTES` | `8388608` (8 Mio) | Le `session_server` **mesure** sa réponse `/live` et délester les fenêtres affichées jusqu'à repasser dessous, en comptant tout dans `truncation`. Borne haute `32 Mio`, **ramenée** sous le plafond de lecture si la configuration l'y fait passer (cf. propriété 3). |
| `OCULAR_MAX_INTERNAL_JSON_BYTES` | `16777216` (16 Mio) | Réponse `/live` **refusée** -> `502`. L'écart avec `OCULAR_MAX_LIVE_JSON_BYTES` interdit le refus permanent, et il est désormais **garanti** par `engine.limits.resolve` (cf. propriété 3), pas seulement recommandé. |

**Ce qui est garanti, et par quelle mesure.** Après `ResultBuilder.build`, `len(json.dumps(result))` ≤ `OCULAR_MAX_RESULT_JSON_BYTES` **ou** le dépassement résiduel est porté dans `truncation.over_cap_bytes` et journalisé : la garde ne rend jamais un résultat hors plafond qui s'annonce complet. Vérifié sur des entrées adverses (octets nuls en console, en `post_data`, tous les champs au plafond) par `tests/test_result_size_limits_adverse.py`, et **champ par champ pour toutes les listes délestables** par `tests/test_result_bounds_derived.py`. Le maillon suivant est vérifié de la même façon (cf. le pire cas du tableau ci-dessus).

**Le délestage est DÉRIVÉ DU MODÈLE, plus jamais d'une liste écrite à la main.** Il portait sur trois noms (`network`, `console`, `static_findings`) et ratait `dom.forms` / `dom.mailtos`, que les quatre tiers remplissent **depuis le contenu de la page** (via `static.extract_forms`/`extract_mailtos`). Mesuré avec `OCULAR_MAX_RESULT_JSON_BYTES=262144` — valeur **dans** les bornes publiées : résultat de **725 493 o.** (×2,8 le plafond), `truncation` à **zéro**, donc annoncé **complet**, sans le moindre WARNING. Désormais chaque champ du modèle porte une **déclaration de nature** (`engine.result.FIELD_VOLUME` : délesté / coupé / protégé / borné par construction / résiduel), le délestage parcourt les champs déclarés délestables, et **un champ de volume variable non déclaré fait échouer l'import d'`engine.result`** — donc la suite entière. Un champ ajouté demain ne peut plus être oublié : il est couvert, ou il ne s'exécute pas.

**Ce qui n'est PAS garanti.** Les champs ci-dessous ne sont ni coupés ni délestés — soit qu'ils portent une preuve qu'on refuse d'amputer (`screenshots`, journal `dynamic_steps`, décomposition `triage.signals`, marqueurs de coupe eux-mêmes), soit qu'aucun producteur n'y verse aujourd'hui de contenu de page. Si de la masse y arrive, le résultat le **dit** (`truncation.over_cap_bytes` + `résultat encore à N octets après délestage complet`) au lieu de s'annoncer complet. **Cette liste est DÉRIVÉE du modèle** (`engine.result.residual_paths()`) et un test échoue si elle diverge de ce fichier — la version écrite à la main omettait `dom.forms` et `dom.mailtos` :

<!-- residual-paths: dérivé de engine.result.residual_paths(), vérifié par tests/test_result_bounds_derived.py -->
`dom.truncated_fields` · `dynamic_steps` · `dynamic_steps[].error` · `screenshots` · `stealth.challenge` · `triage.signals`

De même, `OCULAR_MAX_ARTIFACT_BYTES=0` (« illimité ») rend les blobs non bornés et peut donc repousser `/capture` au-delà de son plafond de lecture : c'est un choix d'exploitation explicite, pas un défaut.

Trois propriétés à ne pas régresser :

1. **Jamais de troncature muette — au niveau du RÉSULTAT *et* de l'ENTRÉE.** Tout résultat amputé porte `OcularResult.truncation` (compteurs à 0 = complet) et le runner journalise `résultat tronqué …` (message **dérivé du modèle**, pour qu'un compteur ajouté ne puisse pas disparaître du journal). Et toute entrée dont un champ a été coupé le **nomme** dans `truncated_fields` : le compteur global ne désigne aucune ligne, si bien qu'une URL amputée avait exactement l'apparence d'une URL entière — sur une balise GET de kit de phishing, ce qui disparaît est la fin de la query string, c'est-à-dire la pièce à conviction. Il n'existe qu'**un** endroit où un champ d'entrée est coupé (`_clip_field`), et il pose le marqueur dans le même appel. Le tier interactif expose le **même marqueur** dans la réponse `/live`, **toujours présent** (y compris à zéro : un marqueur qui n'apparaît qu'en cas de coupe force le client à distinguer « complet » de « ne sait pas »), et `counts` y reste le compte **total** émis depuis le début de la session, tampon borné ou non.

   **Le marqueur doit ATTEINDRE quelqu'un**, sans quoi il ne ferme rien : le `WARNING` du runner part sur **stderr**, que le broker capture puis **jette** quand le job réussit (stderr n'est lu qu'en cas d'échec). Deux canaux sont donc câblés et testés — le broker journalise `résultat tronqué à la réception job_id=…` au moment où il lit le résultat (pour l'exploitant), et l'UI affiche un bandeau « Résultat incomplet : … » en tête de la vue détail **et** du panneau live (pour l'analyste). Un résultat complet ne produit ni bandeau ni journal.
2. **Fail-closed sur la lecture** — une réponse interne hors plafond est une **erreur** rendue à l'appelant, jamais un corps coupé re-parsé comme s'il était complet.
3. **Un plafond ne doit jamais devenir un refus permanent** — c'est la contrepartie de (2). Les bornes de (a)/(b)/(b ter)/(c) sont posées **à la source**, de sorte que la réponse interne ne dépasse pas le plafond de lecture ; sans cela, le fail-closed transforme un dépassement en `502` à chaque appel pour le restant de la session, depuis le contenu analysé. L'invariant est donc : **plafond de lecture ≥ budget de la source + part réservée**, et il est vérifié **DANS LES DEUX SENS**, en un seul endroit (`engine.limits.resolve`, appelé par les deux côtés du réseau : il n'existe pas de chemin qui lise l'une des variables sans confronter les autres).

   **La correction porte sur TOUS les termes, blobs compris.** Corriger la seule source ne peut pas rétablir la fonction quand la part réservée aux blobs dépasse à elle seule le plafond de lecture : la source était alors ramenée à **1 octet** — mesuré avec `OCULAR_MAX_INTERNAL_CAPTURE_BYTES=67108864` (64 Mio, valeur **dans** les bornes) : blobs 89 478 488 o. > lecture 67 108 864 o., budget de la source **1**, payload `/capture` 89 479 705 o. pour un plafond de 67 108 864 -> `502` **permanent**, pendant que le WARNING affirmait que sans correction « la fonction resterait inaccessible », donc qu'avec elle, non. `resolve` corrige maintenant **aussi** `OCULAR_MAX_ARTIFACT_BYTES` (ramené à 25 141 248 o. dans ce cas : tout screenshot plus gros est **ignoré**, le DOM **tronqué**), et `_max_artifact_bytes` lit cette valeur corrigée. Re-mesuré dans la même configuration, mêmes charges : payload 67 044 595 o. ≤ 67 108 864 -> `/capture` **répond**, avec ces pertes-là, et le WARNING les nomme. Le budget de la source a par ailleurs un **plancher** (`65536` o. ; socle mesuré d'un résultat sans aucune entrée : 867 o. à vide, 1 361 o. avec identité complète, un screenshot et `stealth`) : sous ce plancher la réponse n'aurait plus de valeur de preuve, donc le plafond de LECTURE de `/capture` ne peut pas descendre en dessous (`65544` o. plancher, part d'un blob minimal comprise) — toute valeur inférieure est ramenée **et journalisée**.

Il n'était gardé que d'un côté : baisser le plafond de lecture était signalé, **relever le budget de la source ne l'était pas** — et le code SANCTIONNAIT des valeurs qui brisent son propre invariant, la borne haute autorisée pour `OCULAR_MAX_LIVE_JSON_BYTES` (32 Mio) valant **deux fois** le plafond de lecture par défaut (16 Mio). Mesuré avec cette valeur pourtant acceptée : corps `/live` de 23,45 Mio, `truncation` à **zéro** (donc annoncé complet), `502` à chaque poll, **zéro WARNING**. Même asymétrie côté `/capture`, où tout `OCULAR_MAX_RESULT_JSON_BYTES` au-dessus de ~42,7 Mio cassait la fonction sans signal, alors que la borne haute autorisée était 128 Mio.

Une configuration qui brise l'invariant est maintenant **corrigée explicitement et journalisée**, jamais approuvée en silence. La correction porte toujours sur la **source** : produire moins ne peut pas rendre une réponse illisible, tandis que relever le plafond de lecture augmenterait la mémoire que la page analysée peut faire consommer au web puis à Redis. La part que les blobs base64 prennent dans le plafond de lecture de `/capture` est comptée dans le calcul (`2 × cap_artefact × 4/3`) ; avec `OCULAR_MAX_ARTIFACT_BYTES=0` elle n'est pas calculable, ce qui est journalisé plutôt que deviné. Le broker propage les plafonds de lecture au conteneur de session, sans quoi celui-ci réconcilierait contre le défaut du web au lieu de sa valeur réelle.

**Les plafonds se baissent, ils ne se retirent pas** — et cette phrase est désormais appliquée, pas seulement écrite. Chaque variable de (a), (b), (b bis), (b ter) et (c) a une **borne haute** : `20000` entrées, `65536` octets par champ, `16 777 216` caractères de fenêtre d'analyse, `134 217 728` octets de tampon cumulé par famille d'entrées, `32 Mio` pour `OCULAR_MAX_LIVE_JSON_BYTES` (borne omise des éditions précédentes de ce tableau — c'était la seule dont le maximum autorisé valait 2× le plafond de lecture qu'elle doit respecter), `128 Mio` de résultat, `512 Mio` de lecture interne : `OCULAR_MAX_NETWORK_ENTRIES=999999999999` était auparavant accepté tel quel, donc le plafond était supprimé de fait. Aucune de ces variables n'accepte « `0` = illimité » — **seul** `OCULAR_MAX_ARTIFACT_BYTES` suit cette convention, et transposer l'habitude donne ici l'inverse de l'intention (`0` était ramené à `1`, soit **une seule** entrée conservée). Toute valeur illisible ou hors bornes est **journalisée en WARNING** avec la valeur retenue, jamais substituée en silence — **une fois par processus** : émis à chaque lecture, ce WARNING voyait son volume dicté par le trafic de la page analysée (les plafonds par entrée sont relus à chaque requête et à chaque message console ; mesuré : 2 000 requêtes de page -> 4 000 lignes identiques, sur le cas même que le WARNING doit signaler).

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
- [ ] **Redis** avec `requirepass` : poser `OCULAR_REDIS_PASSWORD` dans `deploy/.env` (mécanisme câblé, défaut = pas d'auth) — §2.4.
- [ ] **`OCULAR_DOCKER_GID`** posé à la valeur réelle de l'hôte (`stat -c '%g' /var/run/docker.sock`) — sinon le broker perd le socket et **toutes les sessions interactives échouent** — §2.8.
- [ ] **`OCULAR_BIND`** laissé sur la loopback, sauf reverse-proxy authentifiant en amont — §2.9.
- ~~**Plafonds de taille du résultat**~~ — ✅ fermé dans le code (défauts sûrs, §2.10). À ne réviser que si un tier manque de mémoire ; ne **jamais** tenter de les dé-plafonner.
- ~~**Durcissement des conteneurs du plan de contrôle** (`read_only`/`cap_drop`/`no-new-privileges`/non-root)~~ — ✅ fermé dans le code, §2.8. **Ne ferme PAS** l'évasion via le socket Docker (§2.8), seulement ses étapes intermédiaires.
- [ ] `web` **jamais exposé en direct** : derrière un reverse-proxy authentifié qui strippe les en-têtes d'identité clients ; garder `OCULAR_TOKEN` comme filet ; pare-feu session→web — §2.5.
- [ ] Dépendances **épinglées** + checksum Camoufox — §2.6.
- [ ] Ne **jamais** poser `OCULAR_EGRESS_GUARD=0` en prod (réservé à l'analyse d'une cible interne de confiance en environnement isolé).
- [ ] Superviser les logs : tout `egress guard DÉSACTIVÉ` ou `egress blocked host=…` doit alerter.

---

## 4. Posture

La séparation de privilèges et le bac à sable process d'Ocular sont **solides** (pas d'injection de commande, seccomp strict, non-root, éphémère, analyse `--network none`). Depuis 2026-07-18, les **trois conteneurs du plan de contrôle** sont durcis de façon homogène (§2.8) — le `broker`, qui détient le socket Docker, n'est plus le tier le moins contraint de la stack. **Ce durcissement ne supprime pas le risque structurel du socket Docker monté** : il en ferme les étapes intermédiaires, pas la sortie vers l'hôte (§2.8). Le garde egress est **bien implémenté comme filtre HTTP/CONNECT** (anti-rebinding, blocage metadata/interne, canaux UDP fermés côté navigateur). **La couche à durcir au déploiement est le réseau L3** (§2) : c'est là, et non dans le code applicatif, que se joue la garantie « Ocular n'est pas un pivot » une fois posé dans un vrai réseau.
