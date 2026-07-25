# Politique de sécurité — Ocular

## Signaler une vulnérabilité

**Ne pas ouvrir d'issue publique** pour une vulnérabilité. Utiliser le
signalement privé de la forge (*Security advisories*), ou le contact indiqué
dans les métadonnées du dépôt.

Merci d'inclure : la version ou le commit, le mode de déploiement (compose,
natif), une reproduction minimale, et l'impact que vous estimez.

## Ce qu'est Ocular, et ce que cela implique

Ocular **charge et exécute du contenu web hostile** : c'est sa fonction. La
sécurité du projet ne consiste donc pas à éviter le contenu malveillant, mais à
le confiner.

Toute vulnérabilité permettant à une **page analysée** de s'échapper de son
conteneur, d'atteindre le plan de contrôle, ou de faire émettre au moteur des
requêtes non prévues (SSRF), est considérée comme **critique**.

## Modèle de menace — ce qui est défendu

- **Séparation des privilèges** : le service `web` n'a **pas** accès au socket
  Docker. Seul le `broker` l'a. Une compromission du web ne donne pas le
  lancement de conteneurs.
- **Confinement des runners** : conteneurs éphémères, non-root, `cap_drop: ALL`,
  `no-new-privileges`, rootfs en lecture seule, seccomp, et `--network none`
  pour les profils sans réseau.
- **Isolation réseau par session** : chaque session interactive reçoit son
  propre réseau Docker. Une session ne peut pas joindre une autre session.
- **Garde SSRF / egress** : les URL sont résolues puis **épinglées** à l'IP
  résolue avant connexion, sans nouvelle résolution — ce qui ferme le
  DNS-rebinding. Les plages non routables et internes sont refusées, NAT64
  compris.
- **Appartenance des sessions** : en mode identité, une session n'est
  accessible qu'à son propriétaire. La session d'autrui et un identifiant
  inexistant renvoient **le même 404**, pour ne pas créer d'oracle d'existence.

## Limites connues — assumées, non masquées

Les points suivants sont des propriétés **connues** du design. Les signaler
n'apporte rien de nouveau ; les documenter honnêtement évite un faux sentiment
de sécurité.

- **Le `broker` monte le socket Docker.** Il est durci (non-root, `cap_drop:
  ALL`, `no-new-privileges`, rootfs en lecture seule), mais ce durcissement
  ferme les **étapes intermédiaires** d'une exploitation, pas le pouvoir que
  confère le socket lui-même. Qui exécute du code dans le broker peut obtenir
  l'hôte. C'est inhérent : le broker ne peut pas lancer de conteneurs sans ce
  socket.
- **L'authentification Redis est câblée mais désactivée par défaut**, pour ne
  pas casser les déploiements existants. Redis porte les **secrets de session en
  clair**. L'activer est une ligne dans `deploy/.env`. En déploiement partagé,
  l'activer.
- **L'API écoute sur la loopback par défaut.** L'exposer est un acte explicite
  de l'opérateur. Le jeton Bearer est **statique**, sans rotation ni limitation
  de débit : le modèle documenté suppose un reverse-proxy authentifiant en
  amont.
- **Le mode forward-auth est opt-in et repose sur un contrat.** Le proxy amont
  **doit** supprimer les copies clientes des en-têtes d'identité, sinon ils sont
  falsifiables. Sans le drapeau de confiance, ces en-têtes sont ignorés.
- **Les règles pare-feu IPv6 ne sont pas validées** ; le déploiement de
  référence est IPv4.

Voir `docs/DEPLOY-SECURITY.md` pour les prérequis de déploiement, dont les
règles `DOCKER-USER` (qui doivent utiliser `RETURN`, jamais `ACCEPT`) et le
dimensionnement de `default-address-pools`.
