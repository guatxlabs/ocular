<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Ocular — Roadmap

Moteur autonome de **capture et d'analyse web durcie** : ouvrir une page hostile à la place de
l'analyste, en rendre des **pixels** et des faits mesurés, jamais du contenu exécutable.

Cette page dit **ce qui est livré**, **ce qui reste ouvert** et **comment contribuer**. Le détail
d'un correctif est dans le message du commit qui le porte ; la chronologie des campagnes n'est pas
publiée.

## Ce que fait Ocular

Quatre modes, un même schéma de résultat (`OcularResult`) et un même verdict :

| mode | usage |
|---|---|
| **analyse** | un HTML ou un `.eml` déposé — 47 détecteurs statiques, aucun réseau |
| **capture** | une URL ouverte pour de vrai (Camoufox), copies d'écran, DOM, trafic réseau |
| **interactif** | l'analyste pilote la page en **pixels seuls**, via noVNC — aucun DOM ne rejoint son poste |
| **scripté** | un DSL déclaratif borné (`goto/fill/click/wait/press/capture/scroll`), sans `eval` |

## Livré

- **Séparation de privilèges** — le frontal web n'a jamais accès au socket Docker : il passe par
  Redis, un broker, puis un runner **éphémère et durci** (seccomp deny par défaut, `cap-drop ALL`,
  non-root, système de fichiers en lecture seule, `--network none` pour l'analyse).
- **Isolation par session** — chaque session interactive vit dans son propre réseau Docker, créé au
  lancement et détruit au démontage. Deux sessions n'ont aucune route l'une vers l'autre.
- **Garde egress** — le runner résout puis **épingle l'IP**, refuse les adresses non publiques,
  défait le DNS-rebinding et ne suit pas une redirection vers un réseau interne. WebRTC désactivé.
- **Authentification** — bearer fail-closed à comparaison temps-constant ; **forward-auth** (opt-in
  strict) derrière n'importe quel reverse-proxy ; **validation OIDC JWT dans l'application** pour un
  IdP sans proxy. Les groupes de l'IdP peuvent accorder l'admin, sans escalade possible.
- **Verdict** — calculé à partir des détecteurs, corroboré plutôt que déclenché par un signal isolé,
  et **jamais écrasé** par la révision d'un analyste, qui est enregistrée à côté avec son auteur.
- **Sauvegardes** — SQLite auto-contenu, dédup par empreinte du contenu, provenance (qui, quand,
  Turnstile franchi ou non), purge et export côté admin.
- **Résultats exploitables** — filtrage structuré des entrées réseau et des findings (domaine, type
  MIME, URL, statut ; inclusions et exclusions cumulables), sans expression régulière libre.
- **Cycle de vie** — plafonds anti-OOM déclarés dans le résultat quand ils ont coupé, TTL des jobs,
  reaper de sessions, ramasse-miettes des artefacts.

## Ce qui reste ouvert

- **Filet egress au niveau réseau** — la garde vit dans le runner. Un filet L3 au déploiement
  (iptables, réseau Docker restreint) couvrirait tout canal non proxifié. Responsabilité opérateur,
  au même titre que le strip de l'en-tête forward-auth.
- **Rôles plus fins qu'admin / non-admin** — viewer, analyste. Aucun besoin ne s'est manifesté.
- **Authentik** — la validation OIDC est éprouvée contre un Keycloak réel, pas contre Authentik.
- **Récupération JWKS synchrone** — sur un chemin `async`, bornée (une par TTL, échéance courte).
  La rendre non bloquante imposerait de propager `async` jusque dans les chemins WebSocket.
- **Smoke e2e de l'UI hors matrice CI** — ce n'est pas le navigateur qui manque : il vit dans
  l'image `ocular-runner-recon`, et les runners GitHub ont Docker. C'est le COÛT — bâtir ou
  tirer ~3,4 Go d'image et lever la pile complète, sur un runner dont le disque tient dans une
  quinzaine de gigaoctets. Il reste une cible d'opérateur (`make smoke-ui`), comme les tests
  d'intégration.

## Limites assumées

- **Le pixel n'est pas une garantie de confinement.** Le mode interactif ne fait pas rejoindre le
  poste de l'analyste par du DOM, mais il exécute bien la page dans un conteneur ; la sûreté vient
  de l'isolation et du durcissement, pas du canal d'affichage.
- **Le proxy doit stripper l'en-tête d'identité.** Ocular ne peut pas distinguer seul un en-tête
  forward-auth posé par le proxy de celui posé par un client. C'est pour cela que la lecture est
  opt-in et que le bearer reste un filet.
- **Un jeton OIDC doit porter l'audience attendue.** Un client sans mappeur d'audience produit un
  jeton sans `aud`, refusé — conforme à la RFC 9068, et à configurer côté IdP.
- **Les détecteurs statiques signalent, ils ne prouvent pas.** Un verdict `malicious` exige une
  corroboration ; un signal isolé reste un finding visible sans emporter la conclusion.

## Sous-projets

- **Adaptateur SIEM** — intégrer le tier analyse/capture à un SIEM interne, en construisant
  l'adaptateur côté Ocular et sans modifier le SIEM.
- **Documentation auth/secrets portable** — OIDC/LDAP/reverse-proxy quelconque, `.env` ou Vault/SOPS.

## Gouvernance du dépôt

Deux règles s'appliquent à toute contribution, humaine ou automatisée, et sont **vérifiées par la
machine** : une **identité publique unique** (`guatxlabs <noreply@guatx.com>`, en auteur et en
committer) et un **message adressé à un lecteur public**, pas à un interlocuteur. Le détail, écrit
pour quelqu'un qui arrive sans contexte, est dans [`AGENTS.md`](../AGENTS.md).

## Contribuer

Rien ne se merge sans une vérification **réelle** : la suite unitaire seule a déjà laissé passer
une panne totale des jobs. Lire [`AGENTS.md`](../AGENTS.md) avant d'ouvrir une PR ; pour une
vulnérabilité, suivre [`SECURITY.md`](../SECURITY.md) — pas d'issue publique.

```sh
make test        # suite unitaire, dans une image jetable
make test-int    # intégration : exige Docker
make smoke-ui    # smoke navigateur : exige `make up` + l'image runner
```
