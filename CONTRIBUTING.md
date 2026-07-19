# Contribuer

Merci de l'intérêt porté au projet. Ce document est court à dessein : la
discipline technique du dépôt vit dans [`AGENTS.md`](AGENTS.md), qui s'applique
aux sessions humaines comme aux agents.

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique.** Ocular charge et exécute du contenu web
hostile ; une faille de confinement se signale en privé. Voir
[`SECURITY.md`](SECURITY.md).

## Avant de proposer un changement

- `make test` (suite dockerisée) **et** `make test-int` (intégration) verts.
- Une vérification **live** de ce qui change. Les tests unitaires seuls ont
  déjà laissé passer une panne totale des jobs dans ce dépôt : ils ne
  remplacent pas un essai de bout en bout.
- Un test de non-régression qui **mord** — cassez volontairement votre
  correctif et vérifiez que le test échoue. Un test vert dans les deux cas ne
  prouve rien.

## Mécanique

`main` est protégée : tout passe par une branche et une pull request, la CI
doit être verte, et les commits doivent être **signés**.

```
git config gpg.format ssh
git config user.signingkey ~/.ssh/votre_cle.pub
git config commit.gpgsign true
```

Messages de commit en français, format *conventional-commits*, un commit par
changement cohérent. Indexez **chemin par chemin** — jamais `git add -A`, qui
ramasse aussi ce qui traîne.

## Licence

Le code propre au projet est sous **AGPL-3.0-or-later** ; en contribuant, vous
acceptez que votre contribution le soit aussi. Les composants tiers embarqués
gardent leur licence — voir [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md),
et **ne posez jamais un en-tête SPDX du projet sur du code tiers** : la CI le
refuse, et ce serait une fausse déclaration de licence.
