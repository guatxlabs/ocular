# Composants tiers embarqués

Ocular embarque les composants ci-dessous. Ils sont distribués **sous leur
propre licence**, pas sous l'AGPL v3 d'Ocular. L'AGPL v3 s'applique au code
propre au projet ; rien ici ne la leur substitue.

Ces composants sont volontairement **embarqués** (`vendor/`, `fonts/`) plutôt que
récupérés à l'exécution : le panneau interactif doit fonctionner sans réseau
sortant vers un CDN, et une politique de sécurité de contenu stricte interdit
de toute façon les hôtes externes.

## noVNC

- **Emplacement** : `web/ui/vendor/novnc/`
- **Licence** : Mozilla Public License 2.0 (MPL-2.0)
- **Texte** : [`web/ui/vendor/novnc/LICENSE.txt`](web/ui/vendor/novnc/LICENSE.txt)
- **Amont** : <https://github.com/novnc/noVNC>
- **Version** : ≥ 1.5.0 (le décodeur `h264.js` est présent)
- **Copyright** : The noVNC authors

La MPL-2.0 est un copyleft **par fichier** : un fichier noVNC modifié reste sous
MPL-2.0 et sa source modifiée doit être fournie. Les fichiers embarqués ici sont
**non modifiés** ; leurs en-têtes de licence d'origine sont intacts. Toute
modification future d'un de ces fichiers doit conserver son en-tête et rester
sous MPL-2.0.

La MPL-2.0 est compatible avec une distribution combinée sous AGPL v3 : sa
section 1.12 range explicitement l'AGPL v3 parmi les « licences secondaires »,
et sa section 3.3 autorise cette combinaison — chaque composant restant sous sa
propre licence.

## pako

- **Emplacement** : `web/ui/vendor/novnc/vendor/pako/`
- **Licence** : MIT
- **Texte** : [`web/ui/vendor/novnc/vendor/pako/LICENSE`](web/ui/vendor/novnc/vendor/pako/LICENSE)
- **Amont** : <https://github.com/nodeca/pako>
- **Version** : fork ES6 de pako 1.0.3, tel que distribué par noVNC
- **Copyright** : Vitaly Puzrin et Andrey Tupitsin

Il s'agit de la copie que noVNC embarque lui-même — parties inutilisées retirées
et support des tableaux non typés supprimé (voir le `README.md` du répertoire).

## Inter

- **Emplacement** : `web/ui/fonts/inter-latin.woff2`,
  `web/ui/fonts/inter-latin-ext.woff2`
- **Licence** : SIL Open Font License 1.1 (`OFL-1.1`)
- **Texte** : [`web/ui/fonts/OFL-Inter.txt`](web/ui/fonts/OFL-Inter.txt)
- **Amont** : <https://github.com/rsms/inter>
- **Version** : 4.001 — la table `name` de la police porte
  `Version 4.001;git-66647c0bb`
- **Copyright** : `Copyright 2016 The Inter Project Authors` — le texte OFL amont
  écrit la même chose avec un `(c)` que la table `name` n'a pas

## JetBrains Mono

- **Emplacement** : `web/ui/fonts/jetbrains-mono-latin.woff2`,
  `web/ui/fonts/jetbrains-mono-latin-ext.woff2`
- **Licence** : SIL Open Font License 1.1 (`OFL-1.1`)
- **Texte** : [`web/ui/fonts/OFL-JetBrainsMono.txt`](web/ui/fonts/OFL-JetBrainsMono.txt)
- **Amont** : <https://github.com/JetBrains/JetBrainsMono>
- **Version** : 2.211 — la table `name` de la police porte `Version 2.211`
- **Copyright** : `Copyright 2020 The JetBrains Mono Project Authors`

Les deux avis de copyright ci-dessus sont ceux **lus dans la police elle-même**
(table `name`, identifiant 0), pas déduits du nom de fichier. Chaque texte de
licence a été récupéré de l'amont **tel quel** : celui d'Inter au commit
`66647c0bb` que la police déclare, celui de JetBrains Mono dans une révision où
il est identique d'une version à l'autre autour de la 2.211.

Ces fichiers sont des sous-ensembles `latin` / `latin-ext` convertis en WOFF2 —
donc des **Modified Versions** au sens de l'OFL. Cela reste autorisé : ni Inter
ni JetBrains Mono ne déclarent de **Reserved Font Name** après leur avis de
copyright, la clause 3 ne mord donc pas, et la clause 5 (rester sous OFL) est
respectée puisque nous ne les redistribuons sous aucune autre licence.

L'OFL n'est pas contaminante pour le reste du projet : sa clause 5 précise que
l'obligation de rester sous OFL ne s'étend pas aux documents produits avec la
police, et la clause 2 autorise explicitement la redistribution **groupée avec
n'importe quel logiciel** dès lors que chaque copie porte l'avis de copyright et
la licence. C'est le cas ici pour le source **et pour les images** : `web/` est
copié en entier dans l'image (`deploy/Dockerfile.web`), donc les deux fichiers
de licence voyagent avec les polices qu'ils couvrent.

---

## Note de conformité

Les quatre composants ci-dessus ont eu **le même défaut**, découvert en deux
fois. D'abord noVNC et pako : leurs en-têtes renvoient à un `LICENSE.txt` qui
n'était pas distribué avec le code, alors que la MPL-2.0 (§3.1) et la licence MIT
exigent l'une comme l'autre que leur texte accompagne le source redistribué.
Ensuite les deux polices : le même raisonnement s'y applique **mot pour mot** —
l'OFL 1.1 l'écrit encore plus explicitement (clause 2, « each copy contains the
above copyright notice and this license »), et aucun texte d'OFL n'était présent
dans le dépôt. Les quatre fichiers de licence ont été récupérés depuis l'amont et
ajoutés avant toute publication.

La leçon est que le défaut ne se voit pas en cherchant des *fichiers de licence
manquants* — il se voit en recensant ce que le dépôt **redistribue**, par type de
contenu et non par extension. Le recensement a été refait ainsi ; les images de
`docs/` et `runner_recon/` et les SVG sont des productions du projet, pas des
tiers.

Toute mise à jour de ces composants doit **reprendre le fichier de licence en
même temps que le code ou la police**, et mettre à jour les versions indiquées
ci-dessus. Le job `licence` de la CI vérifie la présence et le caractère non-vide
des quatre textes : l'oubli échoue le build au lieu de passer inaperçu.
