# Convention d'opération — Ocular

Ce fichier s'applique à **toute** session (humaine ou agent) qui travaille dans ce
dépôt. Il complète la convention interne du mainteneur ; en cas de
contradiction, **la convention commune prime** et cette divergence est un bug à
corriger ici.

Le principe qui gouverne tout ce qui suit : **la sûreté vient de la couche
d'application des règles, pas de la confiance accordée à la session.** Un hook
`pre-receive` côté serveur refuse les poussées non conformes — humain ou agent,
même règle. Ce fichier décrit la discipline attendue ; il ne la *garantit* pas.
Ne jamais raisonner comme si respecter ce fichier suffisait à rendre une action
sûre.

## 1. Dépôt et remote

| Dépôt | Remote primaire |
|---|---|
| `ocular` | `ocular.git` |

Une session pousse vers **le remote primaire de son dépôt courant**, et nulle
part ailleurs. Un changement qui traverse plusieurs dépôts se fait par
**passation explicite** (une session par dépôt), jamais par une session qui
pousse dans le dépôt d'une autre.

## 2. Git — règles dures

- **Jamais `git add -A`, `git add .`, ni `git commit -a`.** Indexation
  **explicite, chemin par chemin**. Un `add -A` ramasse tout ce qui traîne —
  fichier de travail, artefact de build, secret local — et c'est précisément
  ainsi qu'un secret finit publié.
- **`git fetch` puis `rebase` avant toute poussée.** Jamais `--force`, jamais
  `--force-with-lease` sans feu vert humain explicite.
- **Jamais `git stash`** : le travail mis de côté devient invisible et se perd
  au changement de session.
- **Ne jamais réécrire ni écraser un commit humain.** En cas de divergence,
  s'arrêter et le signaler — ne pas « résoudre » en écrasant.
- **Ne jamais committer `deploy/.env`** (jeton d'API, mot de passe Redis, GID du
  socket Docker). Il est ignoré par `.gitignore` ; ne pas le forcer avec `-f`.
- Un commit par correctif cohérent, message en français, format
  *conventional-commits*.

### Trailer de commit

```
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

### Identité et registre public — vérifiés par la machine

Deux règles non négociables, valables pour **toute** session, y compris une session sans mémoire
de ce qui précède. Un commit qui les enfreint est refusé.

**1. Une seule identité publique : `guatxlabs <noreply@guatx.com>`**, en auteur **et** en
committer. Aucune adresse personnelle ni nominative, jamais. Un dépôt publié sous un collectif ne
doit pas exposer le compte personnel de qui l'écrit. L'historique de ces dépôts a porté deux
identités pour une même personne, dont un compte GitHub personnel entré par l'**édition via
l'interface web** — d'où le contrôle sur le committer, que l'édition web est seule à changer.

**2. Un message de commit s'adresse à un LECTEUR PUBLIC.** Écrivez pour quelqu'un qui n'était pas
dans la pièce et qui doit pouvoir agir sur ce qu'il lit : **ce qui change et pourquoi**.

*Interdit* — le commit n'est pas un compte rendu de conversation : le récit d'enquête à la première
personne (« j'avais écarté ce champ », « ma vérification »), l'adresse directe à un interlocuteur
(« comme vous l'avez demandé »), la chronologie de session comme fil narratif.

*Admis* — la **voix de l'outil** (« un `skipped` dit *je n'ai PAS pu vérifier* »), une **date de
mesure** (« MESURÉ le 2026-08-16 »), et un **« pourquoi » long** : la longueur n'a jamais été le
défaut, l'adressage l'était.

Le garde lit des **formes**, pas des intentions — il ne sait pas qui parle. Toute élision de
« je » et tout possessif (`mon`, `ma`, `mes`) sont refusés **en bloc**, quel que soit le verbe qui
suit : la version qui énumérait les verbes a laissé passer 56 occurrences dans `guatxlabs/forge`,
dans des commits qu'elle déclarait conformes.

La voix de l'outil s'écrit pourtant à la première personne et doit passer. Elle passe en portant
une **marque de citation** — guillemets « … », code entre backticks, ou ligne `>` :

```
> un `tested` dit « j'ai vérifié, rien trouvé » — d'où le contrôle sur l'oracle
```

Une citation ne traverse pas un saut de paragraphe, et un span de code ne doit pas être coupé par
un retour à la ligne, sinon l'appariement des backticks se décale.

**`hier` est interdit, `aujourd'hui` ne l'est pas** : le premier n'a aucun référent pour un lecteur
qui arrive six mois plus tard, le second dit « à l'état actuel du code ».

**DIVERGENCE ASSUMÉE avec `guatxlabs/forge`, à ne pas resynchroniser sans lire ceci** : ce dépôt
n'a **aucun motif sur « session »**. Une session est ici un conteneur de navigateur isolé — le
concept central du produit — et bannir l'expression refuserait des messages parfaitement corrects.
Un garde qu'on apprend à contourner ne garde plus rien. Un test fige ce choix.

**Les deux slots d'identité sont vérifiés, auteur ET committer** : un `cherry-pick`, un `rebase` ou
l'édition web laissent l'auteur intact et écrivent une autre identité en committer. Une plage que
git n'a pas su lire est un refus, pas un silence.

**Un garde n'attrape que ce qu'il sait décrire.** Les 56 occurrences ci-dessus ont été trouvées par
un audit *indépendant du garde*, écrit avec d'autres motifs, pas par lui. Avant d'affirmer qu'un
dépôt est propre, écrire un contrôle indépendant et trier ses faux positifs à la main.

**Comment ces règles tiennent** — le hook `commit-msg` arrête la faute au poste local, mais il
**ne ferme pas** : `git clone` ne le transporte pas et l'édition web ne l'exécute jamais. C'est le
job CI `registre public`, qui voit tout ce qui arrive au dépôt, qui ferme.

```sh
make hooks                                                   # une fois par clone
python3 scripts/check_commit_register.py --message-file <f>  # avant de committer
python3 scripts/check_commit_register.py --range origin/main..HEAD
```

## 3. Actions sortantes — GATÉES

Ces actions ne sont **jamais** autonomes et exigent un feu vert humain explicite,
demandé pour **chaque** occurrence (une autorisation passée n'en couvre pas une
suivante) :

- poussée vers un remote **public** (GitHub ou autre),
- publication, release, tag de version,
- toute opération qui rend un contenu accessible hors du poste ou du VPS privé.

Publier est **irréversible** : un secret poussé est indexé et mis en cache par
des tiers, y compris après suppression du commit. Le rattrapage n'est pas la
suppression, c'est la **rotation** du secret.

## 4. Concurrence entre sessions

- Une session = **un dépôt** à la fois.
- Jamais deux agents sur le même fichier en parallèle.
- `fetch` + `rebase` traite le cas « le remote a avancé pendant mon travail ».
- Pour du vrai parallélisme, utiliser des worktrees git — pas des copies.

## 5. Spécifique à Ocular — pièges vérifiés

Ces points ont chacun coûté du temps ou provoqué une régression réelle. Ils ne
sont pas des préférences de style.

- **Les runners écrivent leur JSON sur `stdout`**, que `broker/launcher.py`
  parse. Une seule ligne de log sur `stdout` casse le parsing
  (`JSONDecodeError`) et fait échouer le job. `ocular_logging.get_logger`
  écrit sur **stderr** — ne jamais rétablir stdout. *Régression vécue : seuls
  les tests d'intégration l'ont attrapée, les 686 tests unitaires passaient.*
- **Les runners et le `session_server` tournent dans des images.** Après
  modification, `make build-runner` est nécessaire, sinon les mesures live
  portent sur l'ancien code.
- **Ne pas sourcer `deploy/.env` dans le shell qui lance pytest** : il exporte
  `REDIS_URL`, ce qui fait **rougir la suite sur du code sain** et envoie
  chercher une régression inexistante.
- **L'authentification WebSocket noVNC passe par le sous-protocole**
  (`Sec-WebSocket-Protocol: binary, ocular.session.<token>`), jamais par
  l'URL — un token en URL fuit dans les journaux et le referrer.
- **Quand `curl` échoue, `-o fichier` n'est pas créé** : lire le **code retour
  de curl**, jamais l'absence du fichier, qui produit un diagnostic trompeur.
- **Le teardown de session est asynchrone** : attendre ~25 s avant de conclure
  à une fuite de conteneur ou de réseau.
- **Aucun résidu** : ni cache, ni fichier temporaire, ni conteneur, ni réseau.
  Passer par Docker même en natif. Les fichiers temporaires vont dans le
  répertoire de travail de la session, jamais dans `/tmp` nu — partagé avec
  d'autres projets, et des noms génériques y entrent en collision.

## 6. Avant de proposer une fusion

- `make test` (suite dockerisée) **et** `make test-int` (intégration) verts.
- Vérification **live** de bout en bout de ce qui a changé — les tests unitaires
  seuls ont déjà laissé passer une panne totale des jobs.
- Un test de non-régression qui **mord** : le prouver en cassant volontairement
  le correctif et en constatant l'échec du test. Un test qui passe dans les deux
  cas ne prouve rien.
