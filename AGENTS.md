# Convention d'opération — Ocular

Ce fichier s'applique à **toute** session (humaine ou agent) qui travaille dans ce
dépôt. Il complète la convention commune `GUATX/AGENTS.md` ; en cas de
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
