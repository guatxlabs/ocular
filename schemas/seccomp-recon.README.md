# `seccomp-recon.json` — traçabilité du profil seccomp du runner de capture (recon)

Copie **verbatim** de `schemas/seccomp-analysis.json` (voir son README pour la justification
détaillée de chaque syscall inclus/exclu) — les 325 syscalls whitelistés pour le rendu headless
Chromium/Playwright se sont avérés **suffisants tels quels** pour Camoufox (Firefox patché) +
Xvfb, sans aucun ajout. Voir `schemas/seccomp-analysis.README.md` pour la posture générale
(deny-par-défaut `SCMP_ACT_ERRNO`, combinaison avec `--cap-drop ALL` / `--read-only` /
`--user 10001:10001`, familles exclues, survivants cap-gated).

## Pourquoi aucun syscall n'a été ajouté

Le blocage initial rencontré pendant l'implémentation (`BrowserType.launch` : timeout 180s,
`Xvfb`/Camoufox démarrent mais le handshake Playwright↔Firefox ne se termine jamais) a
d'abord semblé être un problème seccomp — c'était l'hypothèse de travail naturelle vu le
changement de moteur (Firefox patché vs Chromium). Isolation empirique, flag par flag :

1. `--security-opt seccomp=unconfined` : **même blocage identique**, syscalls totalement
   déliés → seccomp innocenté d'emblée.
2. Ajout ciblé de `io_uring_setup/enter/register` (observés utilisés par le driver Node
   Playwright) à la whitelist : **aucun effet**.
3. Ajout ciblé de `shmget/shmat/shmdt/shmctl/semget/semop/semctl` (SysV IPC, candidat MIT-SHM
   X11 courant pour Xvfb, présents dans le profil seccomp par défaut de Docker mais absents
   de `seccomp-analysis.json`) : **aucun effet**.
4. Isolation par bisection des flags de durcissement runtime (indépendamment de seccomp) :
   - `--cap-drop ALL` seul (sans `--read-only`) → navigation **OK**.
   - `--read-only` + tmpfs seul (sans `--cap-drop ALL`) → **bloqué**, identique au cas complet.
   → **`--read-only` était le vrai coupable**, pas seccomp ni les capabilities.

Cause réelle (voir aussi `runner_recon/Dockerfile`, commentaire au-dessus du `ENV` final) :
`HOME` pointait vers `/opt/camoufox` (la couche image en lecture seule où vit le binaire
Camoufox) ; sous `--read-only`, tout composant qui écrit un dotfile sous `$HOME` par défaut
(cache fontconfig, `.ICEauthority` X11, dconf/GTK, ...) échoue silencieusement, et la
combinaison finit par bloquer indéfiniment l'initialisation du navigateur — sans jamais
émettre d'erreur seccomp (`ENOSYS`/`EPERM`) puisque ce n'est pas seccomp qui bloque, ce sont
de vrais échecs `EROFS` sur des écritures fichier, tolérés individuellement mais pas en
somme. Fix appliqué dans le Dockerfile (pas dans ce fichier seccomp) : `HOME=/work` (tmpfs
inscriptible) découplé de `XDG_CACHE_HOME=/opt/camoufox/.cache` (où *camoufox* résout son
propre binaire, lecture seule, jamais écrit au runtime).

**Conclusion pour ce profil seccomp** : `schemas/seccomp-analysis.json` s'est révélé être une
whitelist déjà adéquate pour un navigateur headed (Xvfb) multi-process de la famille
Firefox, pas seulement pour Chromium — cohérent avec le fait que les deux moteurs reposent
sur les mêmes primitives noyau Linux de base (processus, mémoire, sockets, fichiers) pour
leur fonctionnement multi-process, indépendamment du moteur de rendu.

## Procédure de modification

Identique à `schemas/seccomp-analysis.json` : toute évolution doit être justifiée ici, puis
re-testée avec le smoke durci complet (`--cap-drop ALL --security-opt no-new-privileges
--read-only --tmpfs /work:... --tmpfs /tmp:... --user 10001:10001 --security-opt
seccomp=schemas/seccomp-recon.json`) pour confirmer qu'une navigation Camoufox réelle aboutit
toujours (`OcularResult` profil `capture`, `screenshots`/`network` non vides, exit 0).
