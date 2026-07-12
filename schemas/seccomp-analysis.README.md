# `seccomp-analysis.json` — traçabilité du profil seccomp du runner d'analyse

Le format JSON du profil seccomp OCI ne permet pas de commentaires. Ce fichier documente
les décisions prises pour `schemas/seccomp-analysis.json` afin que toute évolution future
(ajout/retrait de syscall) reste traçable et review-able.

## Posture générale

- **Deny-par-défaut** : `defaultAction: SCMP_ACT_ERRNO`. Tout syscall non explicitement
  whitelisté échoue avec `ENOSYS`/`EPERM` plutôt que de tuer le process — ce choix (au lieu
  de `SCMP_ACT_KILL`) permet un échec géré côté application plutôt qu'un crash brutal, sans
  affaiblir la garantie de sécurité (le syscall n'est de toute façon jamais exécuté).
- Le profil ne dépend pas uniquement de seccomp : il est **combiné** au runtime avec
  `--cap-drop ALL`, `--security-opt no-new-privileges`, `--network none`, `--read-only`,
  `--user 10001:10001` (non-root). Plusieurs syscalls survivants dans la whitelist ne sont
  inoffensifs **que** grâce à cette combinaison (cap-gating), pas grâce à seccomp seul — voir
  section "survivants conservés" ci-dessous.
- Portée : conteneur de rendu HTML headless (Chromium via Playwright), sans état, sans
  réseau externe, job unique puis destruction. Toute primitive sans usage plausible dans ce
  contexte est exclue, même si elle est théoriquement inoffensive sous cap-drop.

## Familles de syscalls à haut risque explicitement exclues

Ces familles sont **absentes** de la whitelist — jamais de justification légitime pour ce
runner, indépendamment du cap-gating :

- **`ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp`,
  `process_madvise`** — introspection/injection inter-processus. Aucun usage légitime pour un
  rendu isolé mono-job.
- **`bpf`** — surface d'attaque noyau majeure, historique CVE important (privilege
  escalation via verifier bugs).
- **`mount`, `umount`, `umount2`, `unshare`, `setns`** — manipulation de montages et de
  namespaces. Un rendu headless ne remonte jamais rien après le démarrage du conteneur.
- **`keyctl`, `add_key`, `request_key`** — trousseau de clés noyau, non utilisé par
  Chromium/Playwright.
- **`perf_event_open`** — monitoring de performance, vecteur connu de fuite par canal
  auxiliaire (side-channel) et d'élévation de privilèges historique.
- **`process_vm_*`** (voir ptrace ci-dessus) et **`pidfd_getfd`/`kcmp`** — regroupés par
  cohérence avec l'introspection inter-processus.
- **`io_uring_setup`, `io_uring_enter`, `io_uring_register`** — historique CVE élevé sur les
  noyaux récents (multiples bypass de LSM/seccomp documentés), exclu par précaution même si
  non requis par Chromium.
- **`kexec_load`, `kexec_file_load`, `reboot`, `init_module`, `delete_module`,
  `finit_module`** — chargement de code noyau / redémarrage machine, jamais légitime en
  conteneur applicatif.
- **`ioperm`, `iopl`** — accès direct aux ports d'E/S x86, dangereux, jamais légitime en
  conteneur.
- **`chroot`** — changement de racine système de fichiers ; le conteneur n'a besoin d'aucune
  isolation de filesystem supplémentaire au-delà de celle déjà fournie par le runtime OCI, et
  ce syscall n'a aucun usage dans un rendu HTML headless. Retiré par cohérence (défense en
  profondeur) lors du resserrement du profil.
- **Réglage d'horloge système** : `settimeofday`, `stime`, `clock_settime`, `clock_adjtime`,
  `clock_adjtime64`, `adjtimex` — modification de l'horloge système. Un rendu headless ne lit
  que l'heure (`clock_gettime`, `gettimeofday`, conservés), il ne la modifie jamais. Ces
  primitives sont normalement déjà cap-gated (`CAP_SYS_TIME`) donc neutralisées par
  `--cap-drop ALL`, mais retirées explicitement de la whitelist par cohérence : pas de raison
  de laisser un syscall accessible en surface seccomp si son seul garde-fou est une capability
  qu'on retire par ailleurs.

## Survivants cap-gated volontairement conservés

Ces syscalls restent dans la whitelist malgré un potentiel de risque théorique, parce
qu'ils sont **requis pour le fonctionnement réel** (runtime OCI ou Chromium multi-processus)
et sont neutralisés en pratique par la combinaison `--cap-drop ALL` + égalité d'UID
(`--user 10001:10001`, pas de `setuid`-root possible) :

- **API mount moderne** : `fsopen`, `fsconfig`, `fsmount`, `fspick`, `open_tree`,
  `move_mount` (Linux 5.2+). Requise par `runc` pour ouvrir un handle `/proc` privé lors de
  son durcissement anti-TOCTOU au démarrage du conteneur (avant même l'exec de
  l'entrypoint). Sans ces syscalls, `runc` lui-même échoue à initialiser le conteneur
  (vérifié empiriquement). Cap-gated (`CAP_SYS_ADMIN`) dans le profil par défaut de
  Docker/Moby, donc sans effet sous `--cap-drop ALL` — seul `runc`, qui s'exécute avant la
  bascule vers l'utilisateur non privilégié, en a l'usage réel.
- **AIO legacy** : `io_setup`, `io_destroy`, `io_submit`, `io_cancel`, `io_getevents`,
  `io_pgetevents`, `io_pgetevents_time64`. Conservés pour compatibilité glibc — certaines
  versions de la libc ou de Chromium peuvent sonder ces syscalls même sans les utiliser
  activement en chemin critique. Sans capability spéciale requise pour un usage local sans
  état ; neutralisés en pratique par l'absence de fichiers device réels accessibles
  (`--read-only`, `--tmpfs` restreint) et par le bac à sable applicatif de Chromium.
- **`pidfd_open`, `pidfd_send_signal`** — gestion moderne de processus par descripteur de
  fichier, utilisée par le modèle multi-processus de Chromium (navigateur principal, GPU,
  zygote, renderers) pour surveiller/signaler ses propres sous-processus. Sans capability
  spéciale pour signaler ses propres enfants ; combiné à `--pids-limit 256` et à l'absence de
  `CAP_KILL`/`CAP_SYS_PTRACE` sur des PID hors de l'arbre du conteneur, la portée
  d'exploitation est None au-delà de l'auto-gestion légitime du process.

## Procédure de modification

Toute modification de `schemas/seccomp-analysis.json` (ajout ou retrait de syscall) doit :

1. Être justifiée dans ce fichier (catégorie exclue avec motif, ou survivant cap-gated avec
   raison d'usage).
2. Être re-testée avec le smoke-test durci complet (`--network none --cap-drop ALL
   --security-opt no-new-privileges --read-only --tmpfs /work:... --user 10001:10001`) pour
   confirmer qu'un rendu Chromium réel aboutit toujours (`OcularResult` avec `screenshots`
   non vide, exit 0).
3. Ne jamais desserrer une autre contrainte du runtime (cap-drop, réseau, UID, read-only)
   pour compenser un retrait de syscall trop agressif — retirer uniquement le(s) syscall(s)
   strictement nécessaire(s) à la remise en whitelist si le smoke-test casse.
