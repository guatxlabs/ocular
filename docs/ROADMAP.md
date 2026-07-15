# Ocular — Roadmap

Moteur autonome de **capture + analyse web durci** (fusion `web-screenshot-capture` + `malware-html-sandbox` + bypass `browser-automation`). Repo standalone, destiné au GitHub `xguatx`, indépendant de GUATX.

**Méthode** (éprouvée sur toutes les phases) : brainstorm → spec → plan → SDD (implémenteur + relecteur par tâche) → audit indépendant (3 auditeurs archi/sécu/qualité) → **e2e réel Docker** → merge local. On ne merge jamais sans e2e réel : la boucle a attrapé à répétition de vrais défauts (Dockerfiles incomplets, timing-attack, TOCTOU, double-fault, réflexion 422, `/artifacts:ro`, sur-classification de verdict…).

**Contraintes permanentes** : ne JAMAIS toucher `plume`/`core`/`forge` ; séparation de privilèges (web sans docker.sock → Redis → broker → runner éphémère durci) ; pas de fuite de secret (réseau/args/logs) ; portable (OIDC/LDAP/reverse-proxy quelconque, `.env` ou Vault/SOPS) ; DRY, pas de monolithe, pas de hardcode sécu.

Légende : ✅ fait & mergé · 🔜 à faire (priorisé) · ⏳ différé (dette identifiée) · 🧩 sous-projet.

---

## ✅ Fait (mergé sur `main`)

| Tranche | Contenu |
|---|---|
| **Fondation + runner analyse** | Schéma `OcularResult` unifié, 47 détecteurs statiques, runner Chromium durci (seccomp deny-défaut, `--network none`, cap-drop ALL, non-root), séparation web/broker (web sans docker.sock). |
| **Passe 2.5 — Utilisabilité + UI** | Artefacts sur volume disque (anti-traversal, DOM jamais inline), auth Bearer fail-closed temps-constant, **UI PWA vanilla-JS façon plume** (accent `#8b5cf6`, XSS-clean), Makefile + compose durci + GC + README. |
| **Correctness + Observabilité + Hardening** | Verdict calculé (`engine/verdict.py`), chemin `status:error` propagé, logging structuré (jamais token/html), TTL Redis + limites DoS, hardening web (nosniff/CSP/compare_digest), config centralisée `ocular_settings.py`, contrat de file `bus/queue.py`. |
| **Analyses sauvegardées** | Persistance opt-in SQLite auto-contenu (`saved_store.py`), **dédup par `sha256(html)`**, UI Sauvegardes/Admin, admin delete/flush sous token séparé. |
| **Réparation stack Docker** (trouvée par e2e réel) | `docker-cli` (client scindé sur Debian), volumes `/saved`/`/artifacts` possédés uid non-root, broker résilient `restart:`, garde `tests/test_deploy_images.py`. |
| **Phase 3a — Capture recon** | Profil `capture`, runner `runner_recon` (Camoufox headed Xvfb + vision opencv Turnstile + xdotool), URL live, réseau ON durci, `engine/ssrf.py` (garde `is_global`, ~20 bypasses bloqués), `engine/wrapper.py` DRY. |
| **Phase 3b — Interactif noVNC durci** | Tier session (conteneur persistant Camoufox + x11vnc + websockify + noVNC), analyste en **pixels-only** via proxy WS du web (auth sous-protocole), clipboard coupé à la source, réseau interne sans port hôte, **reaper TTL 1800s/idle 600s**, secret par session à la frontière conteneur, bouton Capturer → `OcularResult`. |
| **Phase 3c — Dynamique scripté** | **DSL déclaratif borné** (`goto/fill/click/wait/press/capture/scroll`, aucun eval) rejoué dans le runner 3a, steps sur **stdin** (absents de `docker inspect`), valeurs `fill` redigées, API locator (pas d'injection), budget wall-clock 120s → résultat partiel, réutilise `dynamic_steps`, UI formulaire scripté + journal XSS-clean, garde-corps 413. |

**Phase 3 complète (3a+3b+3c).** Le moteur couvre : analyse hostile · capture recon · interactif durci · dynamique scripté.

---

## 🔜 Phase 3d — Correctness + UX + durcissement interactif

Regroupe le retour utilisateur (2026-07-13) + finitions. Chaque item passe par la méthode (spec courte → SDD → e2e).

> **État** : le batch **3d-1** (✅ A verdict · D nom unique · E GC planifié · F upload .htm/.html · G bandeau CSS · H schéma URL+fallback) est **implémenté** (branche `feat/phase3d-correctness-ux`, en cours d'audit/merge). Reste : **B** (Turnstile), **C** (cycle de vie + analyse interactif), **I** (filtrage SOC), **J** (recalibration détecteurs).

### A. Correctness du verdict
- **A1 — Script externe seul ≠ malveillant.** `engine/static.py:25` classe **tout** `<script src=https://…>` en `critical` → `compute_verdict` renvoie `malicious`. Une page légitime avec un CDN est donc « malicious ». **Attendu** : un script externe seul ne doit **pas** faire basculer en `suspicious`/`malicious`. Fix : abaisser la sévérité de ce détecteur (`low`/`info`, reste visible comme finding) et/ou ne l'élever que combiné à d'autres signaux (obfuscation, `eval`, exfil). Revoir dans la foulée les autres détecteurs à sévérité trop agressive.

### B. Turnstile
- **B1 — Auto-résolution Turnstile à réparer.** `runner_recon/capture.py:149-154` tente déjà vision (template match) + clic OS xdotool, mais **ne résout pas** en pratique dans le conteneur. **Attendu** : la résolution auto doit fonctionner en mode capture/analyse. Investiguer `runner_recon/vision.py` (template `turnstile_checkbox.png`, détection sur le Xvfb headed), le timing (challenge chargé en iframe async), et le clic xdotool (coordonnées/rendu). Tests d'intégration avec une page challenge de référence.

### C. Interactif (3b) — cycle de vie & analyse
- **C1 — Fermeture brutale du navigateur** → nettoyage de session : déconnexion WS ⇒ marquer la session inactive et la reaper après un court délai de grâce (ne pas attendre le TTL 1800s). S'appuyer sur l'événement de fermeture WS côté proxy web + `last_activity`.
- **C2 — Onglet non actif > 1 min → fermeture auto de l'interactif.** Côté UI : Page Visibility API (`visibilitychange`) ⇒ si l'onglet n'est pas au premier plan pendant 1 min, fermer la session (DELETE) ; côté serveur : idle basé sur l'activité WS. Ne pas facturer un conteneur vivant pour un onglet abandonné.
- **C3 — Sauvegarder la session interactive.** Le bouton Capturer produit déjà un `OcularResult` ; garantir le flux « capturer → sauvegarder » (avant fermeture aussi), coule dans les Sauvegardes.
- **C4 — Analyse pendant l'interactif.** Pendant la session, **capturer les appels scripts/réseau** et faire tourner les **détecteurs statiques** (comme l'analyse HTML) sur le DOM live → findings + verdict dans le résultat interactif (pas seulement des pixels).

### D. Sauvegardes
- **D1 — Unicité du NOM.** `saved_store.py` dédup par `input_hash` (colonne UNIQUE) mais le `label` (nom) n'est pas unique. **Attendu** : interdire deux sauvegardes du **même nom** (contrainte/contrôle à l'insertion, message clair côté UI).

### E. Cycle de vie des jobs / GC
- **E1 — Planifier le GC des artefacts.** `broker/gc.py::collect` existe mais **n'est jamais appelé dans la boucle broker** (uniquement `make gc` manuel) ⇒ les artefacts s'accumulent sur le volume. Les **résultats Redis** expirent bien (TTL `result_ttl()` 24h). **Attendu** : lancer le GC périodiquement (thread comme le reaper, intervalle configurable) pour que les artefacts des jobs expirés (dont l'analyse HTML) soient nettoyés automatiquement.

### F. Entrées / upload
- **F1 — Accepter `.htm`/`.html` (analyse ET interactif).** `web/ui/views/submit.js:32` accepte `.eml,message/rfc822,text/html` mais les libellés ne parlent que de `.eml`. **Attendu** : accepter explicitement `.htm` et `.html` (et le préciser dans les libellés/i18n : « HTML, .htm, .html ou .eml »). Rappel utile : un `.eml` est un mail, parfois au format HTML — ok, mais l'utilisateur doit voir qu'il peut aussi déposer directement du HTML. Étendre la même entrée fichier au tier interactif.

### G. UI / finition
- **G1 — Bandeau « IP exposée ».** `.livewarn` (`web/ui/style.css:1163`) : retirer l'élément/décoration à gauche qui **dépasse du rectangle** de la carte — pas de surplus de CSS, garder la carte propre dans ses bords.

### H. Schéma URL
- **H1 — Détection auto http/https + fallback.** `example.com` → `https://` par défaut (normalisation à la soumission via `normalize_url`) ; `http://`/`https://` respectés ; si `https` échoue à la capture → repli **une** fois en `http` (runner). `final_url` reflète l'URL atteinte.

### I. Filtrage & recherche des résultats (intégration SOC)
- **I1 — Recherche/filtre efficace des résultats.** Un résultat peut contenir des **centaines d'entrées réseau** ; il faut pouvoir chercher/filtrer sans scroller : par **type MIME**, par **pattern d'URL**, par **domaine**, avec **inclusions ET exclusions** (négation), filtres **cumulables**. Piloter cela « façon SOC » (rapide, clavier, compteurs de correspondances). Applicable aussi aux findings statiques / console.
- **I2 — Sécurité du filtrage (impératif).** Pas de **ReDoS** : ne pas exposer une regex utilisateur non bornée. Préférer des **filtres structurés** (`domaine =`, `mime contient`, `url contient`, `statut =`) + éventuellement un glob borné ; si regex, la **compiler avec limites** (longueur, complexité) et l'appliquer **côté client** sur les données déjà chargées (pas de nouvelle surface serveur / pas de requête réinjectée). Aucune fuite : le filtre ne doit pas exfiltrer ni logger de contenu sensible.

### J. Calibration des détecteurs (dette découverte en Task A)
- **J1 — Recalibrer le verdict au-delà d'`External script`.** `engine/static.py` classe en `critical`/`high` beaucoup de signaux **bénins en isolation** (formulaires, champ password, `fetch`, storage…) → une page de login légitime ressort `malicious`. Décision de **modèle de menace** à prendre : un verdict `malicious`/`suspicious` devrait exiger une **corroboration** (combinaison de signaux : password + form action externe + texte de harponnage ; ou obfuscation `eval`/`atob`+`Function`), pas un signal isolé. À spécifier séparément (impacte la sémantique cœur).

---

## ⏳ Différés techniques (dette identifiée par les audits, non bloquante)

- **SSRF — DNS-rebinding & suivi de redirections.** `validate_capture_url` valide au submit, mais `page.goto()` (3a/3c) suit les redirections dans le navigateur (réseau ON) → une réponse `302` vers une IP interne contourne la garde. Fix = **filtrage egress du runner** (même chantier que le DNS-rebinding). À traiter au niveau isolation réseau, pas dans le DSL.
- **VNC-passwd par session (3b)** — actuellement absent ; le secret par session à la frontière conteneur couvre l'auth applicative, mais un mot de passe VNC par session (au-delà du DES 8-char faible) durcirait davantage.
- **Dédup `capture_url`/`capture_scripted`** — ~20 lignes de pilotage Camoufox dupliquées (factorisation `_goto_safe`/`_capture_dom`).
- **Plafond de corps `chunked`** — la garde 413 couvre `Content-Length` ; les corps sans `Content-Length` restent bornés seulement par `mem_limit`. Fix complet = plafond au reverse-proxy/serveur ASGI.
- **Finalisation DOM sous timeout** — la phase `page.content()/title()` après un timeout de step n'a pas de budget propre (s'appuie sur la marge broker 60s) ; l'envelopper dans un `asyncio.wait_for` court durcirait le résultat partiel.

---

## 🧩 Sous-projets (hors phase 3)

- **Adaptateur plume** — intégration d'Ocular dans plume (le tier analyse/capture surtout ; `forge` = red team, moins pertinent). **Ne pas modifier plume ; construire l'adaptateur côté Ocular.**
- **Publication GitHub `xguatx`** — licence, mentions légales, CI (la garde e2e `test_deploy_images` couvre déjà le smoke des images), doc auth/secrets portable (OIDC/LDAP/reverse-proxy, `.env`/Vault/SOPS).

---

*Dernière mise à jour : 2026-07-13 (après merge phase 3c). Voir `docs/superpowers/specs/` et `docs/superpowers/plans/` pour le détail de chaque phase.*
