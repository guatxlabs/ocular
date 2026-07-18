# Ocular — Roadmap

Moteur autonome de **capture + analyse web durci** (fusion `web-screenshot-capture` + `malware-html-sandbox` + bypass `browser-automation`). Repo standalone, destiné au GitHub `xguatx`, indépendant de GUATX.

**Méthode** (éprouvée sur toutes les phases) : brainstorm → spec → plan → SDD (implémenteur + relecteur par tâche) → audit indépendant (3 auditeurs archi/sécu/qualité) → **e2e réel Docker** → merge local. On ne merge jamais sans e2e réel : la boucle a attrapé à répétition de vrais défauts (Dockerfiles incomplets, timing-attack, TOCTOU, double-fault, réflexion 422, `/artifacts:ro`, sur-classification de verdict…).

**Contraintes permanentes** : ne JAMAIS toucher `plume`/`core`/`forge` ; séparation de privilèges (web sans docker.sock → Redis → broker → runner éphémère durci) ; pas de fuite de secret (réseau/args/logs) ; portable (OIDC/LDAP/reverse-proxy quelconque, `.env` ou Vault/SOPS) ; DRY, pas de monolithe, pas de hardcode sécu.

Légende : ✅ fait & mergé · 🔜 à faire (priorisé) · ⏳ différé (dette identifiée) · 🧩 sous-projet.

---

## ✅ Phase 3k — finitions batch-3 (retour utilisateur 2026-07-16) — LIVRÉE

Suite dockerisée **verte** (nouveaux tests : extraction forms/mailto, purge captures éphémères, /live forms+mailtos). Schéma `result.schema.json` régénéré (`DomInfo.mailtos`).

- **Favicon adaptatif** : `favicon.svg` reprend EXACTEMENT le tracé du logo d'en-tête (viewBox 24, amande+iris+éclat) et s'adapte au thème système via `@media (prefers-color-scheme)` (teal `#00d4aa` en sombre, `#00a886` + éclat teal clair en clair).
- **Détection formulaires + mailto** (static ET interactif) : `engine/static.extract_forms` (action+méthode, POST/externe/mailto = signal d'exfiltration) + `extract_mailtos` (bornés anti-DoS) ; peuplent `DomInfo.forms`/`DomInfo.mailtos` aux 4 tiers ; nouvelle section UI « Formulaires & mailto » (detail + panneau live, `/live` les expose) mettant en évidence les destinations risquées.
- **Renommages UI** : nav « Analyser » → **« Static »** ; toggle static « Analyser HTML/URL » → **« HTML »/« URL »**, bouton unique **« Analyser »** ; toggle interactif « Ouvrir une URL/Rendre du HTML » → **« URL »/« HTML »**.
- **Flux sauvegarde interactif repensé** : bouton live « Capturer » → **« Sauvegarder »** ; le panneau de nommage apparaît **juste sous la barre** (plus tout en bas) ; **un nom est REQUIS** pour persister ; **aucun avertissement de capture temporaire** — confirmation « Sauvegardé » seulement APRÈS enregistrement effectif ; les captures non nommées sont **purgées** à la fermeture/expiration de session (`broker.sessions.purge_session_results` sur `sesscap-{sid}-*`, appelé dans `reap` + `stop` ; + TTL sur le résultat Redis).
- **Zoom interactif corrigé** : suppression du conflit CSS `overflow` qui coinçait la vue « en haut à droite » (noVNC gère seul clip+pan) ; libellés clarifiés « Ajusté » (page entière à l'écran) ↔ « Zoom 1:1 » (glisser pour naviguer) ; la capture full-page reste le moyen de figer la page entière.

**Correctifs complémentaires (même retour, 2026-07-16) :**
- **Crop bas/droite de la vue interactive (footer coupé sur guatx.com)** — cause racine : le conteneur session n'a PAS de window manager, donc Firefox/Camoufox s'ouvrait plus grand que l'écran Xvfb (1280×720), ancré en haut-gauche → bas+droite hors framebuffer. Fix : `session_server._fit_browser_window()` force la fenêtre à couvrir exactement l'écran via xdotool (déjà présent, best-effort, plusieurs tentatives).
- **Zoom retravaillé (2e passe)** : le clip/pan 1:1 restait perçu comme cassé (« zoome en haut à droite ») → remplacé par un bouton **« Agrandir »/« Réduire »** fiable (le cadre grossit quasi plein écran, `scaleViewport` ré-ajuste toute la fenêtre, aucun pan/clip). Combiné au fit-window ci-dessus = plus de crop.
- **Ctrl+R détruisait la session** (perte de l'état derrière le login/Turnstile) — un rechargement page Ocular (focus hors canvas noVNC) déclenchait un DELETE session silencieux. Fix : `beforeunload` DEMANDE confirmation (`preventDefault`+`returnValue`) ; la suppression serveur ne part qu'au unload RÉEL (`pagehide`) → confirmation annulée = session préservée. (Focus sur le canvas : Ctrl+R va au navigateur distant, cookies persistent, on reste derrière le login — inchangé.)
- **Jobs fantômes** (`GET /jobs/{id}` renvoyait « pending » à l'infini pour un job perdu — Redis éphémère vidé par un down/up, ou jamais traité → accumulation en prod multi-analystes) : marqueur d'acceptation `ocular:accepted:{id}` avec TTL (`OCULAR_JOB_TTL`, 1800s) posé à la soumission, retiré par `set_result`. `GET /jobs` : résultat présent → terminal ; sinon marqueur présent → **pending** ; sinon → **unknown** (TERMINAL). UI : vue Jobs + détail traitent `unknown` comme terminal (arrêt du polling, pastille « expiré », bouton « Nettoyer les terminés » qui purge le `localStorage`).

**Correctifs 3e passe (même retour, 2026-07-16, 580 tests) :**
- **Crop bas/droite PERSISTANT** (xdotool insuffisant) → vraie solution : **matchbox-window-manager** (WM kiosk) ajouté à l'image recon-vnc + lancé dans `entrypoint_vnc.sh` → la fenêtre Camoufox est mise en **plein écran** sur l'Xvfb 1280×720, plus aucun crop. (Helper xdotool `_fit_browser_window` retiré, remplacé par le WM.)
- **« Agrandir » n'ajoutait que du gris** (contenu limité par la largeur) → le cadre passe désormais en **pleine largeur** (breakout `width:100vw; margin-left:calc(50% - 50vw)`) + haute → le rendu 16:9 grossit vraiment.
- **Turnstile non passé en mode SCRIPTÉ** (static URL + steps) : `capture_scripted` ne résolvait PAS le Turnstile → le script (sleep/full_page/selecteur…) tournait sur la page de challenge. Fix : `solve_turnstile` appelé **avant** `run_steps` (même mécanique que `capture_url`), `turnstile_solved` propagé au résultat. Test : ordre turnstile→steps + propagation.
- **Ordre toggle** : finalement **URL à gauche, HTML à droite** (correction du retour) sur les deux formulaires, + **URL sélectionné par défaut** sur le formulaire static.
- **Formulaires & mailto AVANT les URLs** dans le résultat détail ET le panneau live (signal d'exfiltration prioritaire).
- **DSL scripté — seules les captures demandées** : suppression du screenshot auto « post-turnstile » dans `capture_scripted` (le Turnstile reste résolu, mais n'ajoute plus de capture parasite) → un `capture full_page` ne donne QUE la page entière, un `capture` après un clic ne donne QUE l'état post-clic.
- **Crop interactif (footer + droite)** : Xvfb passé de 1280×720 à **1920×1080** (viewport bien plus grand) + matchbox plein écran + `scaleViewport` (montre tout le framebuffer, letterbox, jamais de crop droite/bas). Choix ROBUSTE assumé plutôt que le resize dynamique client-driven (`resizeSession`+xrandr, fragile avec Xvfb+matchbox : risque de non-re-maximisation = pire). Le bas d'une page très longue reste au défilement / à la capture full-page (inhérent à un viewport live).

## ✅ Phase 3m — audit holistique (sécu + correctness + qualité) + remédiation (2026-07-16) — LIVRÉE

Deux passes d'audit adversarial multi-agents (Opus) : (A) **sécu réseau/pivot** (3 agents) → `docs/DEPLOY-SECURITY.md` + durcissement (prefs navigateur QUIC/WebTransport/loopback/DNS-prefetch fermés `engine/browser_prefs`, mode strict `OCULAR_REQUIRE_EGRESS_GUARD` fail-closed + propagation runners, résiduels L3 documentés). (B) **holistique** (5 agents : sécu backend, sécu frontend, correctness engine/runners, correctness web/broker/bus, qualité/archi). Suite **594 tests / 0 échec**. Remédiation des points confirmés :

**Sécu :**
- **[HIGH] ReDoS** `engine/static.py` : patterns urgence EN non bornés (`verify.*account` → 38s CPU sur 240KB) + cousins non-EN `\w*` (exposés par un test renforcé) → tous bornés (`.{0,20/25}`, fusion des quantificateurs adjacents). Broker mono-thread = DoS évité. Test ReDoS durci (inputs mot-clé répété).
- **[MOYEN] Clickjacking** : CSP `frame-ancestors 'none'` + `X-Frame-Options: DENY`.
- **[FAIBLE] `/saved/lookup`** : URL malformée → 422 (plus de 500).

**Correctness :**
- **[HIGH] Crash broker → perte de job** : `process_one` encapsulé try/except (un hoquet Redis dans `set_result` ne tue plus le broker ; job marqué en erreur).
- **[MOYEN] Tri-état Turnstile en batch/scripté** : `solve_turnstile` → `Optional[bool]` (None = aucun challenge) → fini le faux « Turnstile non passé » sur toute page sans challenge (le cas courant).
- **[MOYEN] Reaper vs session active** : `/live` et `_ws_pump` réarment `mark_connected` (M1+M2 : session pollée/WS-flap plus détruite à tort).
- **[FAIBLE]** fuite garde egress sur échec de lancement (try/except `_ensure_browser` + import Camoufox dans le `try`) ; `/goto`+`/load` → 400 (plus de 500) ; index UNIQUE `label` (fin du TOCTOU d'unicité) ; marqueur `accepted` rafraîchi au dépilage (anti faux « expiré » sous file profonde).

**Qualité (gains sûrs) :** dé-dup des constantes JS (`engine/browser_js` : CF indicator + scroll-to-load) ; code mort retiré (`sha256_ref`, UI `removeJob`/`VERDICT_LABEL`) ; `conftest.py` autouse `dependency_overrides.clear()` (bug latent d'ordre des tests). **Différés (proposés, non faits)** : split `web/app.py` (middleware/internal_http), extraction helpers UI (rangée réseau/console/exfil), consolidation des 8 factories `_client` de test, `_FakeRedis`→`fakeredis`. **Confirmé solide** (à ne pas régresser) : SQLi paramétré, injection commande, path traversal, auth/authz, secrets/logs, désérialisation, XSS UI, pinning SSRF, seccomp/cap-drop.

## ✅ Audit holistique (sécu + correctness + qualité) post-3o — REMÉDIÉ (2026-07-18, 655 tests / 0 échec)

3 auditeurs Opus indépendants (read-only) sur tout le dépôt, modèle de menace prod/entreprise. **0 Critical permettant exécution de code / évasion conteneur / accès non-auth.** Corrigés :
- **SSRF NAT64 (Critique)** : `is_ip_allowed` décidait sur `is_global`, qui classe « globale » une IPv6 NAT64/6to4/IPv4-mapped traduisant vers une IPv4 interne (`64:ff9b::a9fe:a9fe` → metadata cloud en réseau DNS64/NAT64). Décide désormais sur l'IPv4 encapsulée. Doc L3 complétée.
- **Reaper figé (Critique)** : une TOCTOU `touch`/`delete` créait un hash Redis partiel qui faisait planter le reaper à vie (fuite de TOUS les conteneurs de session). `expired()` auto-guérissant (ignore+supprime les hash partiels) + `hset` atomique conditionné (anti-résurrection).
- **Calibration (Important)** : une seule sauvegarde malformée avortait toute la calibration → tolérance par-ligne.
- **Monolith (Important, Q1)** : bloc LLM (~210 l, 5 classes) extrait `web/app.py` → `web/llm.py` (1020 → 807 l).
- **Duplication (Important, Q2)** : `_saved_conn()` → context manager `saved_conn()` (supprime 9× `try/finally close`).
- **Divers durcissements** : `_validate_weights` impose `medium<high` ; `agrees_with_rules` Optional (plus de badge « diverge » sur verdict unknown) ; cap réponse LLM 512 KiB (anti-OOM) ; note anti-injection-de-prompt ; `set_result` ttl>0 ; `create_saved` json.loads gardé ; **plafond de sessions concurrentes (429)** ; **compose `OCULAR_REQUIRE_EGRESS_GUARD=1` par défaut**.

**Confirmé solide (auditeurs)** : séparation de privilèges (web sans docker.sock), sandbox conteneurs (seccomp deny-défaut, cap-drop ALL, non-root, `--network none` analyse), egress pin anti-rebinding + no-redirect, injections SQL/commande/traversal/XSS systématiquement fermées, ReDoS borné, secrets jamais loggés/committés, numpy test-only.

**Backlog post-audit — traité (2026-07-18)** : ✅ cap taille DOM/screenshot côté runner (`ResultBuilder`, `OCULAR_MAX_ARTIFACT_BYTES`) ; ✅ helpers UI `verdictPill`/`fmtIso`/`shortHash`+`TONE_STYLE` → `core.js` ; ✅ accessor `artifacts_dir()` ; ✅ `httpError()` factorisé dans `api.js`.

- ~~**Isolation VNC inter-sessions**~~ → **✅ FERMÉ (2026-07-18)** : un réseau docker par session (`ocular-sess-net-{id}`), le broker y attache dynamiquement le web ; deux sessions sont sur des réseaux disjoints. Le VNC-passwd (DES 8 char) a été écarté comme fausse sécurité. Prouvé par un test d'intégration (A ne joint pas B, la sonde-web joint les deux). **Confirmé e2e sur la stack déployée (2026-07-18)** : deux sessions réelles → deux réseaux disjoints contenant chacun exactement `{sa session, ocular-web}` ; A ne joint ni le `:6080` ni le `:8090` de B ; `/live` et une capture réelle (screenshot + triage) transitent par le web ; le teardown supprime conteneurs **et** réseaux, zéro résidu. Corollaire : le broker n'étant attaché à aucun réseau de session, il n'est plus joignable du tout depuis une session. Prérequis opérateur : élargir `default-address-pools` de Docker (cf. DEPLOY-SECURITY §2.3).

## ✅ Phase 3n — refactors qualité (dette de l'audit 3m) — LIVRÉE (2026-07-16, 594 tests / 0 échec)

Refactors **comportement-préservant** (tests verts + redéployé), aucun rewrite.

1. **Helpers UI partagés** (`web/ui/filter.js`) : `networkRow`/`consoleLine`/`exfilFormRow`/`exfilMailtoRow` + constantes `CONSOLE_FIELD_DEFS`/`SEV_CLASS`/`VERDICT_CLASS` ; `fmtIso`/`shortHash`/`verdictPill` exportés une fois (detail/interactive/jobs/admin/submit importent). ~60 lignes dupliquées supprimées (dont le rendu exfil, dont la dérive = risque sécu).
2. **Split `web/app.py`** : `web/internal_http.py` (`_internal_*` + `CaptureError`) + `web/middleware.py` (`MaxBodySizeMiddleware`) + `_check_admin` extrait de `_auth`. ~170 lignes hors de app.py. `_auth`/`_csp`/`_body_size_guard` (petits, ordre-sensible = sécu) laissés en place volontairement.
3. **Tests** : `_FakeRedis` maison remplacés par `fakeredis` réelle (fin de la scan_iter divergente) ; assertion explicite « token jamais renvoyé dans le sous-protocole WS ». La consolidation des 8 factories `_client` **écartée** (elles DIVERGENT réellement : formes de retour, `tmp_path`, params — forcer une fixture = sur-ingénierie que le codebase évite).
4. **Factorisation moteur** : `engine/egress_policy.py` (décision garde + kwargs Camoufox durcis, source unique — les deux tiers y passent, plus de dérive des chaînes d'avertissement sécu) ; `wrapper_payload()` dans `engine.wrapper` (partagé stdout/HTTP). `_dom_info→engine` laissé (marginal, flux tri-état délicat).
5. **Nit** : `SessionRegistry.client` (propriété) au lieu de `registry._r` cross-module.

**Écarté (sur-ingénierie, cf. audit)** : fusion `build_result`/`build_capture_result`, unification des `FakePage`, split `core.js`, consolidation des factories `_client`.

## ✅ Phase 3o — couche IA/ML de triage + 2e avis + calibration — LIVRÉE (2026-07-18, 629 tests / 0 échec ; Docker 627+2 skip node)

Couche **native, résource-consciente**, purement additive : elle **complète** le verdict règles sans jamais l'écraser (`compute_verdict` intact byte-for-byte). Spec/plan : `docs/superpowers/specs|plans/2026-07-18-triage-ia-ocular.*`.

1. **Scoreur linéaire transparent** (`engine/triage.py` + `engine/triage_weights.py`, pur-Python 0 dép runtime) : score de triage 0-100 **entièrement décomposable** (Σ des contributions affichées == score, invariant tenu même sous clamp/arrondi), un **2e avis** (`second_opinion`) dérivé des seuils, `agrees_with_rules` vs le verdict règles. Calculé **une seule fois** dans `ResultBuilder.build()` (les 4 sites runner inchangés). Poids surchargeables via `OCULAR_TRIAGE_WEIGHTS`, **fail-safe** (fichier illisible/malformé → BUILTIN + signal `weights_load_error`, ne lève jamais, résistant à `python -O`).
2. **Persistance + tri/filtre** : colonnes `triage_score`/`triage_band` (migration idempotente, NULL rétro-compat) ; `GET /saved?sort=&order=&min_band=` validé **whitelist-avant-interpolation** (anti-injection) → 422 hors-enum.
3. **UI explicite** (`web/ui/triage.js` helpers **purs** node-testés + panneau dans `detail.js` + pastille/tri dans `saved.js`) : priorité/100 + bande + 2e avis + badge « diverge du verdict règles » + décomposition des signaux + `weights_version`. Tout en `textNode` (jamais `innerHTML`).
4. **Calibration ML hors-ligne** (`tools/calibrate_triage.py`, `make calibrate`) : régression logistique multinomiale **numpy** (déterministe, graine fixe) sur les `analyst_verdict` accumulés, **rejoue `extract_signals`** (une seule source de features, pas de dérive train/serve), **refuse sous seuil de données**, sortie **relue puis activée à la main** par l'opérateur. numpy = **test/offline uniquement** (absent des images runtime). Conteneur jetable, zéro résidu host.
5. **Option LLM d'explication** (`POST /jobs/{id}/explain`) : **off par défaut** (opt-in `OCULAR_LLM_ENABLED`+`_BASE_URL`), OpenAI-compatible (Ollama), **passe par la garde egress** (`validate_capture_url` avant tout appel ; `OCULAR_LLM_ALLOW_INTERNAL` scope l'hôte configuré), **résumé whitelist** (verdict/triage/findings rule+severity/forms action+method — **jamais** HTML brut/artefacts/screenshots/post-bodies, prouvé par test). Sortie LLM rendue en `textNode`. Note d'aide, **jamais** un verdict.

**Sécu** (revue finale opus, 0 Critical/0 Important) : en configuration par défaut, **zéro nouvel egress, zéro nouveau chemin de privilège** ; séparation web→Redis→broker→runner inchangée.

**Décisions notables** : `obfuscation_cluster` 35→50 (poids provisoire calibrable) ; ML natif **avec les données** (heuristique day-1 → classifieur appris à la calibration), pas de modèle pré-entraîné embarqué (pas de dataset fiable).

**⏳ Backlog post-merge (Minors, non bloquants)** :
- ~~`obfuscation_cluster` medium-only divergeait du verdict règles~~ → **✅ FERMÉ (2026-07-18)** : poids 50→**65** (base+65 ≥ high) ; un cluster d'obfuscation ≥2 (même medium) atteint la bande *high* → 2e avis `malicious`, aligné sur `compute_verdict` (plus de fausse divergence sur le signal malveillant le plus fort ; le 2e avis garde sa liberté de diverger sur les signaux plus faibles).
- ~~**`calibrate` pas strictement read-only**~~ → **✅ FERMÉ (2026-07-18)** : `saved_store.connect_readonly()` (`mode=ro`, sans `_migrate`) ; la calibration ne mute plus la base (test : écriture rejetée).
- ~~**DNS-rebinding LLM**~~ → **✅ FERMÉ (2026-07-18)** : appel LLM **épinglé sur l'IP résolue** (`resolve_allowed_ip` + connexions custom, vérif TLS préservée) ; **aucune redirection suivie** et **proxies d'env ignorés** (sinon le pin sauterait) — un 3xx cross-scheme d'un endpoint hostile ne peut plus atteindre un hôte interne. Audit adversarial : Critical redirect-SSRF trouvé puis fermé + re-vérifié.
- ~~**Filtre `min_band` pas exposé en UI**~~ → **✅ FERMÉ (2026-07-18)** : sélecteur de priorité (toutes / triées / ≥ moyenne / haute) dans la vue Sauvegardes, `GET /saved?min_band=…` (filtre SQL serveur).
- ~~**Arrondi JS `Math.round` vs banker Python**~~ → **✅ FERMÉ (2026-07-18)** : `roundHalfEven()` dans `triage.js` (round-half-to-even, comme `round()` Python) → la somme des contributions affichées égale toujours le score, même pour un poids calibré à `.5`.
- ~~Tri `triage_score ASC` place les NULL en tête~~ → **✅ FERMÉ (2026-07-18)** : `ORDER BY (triage_score IS NULL), …` → les analyses sans triage finissent toujours en bas (les deux sens). *(Reste : le message du commit `f461d4b` dit « indexées » sans index créé — cosmétique, historique mergé, non réécrit ; YAGNI au volume actuel.)*

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

> **État — PHASE 3d COMPLÈTE (A–J tous mergés) :**
> - **3d-1** : ✅ A verdict · D nom unique · E GC planifié · F upload .htm/.html · G bandeau CSS · H schéma URL+fallback.
> - **3d-2** : ✅ **I** filtrage SOC (`filter.js`, structuré, sans ReDoS) · ✅ **C** interactif (panneau live pollé/filtrable, fermeture auto onglet 60s + fermeture brutale `disconnected_at`/reaper grâce, sauvegarde) · ✅ **B** Turnstile (mapping viewport→écran `mozInnerScreen` + retry — **VALIDÉ EN DIRECT sur guatx.com** : `img=(315,337)→screen=(315,398)`, `solved=True`) · ✅ **J** recalibration verdict (re-tier + corroboration phishing/obfuscation — login légitime=benign, phishing/malware=malicious, faux négatifs audités+corrigés, EN+FR).
>
> **Suivis (dette, non bloquants)** : (a) Turnstile — le retry ajoute ~4s à toute capture ; gater sur un indicateur Cloudflare (iframe `challenges.cloudflare.com`) pour ne payer le délai que quand un challenge existe. (b) Interactif — le poll `/live` ne réarme pas `mark_connected` (ok tant qu'il n'y a pas de reconnect auto RFB). (c) Langage d'urgence phishing : EN+FR couverts ; autres langues rattrapées par le cluster form-externe mais patterns dédiés = dette.

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

## ✅ Phase 3e — Identité IdP + verdict analyste + provenance (mergé)

- **Identité forward-auth** (opt-in strict `OCULAR_TRUST_FORWARD_AUTH`, défaut OFF) : compatible Keycloak/Authentik/Authelia/oauth2-proxy/LDAP via n'importe quel reverse-proxy ; en-têtes configurables ; bearer = fallback ; anti-spoofing prouvé (opt-in OFF → header ignoré → 401) ; admin non escaladable ; `GET /auth/whoami`.
- **Verdict analyste** : `POST /saved/{id}/verdict` (legitimate/suspicious/malicious + note, qui/quand) — le verdict auto n'est jamais écrasé.
- **Provenance** : sauvegarde = hash + timestamp + `saved_by` (identité) + `turnstile_solved` ; migration SQLite idempotente. UI : bandeau whoami + provenance + contrôles verdict analyste (XSS-clean).
- Impératif déploiement (README) : proxy DOIT stripper l'en-tête client, garder `OCULAR_TOKEN` comme filet, `web` jamais joignable en direct.

## ✅ Phase 3f — Dette technique / durcissement (mergé)

- **Gating Turnstile** : détection vision (~4s) seulement si un indicateur Cloudflare est présent (poll de l'indicateur car injecté async — validé live : example.com sans tentative, guatx.com `solved=True`).
- **Dédup Camoufox** `_capture_dom` (une source) ; `final_url` retombe sur `url` sur exception.
- **Finalisation DOM sous `asyncio.wait_for`** (résultat partiel garanti).
- **Plafond de corps ASGI** : coupe réellement le chunked (sans Content-Length) → **413** (prouvé e2e réel ; l'ancienne version levait une exception avalée par les BaseHTTPMiddleware).

## ✅ Phase 3g — SSRF egress guard (mergé)

Ferme le trou SSRF résiduel (redirections + DNS-rebinding que `validate_capture_url` ne couvrait pas). Proxy HTTP/CONNECT **dans le runner** (`engine/egress_guard.py`) : résout → **épingle l'IP** (pas de re-résolution → défait le rebinding) → `is_global` sinon 403 ; chaque redirection = nouveau CONNECT re-vérifié. WebRTC désactivé (ferme le canal UDP ICE qui contournait le proxy TCP), multicast rejeté. Secure-by-default (`OCULAR_EGRESS_GUARD`, ON ; `=0` pour analyser une cible interne de confiance). Audité (aucun bypass de parsing) + e2e réel (interne bloqué, redirection bloquée, guatx résout à travers, WebRTC off prouvé).

> **Leçon opérationnelle (récurrente)** : un e2e complet doit rebuild **les images runner** (`docker build -f runner_*/Dockerfile`) **ET** les services compose (`docker compose up -d --build` pour web/broker). `compose up -d` seul réutilise des images stale → faux résultats (vu 2× : verdict « malicious », body-cap « 422 »).

## ✅ Phase 3j — Finitions UX + interactif + capture (retour utilisateur 2026-07-15) — LIVRÉE

**Statut** : tous les items ci-dessous livrés le 2026-07-15. Suite dockerisée **564 passés / 0 échec** (18 nouveaux tests : DSL sleep/hide/capture région+full_page, tri-état Turnstile, dédup+filtre console). Schéma `schemas/result.schema.json` régénéré (StealthInfo.turnstile_solved tri-état). Nettoyage : aucun résidu cache/tmp hôte (py compile hôte purgé ; tests exécutés en conteneur).

Résumé des correctifs livrés :
- **Admin token** : footgun `.env` corrigé (valeur `ocular-admin-change-me` + commentaires explicites au lieu de `change-me-or-leave-empty…` illisible) ; aide UI « valeur EXACTE de OCULAR_ADMIN_TOKEN ». Backend inchangé (déjà correct, e2e couvert par test_saved_admin).
- **Turnstile « non passé »** : `turnstile_solved` tri-état (True/False/None) ; None=aucun challenge → aucun badge (plus de faux « non passé ») ; case « Turnstile passé » (déclaration manuelle) relayée au /capture.
- **URL guatx.com/http/https** : champ UI `type="text"` (fini le rejet natif du domaine nu) ; normalisation serveur canonique (déjà correcte).
- **Interactif** : capture `full_page=True` (fini le ~1/3 visible) ; zoom scène ajusté↔1:1 (pan) ; console live + filtre exclure/rechercher + dédup ; réseau dédup ×N ; bouton « Enregistrer la capture » (terme capture).
- **Static/DSL** : verbes `sleep`, `hide`, `capture` étendu `{label, full_page}` (page entière) / `{label, selector}` (région).
- **Console/URL dédup natif** (×N) + **filtre console** (champs text/level) à parité réseau.
- **Nettoyage sessions** : balayage des orphelins `ocular-sess-*` au démarrage broker + cible `make down` (compose ne retire pas les conteneurs hors-compose).
- **Favicon/SVG** : glow retiré (plus flash), teinte `#00d4aa`, amande agrandie (iris ne déborde plus).
- **Process** : travail réalisé directement (aucun agent Sonnet).

**Process (consignes utilisateur)** : agents **Opus uniquement** (plus de Sonnet) ; favicon/SVG à la teinte **exacte** de guatx.com (`#00d4aa`) mais **sans effet flash** (c'est le glow néon le coupable, pas la teinte).

### Bloquants
- **Admin par `X-Admin-Token` non pris en compte** : impossible de supprimer/purger avec le `.env` de base. Backend : `OCULAR_ADMIN_TOKEN` EST résolu par compose (= valeur placeholder du `.env`). → Investiguer le flux UI (token saisi → `deleteSaved`/`flushSaved` → 403/503), rendre ÉVIDENT quel token entrer (placeholder trompeur ?), et vérifier que le fix admin 3h/3j n'a rien cassé. **e2e réel obligatoire** (DELETE /saved avec le token du .env → 200).
- **Turnstile « non passé » à tort** : la capture interactive enregistre « Turnstile non passé » alors que l'analyste l'a passé **manuellement**. En interactif le solve est manuel → ne pas afficher « non passé » (détecter l'absence d'indicateur CF dans le DOM au moment de la capture, ou marquer « manuel / N.A. »).

### Interactif — vue & capture
- **Navigateur complet non visible, pas de zoom/dézoom** : la scène noVNC est limitée → permettre zoom/scale et voir toute la page.
- **Capture ne prend que le visible** (~1/3 de page) : `session_server /capture` fait `full_page=False` → passer en **full-page** (et au-delà du viewport).
- **Console interactive live** : doit s'actualiser selon les appels de la page (comme le réseau) — vérifier/renforcer le poll `/live`.
- **Nettoyage des sessions** : garantir que les conteneurs de session se nettoient (pas d'orphelin ; `docker compose down` ne gère PAS les conteneurs lancés par le broker hors-compose sur `ocular-sessions` — reaper/DELETE doivent couvrir).
- **Renommer** : l'enregistrement interactif → terme « **Capture** » (pas « Sauvegarde ») ; unifier capture vs sauvegarde.
- **Enregistrer l'interactif** : garantir que ça marche de bout en bout (le fix store_blobs 2026-07-15 corrige le 500 ; revérifier après les changements ci-dessus).

### Résultats — filtre & dedup
- **Console filtrable** : même filtre exclure/rechercher que le réseau (réutiliser `filter.js`).
- **Dedup natif URL (réseau) + console** : dédupliquer les entrées identiques (avec compteur d'occurrences).

### Static / capture / DSL
- **Capture full-page en static** (pas seulement le viewport).
- **Actions de capture** : `sleep`, `click`, `hide` (masquer un élément), **capturer une région** seulement — au-delà du DSL scripté 3c existant.

### URL — formes d'entrée
- Gérer `guatx.com`, `http://guatx.com`, `https://guatx.com` en **API ET UI** : normalisation `normalize_url` (H) à vérifier/étendre côté UI ; **respecter `http://` si fourni** (ne pas forcer https) ; l'UI ne doit pas rejeter un domaine nu.

### Favicon / SVG
- **Trop flash** : retirer/atténuer le glow néon ; teinte exacte guatx `#00d4aa`.
- **Proportions** : l'amande (oval) est trop petite vs l'iris rond → l'iris déborde de l'amande. Corriger.

## ⏳ Différés techniques (dette identifiée par les audits, non bloquante)

Nécessitent un **design/plus gros chantier** (pas juste de la dette de code) :
- ~~**SSRF — DNS-rebinding & suivi de redirections**~~ → **✅ FERMÉ (phase 3g)** : egress guard dans le runner (proxy HTTP/CONNECT + résolution+**pinning IP** + `is_global`), WebRTC désactivé (canal UDP ICE), multicast rejeté. Validé e2e (interne bloqué, redirection 302→IP interne bloquée, rebinding défait, guatx résout à travers). **Résiduel (défense en profondeur, non bloquant)** : un **filet L3 egress réseau** au niveau déploiement (iptables / réseau docker restreint sur les conteneurs runner) couvrirait tout canal non-proxy — responsabilité opérateur, comme le strip forward-auth.
- ~~**Mapping groupes IdP → rôles (admin)**~~ → **✅ FAIT (phase 3h)** : `OCULAR_ADMIN_GROUP` + `X-Forwarded-Groups` (opt-in strict, membership exact) accorde l'admin ; `X-Admin-Token` reste fallback ; `whoami` expose `is_admin`/`groups` ; UI masque les contrôles admin. Audité (pas d'escalade/spoofing) + e2e. *(Reste possible : rôles plus fins que admin/non-admin — viewer/analyst — si besoin futur.)*
- **Validation OIDC JWT in-app** (3e) : valider un JWT (iss/aud/exp via JWKS) pour un Keycloak/Authentik **sans** reverse-proxy. Le forward-auth couvre déjà le cas proxifié (le plus courant).
- ~~**VNC-passwd par session (3b)**~~ → **✅ SANS OBJET (2026-07-18)** : le besoin était de protéger le `:6080` (websockify/x11vnc sans auth propre) d'un conteneur de session pair. Réglé par l'**isolation réseau par session** (un réseau docker dédié par session, web attaché dynamiquement) — deux sessions n'ont plus aucune route l'une vers l'autre. Le VNC-passwd (DES 8 caractères) a été **écarté comme fausse sécurité** : il aurait donné l'illusion d'une protection tout en restant cassable. Prouvé par `tests/test_session_isolation_integration.py` **et** vérifié e2e sur la stack déployée.
- **`/goto` initial peut échouer sur une session fraîche (UX, pré-existant 3b)** — `POST /sessions` attend que `/health` du `session_server` réponde, mais `/health` répond dès qu'uvicorn est up, **avant** que Camoufox soit lancé (le navigateur est créé paresseusement par `_ensure_browser`). Le web appelle donc `/goto` trop tôt : il échoue (`session goto/load failed`) et l'analyste arrive sur une **page vide** au lieu de l'URL demandée. Observé en e2e réel (2026-07-18) : session créée à `17:53:49`, `/goto` en échec à `17:53:58` (~9 s). **Non bloquant** — la session reste utilisable (navigation manuelle OK, capture ultérieure réussie avec screenshot + triage). **Correctif** : soit `/health` ne renvoie OK qu'une fois le navigateur prêt (readiness ≠ liveness), soit `/goto` réessaie avec backoff. La 1re option est la plus propre : elle rend `_wait_session_ready` réellement significatif.
- ~~**Langage d'urgence phishing multilingue**~~ → **✅ FAIT (phase 3i)** : EN/FR/**ES/DE/PT** (12 patterns rejoignant le cluster `_URGENCY`, ReDoS-safe, anti-faux-positif). *(Autres langues au besoin.)*
- ~~**Bug `urlnorm` sur `data:`**~~ → **✅ FAIT (phase 3i)** : `normalize_url` robuste (schemes non-réseau/malformé → rejet propre 400, plus de crash 500).
- **poll `/live` → `mark_connected`** (C) : uniquement si un reconnect auto RFB est ajouté un jour (sinon sans objet).

---

## 🧩 Sous-projets (hors phase 3)

- **Adaptateur plume** — intégration d'Ocular dans plume (le tier analyse/capture surtout ; `forge` = red team, moins pertinent). **Ne pas modifier plume ; construire l'adaptateur côté Ocular.**
- **Publication GitHub `xguatx`** — licence, mentions légales, CI (la garde e2e `test_deploy_images` couvre déjà le smoke des images), doc auth/secrets portable (OIDC/LDAP/reverse-proxy, `.env`/Vault/SOPS).

---

*Dernière mise à jour : 2026-07-18 (après merge phase 3o — triage IA/ML). Voir `docs/superpowers/specs/` et `docs/superpowers/plans/` pour le détail de chaque phase.*
