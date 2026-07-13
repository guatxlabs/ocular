# Ocular — Phase 3c : Tier dynamique scripté — Design

- **Date** : 2026-07-13
- **Statut** : Approuvé (design), prêt pour plan
- **Base** : moteur mergé (analysis + capture 3a + sauvegardes + interactif 3b). Ajoute le **tier dynamique scripté** : un **script d'actions déclaratif** rejoue une séquence (remplir → cliquer → attendre) pendant qu'on enregistre TOUT le réseau, pour révéler les appels qui ne partent qu'**après interaction**. **Dernière phase** de la roadmap phase 3.

---

## 1. But & modèle de menace
Besoin SOC : un phishing multi-étapes / un JS qui ne **beacone qu'au clic ou au submit** / une redirection conditionnelle ne se voient pas avec une capture passive (3a) ni ne justifient une session humaine (3b). On veut **rejouer automatiquement une séquence bornée d'actions** et capter les appels réseau **post-interaction** de façon **déterministe et reproductible**.

Contenu **hostile + réseau ON + scripté** → mêmes garde-fous que 3a, plus la **surface du DSL** (à border strictement).

## 2. Décisions figées
| # | Décision |
|---|----------|
| C1 | **DSL déclaratif borné** (verbes en allowlist), **PAS de JS arbitraire**, **aucun `eval`**. Chaque step validé par schéma avant tout lancement. *(tranché avec l'utilisateur)* |
| C2 | **One-shot éphémère façon 3a** : réutilise le runner `runner_recon` (Camoufox, réseau ON, durci, `--rm`) + un **exécuteur de steps**. Pas de conteneur persistant, pas de noVNC. *(tranché avec l'utilisateur)* |
| C3 | Verbes : `goto` · `fill` · `click` · `wait` · `press` · `capture` · `scroll`. Sélecteurs CSS/texte passés à l'**API locator Playwright** (jamais interpolés dans du code → pas d'injection). |
| C4 | Steps transmis au runner via **stdin** (JSON), **pas via env/arg** → les valeurs (`fill`) n'apparaissent **pas** dans `docker inspect`/`ps` (ligne « pas de fuite de secret »). |
| C5 | Résultat = `OcularResult` enrichi d'un **journal d'actions** + **screenshots labellisés** (`capture`) + la trace réseau complète. Coule dans le pipeline existant (broker→web→UI→sauvegardes). |
| C6 | SSRF (`validate_capture_url`) réutilisé sur l'URL initiale **ET** chaque `goto`. Plafonds : nb de steps, longueur sélecteur/valeur, `wait` max, **timeout d'exécution total** (kill des scripts qui traînent). |

## 3. Le DSL (contrat)
Entrée : `{"url": "<url initiale>", "steps": [<step>, ...]}`. Chaque step = objet **mono-clé** :

| Step | Forme | Sémantique | Bornes |
|------|-------|-----------|--------|
| `goto` | `{"goto": "https://…"}` | navigue | SSRF-validé (http/https, `is_global`) |
| `fill` | `{"fill": {"sel": "<css>", "value": "<str>"}}` | remplit un champ | `sel` ≤ 500, `value` ≤ 2000, **value jamais loggée en clair** |
| `click` | `{"click": "<css>"}` | clique | `sel` ≤ 500 |
| `wait` | `{"wait": 1500}` ou `{"wait": {"selector": "<css>"}}` | pause ms **ou** attend un sélecteur | ms ≤ 30000 ; timeout sélecteur ≤ 30000 |
| `press` | `{"press": "Enter"}` | touche clavier | allowlist de touches (`Enter`, `Tab`, `Escape`, `ArrowDown`…, ≤ 20 chars) |
| `capture` | `{"capture": "<label>"}` | screenshot labellisé dans le résultat | `label` ≤ 64, `[\w .:-]` |
| `scroll` | `{"scroll": "bottom"}` / `"top"` / `{"scroll": 500}` | défile | px ≤ 100000 |

Global : `len(steps) ≤ 50`. Un verbe hors allowlist, un step multi-clé, une borne dépassée → **rejet (400/422) avant dispatch**, message clair. Un `capture` final implicite est toujours ajouté (état de fin garanti).

`engine/steps.py` : `validate_steps(raw: list) -> list[Step]` (lève `StepValidationError` avec le motif). **Partagé** web (validation à la soumission) ET runner (re-validation défensive avant exécution) — DRY, jamais deux implémentations.

## 4. Architecture
```
POST /jobs {url, steps}  ──▶ [ web ]  valide steps (schéma+SSRF+bornes) ─▶ file Redis
                                                                              │
                                        [ broker ]  docker run --rm -i runner_recon
                                          steps(JSON) ──stdin──▶ [ runner_recon (mode scripté) ]
                                                                   Camoufox headed + NetworkCapture ON
                                                                   rejoue steps via locator API
                                                                   screenshots @capture + journal
                                                                   engine.wrapper ─▶ OcularResult(base64)
                                        broker stocke artefacts + résultat ◀────────┘
                                          UI : journal d'actions + galerie screenshots + trace réseau
```
- **Runner** (`runner_recon`, mode scripté) : lit `{url, steps}` sur **stdin**, `validate_steps` (défense en profondeur), `goto(url)`, arme `NetworkCapture`, exécute chaque step (`page.locator(sel)` / `page.fill(sel, val)` / `page.click` / `wait_for_*` / `keyboard.press` / `mouse.wheel|evaluate(scroll)`), journalise `{index, verb, ok, ms, error?}` (valeurs `fill` **redigées**), screenshot à chaque `capture` + final, `emit_wrapper` (réutilise `engine.wrapper`). Timeout total (wall-clock) → arrêt + résultat partiel `status:error`.
- **Broker** : profil job = `capture` **avec `steps`** → chemin scripté ; `docker run --rm -i` (durci 3a inchangé : non-root, cap-drop ALL, seccomp-recon, réseau ON sans docker.sock/host-net, mem/pids, timeout conteneur), écrit `{url, steps}` sur le stdin du conteneur. Sans `steps` → 3a inchangé.
- **Web** : `POST /jobs` accepte `steps` optionnel ; `validate_steps` + SSRF (url + chaque `goto`) **côté serveur** avant enqueue ; refus borné. Résultat expose `actions` + screenshots labellisés.
- **UI** : formulaire scripté (textarea JSON + exemples + retour de validation), rendu **XSS-clean** du journal d'actions et galerie de screenshots (protections artefacts existantes : nosniff, DOM jamais inline).

## 5. Sécurité (delta, purple team)
| Risque | Défense |
|--------|---------|
| Injection via sélecteur/valeur | API **locator** Playwright (`sel`=sélecteur, `value`=littéral) ; **jamais** `$eval`/interpolation ; aucun verbe `eval` |
| Steps hostiles / DoS | allowlist verbes, bornes (nb steps, tailles, `wait`, **timeout total**), rejet avant dispatch |
| Fuite des valeurs `fill` (creds de test) | steps via **stdin**, pas env/arg (absents de `docker inspect`) ; valeurs **redigées** des logs/journal |
| SSRF (url initiale + `goto`) | `validate_capture_url` sur l'url **et** chaque `goto` |
| Escape conteneur (hostile+réseau+scripté) | durcissement 3a inchangé (non-root, cap-drop, seccomp-recon, `--rm`, limites, pas de docker.sock/host-net) |
| Résultat hostile servi inline | `OcularResult` servi avec protections existantes (nosniff, DOM `.txt`, screenshots pixels) |
| Deux validateurs qui divergent | `engine/steps.py` **unique**, importé par web ET runner |

> **Différé (documenté, hérité)** : SSRF DNS-rebinding (egress filter runner) ; beacon réseau du contenu hostile en réseau-ON (inhérent au but « capter les appels », contenu par l'isolation conteneur).

## 6. Tests
- **Unit** : `validate_steps` (chaque verbe accepté ; verbe inconnu / step multi-clé / borne dépassée / `goto` SSRF → rejet avec motif) ; exécuteur (page mockée : chaque verbe appelle la bonne méthode Playwright, valeur `fill` redigée du journal, `capture` ajoute un screenshot labellisé) ; timeout total → `status:error` + résultat partiel ; web `POST /jobs` avec `steps` (valide→enqueue, invalide→422, `goto` SSRF→400).
- **Intégration** : image `runner_recon` (inchangée) exécute un **vrai** script contre une page fixture locale (fill+click+capture) → `OcularResult` avec l'appel réseau **post-clic** capté + screenshots labellisés + journal cohérent ; steps via stdin non visibles dans `docker inspect`.
- **e2e (revue finale)** : `POST /jobs {url, steps}` via web → broker → runner scripté → résultat montre journal + screenshots + trace réseau post-interaction ; `goto` SSRF bloqué ; steps surdimensionnés rejetés ; conteneur bien `--rm` (pas d'orphelin) ; valeurs `fill` absentes de `docker inspect`/logs.

## 7. Ordre de livraison (une branche, SDD)
1. `engine/steps.py` : DSL + `validate_steps` (allowlist, bornes, SSRF sur `goto`) + `Step` typé + unit.
2. Exécuteur de steps runner (`runner_recon/` mode scripté) : lit stdin, re-valide, rejoue via locator API, journal (valeurs redigées) + screenshots `capture`, réutilise `engine.wrapper` ; unit (page mockée) + timeout total.
3. Runner : entrypoint/mode scripté (stdin) + **build réel** + **intégration** (page fixture : fill/click/capture → appel post-clic capté, screenshots, stdin invisible dans inspect).
4. Broker : chemin job scripté (`docker run --rm -i`, steps sur stdin, durci 3a inchangé) + unit (args, stdin, pas de leak env).
5. Web : `POST /jobs` accepte `steps` (validate_steps + SSRF url+goto côté serveur, bornes) + résultat expose `actions`/screenshots + tests.
6. UI : formulaire scripté (textarea JSON + exemples + validation), journal d'actions + galerie screenshots **XSS-clean** ; smoke + vérif navigateur.
7. Ops : `make script URL= STEPS=` (ou fichier), README (3c : usage, DSL, sécu), garde `test_deploy_images` (aucune image nouvelle : réutilise `runner_recon`).
8. **Audit indépendant** (3 auditeurs archi/sécu/qualité) + **e2e réel** (script live, post-interaction capté, SSRF goto, stdin invisible, `--rm`) + merge.

## 8. Défauts assumés
Max 50 steps ; `wait` ≤ 30 s ; timeout total d'exécution 120 s (appliqué côté runner : budget wall-clock → **résultat partiel** émis) ; screenshots 1280×720 (comme 3a) ; DSL JSON (pas de builder visuel — textarea + exemples en MVP) ; `press` en allowlist de touches ; pas de boucles/conditions dans le DSL (séquence linéaire — YAGNI, révèle déjà les phishings multi-étapes courants).

- **Turnstile non géré en mode scripté** : contrairement à 3a (`capture_url` qui tente vision + clic OS), `capture_scripted` ne résout pas de challenge Cloudflare Turnstile. Le tier scripté cible le phishing multi-étapes, pas les sites Cloudflare-protégés. Pour une cible protégée, passer par le tier interactif 3b (humain) ou 3a.

## 9. Différé (tickets de suivi, non bloquants pour le merge 3c)
Relevés par l'audit indépendant (3 auditeurs) ; aucun n'est une faille exploitable de bout en bout ni une régression 3c :
- **SSRF via suivi de redirections HTTP** : `validate_capture_url` valide l'URL au submit, mais `page.goto()` (3a ET 3c) suit les redirections dans le navigateur ; un site public peut répondre `302` vers une IP interne. **Préexistant à 3a**, s'applique identiquement au `goto` top-level et aux `goto` de step. Fix = filtrage egress runner (même chantier que le DNS-rebinding déjà différé). À traiter au niveau isolation réseau, pas dans le DSL.
- **Plafond de corps de requête sans `Content-Length`** : la garde 413 ajoutée couvre les requêtes avec `Content-Length` ; les corps chunked restent bornés seulement par `mem_limit` conteneur. Fix complet = plafond au reverse-proxy/serveur ASGI.
- **Déduplication `capture_url`/`capture_scripted`** : ~20 lignes de pilotage Camoufox dupliquées ; factorisation `_goto_safe`/`_capture_dom` reportée pour ne pas déstabiliser le chemin 3a (couvert par intégration Docker) au gate de merge — les deux chemins sont testés séparément.
