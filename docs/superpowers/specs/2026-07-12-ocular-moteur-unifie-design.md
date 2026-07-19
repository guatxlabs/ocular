# Ocular — Moteur unifié capture + analyse web durci — Design

- **Date** : 2026-07-12
- **Statut** : Approuvé (design), prêt pour plan d'implémentation
- **Auteur** : guatx (+ Claude)
- **Sous-projet** : 1/3 (moteur autonome). Suivants : 2) adaptateur plume, 3) publication publique.

---

## 1. Contexte & problème

Deux outils existants se recoupent et doivent être regroupés, un troisième fournit le
vrai moteur anti-bot :

- `web-screenshot-capture` (**ShotURL v3.0**) — FastAPI + Playwright/Chromium, screenshot + DOM + réseau.
- `malware-html-sandbox` (ex-**analyzerHTMLJS**) — Docker-in-Docker + Playwright, analyse HTML malveillant, static + dynamique.
- `YesWeHack/toolkit/browser-automation` — **conteneur Camoufox + vision + noVNC**, bypass Turnstile/DataDome réel et actif.

### Causes racines du bug historique (isolation cassée)

Le sandbox « n'a jamais correctement isolé » — vérifié dans le code, deux causes structurelles :

1. **Rendu du contenu hostile dans le navigateur hôte.** `secure_analyzer/main.py` (~l.1208-1211)
   crée un `<iframe>` chargeant la session noVNC **dans le Chrome de l'analyste**, avec
   `iframe.allow = 'clipboard-read; clipboard-write'` (pont presse-papier conteneur↔hôte) et
   une popup forçant le Chrome hôte à **accepter le certificat du conteneur** (pollution de
   confiance). → « des appels sur mon chrome direct passé même avec iframe ».
2. **Posture infra permissive.** `docker-compose.yml` : `network_mode: host` + montage de
   `/var/run/docker.sock` sur le tier web + `ALLOW_NETWORK_CAPTURE=true` par défaut. Réseau hôte
   + socket Docker = escape / mouvement latéral quasi libre.

Le design ci-dessous **supprime ces deux causes par l'architecture**, pas par des rustines.

---

## 2. Objectifs / non-objectifs

### Objectifs (v1)
- Un moteur **unifié** capture + analyse, **autonome** (repo indépendant, publiable tel quel).
- **Fix sécu structurel** : plus jamais de rendu hostile dans le navigateur de l'analyste ;
  plus de `docker.sock` ni de `network_mode: host` sur la surface exposée.
- Deux profils : `capture` (recon anti-bot) et `analysis` (HTML/EML hostile isolé).
- Trois tiers d'interaction : capture / dynamique scripté / interactif durci.
- **Schéma de résultat JSON stable** = contrat d'intégration future (plume, FAISS).

### Non-objectifs (explicitement hors v1 — YAGNI)
- Intégration plume/forge/FAISS (sous-projet 2 ; seul le **contrat** est prévu ici).
- Solver Turnstile externe payant (le bypass vision+xdotool couvre le cas courant).
- Orchestration k3s/k8s (Docker durci sur 1 VPS suffit ; point d'extension noté).
- Refonte de guatx-ia-vision (déjà porté dans `vision.py`).

---

## 3. Décisions clés (validées, avec rationale)

| # | Décision | Rationale |
|---|---|---|
| D1 | Outil **autonome**, aucun couplage GUATX ; intégration **plume** plus tard | forge = red team ; plume = purple/blue = bon consommateur. Inversion de dépendance via API+schéma. |
| D2 | **Pixels + dynamique scripté** par défaut, jamais de rendu dans le navigateur hôte | tue le vecteur iframe/clipboard/VNC (cause racine #1). |
| D3 | **3 tiers** : capture / dynamique scripté / interactif durci (tous en v1) | captcha/Turnstile + navigation manuelle de sites malveillants sont des besoins SOC réels. |
| D4 | **Docker durci sur 1 VPS**, broker à privilège séparé | pragmatique, dispo partout ; supprime la cause racine #2. |
| D5 | **Camoufox** (recon) + **Chromium durci** (analyse hostile) | Camoufox = bypass prouvé (Firefox anti-detect) ; Chromium = fidélité victime (malwares ciblent Chrome). |
| D6 | Ancrer sur `browser-automation` (pas ShotURL) | ~80 % du moteur (stealth, vision, noVNC, capture réseau, intercept) déjà construit et fonctionnel. |
| D7 | **Pas** de cloudscraper ; stealth = Camoufox natif | cloudscraper (dans `autoBrowser`) est un résidu qui ne touche pas Turnstile. |
| D8 | Vision→clic (opencv template-match + xdotool OS-click) conservé | c'est CE clic X11 réel (`isTrusted`) qui passe le Turnstile interactif, pas `page.mouse`. |

---

## 4. Architecture

### 4.1 Séparation de privilèges (fondation sécu)

```
client ──HTTP──> [ web ] ──file de jobs (Redis)──> [ broker ] ──docker──> [ runner éphémère ]
                (API + UI                          (SEUL à parler         recon:   Camoufox+vision+noVNC
                 pixel-viewer)                       à Docker)            analysis: Chromium durci
   • pas de docker.sock            • valide/whitelist les specs      • --network none|egress-proxy
   • non privilégié                • lance / détruit le runner       • --cap-drop ALL, seccomp profilé
   • ro-rootfs                     • jamais de chemin hôte passé     • no-new-privileges, ro-rootfs+tmpfs
                                                                     • non-root, limites pids/mem/cpu, --rm
```

- **`web`** — surface publique FastAPI : soumission de jobs, auth, restitution des résultats,
  sert l'UI du pixel-viewer (tier 3). **Jamais** d'accès à `docker.sock`. Non privilégié, ro-rootfs.
- **`broker`** — le **seul** composant avec accès Docker. Consomme les jobs, **valide/whitelist**
  la spec (profil, cible, options), lance **1 conteneur runner éphémère par job**, récupère le
  résultat, détruit le conteneur. C'est la frontière de privilège.
- **`runner`** — le cœur moteur, dans un conteneur durci et jetable. Deux images selon le profil.
- **file de jobs** — Redis (déjà présent chez l'utilisateur). Découple `web` de `broker`.

### 4.2 Deux profils, deux moteurs

| | `capture` / recon | `analysis` / hostile |
|---|---|---|
| Moteur | **Camoufox** (Firefox anti-detect) | **Chromium** (Playwright) durci |
| Réseau | **ON** via proxy journalisé (VPN/Tor opt-in, warning IP) | **none** par défaut |
| Conteneur | réutilisable / prewarm possible | **éphémère, jetable, `--rm`** |
| Base | image dérivée de `browser-automation` | image dérivée de `malware-sandbox` |
| Seccomp | profil dédié (⚠️ ne pas rester en `unconfined`) | profil strict obligatoire |

### 4.3 Trois tiers d'interaction (surtout profil capture)

1. **Capture** — `goto` + screenshot + capture des appels réseau + DOM + console. *(existe)*
2. **Dynamique scripté** — remplir formulaire bidon → clic (`click` / `vision-click`) →
   suivre redirections → capture screenshot+réseau **à chaque étape**. **Turnstile auto** via
   `vision-click-os` (opencv localise la case → clic OS X11 réel). Révèle les **appels
   obfusqués/différés** absents du code source. *(existe en grande partie)*
3. **Interactif durci** (`gateway`) — noVNC **pixels uniquement**, relayé par la **passerelle
   TLS du moteur**, authentifié, **canal entrée souris/clavier seulement**, **zéro presse-papier**,
   réseau conteneur **interne**, session éphémère + timeout d'inactivité. Le navigateur de
   l'analyste ne charge **jamais** l'origine malveillante. *(noVNC existe, à durcir)*

---

## 5. Modèle de menace & durcissement (purple team)

### 5.1 Attaques (red team) → défenses (blue team)

| Attaque | Défense |
|---|---|
| HTML hostile exécute du JS dans le navigateur de l'analyste | Contenu rendu **uniquement** dans le conteneur ; analyste ne reçoit que des **pixels** |
| Vol/injection presse-papier via VNC | **Zéro** pont presse-papier ; canal **entrée seulement** |
| Pollution de confiance TLS (cert du conteneur accepté par l'hôte) | TLS **de la passerelle**, jamais du conteneur |
| Escape conteneur → hôte via docker.sock | `web` **sans** socket ; seul `broker` parle à Docker, avec whitelist |
| Mouvement latéral via réseau hôte | Plus de `network_mode: host` ; runner analysis en `--network none` |
| Exfiltration depuis l'analyse | Egress `none` par défaut (analysis) ; capture via proxy journalisé (recon) |
| Persistance / écriture disque du malware | ro-rootfs + tmpfs ; uploads en **tmpfs seulement** ; `--rm` |
| Escalade de privilèges dans le runner | `--cap-drop ALL`, `no-new-privileges`, seccomp profilé, non-root |
| Épuisement de ressources (bombe) | limites pids/mem/cpu, `shm_size` borné, TTL + kill-switch par job |

### 5.2 Checklist de durcissement (à vérifier par tests)
- `web` : non privilégié, aucun `docker.sock`, ro-rootfs.
- `broker` : seul accès Docker ; valide profil/cible/options ; ne passe aucun chemin hôte.
- `runner` : `--network none` (analysis) / egress-proxy (capture) ; `--cap-drop ALL` ;
  `--security-opt seccomp=<profil>` (jamais `unconfined` en analysis) ; `no-new-privileges` ;
  ro-rootfs + tmpfs ; non-root ; limites ; `--rm`.
- `gateway` : TLS moteur, auth, no clipboard, input-only, réseau interne, session éphémère + timeout.
- uploads : tmpfs uniquement, jamais le disque hôte ; caps de taille ; contrôle content-type.
- egress capture : proxy journalisé par défaut ; VPN/Tor opt-in + warning exposition IP.

---

## 6. Schéma de résultat unifié (ancrage intégration)

Contrat JSON **stable**, validé par un JSON Schema versionné (`schemas/result.schema.json`) :

```jsonc
{
  "schema_version": "1.0",
  "job_id": "…", "profile": "capture|analysis", "target": "…",
  "timestamp": "…", "verdict": "benign|suspicious|malicious|unknown",
  "screenshots": [{ "step": 0, "phase": "initial|post-login|…", "image_ref": "…", "viewport": "1920x1080" }],
  "network": [{ "url": "…", "method": "…", "status": 200, "headers": {}, "post_data": "…",
               "resource_type": "…", "timing": {}, "initiator": "…" }],
  "console": [{ "level": "…", "text": "…", "location": "…" }],
  "dom": { "title": "…", "final_url": "…", "redirect_chain": ["…"], "forms": [], "links": [] },
  "static_findings": [{ "rule": "…", "severity": "low|medium|high", "match": "…", "line": 0, "context": "…" }],
  "dynamic_steps": [{ "action": "…", "screenshot_ref": "…", "triggered_requests": ["…"] }],
  "stealth": { "engine": "camoufox|chromium", "turnstile_solved": true, "challenge": "…" },
  "artifacts": { "har_ref": "…", "dom_html_ref": "…" }
}
```

Consommé plus tard par l'adaptateur plume et l'ingesteur FAISS (sous-projet 2). Un **test de
contrat** garantit que toute sortie valide ce schéma.

---

## 7. Migration (garder / abandonner)

| Source | On garde | On abandonne |
|---|---|---|
| `browser-automation` | **cœur** : Camoufox, `vision.py` (port guatx-ia-vision), patch coreBundle, API riche (goto/screenshot/capture/intercept/vision-click-os), noVNC | `restart: unless-stopped`, `seccomp:unconfined`, exposition directe des ports hôte, service `browserless` |
| `malware-html-sandbox` | détecteurs **static** (phishing/creds/obfuscation), parsing `.eml`, idée d'isolation | l'iframe+clipboard+cert (cause racine #1), `network_mode: host` + docker.sock (cause racine #2) |
| `web-screenshot-capture` (ShotURL) | éventuellement le modèle prewarm/cache pour screenshot en volume | le reste (supplanté) |
| `autoBrowser` | rien | cloudscraper (résidu), backends redondants |

---

## 8. Structure du repo

```
ocular/
  engine/              # lib partagée : render.py static.py dynamic.py result.py profiles.py
  runner-recon/        # image Camoufox + vision + noVNC (dérivée de browser-automation)
  runner-analysis/     # image Chromium durci (dérivée de malware-sandbox)
  web/                 # API FastAPI + UI pixel-viewer (aucun accès docker)
  broker/              # orchestrateur (seul accès docker)
  gateway/             # proxy pixel noVNC (tier 3, TLS + auth + no-clipboard)
  schemas/             # result.schema.json (contrat) + seccomp profiles
  deploy/              # docker-compose durci + .env.example
  tests/               # unit + intégration + régression sécu + contrat
  docs/
```

---

## 9. Stratégie de test

- **Unit** : `engine/` (render, détecteurs static, construction du schéma résultat).
- **Intégration** : URL bénigne → screenshot + réseau ; échantillon phishing de `malicious_html/`
  → static_findings peuplés **et aucun contact hôte**.
- **Régression sécu (non négociable)** :
  - `web` n'a **pas** accès à `docker.sock` ;
  - runner `analysis` réellement `--network none` (tentative de sortie → échec) ;
  - `gateway` retire bien les permissions presse-papier ;
  - un échantillon malveillant ne génère **jamais** de requête depuis le contexte hôte/analyste ;
  - runner tourne non-root, caps droppées, seccomp ≠ unconfined.
- **Contrat** : toute sortie valide `result.schema.json`.

---

## 10. Phasage de livraison (v1)

1. **Fondation** : repo, `engine/result.py` + `schemas/result.schema.json`, squelette web/broker + file Redis, docker-compose durci.
2. **Runner analysis (le fix sécu)** : image Chromium durcie, broker → conteneur éphémère `--network none`, port des détecteurs static, tests de régression sécu.
3. **Runner recon** : image dérivée de `browser-automation` (Camoufox + vision + capture), profil capture, prewarm.
4. **Tier 2 dynamique scripté** : orchestration form-fill → clic → capture par étape, Turnstile auto.
5. **Tier 3 gateway durci** : noVNC pixels via passerelle TLS, no-clipboard, input-only, sessions éphémères.
6. **Durcissement + CI** : lint/format/type (ruff/mypy), scan deps (pip-audit), scan image (trivy), profils seccomp, CI qui exécute la régression sécu.

Chaque phase est un lot délégable à un agent, avec checkpoint de revue.

---

## 11. Défauts assumés
- Nom : **Ocular** (modifiable sans impact archi).
- File de jobs : **Redis**.
- Egress profil capture : **proxy journalisé** par défaut ; VPN/Tor opt-in.

## 12. Intégration future (hors v1, contrat prévu)
- **plume** : adaptateur consommant l'API + `result.schema.json` ; le moteur ne connaît pas plume.
- **FAISS** : ingesteur des résultats (screenshots/DOM/findings vectorisés) pour recherche/corrélation.
- **YWH** : le profil capture alimente le recon ; les findings peuvent référencer des jobs Ocular.
