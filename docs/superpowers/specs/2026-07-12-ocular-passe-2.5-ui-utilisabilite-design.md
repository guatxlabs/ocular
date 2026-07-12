# Ocular — Passe 2.5 : Utilisabilité + UI (profil analysis) — Design

- **Date** : 2026-07-12
- **Statut** : Approuvé (design), prêt pour plan d'implémentation
- **Base** : suite du sous-projet 1 (tranche « Fondation + Runner d'analyse durci », déjà mergée sur `main`).
- **Suit** : [[phase 3 — runner recon Camoufox+vision]] (prochaine).

---

## 1. Contexte & problème

La tranche fondation livre un moteur d'analyse durci **fonctionnel mais pas encore exploitable** de bout en bout :
- Les **screenshots ne sont pas récupérables** : `image_ref` = seulement le `sha256` du PNG ; les octets sont jetés par le runner. Idem `dom_html_ref`/`har_ref`.
- **Pas d'auth** sur l'API `/jobs`.
- **Pas d'UI** : seulement CLI/API. Or les deux outils d'origine (ShotURL, malware-sandbox) avaient une interface web, et pour de l'analyse web une UI est nettement supérieure.
- Déploiement pas « une commande » : image runner à pré-builder à la main, `web` `read_only` sans `tmpfs /tmp`, pas de Makefile/quickstart.

**But de la passe 2.5** : rendre le moteur d'analyse **réellement utilisable et déployable**, avec une UI web au **design plume/forge**.

## 2. Objectifs / non-objectifs

### Objectifs
- **Stockage d'artefacts** : screenshots / DOM récupérables via l'API et l'UI.
- **Auth** : token Bearer sur toute la surface `/jobs*`.
- **UI web** vanilla-JS PWA façon plume/forge (soumettre → jobs → détail).
- **Ops/DX** : Makefile, quickstart, compose déployable proprement.

### Non-objectifs (YAGNI)
- Profil `capture`/recon (Camoufox, vision, URL live) → **phase 3**. La passe 2.5 est **analysis-only** ; le champ URL de l'UI est présent mais **grisé**.
- Comptes multi-utilisateur / RBAC (token partagé suffit).
- Object store type MinIO/S3 (volume disque suffit sur 1 VPS) — point d'extension noté.
- Gateway noVNC interactif (tier 3) → plan ultérieur.

## 3. Décisions clés (validées)

| # | Décision | Rationale |
|---|---|---|
| D1 | Artefacts sur **volume disque partagé** (broker rw, web ro), indexés par `sha256` | gère les gros PNG, nettoyage TTL simple, séparation write/read propre |
| D2 | Le **runner** émet `image_b64`/`dom_html_b64` sur stdout ; le **broker** extrait→stocke→remplace par ref→résultat léger en Redis | garde le runner stdout-only (pas de mount hôte supplémentaire), préserve l'isolation |
| D3 | Auth = **token Bearer** (`.env` `OCULAR_TOKEN`), middleware sur `/jobs*` | self-hosted, suffisant solo/équipe restreinte ; proxy Caddy+TLS recommandé devant |
| D4 | UI = **vanilla-JS PWA façon plume/forge** (pas de framework, zéro build) | cohérence visuelle ET comportementale avec la stack, self-hosted, aligné « publiable » |
| D5 | Accent Ocular = **violet/indigo `#8b5cf6`** dans le système plume/forge (dark navy `#0b0e14`, Inter+JetBrains Mono) | « même famille, app distincte » (plume=teal, forge=ambre, ocular=violet). Ajustable |
| D6 | Passe 2.5 **analysis-only** | le recon (URL live) dépend du runner Camoufox = phase 3 |

## 4. Architecture

### 4.1 Flux d'artefacts (extension du pipeline existant)

```
runner (Chromium, isolé)          broker (seul à parler Docker)         web (ro)
  render.py:                        run_analysis_job:                     GET /jobs/{id}
   - screenshots[].image_b64  ─────▶  - parse stdout JSON                   → résultat léger (Redis)
   - dom_html_b64             stdout  - écrit octets dans artifacts/<ref>  GET /jobs/{id}/artifact/{ref}
   - (refs sha256 déjà là)             (volume, nommé par sha256)           → sert le fichier depuis
                                       - retire les *_b64 du résultat          artifacts/ (ro)
                                       - set_result(Redis) = JSON léger
```

- **Volume** `artifacts/` : monté `rw` dans le broker, `ro` dans le web. Fichiers nommés `<sha256>` (déjà la valeur du `ref`, préfixe `sha256:` retiré du nom de fichier). Nettoyage : tâche périodique supprimant les fichiers dont le job a expiré (TTL Redis) — script `broker/gc.py` lancé par cron/timer.
- **Runner** : `render.py` ajoute `image_b64` à chaque `Screenshot` et `dom_html_b64` aux `Artifacts` **uniquement sur stdout** (champs transitoires) ; ils ne font PAS partie du schéma stocké.
- **Schéma** : le contrat `result.schema.json` reste **le résultat léger** (refs seulement). Les champs `*_b64` sont un **canal de transport runner→broker**, documentés hors schéma (le broker les consomme et les retire avant stockage).

### 4.2 Auth

- Middleware FastAPI : toute requête sur `/jobs*` (POST, GET job, GET artifact) exige `Authorization: Bearer <OCULAR_TOKEN>`. Sinon `401`.
- `OCULAR_TOKEN` lu depuis l'env (jamais en dur). Si non défini au démarrage : le web refuse de démarrer (fail-closed) plutôt que de tourner sans auth.
- L'UI : petit écran login (saisie du token) → stocké en `localStorage` → envoyé en header sur chaque appel. `401` → retour au login.

### 4.3 UI (vanilla-JS PWA façon plume/forge)

Servie en statique par le tier web (FastAPI monte `web/ui/` sur `/`). Système repris de plume/forge : dark navy, Inter+JetBrains Mono auto-hébergées (woff2), PWA (`sw.js` + `manifest.webmanifest`), i18n FR/EN, toggle thème clair/sombre. Accent violet `#8b5cf6`.

**Vues** :
- **login** — saisie token.
- **submit** — coller HTML (textarea) / uploader `.eml` / champ URL **grisé** (phase 3) → « Analyser » → job_id.
- **jobs** — liste (id, cible tronquée, badge verdict coloré, date), polling du statut des jobs `pending`.
- **detail** — le cœur (façon sandbox+ShotURL) : grand **screenshot** (via `GET /jobs/{id}/artifact/{ref}`), badge **verdict**, **findings static groupés par sévérité** (critical/high/medium/low, couleurs), **table réseau** (url/method/status/type/initiator), **console**, **DOM** (title/final_url/redirect_chain), lien téléchargement du DOM HTML.

**Fichiers** :
```
web/ui/
  index.html  style.css
  core.js  state.js  i18n.js  api.js        # api.js: fetch + header Bearer + gestion 401
  views/login.js  views/submit.js  views/jobs.js  views/detail.js
  sw.js  manifest.webmanifest  favicon.svg
  fonts/inter-latin.woff2  fonts/jetbrains-mono-latin.woff2
```

### 4.4 Ops / DX

- **Makefile** : `build-runner` (build l'image `ocular-runner-analysis:latest` sur le daemon hôte — prérequis du broker), `up`/`down` (compose), `analyze FILE=…` (mode direct sans stack), `test` / `test-int`, `gc` (nettoyage artefacts).
- **compose** : `web` gagne `tmpfs: [/tmp]` + monte `web/ui` en statique + `artifacts:ro` ; `broker` monte `artifacts:rw` ; volume nommé `ocular-artifacts` ; `OCULAR_TOKEN` passé aux deux via `.env`.
- **README** : sections « Utiliser » (direct + API + UI) et « Déployer » (VPS, pré-build runner, Caddy+TLS devant).
- **pyproject** : `addopts = "-m 'not integration'"` (la CI sans Docker ne lance plus les tests d'intégration par défaut).

## 5. Modèle de menace (delta purple team)
- **Auth** : token en `.env` (pas en dur), fail-closed si absent ; middleware couvre AUSSI `GET artifact` (sinon fuite des screenshots/DOM d'analyses sensibles).
- **Path traversal artefacts** : le `ref` de `GET /jobs/{id}/artifact/{ref}` doit être **validé** (`^sha256:[0-9a-f]{64}$`) et résolu dans `artifacts/` sans jamais permettre `../` — sinon lecture arbitraire de fichiers depuis le tier web.
- **Le web reste sans Docker** : le stockage d'artefacts n'introduit AUCUN accès Docker au web (il ne fait que lire un volume). Contrainte de séparation de privilèges préservée (test maintenu).
- **DOM HTML servi** : `GET artifact` du DOM renvoie le HTML hostile en **`Content-Type: text/plain` + `Content-Disposition: attachment`** (jamais `text/html` inline) — sinon on ré-exécute le malveillant dans le navigateur de l'analyste (la cause racine #1 qu'on a tuée).

## 6. Tests
- **Artefact roundtrip** : broker reçoit un stdout avec `image_b64` → écrit `artifacts/<sha256>` → résultat stocké est léger (sans b64) → `GET /jobs/{id}/artifact/{ref}` renvoie exactement les octets d'origine.
- **Auth** : `401` sans/avec mauvais token ; `200` avec bon token ; le web refuse de démarrer sans `OCULAR_TOKEN`.
- **Path traversal** : `GET /jobs/{id}/artifact/../../etc/passwd` (ou ref non conforme) → `400/404`, jamais de lecture hors `artifacts/`.
- **DOM servi non-inline** : `Content-Type` ≠ `text/html`, `Content-Disposition: attachment`.
- **Séparation privilèges maintenue** : `grep docker web/` reste vide.
- **UI smoke** : `GET /` sert `index.html` ; `api.js` envoie bien le header Bearer.
- **e2e étendu** : submit → poll `GET /jobs/{id}` → `verdict`/findings présents → screenshot récupérable et non vide.

## 7. Phasage de livraison
1. **Artefacts** : runner émet b64 → broker stocke/retire → `GET artifact` (+ validation ref/traversal + non-inline DOM). Tests roundtrip/traversal.
2. **Auth** : middleware Bearer + fail-closed + tests.
3. **UI** : structure `web/ui/` (design plume/forge, PWA, i18n) + vues login/submit/jobs/detail + `api.js`. Servie par le web.
4. **Ops/DX** : Makefile, compose (tmpfs, volume artefacts, static), README quickstart, `pyproject` integration-off par défaut, `broker/gc.py`.

Chaque phase = lot délégable avec checkpoint de revue.

## 8. Défauts assumés
- Accent UI = `#8b5cf6` (ajustable au design front).
- TTL artefacts aligné sur le TTL des résultats Redis (à fixer, défaut 24 h).
- i18n FR/EN, thème par défaut = sombre.
