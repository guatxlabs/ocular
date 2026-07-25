# Ocular — Couche IA/ML de triage & 2e avis — Design

- **Date** : 2026-07-18 · **Statut** : Approuvé (design), prêt pour plan.
- **Base** : moteur complet (phases 3a–3n). Ajoute une **couche de triage native** qui produit, à côté du verdict règles, un **score de priorité 0-100 décomposable**, un **2e avis** (benign/suspicious/malicious) qui *complète sans écraser*, et une **boucle de calibration hors-ligne** (ML appris depuis les verdicts analystes). Une **option LLM d'explication** est prévue, off par défaut.

## 1. But
Aider l'analyste à **trier** (« qu'est-ce qui mérite mon œil en priorité ? ») et à **nuancer** le verdict automatique, sans boîte noire ni coût réseau/ressource notable, et **utilisable en réseau entreprise** (séparation de privilèges et garde egress inchangées). Le traitement doit être **explicite** : on VOIT qu'un calcul a eu lieu, avec quels signaux et quels poids.

## 2. Décisions figées (validées)
| # | Décision |
|---|----------|
| T1 | **Rôle** : triage/priorisation **ET** 2e avis sur le verdict. Le LLM d'explication reste une option off par défaut. |
| T2 | **Modèle = hybride** : scoreur linéaire **transparent** (poids par défaut réglables) day-1 → devient un **classifieur logistique appris** dès qu'une calibration est lancée. Même format de poids dans les deux cas. |
| T3 | **`compute_verdict` n'est JAMAIS touché ni écrasé.** Le triage est un **calcul parallèle** ; verdict règles et 2e avis coexistent visuellement. |
| T4 | **Natif, pur-Python, 0 dépendance runtime ajoutée.** Features déjà présentes dans `OcularResult` → aucune ré-extraction, aucun egress au scoring. |
| T5 | **Consommateurs** : afficher+expliquer, trier/filtrer les Sauvegardes, alimenter le 2e avis, boucle de calibration. |
| T6 | **Calibration hors-ligne uniquement**, dans un conteneur jetable, lancée par l'opérateur, **sortie relue puis activée à la main** (jamais d'auto-mutation en prod, jamais d'apprentissage en ligne). |
| T7 | **Pas de ML day-1** : sans labels, c'est l'heuristique transparente qui tient (+ sert de fallback). Le ML natif arrive avec les données (choix explicite : fiable quand entraîné). |
| T8 | **LLM = option** OpenAI-compatible (Ollama `/v1`), désactivée sauf 2 env armées, appel depuis le **web** via la **garde egress**, note d'aide **jamais** un verdict. |

## 3. Sécurité & ressources (impératif)
- **Aucun nouveau service, aucun nouveau chemin de privilège.** Le scoreur tourne *en process* dans les runners existants (là où `compute_verdict` est déjà appelé). Séparation web (pas de docker.sock) → Redis → broker (seul Docker) → runners éphémères : **inchangée**.
- **Aucun egress au scoring ni à la calibration.** Le scoreur ne lit que des features en mémoire ; le CLI de calibration ne fait que des maths locales sur la base saved (lecture seule).
- **Seul egress possible = l'option LLM**, opt-in strict : `OCULAR_LLM_ENABLED=1` **et** `OCULAR_LLM_BASE_URL` configuré. Appel **depuis le web** (jamais depuis les runners), **via la garde egress** ; un endpoint interne (RFC1918, ex. Ollama LAN) exige `OCULAR_LLM_ALLOW_INTERNAL=1` qui lève le blocage **uniquement pour cet hôte**. Défaut « refuse tout egress » intact.
- **Fail-safe partout** : fichier de poids absent/illisible/malformé → fallback `BUILTIN` + signal `weights_load_error` visible (jamais de crash). Calibration sous le seuil de données → **refus explicite** (pas de modèle sur-ajusté silencieux).
- **Anti-empoisonnement** : la calibration ne s'active jamais seule ; un humain relit le diff des poids avant de pointer `OCULAR_TRIAGE_WEIGHTS` dessus.
- **Coût** : scoring quelques µs/pur-Python ; persistance = 2 colonnes indexées ; calibration = numpy hors-ligne à la demande ; LLM = 0 par défaut.
- **Docker-first, zéro résidu host** : la calibration tourne dans un conteneur jetable (cible `make calibrate`).

## 4. Architecture
```
[runner_* ] analyze_html -> findings
        │  compute_verdict(findings)                -> verdict (règles, INCHANGÉ)
        │  compute_triage(findings, result_fields)  -> Triage (score, band, 2e avis, signaux)
        ▼
   OcularResult { ..., verdict, triage }            (triage Optional, rétro-compatible)
        │
        ├─ web : GET /jobs/{id}        -> result complet (UI panneau Triage)
        ├─ save(): dénormalise triage_score/triage_band en colonnes indexées
        └─ GET /saved?sort&order&min_band -> tri/filtre SQL

[hors-ligne]  make calibrate -> tools/calibrate_triage.py (conteneur jetable)
   lit saved_analysis WHERE analyst_verdict IS NOT NULL
   rejoue LES MÊMES extracteurs -> vecteurs de features + labels
   régression logistique (numpy) -> triage_weights.calibrated-DATE.json + rapport (diff, métrique)
   opérateur relit -> pointe OCULAR_TRIAGE_WEIGHTS dessus -> nouveaux scores portent weights_version="calibrated-…"

[option] web : POST /jobs/{id}/explain (si LLM armé) -> résumé structuré -> Ollama /v1 (via garde egress) -> note d'aide
```

### 4.1 Modèle (`engine/result.py`)
Nouveaux modèles, ajout **rétro-compatible** (comme `stealth` : `Optional`, défaut ; un résultat 1.0 sans triage reste valide) :
```python
class TriageSignal(BaseModel):
    key: str            # ex. "obfuscation_cluster"
    label: str          # libellé FR lisible
    weight: float       # contribution signée (poids × présence)
    detail: str = ""    # ex. "2 patterns d'obfuscation"

class Triage(BaseModel):
    score: int                                    # 0-100
    band: Literal["low", "medium", "high"]
    second_opinion: Verdict                       # benign/suspicious/malicious
    agrees_with_rules: bool
    signals: list[TriageSignal]                   # trié par |weight| desc
    weights_version: str                          # "builtin-1" | "calibrated-YYYY-MM-DD"

class OcularResult(BaseModel):
    ...
    triage: Optional[Triage] = None
```

### 4.2 Scoreur (`engine/triage.py` + `engine/triage_weights.py`)
- `engine/triage_weights.py` : dict `BUILTIN = {version, base, bands:{medium,high}, signals:{key:(poids,label)}}`. **Point de réglage** unique, lisible, versionné en Git.
- `engine/triage.py` :
  - un **extracteur pur par signal** `f(findings, result_fields) -> (present: bool, detail: str)` (obfuscation_cluster, obfuscation_single, cred_and_urgency, cred_external_form, external_form, mailto_exfil, high_severity_finding, many_third_parties, console_errors, redirect_chain). Réutilise les clusters `_OBF/_CRED/_URGENCY` de `engine/verdict.py` (source unique).
  - `load_weights()` : lit `OCULAR_TRIAGE_WEIGHTS` (chemin) sinon `BUILTIN` ; JSON invalide/illisible → `BUILTIN` + marqueur d'erreur.
  - `compute_triage(findings, result_fields) -> Triage` : `score = clamp(0..100, base + Σ poids_i·présence_i)` ; `band` par seuils ; `second_opinion = high→malicious / medium→suspicious / else benign` ; `agrees_with_rules = second_opinion == verdict_règles` ; `signals` = contributions non nulles triées par |poids|, + `base`, + `weights_load_error` le cas échéant.
- **Invariant testé** : `Σ (contributions affichées) == score` (décomposition complète, cœur de l'« explicite »).

### 4.3 Branchement runners
Une ligne à chaque site appelant déjà `compute_verdict` :
- `runner_analysis/render.py:72`, `runner_recon/capture.py:157` & `:590`, `runner_recon_vnc/session_server.py:148` & `:293`.
Le `result_fields` passé = les champs déjà calculés (network, dom.forms/mailtos, console, redirect_chain, verdict règles). Aucun coût d'extraction supplémentaire.

### 4.4 Persistance & Sauvegardes (`saved_store.py`)
- **Migration idempotente** (mécanisme `_NEW_COLUMNS` existant) : `triage_score INTEGER`, `triage_band TEXT`. NULL si résultat pré-triage → rétro-compat (vieilles sauvegardes listables, score vide).
- `save()` : renseigne les 2 colonnes depuis `result.get("triage")` (NULL si absent).
- `_META_COLUMNS` : ajoute `triage_score, triage_band` → remontés par `list_all`/`get_by_hash`/`get_meta` sans requête sup.
- **Scores persistés figés** : une recalibration ne réécrit PAS les scores existants (ils portent le `weights_version` de leur capture — traçable). Ré-scoring de masse = backlog.

### 4.5 API web (`web/app.py`)
- `GET /saved` : query params **optionnels validés serveur** — `sort=saved_at|triage_score` (déf. `saved_at`), `order=desc|asc` (déf. `desc`), `min_band=low|medium|high`. Tri/filtre **en SQL**. Hors-enum → 422 (discipline `/saved/lookup`). Comportement par défaut = ordre actuel (aucune régression).
- (option LLM) `POST /jobs/{id}/explain` : 404 si LLM non armé ; sinon construit un **résumé structuré** (verdict, triage, signaux, findings — **jamais** le HTML brut/artefacts), appelle Ollama `/v1/chat/completions` via la garde egress, renvoie `{explanation, model}`. Timeout court, réponse tronquée.

### 4.6 UI (`web/ui/triage.js` partagé + intégrations)
- `web/ui/triage.js::triagePanel(triage, rulesVerdict)` — composant pur réutilisé par la vue job et la vue saved (pattern `filter.js`). Rend : barre + score/100 + bande (couleur low neutre / medium `--warn` / high `--bad`) ; ligne 2e avis + badge **« diverge du verdict règles »** si `!agrees_with_rules` ; `weights_version` affiché ; liste des signaux triée (libellé + contribution signée + detail). Tout en `el()`/`textNode`, jamais `innerHTML`.
- `triage` absent → « triage non calculé (analyse antérieure) ».
- `web/ui/views/saved.js` : pastille score + contrôle « trier par : date | priorité » + filtre de bande (appelle `GET /saved` avec les query params).
- (option LLM) bouton « Expliquer avec LLM » sur le résultat → `POST /jobs/{id}/explain` → note affichée avec badge « note générée par LLM (modèle X) », en `textContent`.

### 4.7 Calibration (`tools/calibrate_triage.py`, `make calibrate`)
1. Lit `saved_analysis WHERE analyst_verdict IS NOT NULL`. Map label analyste `legitimate→benign`.
2. Relit `result_json`, **rejoue les extracteurs de `engine/triage.py`** (source unique features → pas de dérive train/serve) → vecteur binaire + label.
3. **Régression logistique multinomiale en numpy pur** (montée de gradient, quelques dizaines de lignes ; pas de scikit-learn). Coefficients → poids remis à l'échelle 0-100, arrondis lisibles.
4. **Refus si données insuffisantes** : `≥ N_MIN` labels **et** `≥ K_MIN` par classe (réglables). Sinon message explicite (« 12 labels, 30 requis »), sortie non produite.
5. Écrit `triage_weights.calibrated-YYYY-MM-DD.json` + **rapport** : ancien vs nouveau poids par signal, nombre de labels, accuracy en validation croisée simple. **L'opérateur relit puis décide** de pointer `OCULAR_TRIAGE_WEIGHTS` dessus.
- Déterministe (mêmes labels → même fichier ; graine fixe). Aucun accès réseau. Lecture seule de la base.

### 4.8 Configuration (env)
| Var | Défaut | Rôle |
|---|---|---|
| `OCULAR_TRIAGE_WEIGHTS` | (vide → `BUILTIN`) | chemin d'un fichier de poids (builtin ou calibré) |
| `OCULAR_LLM_ENABLED` | `0` | arme l'option LLM d'explication |
| `OCULAR_LLM_BASE_URL` | (vide) | endpoint OpenAI-compatible (ex. Ollama) |
| `OCULAR_LLM_MODEL` | (vide) | nom de modèle |
| `OCULAR_LLM_ALLOW_INTERNAL` | `0` | autorise l'egress vers l'hôte LLM interne (RFC1918), **cet hôte seulement** |

## 5. Ce qui N'EST PAS fait (YAGNI / backlog roadmap)
- Ré-scoring de masse des sauvegardes après recalibration.
- Bouton UI admin déclenchant le CLI de calibration.
- ML supervisé day-1 (modèle pré-entraîné embarqué) — écarté faute de dataset fiable.
- Détection d'anomalie non-supervisée day-1 — écartée (choix T7 : ML avec les données).
- Édition des poids/seuils depuis l'UI (réglage = fichier opérateur, par sécurité).

## 6. Tests (Dockerisés, `make test`)
- Extracteurs de signaux, un par un (présence/absence + `detail`).
- `compute_triage` : monotonicité du score ; **décomposition Σ contributions == score** ; `band` aux seuils ; `second_opinion`/`agrees_with_rules` dont **règles=benign & score haut → diverge**.
- `load_weights` : fichier valide surchargé ; fichier illisible/malformé → `BUILTIN` + `weights_load_error` (pas de crash).
- Modèle : `OcularResult` sans `triage` reste valide (rétro-compat).
- `saved_store` : migration idempotente ; vieille sauvegarde sans triage listable ; `triage_score/band` renseignés/NULL.
- API `/saved` : tri/filtre SQL corrects ; hors-enum → 422 ; défaut = ordre actuel.
- Calibration : refus sous seuil ; déterminisme (graine fixe) ; format de sortie + rapport ; `legitimate→benign`.
- LLM : désactivé par défaut → `/jobs/{id}/explain` = 404, **aucun** appel réseau sans les 2 env ; armé → passe par la garde egress (mock).

## 7. Livraison incrémentale suggérée
1. **Socle** : modèles + `engine/triage.py` + `triage_weights.py` + branchement runners + tests moteur.
2. **Persistance & UI** : migration `saved_store` + `GET /saved` tri/filtre + `web/ui/triage.js` + intégration vues.
3. **Calibration** : `tools/calibrate_triage.py` + `make calibrate` + tests.
4. **Option LLM** (dernier, isolé) : `POST /jobs/{id}/explain` + bouton UI + garde egress.
