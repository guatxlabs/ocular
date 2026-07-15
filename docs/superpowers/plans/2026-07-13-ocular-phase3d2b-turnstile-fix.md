# Phase 3d-2 (B) — Turnstile : réparer l'auto-résolution — Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** L'auto-résolution Turnstile (capture/recon) ne fonctionne pas ; corriger les 2 causes racines diagnostiquées.

**Diagnostic (root cause) :**
1. **Mapping de coordonnées faux.** `vision.detect()` renvoie des px **image** (le screenshot = viewport de la page). `vision.human_click_xdotool(sx, sy)` clique en px **écran** Xvfb. `capture.py` passe `det[0], det[1]` directement → le clic est décalé de l'offset **viewport→écran** (le chrome Firefox — barre d'URL/onglets — au-dessus du viewport, + position fenêtre) → tombe à côté de la case.
2. **Timing.** La détection ne tourne que sur `png0` (juste après `domcontentloaded`), mais le widget Turnstile se charge dans une iframe async APRÈS → souvent pas encore rendu → pas de match.
3. **Bonus.** `turnstile_solved=True` est posé optimiste (jamais vérifié).

## Global Constraints
- `ocular/` uniquement ; jamais plume/core/forge. DRY. Ne PAS régresser le chemin capture 3a sans Turnstile (pas de widget → comportement inchangé, screenshot initial + suite normale). Logs jamais de secret/URL sensible.
- **Validation** : le mapping et la boucle de retry sont **unit-testables** (helpers purs / page mockée). La validation e2e contre un VRAI challenge Cloudflare n'est pas garantie dans cet environnement — le livrable est le correctif des causes racines + tests unitaires + doc honnête.

---

### Task B1 — Mapping image→écran + détection avec retry + vérif

**Files:** Modify `runner_recon/vision.py` (helper pur), `runner_recon/capture.py` (bloc Turnstile) ; Test `tests/test_vision_coords.py` (nouveau), `tests/test_capture_logic.py` (retry avec page mockée si faisable).

**1. `runner_recon/vision.py` — helper pur `image_to_screen`** :
```python
def image_to_screen(det, moz_x, moz_y, dpr):
    """(x,y) px IMAGE (viewport screenshot) -> (x,y) px ÉCRAN Xvfb.
    Le screenshot Playwright est le viewport en px *device* ; xdotool clique en px
    écran. Firefox/Camoufox expose la position écran (px CSS) du coin haut-gauche du
    viewport via window.mozInnerScreenX/Y. dpr = window.devicePixelRatio."""
    d = dpr or 1
    return (int(round(moz_x + det[0] / d)), int(round(moz_y + det[1] / d)))
```
Unit tests : dpr=1 → offset simple ; dpr=2 → division ; offset non nul ; arrondi.

**2. `runner_recon/capture.py` — bloc Turnstile** : remplace la détection one-shot par :
- **retry** : après `_goto_with_fallback` + `png0` initial, tente la détection jusqu'à ~6 fois espacées de ~0.8s (≈5s au total) — à chaque itération : screenshot + `vision.detect(..., strategy="turnstile")`. Dès qu'un `det` est trouvé, sortir de la boucle. (Le widget async a le temps d'apparaître.) Si jamais trouvé → pas de Turnstile, on continue (comportement 3a).
- **clic aux bonnes coords** : sur `det`, récupérer l'offset : `off = await page.evaluate("() => ({x: window.mozInnerScreenX, y: window.mozInnerScreenY, d: window.devicePixelRatio || 1})")` ; `sx, sy = vision.image_to_screen((det[0],det[1]), off["x"], off["y"], off["d"])` ; `await vision.human_click_xdotool(sx, sy)`.
- **vérif** : après le clic + `await asyncio.sleep(4)`, re-screenshot (`png1`, ajouté aux screenshots comme « post-turnstile ») et **re-détecter** : si `vision.detect(png1) is None` (la case a disparu) → `turnstile_solved = True`, sinon `False` (log « turnstile: non résolu »). Le résultat reflète la réalité.
- **logs** (stderr, jamais stdout) : « turnstile detected img=(x,y) screen=(sx,sy) » puis « turnstile solved=True/False ». Aucune URL/secret.
- garde le `try/except` global (une erreur Turnstile ne casse jamais la capture ; `turnstile_solved` reste False).

- [ ] **Step 1 — Tests** `tests/test_vision_coords.py` : `image_to_screen` (dpr 1/2, offset, arrondi). Si faisable proprement, un test de la boucle de retry avec une `page` mockée dont `screenshot` renvoie des PNG et `detect` (monkeypatché) renvoie None puis un point → vérifie qu'on retente puis clique aux coords mappées (mocke `human_click_xdotool`/`evaluate`). Sinon, teste au minimum `image_to_screen` + la logique de vérif solved (fonction extraite si besoin).
- [ ] **Step 2 — FAIL.**
- [ ] **Step 3 — Implémente** (helper vision + bloc capture).
- [ ] **Step 4** — `pytest -m "not integration" -q` vert ; **rebuild image** `docker build -f runner_recon/Dockerfile -t ocular-runner-recon:latest .` OK ; un run capture sur une page SANS Turnstile (ex. `example.com`) via le test d'intégration existant reste vert (pas de régression : le retry ne trouve rien → continue).
- [ ] **Step 5 — Commit** `fix(3d): Turnstile — mapping viewport->écran (mozInnerScreen) + détection retry + vérif solved`.

---

### Task B2 — Doc + non-régression
- [ ] README/spec : noter que l'auto-Turnstile dépend d'un rendu headed Xvfb correct, que le mapping utilise `mozInnerScreenX/Y` (Gecko), et que la validation finale requiert une cible Cloudflare réelle (limite connue, non e2e-testable ici).
- [ ] Merge via finishing-a-development-branch (option 1) + MAJ mémoire/roadmap (B fait — cause racine corrigée, validation live à faire par l'utilisateur sur une vraie cible).

## Self-review
- Cause 1 (coords) : corrigée par offset `mozInnerScreen` + dpr (testé). Cause 2 (timing) : boucle de retry. Bonus : `turnstile_solved` vérifié. Chemin sans Turnstile inchangé. Pas de secret loggé.
