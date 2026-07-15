# Phase 3f — Dette technique / durcissement — Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Solder la dette actionnable relevée par les audits : gating Turnstile (latence), dédup Camoufox (DRY), finalisation DOM sous timeout (robustesse), plafond de corps chunked (durcissement web). Sans régression.

## Global Constraints
- `ocular/` uniquement ; jamais plume/core/forge. Chemin capture 3a/3c préservé fonctionnellement. Pas de secret loggé. Tests + e2e réel avant merge.

---

### Task F1 — Runner : gating Turnstile + dédup Camoufox + finalisation sous timeout

**Files:** Modify `runner_recon/capture.py` (+ `runner_recon/vision.py` si besoin) ; Test `tests/test_capture_logic.py`.

Lis `runner_recon/capture.py` : `solve_turnstile(page, screenshots, console, vision_mod, next_index)` (boucle de retry ~6×0.8s), `capture_url`, `capture_scripted`, `_goto_with_fallback` (déjà factorisé).

**(a) Gating Turnstile — ne payer les ~4s de retry QUE si un challenge existe.** Au TOUT DÉBUT de `solve_turnstile`, vérifier la présence d'un **indicateur Cloudflare** dans le DOM ; si absent → `return False` immédiatement (aucun retry, aucune latence). Indicateur via `page.evaluate` (booléen, robuste) :
```python
_CF_INDICATOR_JS = (
    "() => !!document.querySelector("
    "'[data-sitekey], .cf-turnstile, "
    "script[src*=\"challenges.cloudflare.com\"], "
    "iframe[src*=\"challenges.cloudflare.com\"]')"
)
```
Le div `.cf-turnstile`/`[data-sitekey]` et le script CF sont présents dans le HTML **avant** le rendu de l'iframe (validé sur guatx.com), donc l'indicateur est fiable dès après `goto`. Si l'indicateur est vrai → exécuter la boucle de retry existante (le widget async a le temps d'apparaître). Documente en commentaire. Ainsi une capture sans Turnstile (cas courant) ne subit plus les ~4s.

**(b) Dédup Camoufox `capture_url`/`capture_scripted`.** Ces deux fonctions dupliquent (~20 lignes) le cycle de vie Camoufox (`AsyncCamoufox(headless=False, os="linux", humanize=0.3, i_know_what_im_doing=True)`, `ctx.new_page()`, `capture.attach(page)`) et l'extraction DOM finale (`page.content()/title()/url` sous try/except). Factorise :
- un helper d'extraction `async def _capture_dom(page) -> tuple[bytes, str, str]` (dom_html, title, final_url ; try/except → valeurs vides + log, comme aujourd'hui) — utilisé par les deux.
- optionnellement un context manager `_camoufox_page()` partagé (si propre) ; sinon garde le `async with` dans chaque fonction mais AU MINIMUM factorise `_capture_dom`. Ne change PAS le comportement (mêmes flags Camoufox, même politique d'erreur). Objectif = une seule source pour éviter la dérive (relevé par 2 auditeurs).

**(c) Finalisation DOM sous timeout (chemin scripté).** Dans `capture_scripted`, l'extraction DOM finale (`_capture_dom`) après `run_steps` n'a aucun budget propre : si le navigateur est bancal après un timeout de step, `page.content()` peut pendre au-delà de la marge broker → stdout vide. Enveloppe l'extraction finale de `capture_scripted` dans `asyncio.wait_for(_capture_dom(page), timeout=<budget résiduel court, ex. 15s>)` ; sur `asyncio.TimeoutError` → dom vide + console warning, MAIS `emit_wrapper` toujours atteint (résultat partiel). (Le chemin `capture_url`/3a peut rester tel quel ou bénéficier du même wrapper — au choix, sans régresser.)

**TDD** (`tests/test_capture_logic.py`, page mockée) :
- `solve_turnstile` : indicateur CF absent (`page.evaluate` → False) → `return False` SANS aucun `screenshot`/`detect`/`sleep` (pas de retry, pas de latence) ; indicateur présent → boucle de retry exécutée (comportement B inchangé). (mocke `page.evaluate` pour l'indicateur ET pour l'offset.)
- `_capture_dom` : page normale → (dom, title, url) ; `page.content()` qui lève → valeurs vides, pas de crash.
- `capture_scripted` finalisation : `_capture_dom` qui pend (mock `asyncio.sleep` long) sous `wait_for` court → TimeoutError capturé, wrapper quand même émis (résultat partiel). Adapte au style des tests existants.
- Les tests Turnstile B existants (mapping, solved) restent verts (l'indicateur est vrai dans ces tests, ou ajuste le mock).

Puis `pytest -m "not integration" -q` vert. Commit : `perf/refactor(3f): gate Turnstile sur indicateur CF + dédup Camoufox + finalisation DOM sous timeout`.

---

### Task F2 — Web : plafond de corps de requête (chunked inclus)

**Files:** Modify `web/app.py` ; Test `tests/test_web*.py`.

La garde 413 actuelle (`_body_size_guard`, 3d-1) rejette sur `Content-Length` mais NE couvre PAS les requêtes `Transfer-Encoding: chunked` (sans `Content-Length`) — un corps chunked géant peut toujours faire gonfler la mémoire.

**Fix** : ajouter une garde qui **compte les octets réellement reçus** (ASGI) et coupe au-delà du plafond (`_MAX_BODY_BYTES` existant), même sans `Content-Length`. Implémentation propre : un middleware ASGI (pur, `class`) qui enveloppe `receive` pour accumuler `len(body)` sur les messages `http.request` et, si le total dépasse le plafond, renvoie une réponse **413** et cesse de lire. Garde le `_body_size_guard` `Content-Length` existant comme court-circuit rapide (rejet avant lecture quand l'en-tête est présent). Ne casse pas les corps légitimes (html/steps sous le plafond) ni les GET.

**TDD** :
- POST avec un corps réel > plafond SANS `Content-Length` (forcer chunked côté client de test si possible, sinon tester l'unité de comptage du middleware) → **413**, la route n'est jamais atteinte.
- POST normal (petit corps) → inchangé (200/422).
- `Content-Length` géant → toujours 413 (court-circuit existant).
Puis `pytest -m "not integration" -q` vert.

Commit : `fix(3f): plafond de corps ASGI (couvre chunked sans Content-Length) -> 413`.

---

### Task F3 — Audit + e2e + merge
- [ ] Audit court (gating ne rate pas un vrai Turnstile ; dédup ne change pas le comportement ; wait_for finalisation n'avale pas d'exception réelle ; body cap ne casse pas les corps légitimes).
- [ ] **e2e réel** (rebuild `ocular-runner-recon`) : (a) capture `example.com` (sans CF) → **rapide** (pas de délai Turnstile ~4s ; mesurer la durée broker `runner done duration_ms`, doit chuter vs avant) ; (b) capture `https://guatx.com` (vrai Turnstile) → **`turnstile_solved=True`** TOUJOURS (le gating ne l'a pas cassé) ; (c) corps chunked géant → 413.
- [ ] Merge via finishing-a-development-branch + MAJ roadmap/mémoire.

## Self-review
- Gating : indicateur CF fiable (présent avant l'iframe), capture normale sans latence, Turnstile réel toujours résolu. Dédup : une source (pas de dérive). Finalisation : résultat partiel garanti. Body cap : chunked couvert.
