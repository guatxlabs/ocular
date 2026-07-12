# Ocular — Phase 3a : Runner capture (Camoufox + vision) — Design

- **Date** : 2026-07-12
- **Statut** : Approuvé (design), prêt pour plan
- **Base** : moteur mergé sur `main` (analysis + sauvegardes). Ajoute le **profil `capture`** (recon URL live). 3b (noVNC interactif) et 3c (dynamique) = sous-projets suivants.

---

## 1. But
Débloquer l'**analyse d'URL live** avec **bypass Turnstile automatique**, via un runner éphémère **Camoufox + vision** porté de `YesWeHack/toolkit/browser-automation`. Coule dans le pipeline existant (broker→web→UI→sauvegardes) sans le réinventer.

## 2. Décisions figées
| # | Décision |
|---|---|
| R1 | Runner **éphémère** `runner_recon/` (comme `runner_analysis`), émet le wrapper `{result, blobs}` sur stdout. |
| R2 | **Camoufox headed** (Xvfb) + **vision.py** (opencv template-match Turnstile) + **xdotool** clic OS `isTrusted`. Réutilise `vision.py` + `turnstile_checkbox.png` + le patch Playwright coreBundle. |
| R3 | Profil `capture` : **réseau ON** (bridge), **égress direct** + passthrough `HTTP_PROXY`/`HTTPS_PROXY` (VPN/Tor opt-in), **warning exposition IP**. |
| R4 | Durci dans la limite du possible : non-root, `--cap-drop ALL`, `no-new-privileges`, seccomp profilé (dérivé), `--read-only`+tmpfs, `--memory 4g`, `--pids-limit`, `--rm`. **JAMAIS** docker.sock ni host-net. |
| R5 | `input_hash` = `sha256` de l'**URL normalisée** (scheme+host lowercase, garde path/query) ; `input_kind="url"`. Dédup **URL exacte** (host-fuzzy = futur). |
| R6 | **Verdict** = détecteurs `engine/static` sur le DOM capturé → `compute_verdict`. |
| R7 | **noVNC PAS exposé** en 3a (interactif = 3b). `--disable-web-security` reste analysis-only (recon = runner séparé). |

## 3. Le runner (`runner_recon/capture.py`)
Entrée : `--url <url>`. Séquence :
1. Xvfb déjà démarré (entrypoint) ; `DISPLAY=:99`.
2. Lance Camoufox headed (`AsyncCamoufox(headless=False, os="linux", humanize=0.3, i_know_what_im_doing=True)`).
3. Arme la capture réseau (`page.on("request")` + `page.on("response")` → `NetworkEntry` avec status).
4. `goto(url, wait_until="domcontentloaded", timeout=30000)`.
5. **Screenshot initial** (step 0).
6. **Détection Turnstile** : `vision.detect(png_to_bgr(screenshot), strategy="turnstile")` → si trouvé, `human_click_xdotool(x, y)` (coords écran) → attendre le passage → **screenshot post** (step 1) ; `turnstile_solved=True`.
7. Capture finale : DOM (`page.content()`), `final_url`, redirect chain, cookies (optionnel).
8. **Static** sur le DOM capturé → `compute_verdict`.
9. Émet le wrapper `{result, blobs}` (mêmes refs sha256 que l'analyse) : `profile="capture"`, `target=url`, `input_hash=sha256(normalized_url)`, `stealth={engine:"camoufox", turnstile_solved}`, `screenshots[]` (1 ou 2 en `dynamic_steps`), `network[]`, `dom{...}`, `static_findings[]`, `verdict`.
10. Ferme, sort (`--rm`).

Robustesse (comme render.py) : le rendu peut échouer → toujours émettre un wrapper valide (findings static garantis si le DOM a été récupéré ; sinon result minimal + `console` d'erreur).

## 4. Image `runner_recon/Dockerfile`
Dérivée de `browser-automation/Dockerfile`, **sans** x11vnc/novnc/websockify (3b) : `python:3.11-slim` + `xvfb xdotool scrot` + libs GTK/X11 + `pip camoufox[geoip] opencv-python-headless numpy playwright` + patch coreBundle + `python -m camoufox fetch` + COPY `capture.py`+`vision.py`+`turnstile_checkbox.png`+`entrypoint_recon.sh`. Entrypoint : démarre Xvfb puis `exec python capture.py "$@"`. Non-root (`USER`), `HOME`/`TMPDIR` sur tmpfs `/work`.

## 5. Launcher — profil `capture`
`build_docker_args(job)` : branche `capture` (aujourd'hui `!= "analysis"` → ValueError ; ajouter `capture`).
- `docker run --rm -i --name ocular-job-{id} --cap-drop ALL --security-opt no-new-privileges:true --security-opt seccomp=schemas/seccomp-recon.json --read-only --tmpfs /work:... --tmpfs /tmp:... --user <uid> --memory 4g --pids-limit 512 <proxy env si défini> ocular-runner-recon:latest --url <job.url>`.
- **PAS** `--network none`. Passthrough `-e HTTP_PROXY -e HTTPS_PROXY` si présents dans l'env du broker.
- `run_analysis_job` → générique `run_job` : dispatch runner selon `job.profile` (analysis→runner-analysis via stdin html ; capture→runner-recon via `--url`). Même parsing du wrapper + stockage artefacts + résultat léger.
- **Warning IP** : loggé au lancement d'un job capture (`log.warning("capture job job_id=%s : IP exposée (proxy=%s)", ...)`).

## 6. Intégration pipeline
- `web/models.JobRequest.profile` : `Literal["analysis","capture"]`. `capture` exige `url` (422 si absent), `analysis` exige `html`.
- `submit_job` : validation par profil ; enqueue `Job(profile, url|html)`.
- **UI submit** : le champ URL n'est plus `disabled` ; un toggle profil (Analyser HTML / Analyser URL) ; le badge « phase 3 » retiré. Dédup : `sha256Hex(normalized_url)` pour le profil URL.
- Le résultat capture s'affiche dans la vue détail existante (`stealth.engine=camoufox`, `turnstile_solved` montré ; screenshots multi-étapes si 2).
- `make analyze URL=<url>` ajouté (mode direct via `run_job`).

## 7. Modèle de menace (delta)
- Cible recon **potentiellement hostile** (exploit navigateur) → contenue par **non-root + éphémère + `--rm` + limites mem/pids**, pas de docker.sock, pas de host-net. Réseau ON = relaxation nécessaire et assumée.
- **IP exposée** → warning + proxy opt-in.
- seccomp recon **profilé** (dérivé au boot comme l'analyse) ; si un syscall Firefox/Xvfb manque, l'ajouter et documenter — **jamais** `unconfined` par défaut si évitable (fallback documenté acceptable si Firefox l'exige réellement).
- Le runner recon ne partage **aucun** code avec `render.py` → le `--disable-web-security` reste cantonné à l'analyse.

## 8. Tests
- **Unit** : normalisation URL + `input_hash` ; `build_docker_args(capture)` a **réseau ON** (pas de `--network none`) + `--cap-drop ALL`/`--rm`/non-root + **pas de docker.sock** + passthrough proxy ; validation modèle (`capture` sans url → 422). `vision.detect(strategy="turnstile")` sur `turnstile_checkbox.png` (fixture) → détection non-None.
- **Intégration** : image recon **build** ; navigation d'une **URL bénigne locale** (petit serveur HTTP de test ou `data:`/`http://localhost`) → wrapper `OcularResult` valide (profile=capture, screenshot, réseau). *(Turnstile réel non déterministe → couvert par le test vision fixture + un mock du clic.)*
- **Garde deploy** : `test_deploy_images` étendu à la 4e image (recon) : build + `import`/`--url` smoke.

## 9. Ordre de livraison (une branche, SDD)
1. Normalisation URL + `input_hash` capture (`engine`), + `input_kind=url`.
2. Port `vision.py`+template dans `runner_recon/` + `capture.py` (script one-shot, émet le wrapper) — testé via mock Playwright/Camoufox pour la logique, réel en intégration.
3. `runner_recon/Dockerfile` + entrypoint + seccomp-recon + **build réel**.
4. Launcher : profil `capture` (réseau ON, durcissement, proxy, warning IP) + `run_job` générique.
5. web/models + submit (profil capture, url requis) + broker route capture.
6. UI : champ URL activé + toggle profil + dédup URL + affichage stealth/turnstile.
7. Ops : `make analyze URL=`, guard `test_deploy_images` (4e image), doc.

## 10. Défauts assumés
Timeout capture 45s (Camoufox plus lent). Viewport 1280x720. 2 screenshots max (initial+post-Turnstile). Proxy via env broker. seccomp-recon dérivé du profil analysis + syscalls Firefox/Xvfb.
