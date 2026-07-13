# Ocular — Phase 3b : Gateway noVNC interactif durci — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Tier interactif : l'analyste navigue à la main (URL live OU HTML hostile) dans un conteneur Camoufox via une passerelle **pixels-only** (noVNC proxifié par le web, TLS+auth), clipboard coupé à la source, conteneur sur réseau interne durci et éphémère.

**Architecture:** Conteneur session persistant (Camoufox+Xvfb+x11vnc+noVNC+session_server) lancé par le broker sur le réseau `ocular-sessions`, sans port hôte ; le web relaie le websocket noVNC et pilote goto/load/capture ; registre session Redis + reaper TTL/idle.

**Tech Stack:** Python 3.11, FastAPI (+ WebSocket + `websockets` client), Camoufox, x11vnc/websockify/noVNC, redis, Docker, vanilla-JS + noVNC embarqué.

## Global Constraints
- **Clipboard coupé à la source** : `x11vnc -noclipboard -nosetclipboard -localhost` (aucun canal presse-papier, quoi que fasse le proxy).
- Conteneur session : réseau ON, **aucun port hôte** (`-p` interdit), sur réseau `ocular-sessions`, durci (non-root, `--cap-drop ALL`, `no-new-privileges`, seccomp-recon, `--read-only`+tmpfs, mem/pids), **JAMAIS** docker.sock/host-net. Détaché (`-d`, pas `--rm -i`) ; détruit par `docker kill/rm`.
- Le **web** reste sans Docker (`grep -riE "docker|launcher|subprocess" web/*.py` vide) — il parle réseau au conteneur + Redis ; le **broker** seul lance/détruit via socket.
- Le **stdout du session_server** n'est pas un wrapper (c'est un serveur HTTP) — mais `/capture` renvoie le même JSON `{result, blobs}` que capture.py, via `engine.wrapper`.
- Auth : middleware étend à `/sessions*` (token normal) ; le **WS** s'authentifie par un **token de session capability** (validé Redis) car un WebSocket navigateur ne pose pas d'en-tête `Authorization`.
- noVNC **embarqué localement** (pas de CDN, CSP `connect-src 'self'`).
- Python 3.11 ; commits fréquents.

## File Structure
```
runner_recon_vnc/{Dockerfile, entrypoint_vnc.sh, session_server.py, __init__.py}
schemas/seccomp-recon.json        # réutilisé (le conteneur vnc = mêmes syscalls que recon + x11vnc/xvfb déjà couverts)
bus/sessions.py                   # registre session Redis
broker/sessions.py                # launch_session/stop_session/reaper (via docker)
broker/main.py                    # + démarrage du reaper
web/app.py                        # + POST/GET/DELETE /sessions, WS proxy, /capture ; _PROTECTED += /sessions
web/ui/vendor/novnc/…             # noVNC embarqué
web/ui/views/interactive.js       # vue interactive
deploy/docker-compose.yml         # réseau ocular-sessions (web + broker), le broker crée le réseau des sessions
pyproject.toml                    # + websockets
tests/…                           # test_sessions_registry, test_broker_sessions, test_web_sessions, test_ws_proxy, test_recon_vnc_dockerfile
```

---

### Task 1: Image `runner_recon_vnc` + `session_server.py` (Camoufox persistant + noVNC clipboard-off)

**Files:** Create `runner_recon_vnc/{__init__.py,Dockerfile,entrypoint_vnc.sh,session_server.py}`, `tests/test_recon_vnc_dockerfile.py`, `tests/test_session_server_logic.py`.

**Interfaces:** conteneur exposant (interne) `session_server` : `GET /health`, `POST /goto {url}`, `POST /load {html}`, `POST /capture` → `{result, blobs}` (via `engine.wrapper.ResultBuilder`) ; noVNC websocket sur `:6080/websockify`.

- [ ] **Step 1: Test contenu Dockerfile** — `tests/test_recon_vnc_dockerfile.py`
```python
from pathlib import Path

def test_vnc_dockerfile_noclipboard_nonroot():
    df = Path("runner_recon_vnc/Dockerfile").read_text()
    ep = Path("runner_recon_vnc/entrypoint_vnc.sh").read_text()
    assert "USER 10001" in df and "novnc" in df.lower() and "x11vnc" in df.lower()
    assert "-noclipboard" in ep and "-nosetclipboard" in ep and "-localhost" in ep  # clipboard coupé + VNC local
    assert "-p " not in ep  # pas de mapping de port dans l'entrypoint
```
- [ ] **Step 2: Échec** — `pytest tests/test_recon_vnc_dockerfile.py -v` → FAIL.

- [ ] **Step 3: `runner_recon_vnc/session_server.py`** — serveur persistant (FastAPI). Réutilise `engine.wrapper` + `runner_recon.vision` pour la capture. `build_capture_result(...)` = logique pure testable ; le pilotage Camoufox garde le contexte vivant.
```python
from __future__ import annotations
import asyncio, base64
from fastapi import FastAPI
from engine.wrapper import NetworkCapture, ResultBuilder, sha256_ref  # noqa
from engine.static import analyze_html
from engine.verdict import compute_verdict
from engine.urlnorm import url_input_hash

app = FastAPI()
_state = {"page": None, "cap": None, "target": None, "kind": None}

async def _ensure_browser():
    if _state["page"] is None:
        from camoufox.async_api import AsyncCamoufox
        cm = AsyncCamoufox(headless=False, os="linux", humanize=0.3, i_know_what_im_doing=True)
        ctx = await cm.__aenter__()
        page = await ctx.new_page()
        cap = NetworkCapture(); cap.attach(page)
        _state.update(page=page, cap=cap, _cm=cm)

@app.get("/health")
async def health(): return {"ok": True}

@app.post("/goto")
async def goto(body: dict):
    await _ensure_browser()
    _state["target"], _state["kind"] = body["url"], "url"
    try: await _state["page"].goto(body["url"], wait_until="domcontentloaded", timeout=45000)
    except Exception as e: return {"error": type(e).__name__}
    return {"ok": True}

@app.post("/load")
async def load(body: dict):
    await _ensure_browser()
    _state["target"], _state["kind"] = "inline-html", "html"
    try: await _state["page"].set_content(body["html"], wait_until="domcontentloaded", timeout=45000)
    except Exception as e: return {"error": type(e).__name__}
    return {"ok": True}

@app.post("/capture")
async def capture(body: dict):
    page, cap = _state["page"], _state["cap"]
    rb = ResultBuilder()
    if page is not None:
        try:
            png = await page.screenshot(full_page=False); rb.add_screenshot(0, "interactive", png)
            dom = (await page.content()).encode(); rb.set_dom(dom); title = await page.title(); final = page.url
        except Exception:
            dom, title, final = b"", "", _state["target"] or ""
    else:
        dom, title, final = b"", "", ""
    from engine.result import DomInfo, StealthInfo
    findings = analyze_html(dom.decode("utf-8","replace")) if dom else []
    ih = url_input_hash(_state["target"]) if _state["kind"] == "url" else ("sha256:" + __import__("hashlib").sha256(body.get("html","").encode() if _state["kind"]=="html" else b"").hexdigest())
    result, blobs = rb.build(job_id="", profile="capture" if _state["kind"]=="url" else "analysis",
                             target=_state["target"] or "", input_hash=ih, verdict=compute_verdict(findings),
                             dom_info=DomInfo(title=title, final_url=final),
                             stealth=StealthInfo(engine="camoufox"))
    # (ResultBuilder.build renvoie (OcularResult, blobs) ; on ajoute network/console/findings)
    result.network = [__import__("engine.result", fromlist=["NetworkEntry"]).NetworkEntry(**n) for n in cap.network] if cap else []
    result.static_findings = findings
    return {"result": result.model_dump(mode="json"),
            "blobs": {r: base64.b64encode(b).decode() for r, b in blobs.items()}}
```
> Note d'implémentation : aligner exactement l'API de `ResultBuilder.build(...)` avec sa signature réelle (issue de la phase 3a) ; l'implémenteur ajuste (network/console peuvent devoir passer par le builder). Le point clé : `/capture` renvoie le MÊME format `{result, blobs}` que capture.py, réutilisant `engine.wrapper`. Extraire `build_capture_result(target, kind, png, dom, title, final, network)` en fonction pure testée dans `test_session_server_logic.py` (sans Camoufox).

- [ ] **Step 4: `runner_recon_vnc/entrypoint_vnc.sh`**
```bash
#!/bin/bash
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99 2>/dev/null || true
Xvfb :99 -screen 0 1280x720x24 >/dev/null 2>&1 &
sleep 2
export DISPLAY=:99
x11vnc -display :99 -forever -shared -rfbport 5900 -noclipboard -nosetclipboard -localhost >/dev/null 2>&1 &
websockify --web=/usr/share/novnc 6080 localhost:5900 >/dev/null 2>&1 &
exec uvicorn runner_recon_vnc.session_server:app --host 127.0.0.1 --port 8090
```
(session_server sur 127.0.0.1 : seul le proxy interne l'atteint via… en fait le web doit l'atteindre — écouter sur 0.0.0.0 mais réseau interne only. Ajuster : `--host 0.0.0.0` car pas de port hôte publié, l'isolation vient de l'absence de `-p` + réseau interne. noVNC websockify écoute 6080 idem.)

- [ ] **Step 5: `runner_recon_vnc/Dockerfile`** — dérivé de `runner_recon/Dockerfile` + `apt-get install x11vnc websockify novnc` + COPY `session_server.py`/`entrypoint_vnc.sh` + `EXPOSE 6080 8090` + `USER 10001` + ENTRYPOINT entrypoint_vnc. Réutilise camoufox déjà installé.

- [ ] **Step 6: build + smoke** —
```bash
docker build -f runner_recon_vnc/Dockerfile -t ocular-runner-recon-vnc:latest .
# smoke : démarre le conteneur (réseau bridge), health + noVNC répondent, clipboard off
CID=$(docker run -d --cap-drop ALL --security-opt no-new-privileges:true --security-opt seccomp=schemas/seccomp-recon.json --read-only --tmpfs /work:size=512m,mode=1777 --tmpfs /tmp:size=64m,mode=1777 --user 10001:10001 --memory 4g --pids-limit 512 ocular-runner-recon-vnc:latest)
sleep 8
docker exec $CID sh -c "curl -sf localhost:8090/health && echo HEALTH_OK"
docker exec $CID sh -c "curl -sf localhost:6080/vnc.html >/dev/null && echo NOVNC_OK"
docker exec $CID sh -c "ps aux | grep -q 'x11vnc.*-noclipboard' && echo CLIPBOARD_OFF"
docker rm -f $CID
```
Attendu : HEALTH_OK, NOVNC_OK, CLIPBOARD_OFF. (curl doit être installé, sinon `wget`/python.)

- [ ] **Step 7: `test_session_server_logic.py`** — teste `build_capture_result` (fonction pure) : url → profile capture + input_hash url ; html → profile analysis ; findings/verdict sur le DOM. Commit.

---

### Task 2: Registre session Redis (`bus/sessions.py`)

**Files:** Create `bus/sessions.py`, `tests/test_sessions_registry.py`.

**Interfaces:** `SessionRegistry(client)` : `create(session_id, container, kind, target, token, ttl)`, `get(id) -> dict|None`, `touch(id)` (met à jour last_activity), `list_active() -> list`, `delete(id)`, `expired(now, ttl, idle) -> list[id]`, `valid_token(id, token) -> bool`.

- [ ] **Step 1: Tests** (fakeredis) — create/get roundtrip ; touch met à jour last_activity ; expired renvoie les sessions dépassant TTL ou idle ; valid_token compare en temps constant ; delete. (Code TDD complet — l'implémenteur écrit les tests puis l'impl paramétrée SQL/Redis.)
- [ ] **Step 2-4:** implémenter (Redis hash par session, `scan_iter("ocular:session:*")`, `secrets.compare_digest` pour le token). Commit.

---

### Task 3: Broker — launch/stop/reaper (`broker/sessions.py`)

**Files:** Create `broker/sessions.py`, `tests/test_broker_sessions.py` ; Modify `broker/main.py`.

**Interfaces:** `build_session_args(session_id, image) -> list[str]` (détaché, réseau `ocular-sessions`, durci, **pas de `-p`**, pas de docker.sock/host-net) ; `launch_session(session_id) -> str` (retourne container) ; `stop_session(container)` ; `reap(registry)` (détruit les conteneurs des sessions expirées).

- [ ] **Step 1: Test unit** — `build_session_args` contient `-d`, `--network ocular-sessions`, `--name ocular-sess-{id}`, durcissement complet, **aucun `-p`/`--publish`**, pas de `docker.sock`/`--network host`/`--privileged`, image `ocular-runner-recon-vnc:latest`. `reap` : pour une session expirée (mock registry), appelle `stop_session`.
- [ ] **Step 2-4:** implémenter. `broker/main.py` : démarrer un **reaper** (thread démon) qui toutes 60s appelle `registry.expired()` → `stop_session` + `registry.delete`. Commit.

---

### Task 4: Réseau `ocular-sessions` (compose)

**Files:** Modify `deploy/docker-compose.yml`.
- [ ] `web` et `broker` rejoignent un réseau `ocular-sessions` (déclaré, `internal: true` si possible pour bloquer l'egress non désiré — MAIS les sessions ont besoin d'egress Internet → **ne pas** `internal: true` ; le réseau sert au web↔conteneur). Le broker lance les sessions sur ce réseau (via `--network ocular-sessions` dans build_session_args). Documenter que le réseau doit préexister (le broker le crée au démarrage si absent : `docker network create ocular-sessions` idempotent, ou compose le déclare et les sessions le rejoignent par nom). Valider `docker compose config`.

---

### Task 5: Web — POST/GET/DELETE /sessions + auth

**Files:** Modify `web/app.py` ; Create `tests/test_web_sessions.py`.
- [ ] `_PROTECTED += ("/sessions",)` (+ `_csp` skip `/sessions*`).
- [ ] `POST /sessions {url|html}` : valide (url → `validate_capture_url` SSRF ; ni url ni html → 422) ; **enqueue une demande de lancement** sur une file Redis (le broker lance, car le web n'a pas Docker) → attend/poll que le `session_server` réponde health via le réseau interne → déclenche `/goto` ou `/load` → génère un **token de session** (`secrets.token_urlsafe`) → `registry.create` → renvoie `{session_id, token}`. Warning IP/hostile loggé.
- [ ] `GET /sessions` (liste), `DELETE /sessions/{id}` (enqueue stop au broker + `registry.delete`).
- [ ] Tests (fakeredis + mock du health/goto) : SSRF→400, 422, création renvoie token, delete.
> Le lancement passe par le broker : réutiliser le pattern file Redis — une file `ocular:session-cmds` (`{action:launch|stop, session_id}`) que le broker consomme dans sa boucle (à côté des jobs). Le broker lance le conteneur, écrit le container name dans le registre, le web poll le registre.

---

### Task 6: Web — WS proxy noVNC (`WS /sessions/{id}/ws`)

**Files:** Modify `web/app.py`, `pyproject.toml` (+`websockets`) ; Create `tests/test_ws_proxy.py`.
- [ ] `pyproject` : ajouter `websockets>=12` aux dependencies.
- [ ] `@app.websocket("/sessions/{sid}/ws")` : **auth par sous-protocole WebSocket (token HORS URL — pas de `?token=` qui fuiterait en logs/referrer)**. Le client envoie deux valeurs dans `Sec-WebSocket-Protocol` : `["binary", "ocular.session.<token>"]` (pattern k8s bearer-subprotocol). Le serveur lit `ws.headers["sec-websocket-protocol"]`, extrait le token du 2e élément, le valide via `registry.valid_token(sid, token)` (temps constant) ; sinon `close(1008)`. Puis `accept(subprotocol="binary")` (ne renvoie QUE `binary`, jamais le token) → `websockets.connect(f"ws://{container}:6080/websockify", subprotocols=["binary"])` → **pump bidirectionnel** octets bruts (RFB) `ws.iter_bytes()`↔`upstream` ; `registry.touch` périodique. Fermer proprement à la déconnexion. **Ne JAMAIS logger le token ni le sous-protocole.**
- [ ] Test (`tests/test_ws_proxy.py`) : token invalide → refus (close 1008) ; avec un faux upstream websocket (serveur de test), les octets transitent dans les deux sens ; touch appelé. (Utiliser `websockets` en test ou un stub.)

---

### Task 7: Web — POST /sessions/{id}/capture

**Files:** Modify `web/app.py` ; Modify `tests/test_web_sessions.py`.
- [ ] `POST /sessions/{id}/capture` (auth normale) : appelle le `session_server`/capture (HTTP interne via `httpx`/`urllib` sur le réseau interne) → wrapper `{result,blobs}` → `_store_blobs` + stocke le résultat léger (comme un job, `set_result` avec un id dérivé) → renvoie le résultat. Réutilise `_read...`/`_store_blobs` existants (factoriser depuis launcher si nécessaire — mais launcher est côté broker ; le web refait un petit store d'artefacts en réutilisant `engine.artifacts.ref_to_filename`, SANS Docker).
- [ ] Test : `/capture` (mock session_server) → artefacts stockés + résultat renvoyé.

---

### Task 8: UI — noVNC embarqué + vue interactive

**Files:** Create `web/ui/vendor/novnc/…`, `web/ui/views/interactive.js` ; Modify `web/ui/core.js` (nav/route), `web/ui/api.js`, `web/ui/i18n.js`, `web/app.py` (CSP `connect-src 'self'`).
- [ ] Embarquer noVNC : copier les fichiers noVNC (depuis le paquet debian `novnc` d'un conteneur : `docker run --rm ocular-runner-recon-vnc:latest tar -C /usr/share/novnc -c core vendor app | tar -C web/ui/vendor/novnc -x`, ou l'équivalent) dans `web/ui/vendor/novnc/`. Vérifier que `core/rfb.js` (module ES) est présent.
- [ ] `api.js` : `createSession({url|html})`, `deleteSession(id)`, `captureSession(id)`.
- [ ] `interactive.js` : `POST /sessions` → import `RFB` de `/vendor/novnc/core/rfb.js` → `new RFB(canvas, wsUrl+"?token="+token)` (pixels) → boutons **Capturer** (`/capture` → affiche résultat) et **Fermer** (`DELETE`). Bandeau warning (IP exposée, contenu hostile rendu côté conteneur). Anti-XSS habituel.
- [ ] `web/app.py` CSP : ajouter `connect-src 'self'` (WS same-origin) au header CSP existant.
- [ ] Route/nav `#/interactive` + libellés i18n.
- [ ] smoke + vérif navigateur (documenté).

---

### Task 9: Ops — Makefile + guard 5e image + README

**Files:** Modify `Makefile`, `tests/test_deploy_images.py`, `README.md`.
- [ ] `build-runner` build aussi `ocular-runner-recon-vnc`. `test_deploy_images` : build+smoke de l'image vnc (health + noVNC + clipboard-off, `@pytest.mark.integration`). README : section « Interactif » (sécu : pixels-only, clipboard off, réseau interne, éphémère ; warning IP/hostile).

---

### Task 10: Audit indépendant + e2e réel + finitions
- [ ] Dispatcher 3 auditeurs (archi/DRY, sécu, qualité) sur la branche (mandat : pas de faille — surtout la surface WS/proxy/session ; clipboard réellement off ; pas de port hôte ; pas de duplication). Remédier les Important+.
- [ ] e2e réel (revue finale) : `POST /sessions {url}` → conteneur sur réseau interne (`docker port` vide), WS proxy transmet du RFB, `/capture` produit un résultat, `DELETE` détruit, reaper nettoie une session abandonnée, **clipboard off vérifié** (args x11vnc).

---

## Self-Review (effectuée)
- **Couverture spec** : conteneur session+session_server (T1), registre (T2), broker launch/stop/reaper (T3), réseau interne (T4), endpoints sessions (T5), WS proxy (T6), capture (T7), UI noVNC (T8), ops (T9), audit+e2e (T10). Clipboard-off (T1 entrypoint + tests), pas de port hôte (T3 test), web sans Docker (T5/T7), auth WS token (T6), DRY (`engine.wrapper` réutilisé T1/T7).
- **Placeholders** : les points d'ajustement (signature `ResultBuilder.build`, host session_server, source noVNC) sont explicités avec la démarche, pas muets.
- **Risques** : T6 (WS proxy) et T1 (conteneur persistant + session_server) sont les plus durs ; itérer les smokes.

## Notes de délégation
Sans Docker : T2, T5(unit), T6(unit stub), T7(unit). Avec Docker : T1 (build vnc), T3 (args, e2e), T8 (noVNC copie), T9, T10. Le WS proxy (T6) est sécu-critique — auth token stricte, fail-closed.
