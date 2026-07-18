# Isolation réseau par session interactive — Plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Donner à chaque session interactive son propre réseau docker, pour qu'un conteneur de session compromis ne puisse plus joindre le `:6080`/`:8090` d'un pair.

**Architecture:** Un réseau bridge par session (`ocular-sess-net-{id}`) créé au lancement et détruit au teardown ; le broker y attache dynamiquement le conteneur web (`docker network connect`) pour qu'il continue de résoudre la session par DNS Docker. Tout le cycle de vie réseau est encapsulé dans les trois fonctions launcher de `broker/sessions.py` — `process_session_cmd`, `reap`, `bus/sessions.py` et `web/app.py` restent **inchangés**.

**Tech Stack:** Python 3, `subprocess` + CLI Docker (le broker est le seul à avoir `docker.sock`), pytest (+ marqueur `integration` pour le test Docker réel), docker compose.

## Global Constraints

- **Secure-by-default, aucun flag** : toute session est isolée ; la constante `_SESSION_NETWORK = "ocular-sessions"` est **supprimée**.
- **PAS `--internal`** sur les réseaux de session : l'egress recon reste nécessaire ; la garde egress applicative reste le filtre.
- **Aucun port hôte publié** (`-p`) — principe existant préservé.
- **`process_session_cmd`, `reap`, `_reaper_loop`, `bus/sessions.py`, `web/app.py` : INCHANGÉS.** Si une tâche vous pousse à les modifier, c'est le signe d'une erreur — remontez-le.
- Toutes les commandes Docker sont **best-effort** (`capture_output=True, check=False`) : robustes au TOCTOU, ne lèvent jamais.
- **Ordre contraignant au teardown** : le conteneur part AVANT `network rm` (Docker refuse de supprimer un réseau utilisé).
- Ne jamais logger de secret. Ne jamais toucher `GUATX/plume`, `GUATX/core`, `GUATX/forge`.
- Commits conventional-commits FR + trailer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Pas de push (aucun remote). Ne jamais committer `deploy/.env`.
- Tests : cycle rapide `. .venv/bin/activate && pytest tests/<f>.py -q` ; validation `make test` (Dockerisé, exclut `integration`) ; le test Docker réel se lance via `make test-int`.

---

## Structure des fichiers

- Modify: `ocular_settings.py` — accessor `web_container()`.
- Modify: `broker/sessions.py` — helper `_session_net`, réseau dans `build_session_args`, cycle de vie dans `launch_session`/`stop_session`, balayage réseaux dans `sweep_orphans`. **Tout le réseau vit ici.**
- Modify: `deploy/docker-compose.yml` — `container_name: ocular-web` + `OCULAR_WEB_CONTAINER` sur le broker.
- Modify: `docs/DEPLOY-SECURITY.md` — §2.3 (isolation session) + prérequis `default-address-pools`.
- Modify: `docs/ROADMAP.md` — résiduel VNC fermé.
- Test: `tests/test_settings.py`, `tests/test_broker_sessions.py` (dont mise à jour de l'assertion réseau existante), `tests/test_session_isolation_integration.py` (créé, marqué `integration`).

---

### Task 1 : Accessor `web_container()` + câblage compose

**Files:**
- Modify: `ocular_settings.py`
- Modify: `deploy/docker-compose.yml`
- Test: `tests/test_settings.py`

**Interfaces:**
- Produces: `web_container() -> str` — nom du conteneur web que le broker attache/détache. Défaut `"ocular-web"`, surchargeable par `OCULAR_WEB_CONTAINER`. Consommé par `launch_session`, `stop_session`, `sweep_orphans` (tâches 3-5).

- [ ] **Step 1: Écrire les tests**

Ajouter à `tests/test_settings.py` :
```python
def test_web_container_default(monkeypatch):
    monkeypatch.delenv("OCULAR_WEB_CONTAINER", raising=False)
    from ocular_settings import web_container
    assert web_container() == "ocular-web"


def test_web_container_env_override(monkeypatch):
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "mon-web")
    from ocular_settings import web_container
    assert web_container() == "mon-web"


def test_web_container_blank_falls_back_to_default(monkeypatch):
    # une valeur vide/espaces ne doit pas produire un nom de conteneur vide
    # (docker network connect échouerait de façon opaque).
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "   ")
    from ocular_settings import web_container
    assert web_container() == "ocular-web"
```

- [ ] **Step 2: Lancer les tests — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_settings.py -k web_container -q`
Expected: FAIL — `ImportError: cannot import name 'web_container'`

- [ ] **Step 3: Ajouter l'accessor**

Dans `ocular_settings.py`, juste avant `def max_sessions()` :
```python
def web_container() -> str:
    """Nom du conteneur web, que le broker attache/détache aux réseaux
    per-session (`docker network connect`). Le compose fixe
    `container_name: ocular-web` pour que ce nom soit DÉTERMINISTE (sinon
    Docker génère `<projet>-web-1`, non devinable par le broker).
    Surchargeable par `OCULAR_WEB_CONTAINER` ; une valeur vide retombe sur
    le défaut (un nom vide ferait échouer `network connect` de façon opaque)."""
    return os.environ.get("OCULAR_WEB_CONTAINER", "").strip() or "ocular-web"
```

- [ ] **Step 4: Lancer les tests — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_settings.py -k web_container -q`
Expected: PASS (3 tests)

- [ ] **Step 5: Câbler le compose**

Dans `deploy/docker-compose.yml`, service `web`, ajouter la clé `container_name` juste sous `build:` :
```yaml
    # Nom DÉTERMINISTE : le broker attache ce conteneur aux réseaux per-session
    # (docker network connect). Sans container_name, Docker générerait
    # `<projet>-web-1`, que le broker ne peut pas deviner.
    container_name: ocular-web
```
Puis, service `broker`, dans `environment:`, ajouter :
```yaml
      # Conteneur web que le broker attache/détache aux réseaux per-session.
      OCULAR_WEB_CONTAINER: "${OCULAR_WEB_CONTAINER:-ocular-web}"
```

- [ ] **Step 6: Vérifier que les tests deploy passent toujours**

Run: `. .venv/bin/activate && pytest tests/test_deploy_images.py tests/test_dockerfile.py tests/test_settings.py -q`
Expected: PASS

- [ ] **Step 7: Commit**
```bash
git add ocular_settings.py deploy/docker-compose.yml tests/test_settings.py
git commit -m "$(cat <<'EOF'
feat(sessions): accessor web_container() + container_name déterministe

Le broker doit référencer le conteneur web par un nom stable pour
l'attacher aux réseaux per-session. container_name: ocular-web fixe ce
nom ; OCULAR_WEB_CONTAINER permet de le surcharger.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2 : Réseau per-session dans `build_session_args`

**Files:**
- Modify: `broker/sessions.py`
- Test: `tests/test_broker_sessions.py` (dont **mise à jour** d'une assertion existante)

**Interfaces:**
- Produces: `_session_net(session_id: str) -> str` → `"ocular-sess-net-{session_id}"` (miroir de `_session_name`). Consommé par `launch_session`/`stop_session`/`sweep_orphans` (tâches 3-5).
- `build_session_args(session_id, secret="", image=...)` : signature inchangée, mais `--network` vaut désormais `_session_net(session_id)`.

- [ ] **Step 1: Mettre à jour le test existant + en ajouter**

Dans `tests/test_broker_sessions.py`, **remplacer** le corps de `test_build_session_args_names_container_and_network` (l'assertion attend aujourd'hui `ocular-sessions`) :
```python
def test_build_session_args_names_container_and_network():
    a = build_session_args("s1")
    assert "--name" in a and "ocular-sess-s1" in a
    # réseau DÉDIÉ à la session (isolation conteneur-à-conteneur) — plus
    # jamais le réseau partagé `ocular-sessions`.
    assert "--network" in a and "ocular-sess-net-s1" in a
    assert "ocular-sessions" not in a
```
Et ajouter :
```python
def test_session_net_mirrors_session_name():
    from broker.sessions import _session_net, _session_name
    assert _session_name("abc") == "ocular-sess-abc"
    assert _session_net("abc") == "ocular-sess-net-abc"
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_broker_sessions.py -k "names_container_and_network or session_net_mirrors" -q`
Expected: FAIL — `ImportError: cannot import name '_session_net'` et l'assertion `ocular-sess-net-s1` échoue.

- [ ] **Step 3: Implémenter**

Dans `broker/sessions.py` : **supprimer** la ligne `_SESSION_NETWORK = "ocular-sessions"` et ajouter après `_session_name` :
```python
def _session_net(session_id: str) -> str:
    """Réseau docker DÉDIÉ à une session (miroir de `_session_name`). Chaque
    session vit sur son propre réseau bridge : deux sessions n'ont donc aucune
    route l'une vers l'autre (un conteneur compromis ne peut plus joindre le
    :6080/:8090 d'un pair). Le web y est attaché dynamiquement par le broker."""
    return f"ocular-sess-net-{session_id}"
```
Puis dans `build_session_args`, remplacer :
```python
        "--network", _SESSION_NETWORK,
```
par :
```python
        "--network", _session_net(session_id),
```
Et mettre à jour la docstring de `build_session_args` : remplacer « Réseau `ocular-sessions` ON » par « Réseau **dédié à la session** (`ocular-sess-net-{id}`) ON ».

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_broker_sessions.py -q`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add broker/sessions.py tests/test_broker_sessions.py
git commit -m "$(cat <<'EOF'
feat(sessions): chaque session naît sur son propre réseau docker

_session_net(id) -> ocular-sess-net-{id} ; build_session_args l'utilise à
la place du réseau partagé ocular-sessions (constante supprimée).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3 : `launch_session` — créer le réseau puis y attacher le web

**Files:**
- Modify: `broker/sessions.py`
- Test: `tests/test_broker_sessions.py`

**Interfaces:**
- Consumes: `_session_net` (tâche 2), `web_container()` (tâche 1).
- Produces: `launch_session(session_id, secret="") -> str` — **signature et retour inchangés** ; émet désormais 3 commandes ordonnées.

- [ ] **Step 1: Écrire les tests**

Ajouter à `tests/test_broker_sessions.py` :
```python
def test_launch_session_creates_net_runs_then_connects_web(monkeypatch):
    # L'ORDRE est la garantie anti-race : le web est attaché AVANT que
    # process_session_cmd n'expose la session au registre.
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "ocular-web")

    name = launch_session("s1", secret="sec")

    assert name == "ocular-sess-s1"
    assert calls[0] == ["docker", "network", "create", "ocular-sess-net-s1"]
    assert calls[1][:3] == ["docker", "run", "-d"]
    assert calls[2] == ["docker", "network", "connect", "ocular-sess-net-s1", "ocular-web"]


def test_launch_session_survives_network_connect_failure(monkeypatch):
    # Si le web n'est pas joignable, on logue mais on ne lève pas : le poll
    # de santé côté web décidera (504 -> teardown), pas d'exception ici.
    def fake_run(args, capture_output=None, check=None):
        rc = 1 if args[:3] == ["docker", "network", "connect"] else 0
        return type("P", (), {"returncode": rc, "stdout": b"", "stderr": b"no such container"})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    assert launch_session("s1") == "ocular-sess-s1"


def test_launch_session_survives_network_create_failure(monkeypatch):
    # Pool d'adresses Docker épuisé : on logue un warning distinctif, on ne lève pas.
    def fake_run(args, capture_output=None, check=None):
        rc = 1 if args[:3] == ["docker", "network", "create"] else 0
        return type("P", (), {"returncode": rc, "stdout": b"", "stderr": b"could not find an available predefined subnet"})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    assert launch_session("s1") == "ocular-sess-s1"
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_broker_sessions.py -k launch_session -q`
Expected: FAIL — `calls[0]` vaut `["docker","run","-d",...]` (aucun `network create` émis).

- [ ] **Step 3: Implémenter**

Dans `broker/sessions.py`, ajouter l'import en tête (avec les autres imports `ocular_settings`) :
```python
from ocular_settings import session_screen, web_container
```
Puis remplacer entièrement le corps de `launch_session` :
```python
def launch_session(session_id: str, secret: str = "") -> str:
    """Lance un conteneur de session détaché sur son réseau DÉDIÉ et y attache
    le conteneur web, puis retourne le nom du conteneur
    (`ocular-sess-{session_id}`). Seul le broker (jamais le web) exécute ceci.

    Ordre CONTRAIGNANT (garantie anti-race) : réseau créé -> conteneur lancé
    dessus -> web attaché. `process_session_cmd` n'écrit au registre qu'APRÈS
    le retour d'ici, donc quand le web commence son poll de santé il est déjà
    sur le réseau et résout `ocular-sess-{id}` par DNS Docker.

    Tout est best-effort : le nom est toujours retourné, même si une commande
    échoue — c'est le poll de santé aval qui décide de l'état réel."""
    name = _session_name(session_id)
    net = _session_net(session_id)
    log.info("session launch session_id=%s net=%s", session_id, net)  # jamais le secret

    created = subprocess.run(
        ["docker", "network", "create", net], capture_output=True, check=False
    )
    if created.returncode != 0:
        stderr = created.stderr.decode(errors="replace")
        if "already exists" not in stderr:
            # Warning DISTINCTIF : la cause la plus probable est l'épuisement du
            # pool d'adresses Docker (cf. docs/DEPLOY-SECURITY.md, élargir
            # default-address-pools). Sans ce log, l'échec serait opaque.
            log.warning(
                "session network create failed session_id=%s net=%s stderr=%s "
                "(pool d'adresses Docker épuisé ? cf. default-address-pools)",
                session_id, net, stderr[:200],
            )

    proc = subprocess.run(
        build_session_args(session_id, secret=secret), capture_output=True, check=False
    )
    if proc.returncode != 0:
        log.warning(
            "session launch failed session_id=%s returncode=%s stderr=%s",
            session_id, proc.returncode, proc.stderr.decode(errors="replace")[:200],
        )

    web = web_container()
    conn = subprocess.run(
        ["docker", "network", "connect", net, web], capture_output=True, check=False
    )
    if conn.returncode != 0:
        log.warning(
            "session network connect failed session_id=%s net=%s web=%s stderr=%s",
            session_id, net, web, conn.stderr.decode(errors="replace")[:200],
        )
    return name
```

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_broker_sessions.py -q`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add broker/sessions.py tests/test_broker_sessions.py
git commit -m "$(cat <<'EOF'
feat(sessions): launch_session crée le réseau dédié puis y attache le web

Ordre contraignant create -> run -> connect : le web est attaché AVANT que
le registre n'expose la session, donc son poll de santé résout la session
par DNS Docker sans race. Best-effort ; warning distinctif si le pool
d'adresses Docker est épuisé.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4 : `stop_session` — détacher le web et supprimer le réseau

**Files:**
- Modify: `broker/sessions.py`
- Test: `tests/test_broker_sessions.py`

**Interfaces:**
- Consumes: `_session_net`, `web_container()`.
- Produces: `stop_session(container: str) -> None` — **signature inchangée** (appelée par `process_session_cmd` et `reap` avec le nom déterministe) ; émet 4 commandes ordonnées.

- [ ] **Step 1: Écrire les tests**

Ajouter à `tests/test_broker_sessions.py` :
```python
def test_stop_session_removes_container_then_network(monkeypatch):
    # ORDRE CONTRAIGNANT : Docker refuse `network rm` tant qu'un conteneur y
    # est attaché -> le conteneur doit partir AVANT.
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "ocular-web")

    stop_session("ocular-sess-s1")

    assert calls[0] == ["docker", "kill", "ocular-sess-s1"]
    assert calls[1] == ["docker", "rm", "-f", "ocular-sess-s1"]
    assert calls[2] == ["docker", "network", "disconnect", "-f", "ocular-sess-net-s1", "ocular-web"]
    assert calls[3] == ["docker", "network", "rm", "ocular-sess-net-s1"]


def test_stop_session_ignores_container_without_session_prefix(monkeypatch):
    # Nom inattendu -> on ne dérive aucun réseau (pas de `network rm` sauvage).
    calls = []

    def fake_run(args, capture_output=None, check=None):
        calls.append(args)
        return type("P", (), {"returncode": 0, "stdout": b"", "stderr": b""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    stop_session("un-autre-conteneur")
    assert all("network" not in a for a in calls)
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_broker_sessions.py -k stop_session -q`
Expected: FAIL — `IndexError: list index out of range` sur `calls[2]` (seules kill+rm sont émises).

- [ ] **Step 3: Implémenter**

Dans `broker/sessions.py`, ajouter la constante sous `_SESSION_IMAGE` :
```python
_CONTAINER_PREFIX = "ocular-sess-"
_NET_PREFIX = "ocular-sess-net-"
```
Puis remplacer entièrement le corps de `stop_session` :
```python
def stop_session(container: str) -> None:
    """Arrête et supprime un conteneur de session PUIS libère son réseau dédié
    (détache le web, supprime le réseau). Best-effort (`check=False`) : robuste
    au TOCTOU (conteneur/réseau déjà disparu — `reap` peut appeler ceci sur un
    fantôme sans lever).

    L'ORDRE est contraignant : Docker refuse de supprimer un réseau encore
    utilisé, donc le conteneur part d'abord."""
    subprocess.run(["docker", "kill", container], capture_output=True, check=False)
    subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)

    if not container.startswith(_CONTAINER_PREFIX):
        return  # nom inattendu : ne jamais dériver/supprimer un réseau au hasard
    session_id = container[len(_CONTAINER_PREFIX):]
    net = _session_net(session_id)
    subprocess.run(
        ["docker", "network", "disconnect", "-f", net, web_container()],
        capture_output=True, check=False,
    )
    subprocess.run(["docker", "network", "rm", net], capture_output=True, check=False)
```

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_broker_sessions.py tests/test_reaper_e2e.py -q`
Expected: PASS (le reaper appelle `stop_session` : non-régression vérifiée ici)

- [ ] **Step 5: Commit**
```bash
git add broker/sessions.py tests/test_broker_sessions.py
git commit -m "$(cat <<'EOF'
feat(sessions): stop_session libère le réseau dédié (détache le web + rm)

Ordre contraignant kill -> rm -f -> network disconnect -f -> network rm
(Docker refuse de supprimer un réseau encore utilisé). Best-effort ; un
nom de conteneur inattendu ne dérive aucun réseau.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5 : `sweep_orphans` — balayer aussi les réseaux orphelins

**Files:**
- Modify: `broker/sessions.py`
- Test: `tests/test_broker_sessions.py`

**Interfaces:**
- Consumes: `_NET_PREFIX`, `_session_net`, `web_container()`.
- Produces: `sweep_orphans(registry) -> int` — retourne toujours le nombre de **conteneurs** supprimés (contrat inchangé) ; supprime en plus les réseaux orphelins (compté dans un log dédié). Nouveau helper interne `_sweep_orphan_networks(registry) -> int`.

- [ ] **Step 1: Écrire les tests**

Ajouter à `tests/test_broker_sessions.py` :
```python
class _FakeReg:
    """Registre minimal : seules les sessions listées sont 'vivantes'."""
    def __init__(self, alive):
        self._alive = set(alive)

    def get(self, session_id):
        return {"session_id": session_id} if session_id in self._alive else None


def test_sweep_orphans_removes_orphan_networks_only(monkeypatch):
    from broker.sessions import sweep_orphans
    calls = []

    def fake_run(args, capture_output=None, check=None, text=None):
        calls.append(args)
        if args[:2] == ["docker", "ps"]:
            return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if args[:3] == ["docker", "network", "ls"]:
            # un réseau orphelin (s-dead) + un réseau de session vivante (s-live)
            return type("P", (), {"returncode": 0,
                                  "stdout": "ocular-sess-net-s-dead\nocular-sess-net-s-live\n",
                                  "stderr": ""})()
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", "ocular-web")

    sweep_orphans(_FakeReg(alive={"s-live"}))

    assert ["docker", "network", "rm", "ocular-sess-net-s-dead"] in calls
    assert ["docker", "network", "rm", "ocular-sess-net-s-live"] not in calls
    assert ["docker", "network", "disconnect", "-f", "ocular-sess-net-s-dead", "ocular-web"] in calls


def test_sweep_orphans_network_substring_guard(monkeypatch):
    # `--filter name=` est un filtre SUBSTRING : un réseau au nom voisin ne
    # doit pas être supprimé.
    from broker.sessions import sweep_orphans
    calls = []

    def fake_run(args, capture_output=None, check=None, text=None):
        calls.append(args)
        if args[:2] == ["docker", "ps"]:
            return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        if args[:3] == ["docker", "network", "ls"]:
            return type("P", (), {"returncode": 0,
                                  "stdout": "prefixe-ocular-sess-net-x\n", "stderr": ""})()
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(sessions_mod.subprocess, "run", fake_run)
    sweep_orphans(_FakeReg(alive=set()))
    assert all(a[:3] != ["docker", "network", "rm"] for a in calls)
```

- [ ] **Step 2: Lancer — échec attendu**

Run: `. .venv/bin/activate && pytest tests/test_broker_sessions.py -k sweep_orphans -q`
Expected: FAIL — aucune commande `docker network ls` n'est émise.

- [ ] **Step 3: Implémenter**

Dans `broker/sessions.py`, ajouter avant `sweep_orphans` :
```python
def _sweep_orphan_networks(registry) -> int:
    """Supprime les réseaux `ocular-sess-net-*` qui ne correspondent à AUCUNE
    session vivante — résidus d'un crash broker, d'un `compose down`, ou d'un
    `network rm` qui avait échoué (conteneur pas encore parti). Un réseau
    orphelin est inerte mais consomme un sous-réseau du pool d'adresses Docker,
    qui est une ressource FINIE : sans ce balayage, les lancements finiraient
    par échouer. Best-effort."""
    proc = subprocess.run(
        ["docker", "network", "ls", "--filter", f"name={_NET_PREFIX}", "--format", "{{.Name}}"],
        capture_output=True, check=False, text=True,
    )
    if proc.returncode != 0:
        return 0
    removed = 0
    web = web_container()
    for name in proc.stdout.split():
        if not name.startswith(_NET_PREFIX):
            continue  # garde-fou : le filtre `name=` est un substring
        session_id = name[len(_NET_PREFIX):]
        if registry.get(session_id) is not None:
            continue  # session vivante : on ne touche pas à son réseau
        subprocess.run(
            ["docker", "network", "disconnect", "-f", name, web],
            capture_output=True, check=False,
        )
        subprocess.run(["docker", "network", "rm", name], capture_output=True, check=False)
        removed += 1
    if removed:
        log.info("session orphan networks swept count=%d", removed)
    return removed
```
Puis, à la fin de `sweep_orphans`, **avant** le `return removed` final, insérer :
```python
    # Les conteneurs orphelins sont partis -> leurs réseaux peuvent être libérés
    # (ordre contraignant, comme dans stop_session).
    _sweep_orphan_networks(registry)
```

- [ ] **Step 4: Lancer — succès attendu**

Run: `. .venv/bin/activate && pytest tests/test_broker_sessions.py -q`
Expected: PASS

- [ ] **Step 5: Suite complète**

Run: `. .venv/bin/activate && pytest -m "not integration" -q`
Expected: PASS (aucune régression ; `process_session_cmd`/`reap`/web intacts)

- [ ] **Step 6: Commit**
```bash
git add broker/sessions.py tests/test_broker_sessions.py
git commit -m "$(cat <<'EOF'
feat(sessions): sweep_orphans balaie aussi les réseaux orphelins

Un réseau ocular-sess-net-* sans session vivante est un résidu (crash
broker, compose down, network rm échoué) qui consomme un sous-réseau du
pool d'adresses Docker — ressource finie. Balayé au démarrage du broker,
avec le même garde-fou substring que les conteneurs.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6 : Test d'intégration — la preuve de l'isolation

**Files:**
- Create: `tests/test_session_isolation_integration.py`

**Interfaces:**
- Consumes: `launch_session`, `stop_session` (tâches 3-4), `web_container()` (tâche 1).

Ce test est **la seule preuve** de la propriété de sécurité. Il crée un conteneur « sonde » qui joue le rôle du web (attaché aux réseaux par `launch_session` via `OCULAR_WEB_CONTAINER`), lance deux vraies sessions, puis vérifie que **A ne joint pas B** alors que **la sonde joint les deux**.

- [ ] **Step 1: Écrire le test**

Créer `tests/test_session_isolation_integration.py` :
```python
"""Preuve d'intégration de l'isolation réseau par session (design
2026-07-18) : deux sessions réelles vivent sur des réseaux docker DISJOINTS,
donc un conteneur de session compromis ne peut PAS joindre le :6080/:8090
d'un pair — alors que le conteneur web (ici une « sonde » qui en joue le
rôle, attachée par launch_session) joint les deux.

Marqué `integration` : nécessite le démon Docker + l'image de session.
Lancer via `make test-int`."""
import shutil
import subprocess
import time
import uuid

import pytest

import broker.sessions as sessions_mod
from broker.sessions import launch_session, stop_session

pytestmark = pytest.mark.integration

_SESSION_IMAGE = "ocular-runner-recon-vnc:latest"


def _docker() -> str:
    exe = shutil.which("docker")
    if exe is None:
        pytest.skip("docker CLI absent de l'hôte")
    return exe


def _require_image(docker: str) -> None:
    proc = subprocess.run([docker, "image", "inspect", _SESSION_IMAGE],
                          capture_output=True, check=False)
    if proc.returncode != 0:
        pytest.skip(f"image {_SESSION_IMAGE} absente (make build-runner)")


def _can_reach(docker: str, from_container: str, host: str, port: int) -> bool:
    """curl depuis `from_container` vers host:port. True si la connexion TCP
    aboutit (peu importe le code HTTP), False si DNS/connexion échoue."""
    proc = subprocess.run(
        [docker, "exec", from_container, "curl", "-s", "-m", "3", "-o", "/dev/null",
         f"http://{host}:{port}/"],
        capture_output=True, check=False,
    )
    # curl: 6=DNS introuvable, 7=connexion refusée, 28=timeout -> injoignable.
    return proc.returncode == 0


def _wait_reachable(docker: str, from_container: str, host: str, port: int,
                    timeout_s: float = 60.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _can_reach(docker, from_container, host, port):
            return True
        time.sleep(1.0)
    return False


def test_two_sessions_cannot_reach_each_other(monkeypatch):
    docker = _docker()
    _require_image(docker)

    suffix = uuid.uuid4().hex[:8]
    sid_a, sid_b = f"iso-a-{suffix}", f"iso-b-{suffix}"
    probe = f"ocular-web-probe-{suffix}"

    # La « sonde » joue le rôle du conteneur web : launch_session l'attachera
    # à chaque réseau de session via OCULAR_WEB_CONTAINER.
    monkeypatch.setenv("OCULAR_WEB_CONTAINER", probe)

    subprocess.run(
        [docker, "run", "-d", "--name", probe, "--entrypoint", "sleep",
         _SESSION_IMAGE, "3600"],
        capture_output=True, check=False,
    )
    try:
        launch_session(sid_a)
        launch_session(sid_b)
        ca, cb = f"ocular-sess-{sid_a}", f"ocular-sess-{sid_b}"
        try:
            # 1) Contrôle POSITIF : la sonde (= le web) joint les DEUX sessions.
            #    Attente de disponibilité : websockify met quelques secondes.
            assert _wait_reachable(docker, probe, ca, 6080), \
                "la sonde (web) doit joindre la session A"
            assert _wait_reachable(docker, probe, cb, 6080), \
                "la sonde (web) doit joindre la session B"

            # 2) PROPRIÉTÉ DE SÉCURITÉ : A ne joint PAS B (réseaux disjoints).
            assert not _can_reach(docker, ca, cb, 6080), \
                "ISOLATION ROMPUE : la session A joint le :6080 de la session B"
            assert not _can_reach(docker, ca, cb, 8090), \
                "ISOLATION ROMPUE : la session A joint le :8090 de la session B"
            assert not _can_reach(docker, cb, ca, 6080), \
                "ISOLATION ROMPUE : la session B joint le :6080 de la session A"
        finally:
            stop_session(ca)
            stop_session(cb)
    finally:
        subprocess.run([docker, "rm", "-f", probe], capture_output=True, check=False)


def test_stop_session_removes_the_dedicated_network():
    docker = _docker()
    _require_image(docker)

    suffix = uuid.uuid4().hex[:8]
    sid = f"iso-net-{suffix}"
    net = sessions_mod._session_net(sid)
    try:
        launch_session(sid)
        listed = subprocess.run(
            [docker, "network", "ls", "--filter", f"name={net}", "--format", "{{.Name}}"],
            capture_output=True, check=False, text=True,
        )
        assert net in listed.stdout, "le réseau dédié doit exister après launch"
    finally:
        stop_session(f"ocular-sess-{sid}")

    listed = subprocess.run(
        [docker, "network", "ls", "--filter", f"name={net}", "--format", "{{.Name}}"],
        capture_output=True, check=False, text=True,
    )
    assert net not in listed.stdout, "le réseau dédié doit être supprimé au teardown"
```

- [ ] **Step 2: Vérifier que le test est bien exclu de la suite unitaire**

Run: `. .venv/bin/activate && pytest -m "not integration" -q --collect-only 2>&1 | grep -c session_isolation`
Expected: `0` (le marqueur `integration` l'exclut de `make test`)

- [ ] **Step 3: Lancer le test d'intégration réel**

Run: `make test-int`
Expected: PASS — en particulier `test_two_sessions_cannot_reach_each_other`. Si l'image de session est absente, le test SKIP proprement (construire d'abord : `make build-runner` puis l'image vnc).
Si une assertion « ISOLATION ROMPUE » échoue, **ne pas continuer** : c'est que l'isolation ne fonctionne pas.

- [ ] **Step 4: Commit**
```bash
git add tests/test_session_isolation_integration.py
git commit -m "$(cat <<'EOF'
test(sessions): preuve d'intégration de l'isolation réseau inter-sessions

Deux sessions réelles sur réseaux disjoints : A ne joint ni le :6080 ni le
:8090 de B (et réciproquement), alors qu'une sonde jouant le rôle du web —
attachée par launch_session — joint les deux. Vérifie aussi que le réseau
dédié est bien supprimé au teardown.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7 : Documentation opérateur (prérequis pool d'adresses)

**Files:**
- Modify: `docs/DEPLOY-SECURITY.md`
- Modify: `docs/ROADMAP.md`

- [ ] **Step 1: Mettre à jour §2.3 de DEPLOY-SECURITY.md**

Dans `docs/DEPLOY-SECURITY.md`, remplacer la section `### 2.3 Isolation inter-sessions & VNC (HIGH)` par :
```markdown
### 2.3 Isolation inter-sessions & VNC — ✅ FERMÉ DANS LE CODE (2026-07-18)
Chaque session interactive vit désormais sur son **propre réseau docker**
(`ocular-sess-net-{id}`), auquel le broker attache dynamiquement le conteneur
web. Deux sessions sont sur des réseaux **disjoints** : un conteneur de session
compromis ne peut plus joindre le `:6080` (websockify, sans auth propre) ni le
`:8090` d'un pair. Prouvé par `tests/test_session_isolation_integration.py`.

**PRÉREQUIS DE DÉPLOIEMENT — pool d'adresses Docker.** Chaque session consomme
un sous-réseau du pool d'adresses local. Le pool **par défaut** de Docker
(`base 172.17.0.0/12, size 16`) ne fournit qu'une poignée de réseaux `/16` —
avec `OCULAR_MAX_SESSIONS` à 25, une charge soutenue peut **l'épuiser**
(`docker network create` échoue, la session part en 504 — fail-safe mais
dégradé, et le broker logue `session network create failed … pool d'adresses
Docker épuisé ?`). **À faire** : élargir le pool dans `/etc/docker/daemon.json`,
par ex.
```json
{"default-address-pools":[{"base":"172.16.0.0/12","size":24},
                          {"base":"10.200.0.0/16","size":24}]}
```
(des `/24` donnent des centaines de réseaux), **ou** abaisser
`OCULAR_MAX_SESSIONS`. Redémarrer le démon Docker après modification.
```

- [ ] **Step 2: Mettre à jour la checklist §3**

Dans la checklist de déploiement (§3), ajouter une ligne :
```markdown
- [ ] **Pool d'adresses Docker** élargi (`default-address-pools`) ou `OCULAR_MAX_SESSIONS` abaissé — §2.3.
```

- [ ] **Step 3: Mettre à jour la ROADMAP**

Dans `docs/ROADMAP.md`, remplacer le paragraphe « **⏳ Reste (décision de design, non bloquant)** : **isolation VNC inter-sessions**… » par :
```markdown
- ~~**Isolation VNC inter-sessions**~~ → **✅ FERMÉ (2026-07-18)** : un réseau docker par session (`ocular-sess-net-{id}`), le broker y attache dynamiquement le web ; deux sessions sont sur des réseaux disjoints. Le VNC-passwd (DES 8 char) a été écarté comme fausse sécurité. Prouvé par un test d'intégration (A ne joint pas B, la sonde-web joint les deux). Prérequis opérateur : élargir `default-address-pools` de Docker (cf. DEPLOY-SECURITY §2.3).
```

- [ ] **Step 4: Vérifier les tests docs/deploy**

Run: `. .venv/bin/activate && pytest tests/test_deploy_images.py tests/test_dockerfile.py -q`
Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add docs/DEPLOY-SECURITY.md docs/ROADMAP.md
git commit -m "$(cat <<'EOF'
docs(sessions): isolation réseau par session livrée + prérequis pool Docker

DEPLOY-SECURITY §2.3 passe de résiduel opérateur à fermé dans le code, avec
le prérequis default-address-pools (le pool par défaut peut être épuisé par
OCULAR_MAX_SESSIONS=25). ROADMAP mise à jour.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Validation finale (après la dernière tâche)

- [ ] **Suite Dockerisée complète**

Run: `make test`
Expected: PASS, aucune régression (les tests `integration` sont exclus).

- [ ] **Test d'intégration réel**

Run: `make test-int`
Expected: PASS, dont `test_two_sessions_cannot_reach_each_other`.

- [ ] **Vérification e2e manuelle**

Démarrer la stack (`make up`), ouvrir une session interactive depuis l'UI : le flux noVNC doit s'afficher et « Sauvegarder » doit produire une capture. Puis `docker network ls | grep ocular-sess-net-` pendant la session (le réseau existe) et après fermeture (il a disparu).

---

## Self-review (fait à l'écriture du plan)

- **Couverture spec** : N1 (réseau par session) → T2 ; N2 (secure-by-default, constante supprimée) → T2 ; N3 (attache dynamique du web) → T1+T3 ; N4 (pas `--internal`) → T2 (aucun `--internal` ajouté) ; N5 (encapsulation, web/reap inchangés) → T3/T4/T5 + vérifié par la non-régression T5 step 5 ; N6 (pas de port hôte) → aucun `-p` introduit. §3.3 (identification web) → T1. §3.4 (changements précis) → T2-T5. §4 (robustesse : redémarrages, échecs, pool, concurrence) → T3 (échecs create/connect), T4 (ordre teardown), T5 (orphelins), T7 (pool documenté). §5 (tests 1-7) → T2 (test 1), T3 (tests 2-3), T4 (test 4), T5 (test 5), T1 (test 6), T6 (test 7 intégration).
- **Placeholders** : aucun « TBD/TODO » ; chaque step de code porte le code réel. Les modifications de docs citent le texte de remplacement complet.
- **Cohérence des types** : `_session_net(session_id) -> str` et `web_container() -> str` utilisés à l'identique dans T3/T4/T5 ; `launch_session(session_id, secret="") -> str` et `stop_session(container) -> None` conservent leurs signatures d'origine (exigence N5) ; `_CONTAINER_PREFIX`/`_NET_PREFIX` définis en T4 et réutilisés en T5.
