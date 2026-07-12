# Ocular — Analyses sauvegardées — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Persistance opt-in des analyses dans SQLite auto-contenu (blobs), dédup par `sha256(html)` avec modal au submit, UI admin (delete/flush) sous token admin séparé.

**Architecture:** Le runner ajoute `input_hash` au résultat. Le tier web persiste (résultat + octets d'artefacts) dans `saved.db` (SQLite, volume `/saved` rw), dédup sur les sauvegardes, sert les artefacts sauvegardés avec les mêmes protections, et gate les ops destructives sous `OCULAR_ADMIN_TOKEN`.

**Tech Stack:** Python 3.11, FastAPI, sqlite3 (stdlib), Playwright, pytest, vanilla-JS.

## Global Constraints
- `web` reste **sans Docker** (`grep -riE "docker|launcher|subprocess" web/` vide). SQLite = stdlib, pas une dépendance Docker.
- Requêtes SQLite **paramétrées** partout (zéro concaténation de valeurs). `PRAGMA foreign_keys = ON`.
- Artefacts sauvegardés servis **nosniff** ; DOM jamais `text/html` inline (→ `text/plain` + `attachment`) ; `ref` validé anti-traversal via `engine.artifacts.ref_to_filename`.
- Ops destructives (`DELETE /saved*`) sous **`OCULAR_ADMIN_TOKEN`** (header `X-Admin-Token`), **fail-closed** (503 si non configuré, 403 si absent/faux), comparaison temps-constant en bytes. Le token admin n'est **jamais** loggé.
- `input_hash` = `sha256` de la **chaîne HTML UTF-8 exacte**, identique côté runner et côté client (dédup).
- Middleware auth existant (`/jobs*`) étendu à `/saved*` (token normal). CSP skip aussi `/saved*`.
- Python 3.11 ; commits fréquents.

---

### Task 1: `input_hash` dans le résultat (runner)

**Files:** Modify `engine/result.py`, `runner_analysis/render.py`, `tests/test_render.py`, `tests/test_result_schema.py`.

**Interfaces:** `OcularResult.input_hash: Optional[str]` ; le runner le remplit avec `sha256(html)`.

- [ ] **Step 1: Test qui échoue** — dans `tests/test_render.py`, ajouter au test d'intégration existant une assertion :
```python
    import hashlib
    html = "<html><title>Hi</title><body>hello</body></html>"
    r, _ = render.render_html(html, "job-1")
    assert r.input_hash == "sha256:" + hashlib.sha256(html.encode()).hexdigest()
```

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_render.py -m integration -v` → FAIL (`input_hash` inexistant).

- [ ] **Step 3: `engine/result.py`** — ajouter le champ à `OcularResult` (après `target`) :
```python
    input_hash: Optional[str] = None
```

- [ ] **Step 4: `runner_analysis/render.py`** — dans `render_html`, calculer et passer `input_hash` :
```python
    result = OcularResult(
        job_id=job_id, profile="analysis", target="inline-html",
        input_hash=_sha256_ref(html.encode()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        ...
    )
```
(`_sha256_ref` renvoie déjà `"sha256:"+hexdigest` — réutilisé.)

- [ ] **Step 5: Régénérer le schéma** — le contrat `schemas/result.schema.json` change (nouveau champ). Régénérer :
```bash
. .venv/bin/activate
python -c "import json,pathlib; from engine.result import OcularResult; pathlib.Path('schemas/result.schema.json').write_text(json.dumps(OcularResult.model_json_schema(), indent=2))"
```
Le test `test_generated_schema_validates_payload_and_is_written` (fidélité disque/modèle) doit rester vert.

- [ ] **Step 6: Rebuild + vérifier** — `docker build -f runner_analysis/Dockerfile -t ocular-runner-analysis:latest .` ; `pytest -m "not integration" -q` + `pytest -m integration -v` verts.
- [ ] **Step 7: Commit** — `git add -A && git commit -m "feat(engine): input_hash (sha256 du html) dans le résultat"`

---

### Task 2: Store SQLite `saved_store.py`

**Files:** Create `saved_store.py`, `tests/test_saved_store.py` ; Modify `ocular_settings.py`.

**Interfaces:** `saved_store.connect(path)`, `save(conn, result, blobs, label, now_iso) -> int`, `get_by_hash(conn, input_hash) -> dict|None`, `get_result(conn, id) -> dict|None`, `list_all(conn) -> list[dict]`, `get_artifact(conn, id, ref) -> bytes|None`, `delete(conn, id) -> bool`, `flush(conn) -> int`, `refs_of(result) -> list[str]`. `ocular_settings.saved_db_path()`.

- [ ] **Step 1: `ocular_settings.py`** — ajouter :
```python
def saved_db_path() -> str:
    return os.environ.get("OCULAR_SAVED_DB", "/saved/saved.db")


def admin_token() -> str | None:
    return os.environ.get("OCULAR_ADMIN_TOKEN")
```

- [ ] **Step 2: Test qui échoue** — `tests/test_saved_store.py`
```python
import saved_store as ss


def _result(h="sha256:" + "a" * 64, refs=("sha256:" + "b" * 64,)):
    return {
        "input_hash": h, "job_id": "j", "verdict": "malicious",
        "screenshots": [{"image_ref": r} for r in refs],
        "artifacts": {"dom_html_ref": None},
    }


def _conn():
    return ss.connect(":memory:")


def test_save_and_get_by_hash_and_result_and_artifact():
    c = _conn()
    blobs = {"sha256:" + "b" * 64: b"PNGBYTES"}
    sid = ss.save(c, _result(), blobs, "note", "2026-07-12T00:00:00Z")
    meta = ss.get_by_hash(c, "sha256:" + "a" * 64)
    assert meta and meta["verdict"] == "malicious" and meta["label"] == "note"
    assert ss.get_result(c, sid)["verdict"] == "malicious"
    assert ss.get_artifact(c, sid, "sha256:" + "b" * 64) == b"PNGBYTES"


def test_upsert_replaces_same_hash():
    c = _conn()
    ss.save(c, _result(), {"sha256:" + "b" * 64: b"X"}, "v1", "t1")
    ss.save(c, {**_result(), "verdict": "benign"}, {"sha256:" + "b" * 64: b"Y"}, "v2", "t2")
    assert len(ss.list_all(c)) == 1
    meta = ss.get_by_hash(c, "sha256:" + "a" * 64)
    assert meta["verdict"] == "benign" and meta["label"] == "v2"


def test_multistep_stores_all_blobs():
    c = _conn()
    r = {"input_hash": "sha256:" + "c" * 64, "verdict": "suspicious",
         "screenshots": [{"image_ref": "sha256:" + "1" * 64}, {"image_ref": "sha256:" + "2" * 64}],
         "artifacts": {"dom_html_ref": "sha256:" + "3" * 64}}
    blobs = {"sha256:" + "1" * 64: b"A", "sha256:" + "2" * 64: b"B", "sha256:" + "3" * 64: b"C"}
    sid = ss.save(c, r, blobs, None, "t")
    assert ss.get_artifact(c, sid, "sha256:" + "2" * 64) == b"B"
    assert ss.get_artifact(c, sid, "sha256:" + "3" * 64) == b"C"


def test_delete_cascades_and_flush():
    c = _conn()
    sid = ss.save(c, _result(), {"sha256:" + "b" * 64: b"X"}, None, "t")
    assert ss.delete(c, sid) is True
    assert ss.get_artifact(c, sid, "sha256:" + "b" * 64) is None  # cascade
    ss.save(c, _result(), {"sha256:" + "b" * 64: b"X"}, None, "t")
    assert ss.flush(c) == 1 and ss.list_all(c) == []


def test_label_is_parameterized_not_injected():
    c = _conn()
    evil = "'); DROP TABLE saved_analysis;--"
    ss.save(c, _result(), {"sha256:" + "b" * 64: b"X"}, evil, "t")
    # la table existe toujours et le label est stocké littéralement
    assert ss.get_by_hash(c, "sha256:" + "a" * 64)["label"] == evil
```

- [ ] **Step 3: Vérifier l'échec** — `pytest tests/test_saved_store.py -v` → FAIL.

- [ ] **Step 4: Implémenter `saved_store.py`**
```python
from __future__ import annotations

import json
import sqlite3
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS saved_analysis (
  id INTEGER PRIMARY KEY,
  input_hash TEXT NOT NULL UNIQUE,
  input_kind TEXT NOT NULL,
  job_id TEXT,
  verdict TEXT,
  label TEXT,
  result_json TEXT NOT NULL,
  saved_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS saved_artifact (
  saved_id INTEGER NOT NULL REFERENCES saved_analysis(id) ON DELETE CASCADE,
  ref TEXT NOT NULL,
  bytes BLOB NOT NULL,
  PRIMARY KEY (saved_id, ref)
);
"""


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    return conn


def refs_of(result: dict) -> list[str]:
    refs: list[str] = []
    for s in result.get("screenshots", []) or []:
        if s.get("image_ref"):
            refs.append(s["image_ref"])
    for st in result.get("dynamic_steps", []) or []:
        if st.get("screenshot_ref"):
            refs.append(st["screenshot_ref"])
    art = result.get("artifacts") or {}
    for k in ("dom_html_ref", "har_ref"):
        if art.get(k):
            refs.append(art[k])
    return list(dict.fromkeys(refs))  # dédup en gardant l'ordre


def save(conn: sqlite3.Connection, result: dict, blobs: dict, label: Optional[str], now_iso: str) -> int:
    input_hash = result["input_hash"]
    kind = "url" if result.get("profile") == "capture" else "html"
    with conn:  # transaction atomique
        conn.execute("DELETE FROM saved_analysis WHERE input_hash = ?", (input_hash,))  # UPSERT
        cur = conn.execute(
            "INSERT INTO saved_analysis (input_hash, input_kind, job_id, verdict, label, result_json, saved_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (input_hash, kind, result.get("job_id"), result.get("verdict"),
             label, json.dumps(result), now_iso),
        )
        sid = cur.lastrowid
        for ref in refs_of(result):
            if ref in blobs:
                conn.execute(
                    "INSERT INTO saved_artifact (saved_id, ref, bytes) VALUES (?,?,?)",
                    (sid, ref, sqlite3.Binary(blobs[ref])),
                )
    return sid


def get_by_hash(conn, input_hash: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT id, input_hash, verdict, label, saved_at FROM saved_analysis WHERE input_hash = ?",
        (input_hash,),
    ).fetchone()
    return dict(row) if row else None


def get_result(conn, sid: int) -> Optional[dict]:
    row = conn.execute("SELECT result_json FROM saved_analysis WHERE id = ?", (sid,)).fetchone()
    return json.loads(row["result_json"]) if row else None


def list_all(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT id, input_hash, verdict, label, saved_at FROM saved_analysis ORDER BY id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def get_artifact(conn, sid: int, ref: str) -> Optional[bytes]:
    row = conn.execute(
        "SELECT bytes FROM saved_artifact WHERE saved_id = ? AND ref = ?", (sid, ref)
    ).fetchone()
    return bytes(row["bytes"]) if row else None


def delete(conn, sid: int) -> bool:
    with conn:
        cur = conn.execute("DELETE FROM saved_analysis WHERE id = ?", (sid,))
    return cur.rowcount > 0


def flush(conn) -> int:
    with conn:
        cur = conn.execute("DELETE FROM saved_analysis")
    return cur.rowcount
```

- [ ] **Step 5: Vérifier le succès** — `pytest tests/test_saved_store.py -v` → 5 PASS.
- [ ] **Step 6: Commit** — `git add saved_store.py tests/test_saved_store.py ocular_settings.py && git commit -m "feat: store SQLite auto-contenu des analyses sauvegardées"`

---

### Task 3: Endpoints save/lookup/list/result + auth `/saved*`

**Files:** Modify `web/app.py` ; Create `tests/test_saved_api.py`.

**Interfaces:** `POST /saved {job_id,label?}` → `{id,input_hash}` ; `GET /saved/{hash}` → 200 méta / 404 ; `GET /saved` → liste ; `GET /saved/{id}/result` → result_json.

- [ ] **Step 1: Test qui échoue** — `tests/test_saved_api.py`
```python
import json

import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from bus.queue import RedisJobQueue


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    (tmp_path / "artifacts").mkdir()
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    c = TestClient(app)
    c.headers.update({"Authorization": "Bearer t"})
    return c, q, tmp_path


def _seed_job(q, tmp_path, job_id="jx"):
    ref = "sha256:" + "b" * 64
    (tmp_path / "artifacts" / ("sha256_" + "b" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nX")
    q.set_result(job_id, json.dumps({
        "input_hash": "sha256:" + "a" * 64, "job_id": job_id, "verdict": "malicious",
        "screenshots": [{"image_ref": ref}], "artifacts": {"dom_html_ref": None},
    }))
    return ref


def test_save_then_lookup_and_result(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    _seed_job(q, tp)
    r = c.post("/saved", json={"job_id": "jx", "label": "note"})
    assert r.status_code == 200 and r.json()["input_hash"] == "sha256:" + "a" * 64
    sid = r.json()["id"]
    assert c.get("/saved/sha256:" + "a" * 64).status_code == 200
    assert c.get("/saved/sha256:" + "z" * 64).status_code == 404
    assert c.get(f"/saved/{sid}/result").json()["verdict"] == "malicious"
    assert any(x["id"] == sid for x in c.get("/saved").json())


def test_save_requires_token(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    c.headers.pop("Authorization")
    assert c.post("/saved", json={"job_id": "jx"}).status_code == 401


def test_save_expired_artifact_409(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    # résultat référence un ref dont le fichier n'existe pas (GC-é)
    q.set_result("jy", json.dumps({"input_hash": "sha256:" + "d" * 64, "verdict": "benign",
                 "screenshots": [{"image_ref": "sha256:" + "e" * 64}], "artifacts": {}}))
    assert c.post("/saved", json={"job_id": "jy"}).status_code == 409
```

- [ ] **Step 2: Vérifier l'échec** — `pytest tests/test_saved_api.py -v` → FAIL.

- [ ] **Step 3: Étendre le middleware auth** dans `web/app.py` — remplacer `request.url.path.startswith("/jobs")` par une garde couvrant les deux préfixes :
```python
_PROTECTED = ("/jobs", "/saved")
...
    if request.url.path.startswith(_PROTECTED):
```
(idem dans `_csp` : `if not request.url.path.startswith(_PROTECTED):`)

- [ ] **Step 4: Helper connexion + endpoints** — ajouter dans `web/app.py` :
```python
import saved_store
from ocular_settings import saved_db_path

def _saved_conn():
    import os
    path = saved_db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    return saved_store.connect(path)

def _read_artifact_bytes(ref: str) -> bytes | None:
    try:
        fname = ref_to_filename(ref)
    except ValueError:
        return None
    path = os.path.join(os.environ.get("OCULAR_ARTIFACTS_DIR", "artifacts"), fname)
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        return fh.read()


@app.post("/saved")
def create_saved(body: dict, queue: RedisJobQueue = Depends(get_queue)) -> dict:
    from datetime import datetime, timezone
    job_id = body.get("job_id")
    result_json = queue.get_result(job_id) if job_id else None
    if not result_json:
        raise HTTPException(status_code=404, detail="job inconnu")
    result = json.loads(result_json)
    blobs = {}
    for ref in saved_store.refs_of(result):
        data = _read_artifact_bytes(ref)
        if data is None:
            raise HTTPException(status_code=409, detail="artefacts expirés, relancer l'analyse")
        blobs[ref] = data
    conn = _saved_conn()
    sid = saved_store.save(conn, result, blobs, body.get("label"),
                           datetime.now(timezone.utc).isoformat())
    conn.close()
    log.info("saved job_id=%s id=%s verdict=%s", job_id, sid, result.get("verdict"))
    return {"id": sid, "input_hash": result.get("input_hash")}


@app.get("/saved/{ref_or_id}")
def get_saved(ref_or_id: str) -> dict:
    conn = _saved_conn()
    try:
        if ref_or_id.startswith("sha256:"):
            meta = saved_store.get_by_hash(conn, ref_or_id)
            if not meta:
                raise HTTPException(status_code=404, detail="aucune sauvegarde")
            return meta
        raise HTTPException(status_code=404, detail="introuvable")
    finally:
        conn.close()


@app.get("/saved")
def list_saved() -> list:
    conn = _saved_conn()
    try:
        return saved_store.list_all(conn)
    finally:
        conn.close()


@app.get("/saved/{sid}/result")
def get_saved_result(sid: int) -> dict:
    conn = _saved_conn()
    try:
        res = saved_store.get_result(conn, sid)
        if res is None:
            raise HTTPException(status_code=404, detail="introuvable")
        return res
    finally:
        conn.close()
```
> Note routage : `GET /saved/{ref_or_id}` (hash) et `GET /saved/{sid}/result` coexistent ; FastAPI matche la route la plus spécifique. Placer `GET /saved` (liste) et `GET /saved/{sid}/result` de façon à éviter les collisions — si conflit, renommer la lookup par hash en `GET /saved/by-hash/{hash}` (ajuster l'UI en conséquence, Task 7).

- [ ] **Step 5: Vérifier + Commit** — `pytest tests/test_saved_api.py -v` PASS ; `grep -riE "docker|launcher|subprocess" web/` vide (sqlite3 ≠ docker) ; `git add web/app.py tests/test_saved_api.py && git commit -m "feat(web): endpoints save/lookup/list/result (+ auth /saved*)"`

---

### Task 4: `GET /saved/{id}/artifact/{ref}` (depuis SQLite)

**Files:** Modify `web/app.py` ; Modify `tests/test_saved_api.py`.

- [ ] **Step 1: Test qui échoue** — ajouter à `tests/test_saved_api.py`
```python
def test_saved_artifact_nosniff_and_dom_attachment(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch)
    ref = _seed_job(q, tp)
    sid = c.post("/saved", json={"job_id": "jx"}).json()["id"]
    r = c.get(f"/saved/{sid}/artifact/{ref}")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert c.get(f"/saved/{sid}/artifact/sha256:{'A'*64}").status_code == 400  # anti-traversal
    assert c.get(f"/saved/{sid}/artifact/sha256:{'f'*64}").status_code == 404  # absent
```

- [ ] **Step 2: Vérifier l'échec** — FAIL.

- [ ] **Step 3: Factoriser le service d'octets + endpoint** — dans `web/app.py`, extraire un helper réutilisé par `/jobs` ET `/saved` :
```python
def _serve_artifact_bytes(data: bytes, fname: str) -> Response:
    if data[:8] == _PNG_MAGIC:
        return Response(content=data, media_type="image/png",
                        headers={"X-Content-Type-Options": "nosniff"})
    return Response(content=data, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.txt"',
                             "X-Content-Type-Options": "nosniff"})
```
(refactorer `get_artifact` de `/jobs` pour l'utiliser aussi — même comportement.) Puis :
```python
@app.get("/saved/{sid}/artifact/{ref}")
def get_saved_artifact(sid: int, ref: str) -> Response:
    try:
        fname = ref_to_filename(ref)
    except ValueError:
        raise HTTPException(status_code=400, detail="ref invalide")
    conn = _saved_conn()
    try:
        data = saved_store.get_artifact(conn, sid, ref)
    finally:
        conn.close()
    if data is None:
        raise HTTPException(status_code=404, detail="artefact absent")
    return _serve_artifact_bytes(data, fname)
```

- [ ] **Step 4: Vérifier + Commit** — `pytest tests/test_saved_api.py -v` PASS ; `git add web/app.py tests/test_saved_api.py && git commit -m "feat(web): artefact sauvegardé depuis SQLite (nosniff, DOM attachment, anti-traversal)"`

---

### Task 5: Auth admin + DELETE (fail-closed)

**Files:** Modify `web/app.py` ; Create `tests/test_saved_admin.py`.

**Interfaces:** `DELETE /saved/{id}` et `DELETE /saved` exigent `X-Admin-Token` == `OCULAR_ADMIN_TOKEN` (503 si non configuré, 403 sinon).

- [ ] **Step 1: Test qui échoue** — `tests/test_saved_admin.py`
```python
import json

import fakeredis
from fastapi.testclient import TestClient

from web.app import app, get_queue
from bus.queue import RedisJobQueue


def _client(tmp_path, monkeypatch, admin=None):
    monkeypatch.setenv("OCULAR_TOKEN", "t")
    monkeypatch.setenv("OCULAR_SAVED_DB", str(tmp_path / "saved.db"))
    monkeypatch.setenv("OCULAR_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    (tmp_path / "artifacts").mkdir()
    if admin is None:
        monkeypatch.delenv("OCULAR_ADMIN_TOKEN", raising=False)
    else:
        monkeypatch.setenv("OCULAR_ADMIN_TOKEN", admin)
    q = RedisJobQueue(fakeredis.FakeStrictRedis())
    app.dependency_overrides[get_queue] = lambda: q
    c = TestClient(app)
    c.headers.update({"Authorization": "Bearer t"})
    return c, q, tmp_path


def _seed_saved(c, q, tp, job_id="jx", h="a"):
    ref = "sha256:" + "b" * 64
    (tp / "artifacts" / ("sha256_" + "b" * 64)).write_bytes(b"\x89PNG\r\n\x1a\nX")
    q.set_result(job_id, json.dumps({"input_hash": "sha256:" + h * 64, "verdict": "benign",
                 "screenshots": [{"image_ref": ref}], "artifacts": {}}))
    return c.post("/saved", json={"job_id": job_id}).json()["id"]


def test_delete_without_admin_configured_is_503(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch, admin=None)
    sid = _seed_saved(c, q, tp)
    assert c.delete(f"/saved/{sid}").status_code == 503


def test_delete_wrong_admin_403_correct_200(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch, admin="ADM")
    sid = _seed_saved(c, q, tp)
    assert c.delete(f"/saved/{sid}").status_code == 403
    assert c.delete(f"/saved/{sid}", headers={"X-Admin-Token": "nope"}).status_code == 403
    assert c.delete(f"/saved/{sid}", headers={"X-Admin-Token": "ADM"}).status_code == 200
    assert c.get(f"/saved/{sid}/result").status_code == 404  # supprimé


def test_flush_requires_admin(tmp_path, monkeypatch):
    c, q, tp = _client(tmp_path, monkeypatch, admin="ADM")
    _seed_saved(c, q, tp, job_id="j1", h="a")
    _seed_saved(c, q, tp, job_id="j2", h="c")
    assert c.delete("/saved").status_code == 403
    r = c.delete("/saved", headers={"X-Admin-Token": "ADM"})
    assert r.status_code == 200 and r.json()["flushed"] == 2
    assert c.get("/saved").json() == []
```

- [ ] **Step 2: Vérifier l'échec** — FAIL.

- [ ] **Step 3: Gate admin dans le middleware `_auth`** — après le check du token normal, ajouter (dans le même middleware, après avoir validé le token normal) :
```python
        if request.method == "DELETE" and request.url.path.startswith("/saved"):
            adm = os.environ.get("OCULAR_ADMIN_TOKEN")
            if not adm:
                log.warning("admin rejected path=%s status=%d", request.url.path, 503)
                return JSONResponse({"detail": "OCULAR_ADMIN_TOKEN non configuré"}, status_code=503)
            provided_adm = request.headers.get("x-admin-token", "")
            if not secrets.compare_digest(provided_adm.encode("utf-8", "ignore"), adm.encode()):
                log.warning("admin rejected path=%s status=%d", request.url.path, 403)
                return JSONResponse({"detail": "admin requis"}, status_code=403)
```

- [ ] **Step 4: Endpoints DELETE** — dans `web/app.py` :
```python
@app.delete("/saved/{sid}")
def delete_saved(sid: int) -> dict:
    conn = _saved_conn()
    try:
        ok = saved_store.delete(conn, sid)
    finally:
        conn.close()
    if not ok:
        raise HTTPException(status_code=404, detail="introuvable")
    log.info("saved deleted id=%s", sid)
    return {"deleted": sid}


@app.delete("/saved")
def flush_saved() -> dict:
    conn = _saved_conn()
    try:
        n = saved_store.flush(conn)
    finally:
        conn.close()
    log.warning("saved flushed count=%d", n)
    return {"flushed": n}
```

- [ ] **Step 5: Vérifier + Commit** — `pytest tests/test_saved_admin.py -v` PASS ; le token admin n'apparaît dans aucun log (`log.warning` ne passe que path+status). `git add web/app.py tests/test_saved_admin.py && git commit -m "feat(web): auth admin (X-Admin-Token, fail-closed) + DELETE /saved (delete/flush)"`

---

### Task 6: Ops — volume `ocular-saved` + `OCULAR_ADMIN_TOKEN`

**Files:** Modify `deploy/docker-compose.yml`, `deploy/.env.example`, `deploy/Dockerfile.web`.

- [ ] **Step 1: `deploy/docker-compose.yml`** — sur le service `web` : ajouter le volume rw `saved` + le token admin :
```yaml
    environment:
      REDIS_URL: "redis://redis:6379"
      OCULAR_TOKEN: "${OCULAR_TOKEN:?OCULAR_TOKEN requis}"
      OCULAR_ADMIN_TOKEN: "${OCULAR_ADMIN_TOKEN:-}"
      OCULAR_ARTIFACTS_DIR: "/artifacts"
      OCULAR_SAVED_DB: "/saved/saved.db"
    volumes:
      - ocular-artifacts:/artifacts:ro
      - ocular-saved:/saved
```
et déclarer le volume :
```yaml
volumes:
  ocular-artifacts:
  ocular-saved:
```
(le rootfs `web` reste `read_only: true` ; `/saved` est un volume monté inscriptible, `/tmp` déjà en tmpfs.)

- [ ] **Step 2: `deploy/.env.example`** — ajouter `OCULAR_ADMIN_TOKEN=change-me-or-leave-empty-to-disable-admin`.

- [ ] **Step 3: `deploy/Dockerfile.web`** — copie `saved_store.py` (nouveau module racine importé par `web/app.py`) : ajouter `COPY saved_store.py ocular_settings.py ocular_logging.py ./` (vérifier que `saved_store.py` y figure).

- [ ] **Step 4: Vérifier** — `OCULAR_TOKEN=x docker compose -f deploy/docker-compose.yml config` valide (volume `ocular-saved` présent, `web` sans socket) ; build réel + import :
```bash
docker build -f deploy/Dockerfile.web -t ocular-web-test . && docker run --rm ocular-web-test python -c "import web.app, saved_store; print('web+saved import OK')" && docker rmi ocular-web-test
```
- [ ] **Step 5: Commit** — `git add deploy/ && git commit -m "feat(ops): volume ocular-saved rw + OCULAR_ADMIN_TOKEN + Dockerfile.web copie saved_store"`

---

### Task 7: UI — Sauvegarder + vues Saved/Admin + modal dédup

**Files:** Modify `web/ui/views/detail.js`, `web/ui/views/submit.js`, `web/ui/core.js` (nav/routes), `web/ui/api.js`, `web/ui/i18n.js`, `web/ui/style.css` ; Create `web/ui/views/saved.js`, `web/ui/views/admin.js` ; Modify `tests/test_ui_smoke.py`.

**SOUS-COMPÉTENCE** : `frontend-design` ; réutiliser le système plume existant (`.card`, `.qtable`, `.sev`, accent violet). Anti-XSS : données via `textContent`/`setAttribute`, jamais `innerHTML`.

- [ ] **Step 1: `api.js`** — ajouter les appels (tous via `authFetch` = header Bearer) : `saveAnalysis(jobId,label)` (POST /saved), `lookupSaved(hash)` (GET /saved/{hash} → null si 404), `listSaved()`, `getSavedResult(id)`, `savedArtifactObjectUrl(id,ref)` (fetch blob + Bearer), `deleteSaved(id,adminToken)` / `flushSaved(adminToken)` (DELETE + header `X-Admin-Token`). Fonction `sha256Hex(text)` via `crypto.subtle.digest('SHA-256', utf8)` → `"sha256:"+hex`.

- [ ] **Step 2: detail.js** — bouton **« Sauvegarder »** + input `label` sur une analyse terminée → `saveAnalysis(job_id,label)` → état « sauvegardée ✓ » ; sur `409` afficher « artefacts expirés, relancer ». Réutiliser le rendu détail pour les analyses sauvegardées (paramétrer la source : job vs saved endpoints).

- [ ] **Step 3: submit.js — modal dédup** — avant `POST /jobs` : `h = await sha256Hex(htmlValue)` → `meta = await lookupSaved(h)` → si non-null, afficher un **modal** (élément `.card` en overlay) : « Analyse sauvegardée existante — verdict {meta.verdict}, {meta.saved_at}, {meta.label} » + boutons **Voir** (→ route détail sauvegardé `#/saved/{meta.id}`), **Analyser quand même** (→ POST /jobs), **Annuler**. Tout en textNode/setAttribute.

- [ ] **Step 4: saved.js (nouvelle vue)** — `listSaved()` → table (verdict badge, date, label, hash tronqué) → clic route `#/saved/{id}` = détail rendu depuis `getSavedResult(id)` + `savedArtifactObjectUrl`.

- [ ] **Step 5: admin.js (nouvelle vue)** — champ « token admin » (gardé en variable de session, PAS localStorage) ; liste des sauvegardes avec bouton **Supprimer** (→ `deleteSaved(id, adminToken)`) et bouton **Flush** (confirmation → `flushSaved(adminToken)`). Sur 403/503, message clair.

- [ ] **Step 6: nav/routes** — `core.js` : ajouter les entrées nav « Sauvegardes » et « Admin » + les routes `#/saved`, `#/saved/{id}`, `#/admin`. `i18n.js` : libellés FR/EN.

- [ ] **Step 7: smoke + vérif manuelle** — `tests/test_ui_smoke.py` : `/saved.js`, `/admin.js` servis (200). Lancer `OCULAR_TOKEN=t OCULAR_ADMIN_TOKEN=a uvicorn web.app:app`, vérifier au navigateur (documenter) : sauvegarder une analyse, la retrouver dans « Sauvegardes », re-soumettre le même HTML → modal, supprimer via Admin avec le token. `grep -nE "innerHTML" web/ui/views/{saved,admin,submit,detail}.js` → seulement icônes.
- [ ] **Step 8: Commit** — `git add web/ui tests/test_ui_smoke.py && git commit -m "feat(ui): Sauvegarder + vues Saved/Admin + modal dédup"`

---

## Self-Review (effectuée)
- **Couverture spec** : store SQLite auto-contenu (T2), input_hash (T1), endpoints save/lookup/list/result (T3), artefact sauvegardé nosniff/attachment/anti-traversal (T4), admin fail-closed + DELETE (T5), ops volume+token (T6), UI save/saved/admin/dédup (T7). Multi-étapes (refs_of boucle tout, T2). 409 artefact expiré (T3). Param SQL testé (T2).
- **Placeholders** : aucun muet ; T3 note un risque de collision de route `GET /saved/{hash}` vs `GET /saved/{id}/result` avec le repli `by-hash/` explicite si conflit.
- **Cohérence types** : `input_hash` (T1) consommé par `saved_store.save`/dédup ; `saved_store.*` (T2) par les endpoints (T3-T5) ; `_serve_artifact_bytes` (T4) factorisé pour /jobs+/saved ; `X-Admin-Token` middleware (T5) ↔ `deleteSaved/flushSaved` UI (T7).

## Notes de délégation
Sans Docker : T1(unit), T2, T3, T4, T5. Avec Docker : T1 (rebuild+integration), T6 (build web+import), T7 (vérif navigateur). T3 : surveiller la collision de routes FastAPI (`/saved/{hash}` vs `/saved/{id}/result` vs `/saved` liste) — tester tôt, basculer sur `by-hash/` si besoin.
