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


class DuplicateLabelError(ValueError):
    """Levée quand un `label` (nom) non vide est déjà utilisé par une sauvegarde
    portant un `input_hash` différent. Le re-save du MÊME `input_hash` (UPSERT)
    n'est jamais bloqué, même avec un label identique."""


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
        if label:
            # unicité du nom : un label non vide ne peut pas être réutilisé par un
            # input_hash différent. Vérifié DANS la transaction (pas de round-trip
            # séparé) pour éviter un TOCTOU entre le check et l'INSERT ci-dessous ;
            # le re-save du MÊME input_hash (UPSERT) est explicitement exclu.
            dup = conn.execute(
                "SELECT 1 FROM saved_analysis WHERE label = ? AND input_hash != ?",
                (label, input_hash),
            ).fetchone()
            if dup:
                raise DuplicateLabelError(f"label déjà utilisé: {label!r}")
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
