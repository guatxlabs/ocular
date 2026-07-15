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


# Colonnes ajoutées après le schéma initial (Phase 3e). Ajoutées via ALTER TABLE
# idempotent dans connect() : couvre à la fois les bases neuves (le CREATE TABLE
# IF NOT EXISTS reste minimal) et les bases existantes créées à l'ancien schéma.
_NEW_COLUMNS = [
    ("saved_by", "TEXT"),
    ("turnstile_solved", "INTEGER"),
    ("analyst_verdict", "TEXT"),
    ("analyst", "TEXT"),
    ("analyst_at", "TEXT"),
    ("analyst_note", "TEXT"),
]

_ANALYST_VERDICTS = {"legitimate", "suspicious", "malicious"}


def _migrate(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(saved_analysis)")}
    for name, col_type in _NEW_COLUMNS:
        if name not in existing:
            conn.execute(f"ALTER TABLE saved_analysis ADD COLUMN {name} {col_type}")
    conn.commit()


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(_SCHEMA)
    _migrate(conn)
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


def save(
    conn: sqlite3.Connection,
    result: dict,
    blobs: dict,
    label: Optional[str],
    now_iso: str,
    saved_by: Optional[str] = None,
) -> int:
    input_hash = result["input_hash"]
    kind = "url" if result.get("profile") == "capture" else "html"
    stealth = result.get("stealth")
    turnstile_solved = 1 if (stealth or {}).get("turnstile_solved") else (0 if stealth is not None else None)
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
            "INSERT INTO saved_analysis"
            " (input_hash, input_kind, job_id, verdict, label, result_json, saved_at, saved_by, turnstile_solved)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (input_hash, kind, result.get("job_id"), result.get("verdict"),
             label, json.dumps(result), now_iso, saved_by, turnstile_solved),
        )
        sid = cur.lastrowid
        for ref in refs_of(result):
            if ref in blobs:
                conn.execute(
                    "INSERT INTO saved_artifact (saved_id, ref, bytes) VALUES (?,?,?)",
                    (sid, ref, sqlite3.Binary(blobs[ref])),
                )
    return sid


_META_COLUMNS = (
    "id, input_hash, verdict, label, saved_at, saved_by, turnstile_solved,"
    " analyst_verdict, analyst, analyst_at"
)


def get_by_hash(conn, input_hash: str) -> Optional[dict]:
    row = conn.execute(
        f"SELECT {_META_COLUMNS} FROM saved_analysis WHERE input_hash = ?",
        (input_hash,),
    ).fetchone()
    return dict(row) if row else None


def get_result(conn, sid: int) -> Optional[dict]:
    row = conn.execute("SELECT result_json FROM saved_analysis WHERE id = ?", (sid,)).fetchone()
    return json.loads(row["result_json"]) if row else None


def get_meta(conn, sid: int) -> Optional[dict]:
    row = conn.execute(
        f"SELECT {_META_COLUMNS}, analyst_note FROM saved_analysis WHERE id = ?",
        (sid,),
    ).fetchone()
    return dict(row) if row else None


def set_analyst_verdict(
    conn: sqlite3.Connection,
    sid: int,
    analyst_verdict: str,
    analyst: Optional[str],
    analyst_at: str,
    note: Optional[str] = None,
) -> bool:
    if analyst_verdict not in _ANALYST_VERDICTS:
        raise ValueError(f"analyst_verdict invalide: {analyst_verdict!r}")
    if note is not None:
        note = note[:2000]
    with conn:
        cur = conn.execute(
            "UPDATE saved_analysis SET analyst_verdict=?, analyst=?, analyst_at=?, analyst_note=? WHERE id=?",
            (analyst_verdict, analyst, analyst_at, note, sid),
        )
    return cur.rowcount > 0


def list_all(conn) -> list[dict]:
    rows = conn.execute(
        f"SELECT {_META_COLUMNS} FROM saved_analysis ORDER BY id DESC"
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
