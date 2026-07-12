from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Optional

_PREFIX = "ocular:session:"


def _iso_to_epoch(iso: str) -> float:
    """Convertit un timestamp ISO 8601 en epoch (secondes). Naïf => supposé UTC."""
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _decode(raw: dict) -> dict:
    def d(v):
        return v.decode() if isinstance(v, bytes) else v

    return {d(k): d(v) for k, v in raw.items()}


class SessionRegistry:
    """Registre Redis des sessions interactives (un hash par session).

    Clé : `ocular:session:{session_id}`. Champs : session_id, container, kind,
    target, token, created_at, last_activity (ces deux derniers stockés en
    epoch — cohérent avec `expired()` qui compare des epochs).
    """

    def __init__(self, client) -> None:
        self._r = client

    def _key(self, session_id: str) -> str:
        return f"{_PREFIX}{session_id}"

    def create(
        self,
        session_id: str,
        container: str,
        kind: str,
        target: str,
        token: str,
        now_iso: str,
    ) -> None:
        epoch = _iso_to_epoch(now_iso)
        self._r.hset(
            self._key(session_id),
            mapping={
                "session_id": session_id,
                "container": container,
                "kind": kind,
                "target": target,
                "token": token,
                "created_at": epoch,
                "last_activity": epoch,
            },
        )

    def get(self, session_id: str) -> Optional[dict]:
        raw = self._r.hgetall(self._key(session_id))
        if not raw:
            return None
        return _decode(raw)

    def touch(self, session_id: str, now_iso: str) -> None:
        key = self._key(session_id)
        if not self._r.exists(key):
            return  # session inconnue/expirée déjà supprimée : no-op
        self._r.hset(key, "last_activity", _iso_to_epoch(now_iso))

    def list_active(self) -> list[dict]:
        out = []
        for key in self._r.scan_iter(match=f"{_PREFIX}*"):
            raw = self._r.hgetall(key)
            if raw:
                out.append(_decode(raw))
        return out

    def delete(self, session_id: str) -> None:
        self._r.delete(self._key(session_id))

    def expired(self, now_epoch: float, ttl: float, idle: float) -> list[str]:
        """Ids des sessions dont l'âge dépasse `ttl` (absolu depuis created_at)
        OU dont l'inactivité dépasse `idle` (depuis last_activity)."""
        ids = []
        for sess in self.list_active():
            created = float(sess["created_at"])
            last = float(sess["last_activity"])
            if (now_epoch - created) > ttl or (now_epoch - last) > idle:
                ids.append(sess["session_id"])
        return ids

    def valid_token(self, session_id: str, token: str) -> bool:
        """Comparaison en temps constant. Le token n'est jamais loggé ici."""
        sess = self.get(session_id)
        if sess is None or token is None:
            return False
        stored = sess.get("token", "")
        return secrets.compare_digest(stored.encode(), token.encode())
