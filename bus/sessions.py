from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from typing import Optional

_PREFIX = "ocular:session:"
_CMD_QUEUE_KEY = "ocular:session-cmds"


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


def _key_to_id(key) -> str:
    k = key.decode() if isinstance(key, bytes) else key
    return k[len(_PREFIX):]


class SessionRegistry:
    """Registre Redis des sessions interactives (un hash par session).

    Clé : `ocular:session:{session_id}`. Champs : session_id, container, kind,
    target, token, created_at, last_activity (ces deux derniers stockés en
    epoch — cohérent avec `expired()` qui compare des epochs).
    """

    def __init__(self, client) -> None:
        self._r = client

    @property
    def client(self):
        """Client Redis sous-jacent — exposé pour les opérations transverses
        (ex. purge des résultats de capture au nettoyage de session côté broker),
        sans réutiliser l'attribut privé `_r` d'un autre module."""
        return self._r

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
        secret: str = "",
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
                "secret": secret,
                "created_at": epoch,
                "last_activity": epoch,
            },
        )

    def get(self, session_id: str) -> Optional[dict]:
        raw = self._r.hgetall(self._key(session_id))
        if not raw:
            return None
        return _decode(raw)

    def _hset_if_alive(self, key: str, field: str, value) -> None:
        """`hset` atomique conditionné à ce que la session soit encore VIVANTE
        (champ `created_at` présent). Ferme la TOCTOU où un `delete` concurrent,
        entre un simple `exists` et le `hset`, RESSUSCITERAIT un hash partiel
        (ghost sans `created_at` → faisait planter le reaper). WATCH : si la clé
        change entre-temps, on réessaie et, la clé étant alors supprimée/sans
        `created_at`, on n'écrit rien. Best-effort : une erreur redis transitoire
        n'est jamais propagée (mise à jour d'activité non critique)."""
        with self._r.pipeline() as pipe:
            while True:
                try:
                    pipe.watch(key)
                    if not pipe.hexists(key, "created_at"):
                        pipe.reset()
                        return
                    pipe.multi()
                    pipe.hset(key, field, value)
                    pipe.execute()
                    return
                except Exception as exc:  # noqa: BLE001
                    if type(exc).__name__ == "WatchError":
                        continue  # clé modifiée -> réessaie (sortira si supprimée)
                    pipe.reset()
                    return

    def touch(self, session_id: str, now_iso: str) -> None:
        # hset conditionné (anti-résurrection) : ne réécrit que si la session
        # a encore son created_at, sinon no-op (session déjà supprimée).
        self._hset_if_alive(self._key(session_id), "last_activity", _iso_to_epoch(now_iso))

    def mark_connected(self, session_id: str) -> None:
        """Efface `disconnected_at` : la session est (de nouveau) activement
        connectée (WS ouvert, ou poll `/live` en cours). Sans effet si le
        champ était déjà absent (session jamais déconnectée). `hdel` ne crée
        jamais de clé -> pas de risque de résurrection ici."""
        self._r.hdel(self._key(session_id), "disconnected_at")

    def mark_disconnected(self, session_id: str, now_epoch: float) -> None:
        """Marque l'heure (epoch) de déconnexion — utilisée par `expired()`
        (règle de grâce) pour nettoyer une session dont le navigateur est
        parti brutalement. No-op (anti-résurrection) sur une session
        inconnue/déjà supprimée (cohérent avec `touch`)."""
        self._hset_if_alive(self._key(session_id), "disconnected_at", now_epoch)

    def get_secret(self, session_id: str) -> Optional[str]:
        """Secret de session (frontière conteneur) que SEUL le web connaît, pour
        signer ses appels internes `/goto`/`/load`/`/capture` (header
        `X-Session-Secret`). Distinct du token WS. Jamais renvoyé par
        `list_active` ni loggé. Retourne None si la session est inconnue."""
        raw = self._r.hget(self._key(session_id), "secret")
        if raw is None:
            return None
        return raw.decode() if isinstance(raw, bytes) else raw

    def list_active(self) -> list[dict]:
        out = []
        for key in self._r.scan_iter(match=f"{_PREFIX}*"):
            raw = self._r.hgetall(key)
            if raw:
                sess = _decode(raw)
                # anti-fuite frontière conteneur : le secret n'est JAMAIS
                # renvoyé dans une liste (comme le token WS filtré côté web).
                sess.pop("secret", None)
                out.append(sess)
        return out

    def delete(self, session_id: str) -> None:
        self._r.delete(self._key(session_id))

    def expired(
        self,
        now_epoch: float,
        ttl: float,
        idle: float,
        disconnect_grace: Optional[float] = None,
    ) -> list[str]:
        """Ids des sessions dont l'âge dépasse `ttl` (absolu depuis created_at)
        OU dont l'inactivité dépasse `idle` (depuis last_activity) — logique
        inchangée. Si `disconnect_grace` est fourni (signature rétro-compatible
        : défaut `None` == comportement d'avant), reaper AUSSI une session
        dont `disconnected_at` est présent et > 0 ET dont l'écoulement depuis
        cette déconnexion dépasse `disconnect_grace` (fermeture brutale du
        navigateur). Une session sans `disconnected_at` (jamais connectée, ou
        actuellement connectée — `mark_connected` l'efface) n'est JAMAIS
        reaper par cette règle, seulement par ttl/idle ci-dessus."""
        ids = []
        # Itère les CLÉS (pas list_active) pour pouvoir supprimer un hash partiel
        # via sa clé même s'il n'a pas de champ session_id.
        for key in self._r.scan_iter(match=f"{_PREFIX}*"):
            raw = self._r.hgetall(key)
            if not raw:
                continue
            sess = _decode(raw)
            # AUTO-GUÉRISON : un hash partiel (ghost sans created_at/last_activity,
            # ou valeurs non numériques — créé jadis par une TOCTOU touch/delete)
            # faisait planter le reaper (KeyError) qui abandonnait le cycle AVANT
            # de rien nettoyer -> reaper mort à vie + fuite de tous les conteneurs.
            # On le supprime et on continue, au lieu de lever.
            try:
                created = float(sess["created_at"])
                last = float(sess["last_activity"])
            except (KeyError, TypeError, ValueError):
                self._r.delete(key)
                continue
            reap_it = (now_epoch - created) > ttl or (now_epoch - last) > idle
            if not reap_it and disconnect_grace is not None:
                disconnected_at = sess.get("disconnected_at")
                if disconnected_at not in (None, ""):
                    try:
                        disconnected_at = float(disconnected_at)
                    except (TypeError, ValueError):
                        disconnected_at = 0.0
                    if disconnected_at > 0 and (now_epoch - disconnected_at) > disconnect_grace:
                        reap_it = True
            if reap_it:
                ids.append(sess.get("session_id") or _key_to_id(key))
        return ids

    def valid_token(self, session_id: str, token: str) -> bool:
        """Comparaison en temps constant. Le token n'est jamais loggé ici."""
        sess = self.get(session_id)
        if sess is None or token is None:
            return False
        stored = sess.get("token", "")
        return secrets.compare_digest(stored.encode(), token.encode())


class SessionCmdQueue:
    """File Redis `ocular:session-cmds` : le web (sans Docker) enqueue des
    demandes `launch`/`stop`, le broker (seul à avoir accès à Docker) les
    consomme dans sa boucle et exécute `launch_session`/`stop_session` +
    tient le registre à jour. Symétrique à `RedisJobQueue` (bus/queue.py)."""

    def __init__(self, client) -> None:
        self._r = client

    def enqueue_cmd(self, action: str, session_id: str, **fields) -> None:
        payload = {"action": action, "session_id": session_id, **fields}
        self._r.rpush(_CMD_QUEUE_KEY, json.dumps(payload))

    def dequeue_cmd(self, timeout: int = 0) -> Optional[dict]:
        try:
            item = self._r.blpop([_CMD_QUEUE_KEY], timeout=timeout)
        except Exception:  # noqa: BLE001
            # timeout/déconnexion redis transitoire : ne pas tuer le broker,
            # même effet volontairement étroit que RedisJobQueue.dequeue.
            return None
        if item is None:
            return None
        _, raw = item
        raw = raw.decode() if isinstance(raw, bytes) else raw
        return json.loads(raw)
