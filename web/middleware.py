# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Middleware ASGI de plafonnement du corps de requête. Extrait de `web/app.py`
(audit qualité 3m). Les gardes courtes `_auth`/`_csp`/`_body_size_guard`
(en-têtes seulement) restent dans `web/app.py` — leur ordre d'enregistrement est
sensible ; seule cette classe ASGI autonome (~80 lignes) est déplacée."""
from __future__ import annotations

from ocular_logging import get_logger

log = get_logger("web.middleware")


class MaxBodySizeMiddleware:
    """Middleware ASGI pur (pas de `BaseHTTPMiddleware`) : filet de sécurité pour
    les corps `Transfer-Encoding: chunked` (donc sans `Content-Length`), que la
    garde par en-têtes ne voit pas. Enveloppe `receive` et accumule `len(body)`
    sur chaque message `http.request`.

    Dès que le total dépasse `max_bytes`, il émet LUI-MÊME la réponse 413 via
    `send` puis renvoie un `http.disconnect` à l'app enveloppée pour qu'elle
    cesse de lire. On NE lève PAS d'exception : une exception depuis le `receive`
    enveloppé ne remonte pas jusqu'ici — elle est avalée par le parsing de corps
    de FastAPI/Starlette et ressortirait en 400/422, jamais en 413. Émettre la
    réponse directement depuis `receive` est le seul chemin fiable.

    Anti double-réponse : `_guarded_send` laisse passer les messages tant que
    NOUS n'avons pas déjà répondu 413 ; une fois notre 413 émis, les `send`
    ultérieurs de l'app sont ignorés. Ne touche pas aux scopes non-http ni aux
    requêtes sans corps (GET)."""

    def __init__(self, app, max_bytes: int, payload: bytes):
        self.app = app
        self.max_bytes = max_bytes
        self.payload = payload

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        total = 0
        state = {"our_413_sent": False, "app_response_started": False}

        async def _guarded_send(message):
            if state["our_413_sent"]:
                return
            if message["type"] == "http.response.start":
                state["app_response_started"] = True
            await send(message)

        async def _guarded_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes and not state["our_413_sent"]:
                    if not state["app_response_started"]:
                        log.warning(
                            "body rejected (streamed) path=%s total=%d limit=%d",
                            scope.get("path"), total, self.max_bytes,
                        )
                        await send({
                            "type": "http.response.start",
                            "status": 413,
                            "headers": [
                                (b"content-type", b"application/json"),
                                (b"content-length", str(len(self.payload)).encode()),
                            ],
                        })
                        await send({"type": "http.response.body", "body": self.payload})
                        state["our_413_sent"] = True
                    return {"type": "http.disconnect"}
            return message

        await self.app(scope, _guarded_receive, _guarded_send)
