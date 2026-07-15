from __future__ import annotations

import asyncio
import contextlib
from urllib.parse import urlsplit

from engine.ssrf import resolve_allowed_ip
from ocular_logging import get_logger

logger = get_logger("egress_guard")

_DEFAULT_CONNECT_TIMEOUT = 10.0
_DEFAULT_IDLE_TIMEOUT = 60.0
_RELAY_CHUNK = 65536
_MAX_HEADER_LINES = 200


def _split_host_port(target: str, default_port: int) -> tuple[str, int] | None:
    """Parse "host:port", "[ipv6]:port" ou un host nu. `None` si malformé."""
    target = target.strip()
    if not target:
        return None

    if target.startswith("["):
        end = target.find("]")
        if end == -1:
            return None
        host = target[1:end]
        rest = target[end + 1:]
        if rest == "":
            port_str = str(default_port)
        elif rest.startswith(":"):
            port_str = rest[1:]
        else:
            return None
    elif target.count(":") > 1:
        # IPv6 littéral sans crochets : ambigu, on refuse plutôt que deviner.
        return None
    elif ":" in target:
        host, port_str = target.rsplit(":", 1)
    else:
        host, port_str = target, str(default_port)

    if not host:
        return None
    try:
        port = int(port_str)
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    return host, port


class EgressGuard:
    """Proxy asyncio HTTP/CONNECT filtrant utilisé comme egress guard des
    runners réseau-ON.

    Sécurité clé : la résolution IP se fait au moment de la connexion
    (`engine.ssrf.resolve_allowed_ip`) et le garde se connecte exactement à
    l'IP retournée — jamais de re-résolution entre le check et le connect
    (pinning). Ceci défait le DNS-rebinding : chaque nouvelle requête
    (y compris une redirection suivie par le navigateur, qui émet un nouveau
    CONNECT/requête) est re-vérifiée indépendamment. Le garde ne suit jamais
    lui-même de redirection.

    Chaque connexion cliente est traitée dans sa propre tâche asyncio avec
    ses propres timeouts : une connexion lente ou hostile ne bloque pas le
    serveur ni les autres connexions.
    """

    def __init__(
        self,
        connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
        idle_timeout: float = _DEFAULT_IDLE_TIMEOUT,
    ) -> None:
        self._server: asyncio.AbstractServer | None = None
        self._connect_timeout = connect_timeout
        self._idle_timeout = idle_timeout

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None

    # -- gestion d'une connexion cliente -------------------------------

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._dispatch(reader, writer)
        except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
            pass
        except Exception:
            logger.exception("egress guard: erreur inattendue")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _dispatch(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            first_line = await asyncio.wait_for(reader.readline(), timeout=self._connect_timeout)
        except asyncio.TimeoutError:
            await self._send_status(writer, 400, "Bad Request")
            return
        if not first_line:
            return

        try:
            line = first_line.decode("latin-1").rstrip("\r\n")
        except UnicodeDecodeError:
            await self._send_status(writer, 400, "Bad Request")
            return

        parts = line.split(" ")
        if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
            await self._send_status(writer, 400, "Bad Request")
            return

        method, target, _version = parts

        if method.upper() == "CONNECT":
            await self._handle_connect(reader, writer, target)
            return

        if target.lower().startswith(("http://", "https://")):
            await self._handle_absolute_http(reader, writer, method, target, line)
            return

        await self._send_status(writer, 400, "Bad Request")

    async def _handle_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: str
    ) -> None:
        hp = _split_host_port(target, 443)
        if hp is None:
            await self._send_status(writer, 400, "Bad Request")
            return
        host, port = hp

        # CONNECT n'a pas de corps ; on draine les en-têtes (souvent absents/inutiles).
        await self._read_headers(reader)

        ip = resolve_allowed_ip(host, port)
        if ip is None:
            logger.warning("egress blocked host=%s", host)
            await self._send_status(writer, 403, "Forbidden")
            return

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self._connect_timeout
            )
        except (OSError, asyncio.TimeoutError):
            await self._send_status(writer, 502, "Bad Gateway")
            return

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        await self._relay(reader, writer, upstream_reader, upstream_writer)

    async def _handle_absolute_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        first_line: str,
    ) -> None:
        headers, raw_headers = await self._read_headers(reader)
        parsed = urlsplit(target)
        host = parsed.hostname
        if not host:
            host = headers.get("host", "").rsplit(":", 1)[0] or None
        if not host:
            await self._send_status(writer, 400, "Bad Request")
            return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        ip = resolve_allowed_ip(host, port)
        if ip is None:
            logger.warning("egress blocked host=%s", host)
            await self._send_status(writer, 403, "Forbidden")
            return

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self._connect_timeout
            )
        except (OSError, asyncio.TimeoutError):
            await self._send_status(writer, 502, "Bad Gateway")
            return

        origin_path = parsed.path or "/"
        if parsed.query:
            origin_path += "?" + parsed.query
        version = first_line.rsplit(" ", 1)[-1]
        new_first_line = f"{method} {origin_path} {version}\r\n"
        upstream_writer.write(new_first_line.encode("latin-1"))
        upstream_writer.write(raw_headers)
        await upstream_writer.drain()

        await self._relay(reader, writer, upstream_reader, upstream_writer)

    # -- primitives ------------------------------------------------------

    async def _read_headers(self, reader: asyncio.StreamReader) -> tuple[dict[str, str], bytes]:
        """Lit les lignes d'en-têtes jusqu'à la ligne vide. Retourne le dict
        (clés en minuscules) et le bloc brut (pour ré-émission telle quelle)."""
        headers: dict[str, str] = {}
        raw = bytearray()
        for _ in range(_MAX_HEADER_LINES):
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=self._connect_timeout)
            except asyncio.TimeoutError:
                break
            if not line:
                break
            raw += line
            if line in (b"\r\n", b"\n"):
                break
            decoded = line.decode("latin-1").rstrip("\r\n")
            if ":" in decoded:
                key, _, value = decoded.partition(":")
                headers[key.strip().lower()] = value.strip()
        if not raw.endswith(b"\r\n\r\n") and not raw.endswith(b"\n\n"):
            raw += b"\r\n"
        return headers, bytes(raw)

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    try:
                        chunk = await asyncio.wait_for(src.read(_RELAY_CHUNK), timeout=self._idle_timeout)
                    except asyncio.TimeoutError:
                        break
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    dst.write_eof()

        try:
            await asyncio.gather(
                pump(client_reader, upstream_writer),
                pump(upstream_reader, client_writer),
            )
        finally:
            with contextlib.suppress(Exception):
                upstream_writer.close()
                await upstream_writer.wait_closed()

    async def _send_status(self, writer: asyncio.StreamWriter, code: int, reason: str) -> None:
        with contextlib.suppress(Exception):
            writer.write(f"HTTP/1.1 {code} {reason}\r\n\r\n".encode("latin-1"))
            await writer.drain()
