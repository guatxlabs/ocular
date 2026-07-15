from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = {"http", "https"}


def is_ip_allowed(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Source unique de vérité pour la décision IP SSRF.

    `True` ssi `ip` désigne une adresse globale/routable publiquement
    (`ipaddress.is_global`). Rejette (`False`) loopback, RFC1918, link-local
    (169.254.0.0/16, fe80::/10 — couvre le service de metadata cloud),
    CGNAT (100.64.0.0/10), ULA (fd00::/8), réservé, multicast.

    Accepte soit une `str`, soit un objet `ipaddress.IPv4Address` /
    `IPv6Address` déjà construit. Une `str` qui n'est pas une IP valide
    retourne `False` (jamais de levée d'exception — appelable en toute
    sécurité sur une entrée non fiable).
    """
    if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        addr = ip
    else:
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
    return addr.is_global


def resolve_allowed_ip(host: str, port: int = 0) -> str | None:
    """Primitive de PINNING egress : résout `host` (littéral IP géré
    directement, sinon `socket.getaddrinfo`) et retourne la **première** IP
    résolue qui est `is_ip_allowed`, sous forme de `str`, ou `None` si aucune
    IP autorisée n'a pu être obtenue (littéral interdit, échec DNS, ou
    toutes les IP résolues sont internes).

    C'est cette fonction que le garde egress doit appeler juste avant
    d'ouvrir la connexion sortante réelle, et il doit se connecter
    exactement à l'IP renvoyée (jamais de re-résolution) : la résolution au
    plus près de la connexion + le pinning sur cette IP défait le
    DNS-rebinding.
    """
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        return str(literal) if is_ip_allowed(literal) else None

    try:
        infos = socket.getaddrinfo(host, port or None)
    except socket.gaierror:
        return None

    for _family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        if is_ip_allowed(addr):
            return addr
    return None


def validate_capture_url(url: str) -> None:
    """Best-effort garde SSRF pour le profil `capture` : le runner va fetcher
    cette URL avec le réseau ON, donc il faut empêcher qu'elle pointe vers
    file://, le service de metadata cloud (169.254.169.254), loopback,
    ou tout autre réseau privé/interne.

    Lève `ValueError` si :
    - le scheme n'est pas dans l'allowlist {http, https} (rejette
      file/gopher/ftp/data/... qui n'ont pas de sens pour un fetch réseau) ;
    - le host est vide ;
    - le host (littéral IP ou nom résolu via `socket.getaddrinfo`) désigne une
      IP loopback / privée (RFC1918) / link-local (169.254.0.0/16, fe80::/10 —
      couvre le service de metadata cloud) / réservée / multicast.

    Limite connue (DNS-rebinding) : la résolution DNS effectuée ici, au moment
    du submit, peut différer de celle que fera le runner au moment du fetch
    (TTL court, réponse DNS adversariale changeant d'IP entre les deux). Cette
    fonction ne protège donc PAS, seule, contre un DNS-rebinding actif — c'est
    le garde egress (`engine/egress_guard.py`, résolution + pinning au moment
    de la connexion) qui ferme ce trou côté runner. Ce garde-fou au submit
    reste un best-effort complémentaire.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"scheme non autorisé: {scheme!r}")

    host = parts.hostname
    if not host:
        raise ValueError("host vide")

    for candidate_ip in _resolve_ips(host):
        if not is_ip_allowed(candidate_ip):
            raise ValueError(f"URL interdite (IP non routable/interne): {url!r}")


def _resolve_ips(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    # Host déjà un littéral IP (v4 ou v6, avec ou sans crochets déjà retirés par urlsplit).
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"résolution DNS impossible: {host!r}") from exc

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        ips.append(ipaddress.ip_address(addr))
    if not ips:
        raise ValueError(f"résolution DNS vide: {host!r}")
    return ips
