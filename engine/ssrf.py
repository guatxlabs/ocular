from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = {"http", "https"}


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
    fonction ne protège donc PAS contre un DNS-rebinding actif — seule une
    mitigation complète (filtrage egress réseau côté runner, résolution au
    plus près du fetch avec pinning de l'IP) le permettrait, et c'est hors
    scope de la phase 3a. Ce garde-fou est un best-effort au submit.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"scheme non autorisé: {scheme!r}")

    host = parts.hostname
    if not host:
        raise ValueError("host vide")

    for candidate_ip in _resolve_ips(host):
        if (
            candidate_ip.is_private
            or candidate_ip.is_loopback
            or candidate_ip.is_link_local
            or candidate_ip.is_reserved
            or candidate_ip.is_multicast
        ):
            raise ValueError(f"IP interdite: {candidate_ip}")


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
