from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = {"http", "https"}

# Préfixes NAT64 (RFC 6052 / RFC 8215) : une IPv6 dans ces plages traduit vers
# une IPv4. Le préfixe « well-known » /96 encode l'IPv4 dans les 32 bits de
# poids faible (décodable). Le préfixe « à usage local » /48 encode l'IPv4 à un
# offset dépendant de la longueur de préfixe (non décodé de façon fiable ici).
_NAT64_WELL_KNOWN = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL_USE = ipaddress.ip_network("64:ff9b:1::/48")


def _embedded_ipv4(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """IPv4 réellement jointe encapsulée dans une IPv6 (IPv4-mapped `::ffff:x`,
    6to4 `2002::`, ou NAT64 well-known `64:ff9b::/96`), sinon `None`. Défait les
    contournements SSRF où une IPv6 classée « globale » par `is_global` traduit
    en fait vers une IPv4 interne (ex. `64:ff9b::a9fe:a9fe` -> `169.254.169.254`,
    le service de metadata cloud, en réseau DNS64/NAT64)."""
    if not isinstance(addr, ipaddress.IPv6Address):
        return None
    if addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    if addr.sixtofour is not None:
        return addr.sixtofour
    if addr in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    return None


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
    # `is_global` seul NE rejette PAS le multicast (224.0.0.0/4, ff00::/8) :
    # ces adresses ne sont pas "privées" au sens `is_private`, donc
    # `is_global` les laisse passer alors qu'elles n'ont aucun sens pour un
    # fetch/CONNECT sortant et peuvent servir à joindre des services de
    # découverte internes (SSDP 239.255.255.250, mDNS ff02::fb, ...). On les
    # rejette explicitement (durcissement audit 3g I1) — cohérent avec le
    # docstring ci-dessus qui annonçait déjà le rejet du multicast.

    # Anti-bypass NAT64/IPv4-embedding : une IPv6 « globale » peut traduire vers
    # une IPv4 interne. On décide alors sur l'IPv4 réellement jointe (récursif).
    embedded = _embedded_ipv4(addr)
    if embedded is not None:
        return is_ip_allowed(embedded)
    # NAT64 à usage local (/48) : offset d'encodage v4 dépendant du préfixe
    # (RFC 6052), non décodé ici -> rejet prudent (préfixe de traduction, jamais
    # une cible de fetch directe légitime).
    if isinstance(addr, ipaddress.IPv6Address) and addr in _NAT64_LOCAL_USE:
        return False
    return addr.is_global and not addr.is_multicast


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
