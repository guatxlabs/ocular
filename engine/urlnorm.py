from __future__ import annotations

import hashlib
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(url: str) -> str:
    """Normalise une URL de façon à MATCHER `new URL(url)` en JS (pour que la dédup
    client/serveur coïncide) : scheme https par défaut si absent, scheme+host en
    minuscules, port par défaut retiré, path vide -> '/', fragment retiré.
    (Limite connue : l'IDN/punycode n'est pas appliqué — rare pour ce cas d'usage.)"""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    p = urlsplit(url)
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower()
    netloc = host
    if p.port is not None and p.port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{p.port}"
    path = p.path or "/"
    return urlunsplit((scheme, netloc, path, p.query, ""))


def url_input_hash(url: str) -> str:
    return "sha256:" + hashlib.sha256(normalize_url(url).encode()).hexdigest()
