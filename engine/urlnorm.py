from __future__ import annotations

import hashlib
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(url: str) -> str:
    """Normaliseur URL CANONIQUE unique (utilisé pour le hash de dédup /jobs ET
    /saved/lookup) : scheme https par défaut si absent, scheme+host en minuscules,
    port par défaut retiré, path vide -> '/', fragment retiré. La dédup URL se fait
    entièrement côté serveur — aucun parseur URL client (JS) ne doit reproduire cette
    logique, pour éviter toute divergence (IPv6, IDN/punycode, percent-encoding du path)."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    p = urlsplit(url)
    scheme = (p.scheme or "https").lower()
    host = (p.hostname or "").lower()
    if ":" in host:                 # IPv6 littéral -> crochets
        host = f"[{host}]"
    netloc = host
    if p.port is not None and p.port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{p.port}"
    path = p.path or "/"
    return urlunsplit((scheme, netloc, path, p.query, ""))


def url_input_hash(url: str) -> str:
    return "sha256:" + hashlib.sha256(normalize_url(url).encode()).hexdigest()
