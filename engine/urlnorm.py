from __future__ import annotations

import hashlib
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    p = urlsplit(url.strip())
    scheme = p.scheme.lower() or "http"
    netloc = p.netloc.lower()
    # garde path/query, retire le fragment
    return urlunsplit((scheme, netloc, p.path, p.query, ""))


def url_input_hash(url: str) -> str:
    return "sha256:" + hashlib.sha256(normalize_url(url).encode()).hexdigest()
