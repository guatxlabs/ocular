# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}

# Un scheme n'est reconnu que sous deux formes non ambiguës :
#  - absolu explicite "scheme://..." (http://, https://, ftp://, ws://, ...) ;
#  - un des schemes CONNUS qui s'écrivent sans "//" (data:, mailto:,
#    javascript:, ...).
# Tout le reste ("example.com", "example.com:8080", "abc:notaport") est
# traité comme SANS scheme -> reçoit le préfixe "https://". C'est ce qui
# évite de confondre un "host:port" nu (ex. "example.com:8080") avec un
# scheme, tout en laissant "data:"/"mailto:"/"javascript:" intacts (ils
# seront rejetés en aval par validate_capture_url, qui n'autorise que
# http/https — jamais un 500 côté normalisation).
_ABSOLUTE_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_KNOWN_NO_SLASH_SCHEMES = (
    "data", "mailto", "javascript", "file", "about", "blob", "tel", "ftp", "ws", "wss",
)
_KNOWN_NO_SLASH_SCHEME_RE = re.compile(
    r"^(?:" + "|".join(_KNOWN_NO_SLASH_SCHEMES) + r"):", re.IGNORECASE
)


def normalize_url(url: str) -> str:
    """Normaliseur URL CANONIQUE unique (utilisé pour le hash de dédup /jobs ET
    /saved/lookup) : scheme https par défaut si absent, scheme+host en minuscules,
    port par défaut retiré, path vide -> '/', fragment retiré. La dédup URL se fait
    entièrement côté serveur — aucun parseur URL client (JS) ne doit reproduire cette
    logique, pour éviter toute divergence (IPv6, IDN/punycode, percent-encoding du path).

    Ne lève JAMAIS d'exception brute d'urlsplit : toute entrée qui ne peut pas être
    parsée proprement (scheme malformé, port non numérique, ...) fait lever une
    `ValueError("URL invalide")` explicite, à charge de l'appelant de la catcher
    (cf. web/app.py: submit_job/create_session -> HTTP 400). Une entrée à scheme
    non-réseau reconnu (data:, mailto:, javascript:, file:, ...) n'est PAS rejetée
    ici — elle est renvoyée telle quelle avec son scheme préservé ; c'est
    `validate_capture_url` en aval qui la rejette (seuls http/https sont autorisés)."""
    url = url.strip()
    try:
        if not _ABSOLUTE_SCHEME_RE.match(url) and not _KNOWN_NO_SLASH_SCHEME_RE.match(url):
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
    except ValueError as e:
        raise ValueError("URL invalide") from e


def url_input_hash(url: str) -> str:
    return "sha256:" + hashlib.sha256(normalize_url(url).encode()).hexdigest()
