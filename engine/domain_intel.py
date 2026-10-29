# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Âge et titulaire des domaines de la chaîne de redirection, via RDAP.

Un lien de phishing tient souvent sur un domaine né la veille, ou rebondit
d'un domaine jetable vers la marque imitée. Le contenu de la page ne le dit
pas ; le registre, si. Ce module interroge le serveur RDAP officiel de chaque
TLD (annuaire IANA) et rend une `DomainInfo` par domaine enregistrable.

Appelé par le BROKER après la capture, jamais par le runner : le bac à sable
de capture n'a aucune raison de joindre les registres. Les URLs interrogées
viennent de l'annuaire IANA (et du lien `related` que rend le registre), le
nom de domaine n'est qu'un segment de chemin validé — la page analysée ne
choisit aucun hôte contacté ici.

Fail-safe : aucune fonction publique ne lève. Une consultation ratée donne
une `DomainInfo(error=...)`, et un champ masqué par le registre (RGPD) reste
`None` : inconnu n'est jamais « différent »."""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

from engine.result import DomainInfo
from ocular_logging import get_logger

log = get_logger("domain_intel")

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_TTL_S = 24 * 3600
_HTTP_TIMEOUT_S = 5.0
_TOTAL_BUDGET_S = 10.0
_MAX_BODY_BYTES = 1024 * 1024
# Une chaîne bornée à 20 sauts (engine.wrapper) peut toucher autant de
# domaines ; au-delà de quelques-uns, la page est déjà bruyante et chaque
# consultation coûte une requête à un registre tiers.
MAX_DOMAINS = 5

# Suffixes publics à DEUX niveaux les plus courants. Heuristique assumée (pas
# la Public Suffix List complète, ~10k entrées) : un suffixe absent d'ici fait
# prendre `x.suffixe` pour le domaine enregistrable, ce qui rend au pire une
# consultation RDAP ratée (`error`), jamais un faux titulaire.
_TWO_LEVEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.kr", "co.in", "co.za",
    "com.br", "com.cn", "com.mx", "com.tr", "com.ar", "com.sg", "com.hk",
    "asso.fr", "gouv.fr", "tm.fr", "com.fr", "nom.fr",
    "co.il", "com.pl", "com.es", "com.pt",
})
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
# Valeurs que les registres mettent à la place d'un titulaire masqué.
_REDACTED_RE = re.compile(r"redact|privacy|not disclosed|withheld|non publi|masqu", re.I)


def registrable_domain(url_or_host: str) -> Optional[str]:
    """`https://a.b.exemple.co.uk/x` -> `exemple.co.uk`. `None` pour une IP,
    un hôte sans point ou un nom invalide (rien à demander à un registre)."""
    host = urlsplit(url_or_host).hostname if "://" in url_or_host else url_or_host
    host = (host or "").strip(".").lower()
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not _DOMAIN_RE.match(host):
        return None
    labels = host.split(".")
    n = 3 if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES else 2
    return ".".join(labels[-n:]) if len(labels) >= n else None


def chain_domains(chain: list[str]) -> list[str]:
    """Domaines enregistrables de la chaîne, dans l'ordre, sans doublon,
    bornés à `MAX_DOMAINS`."""
    seen: list[str] = []
    for url in chain:
        d = registrable_domain(url)
        if d and d not in seen:
            seen.append(d)
    return seen[:MAX_DOMAINS]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Les serveurs RDAP de l'annuaire répondent en direct : un 3xx lève au
    lieu d'emmener la requête vers un hôte que personne n'a choisi."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))


def _fetch_json(url: str) -> Any:
    if urlsplit(url).scheme != "https":
        raise ValueError("RDAP hors https refusé")
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json"})
    with _OPENER.open(req, timeout=_HTTP_TIMEOUT_S) as resp:
        body = resp.read(_MAX_BODY_BYTES + 1)
    if len(body) > _MAX_BODY_BYTES:
        raise ValueError("réponse RDAP trop grande")
    return json.loads(body)


_bootstrap_lock = threading.Lock()
_bootstrap: dict[str, Any] = {"at": 0.0, "map": {}}


def _rdap_base(tld: str, fetch: Callable[[str], Any]) -> Optional[str]:
    with _bootstrap_lock:
        if time.monotonic() - _bootstrap["at"] > _BOOTSTRAP_TTL_S or not _bootstrap["map"]:
            data = fetch(_BOOTSTRAP_URL)
            mapping: dict[str, str] = {}
            for tlds, urls in data.get("services", []):
                https = [u for u in urls if u.startswith("https://")]
                for t in tlds:
                    if https:
                        mapping[t.lower()] = https[0]
            _bootstrap.update(at=time.monotonic(), map=mapping)
        return _bootstrap["map"].get(tld)


def _vcard_name(entity: dict) -> Optional[str]:
    """Organisation (`org`) de préférence, sinon nom (`fn`) ; `None` si vide
    ou masqué."""
    props = (entity.get("vcardArray") or [None, []])[1] or []
    by_kind = {p[0]: p[3] for p in props if isinstance(p, list) and len(p) >= 4}
    for kind in ("org", "fn"):
        v = by_kind.get(kind)
        if isinstance(v, list):
            v = " ".join(str(x) for x in v if x)
        if isinstance(v, str) and v.strip() and not _REDACTED_RE.search(v):
            return v.strip()
    return None


def _walk_entities(entities: list) -> list[dict]:
    out: list[dict] = []
    for e in entities or []:
        if isinstance(e, dict):
            out.append(e)
            out.extend(_walk_entities(e.get("entities", [])))
    return out


def _by_role(doc: dict, role: str) -> Optional[str]:
    for e in _walk_entities(doc.get("entities", [])):
        if role in (e.get("roles") or []):
            name = _vcard_name(e)
            if name:
                return name
    return None


def parse_rdap(domain: str, doc: dict, now: datetime,
               related: Optional[dict] = None) -> DomainInfo:
    """Fonction pure : réponse RDAP du registre (+ celle du registraire,
    `related`, pour les registres « minces » comme .com) -> `DomainInfo`."""
    created = None
    for ev in doc.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            created = str(ev["eventDate"])
            break
    age_days = None
    if created:
        try:
            dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = max(0, (now - dt).days)
        except ValueError:
            created = None
    registrant = _by_role(doc, "registrant") or (related and _by_role(related, "registrant"))
    registrar = _by_role(doc, "registrar") or (related and _by_role(related, "registrar"))
    return DomainInfo(domain=domain, created=created, age_days=age_days,
                      registrant=registrant or None, registrar=registrar or None)


def lookup(domain: str, *, fetch: Callable[[str], Any] = _fetch_json,
           now: Optional[datetime] = None) -> DomainInfo:
    """Fiche RDAP de `domain` (déjà enregistrable). Ne lève jamais."""
    now = now or datetime.now(timezone.utc)
    try:
        base = _rdap_base(domain.rsplit(".", 1)[-1], fetch)
        if not base:
            return DomainInfo(domain=domain, error="TLD sans serveur RDAP")
        doc = fetch(base.rstrip("/") + "/domain/" + domain)
        related = None
        if not _by_role(doc, "registrant"):
            # Registre « mince » (.com, .net) : le titulaire n'est publié que
            # par le registraire, désigné par le lien `related` du registre.
            href = next((lk.get("href") for lk in doc.get("links", [])
                         if lk.get("rel") == "related" and str(lk.get("href", "")).startswith("https://")), None)
            if href:
                try:
                    related = fetch(href)
                except Exception as exc:  # noqa: BLE001 - le registre suffit
                    log.info("rdap related domain=%s err=%s", domain, type(exc).__name__)
        return parse_rdap(domain, doc, now, related)
    except Exception as exc:  # noqa: BLE001 - fail-safe, cf. docstring du module
        log.info("rdap lookup domain=%s err=%s", domain, type(exc).__name__)
        return DomainInfo(domain=domain, error=type(exc).__name__)


def lookup_chain(chain: list[str], *, fetch: Callable[[str], Any] = _fetch_json,
                 now: Optional[datetime] = None) -> list[DomainInfo]:
    """Fiches des domaines de `chain`, en parallèle, sous un budget total de
    `_TOTAL_BUDGET_S` (le broker traite les jobs un par un). Un domaine hors
    budget rend `error="timeout"`."""
    domains = chain_domains(chain)
    if not domains:
        return []
    pool = ThreadPoolExecutor(max_workers=len(domains))
    futures = [pool.submit(lookup, d, fetch=fetch, now=now) for d in domains]
    wait(futures, timeout=_TOTAL_BUDGET_S)
    pool.shutdown(wait=False, cancel_futures=True)
    return [f.result() if f.done() else DomainInfo(domain=d, error="timeout")
            for d, f in zip(domains, futures)]
