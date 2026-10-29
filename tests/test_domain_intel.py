# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Âge/titulaire des domaines de la chaîne (engine/domain_intel.py), signaux
de triage qui en découlent, et branchement côté broker — sans réseau : le
`fetch` RDAP est un dictionnaire d'URL -> réponse."""
import json
from datetime import datetime, timezone

import pytest

from broker.launcher import enrich_domains
from engine import domain_intel
from engine.domain_intel import chain_domains, lookup, lookup_chain, registrable_domain
from engine.result import DomainInfo, DomInfo, OcularResult
from engine.triage import compute_triage, extract_signals

NOW = datetime(2026, 10, 29, tzinfo=timezone.utc)

_BOOTSTRAP = {"services": [
    [["fr"], ["https://rdap.nic.fr/"]],
    [["example"], ["https://rdap.nic.example/"]],
    [["com", "net"], ["http://insecure.example/", "https://rdap.verisign.com/com/v1/"]],
]}


def _vcard(name, kind="fn"):
    return ["vcard", [["version", {}, "text", "4.0"], [kind, {}, "text", name]]]


def _rdap(created, registrant=None, registrar="OVH", related=None):
    ents = [{"roles": ["registrar"], "vcardArray": _vcard(registrar)}]
    if registrant is not None:
        ents.append({"roles": ["registrant"], "vcardArray": _vcard(registrant, "org")})
    doc = {"events": [{"eventAction": "registration", "eventDate": created}], "entities": ents}
    if related:
        doc["links"] = [{"rel": "related", "href": related}]
    return doc


def _fetcher(responses):
    calls = []

    def fetch(url):
        calls.append(url)
        if url not in responses:
            raise OSError("404 " + url)
        return responses[url]
    fetch.calls = calls
    return fetch


@pytest.fixture(autouse=True)
def _fresh_bootstrap(monkeypatch):
    # cache d'annuaire IANA module-global : isolé par test
    monkeypatch.setattr(domain_intel, "_bootstrap", {"at": 0.0, "map": {}})


@pytest.mark.parametrize("raw,expected", [
    ("https://a.b.lien-court.example/tiny/login", "lien-court.example"),
    ("https://www.exemple.co.uk/x", "exemple.co.uk"),
    ("http://EXAMPLE.COM:8080/", "example.com"),
    ("https://xn--bcher-kva.de/", "xn--bcher-kva.de"),
    ("https://bücher.de/", "xn--bcher-kva.de"),
    ("http://192.0.2.10/login", None),     # IP : rien à demander à un registre
    ("http://localhost/", None),
    ("https://../etc/passwd", None),
])
def test_registrable_domain(raw, expected):
    assert registrable_domain(raw) == expected


def test_chain_domains_dedupes_in_order_and_is_bounded():
    chain = ["http://lien-court.example/", "https://lien-court.example/tiny/", "https://example.com/"]
    assert chain_domains(chain) == ["lien-court.example", "example.com"]
    many = [f"https://d{i}.com/" for i in range(30)]
    assert len(chain_domains(many)) == domain_intel.MAX_DOMAINS


def test_lookup_reads_age_registrant_registrar():
    fetch = _fetcher({
        domain_intel._BOOTSTRAP_URL: _BOOTSTRAP,
        "https://rdap.nic.example/domain/lien-court.example": _rdap("2020-10-02T13:01:50Z", "Exemple Recouvrement SAS"),
    })
    d = lookup("lien-court.example", fetch=fetch, now=NOW)
    assert d.error is None and d.registrant == "Exemple Recouvrement SAS" and d.registrar == "OVH"
    assert d.created.startswith("2020-10-02") and d.age_days == 2217  # 13:01 le 02/10 -> le 2218e jour n'est pas révolu


def test_lookup_thin_registry_follows_related_and_keeps_redacted_unknown():
    # .com : le registre ne publie pas le titulaire ; le registraire le masque.
    fetch = _fetcher({
        domain_intel._BOOTSTRAP_URL: _BOOTSTRAP,
        "https://rdap.verisign.com/com/v1/domain/example.com":
            _rdap("1998-06-17T04:00:00Z", related="https://rdap.registrar.example/domain/EXAMPLE.COM"),
        "https://rdap.registrar.example/domain/EXAMPLE.COM": _rdap("1998-06-17T04:00:00Z", "REDACTED FOR PRIVACY"),
    })
    d = lookup("example.com", fetch=fetch, now=NOW)
    assert d.registrant is None            # masqué = inconnu, jamais une valeur
    assert "https://rdap.registrar.example/domain/EXAMPLE.COM" in fetch.calls
    # l'URL http de l'annuaire n'est jamais choisie
    assert not any(u.startswith("http://") for u in fetch.calls)


def test_lookup_never_raises():
    d = lookup("inconnu.zz", fetch=_fetcher({domain_intel._BOOTSTRAP_URL: _BOOTSTRAP}), now=NOW)
    assert d.error == "TLD sans serveur RDAP"
    d = lookup("lien-court.example", fetch=_fetcher({domain_intel._BOOTSTRAP_URL: _BOOTSTRAP}), now=NOW)
    assert d.error == "OSError"


def test_fetch_refuses_plain_http():
    with pytest.raises(ValueError):
        domain_intel._fetch_json("http://rdap.example/domain/x.fr")


@pytest.mark.parametrize("url", [
    "https://127.0.0.1/domain/x.fr",
    "https://169.254.169.254/latest/meta-data/",
    "https://[::1]/domain/x.fr",
    "https://10.0.0.5:8443/domain/x.fr",
])
def test_fetch_refuses_internal_hosts(url):
    # lien `related` hostile d'un registraire : jamais de connexion interne
    with pytest.raises(ValueError, match="non public"):
        domain_intel._fetch_json(url)


def test_fetch_connects_to_the_checked_ip_not_a_reresolution(monkeypatch):
    # DNS-rebinding : la connexion part vers l'IP VÉRIFIÉE, sans 2e résolution.
    monkeypatch.setattr(domain_intel, "resolve_allowed_ip", lambda host, port: "192.0.2.7")
    seen = []

    def fake_create_connection(addr, timeout=None):
        seen.append(addr)
        raise OSError("stop")
    monkeypatch.setattr(domain_intel.socket, "create_connection", fake_create_connection)
    with pytest.raises(OSError):
        domain_intel._fetch_json("https://rdap.example/domain/x.fr")
    assert seen == [("192.0.2.7", 443)]


def test_lookup_chain_marks_slow_domains_timeout(monkeypatch):
    monkeypatch.setattr(domain_intel, "_TOTAL_BUDGET_S", 0.2)
    import threading
    gate = threading.Event()

    def slow_fetch(url):
        gate.wait(2)
        raise OSError("lent")
    out = lookup_chain(["https://a.fr/", "https://b.fr/"], fetch=slow_fetch, now=NOW)
    gate.set()
    assert [d.error for d in out] == ["timeout", "timeout"]


# --- signaux de triage -------------------------------------------------------

def _dom(chain, domains):
    return DomInfo(redirect_chain=chain, domains=domains)


def test_young_domain_signal_fires_under_threshold_only():
    chain = ["https://colis-suivi-fr.top/x", "https://www.laposte.fr/"]
    young = _dom(chain, [DomainInfo(domain="colis-suivi-fr.top", age_days=3),
                         DomainInfo(domain="laposte.fr", age_days=9000)])
    sig = extract_signals([], [], [], young)
    assert sig["young_domain"] == (True, "colis-suivi-fr.top : 3 j")
    old = _dom(chain, [DomainInfo(domain="colis-suivi-fr.top", age_days=400)])
    assert extract_signals([], [], [], old)["young_domain"][0] is False
    unknown = _dom(chain, [DomainInfo(domain="colis-suivi-fr.top", error="timeout")])
    assert extract_signals([], [], [], unknown)["young_domain"][0] is False


def test_registrant_mismatch_needs_two_known_owners():
    chain = ["https://a.fr/", "https://b.com/"]
    differ = _dom(chain, [DomainInfo(domain="a.fr", registrant="Arnaque SARL"),
                          DomainInfo(domain="b.com", registrant="Banque SA")])
    assert extract_signals([], [], [], differ)["registrant_mismatch"][0] is True
    same = _dom(chain, [DomainInfo(domain="a.fr", registrant="Banque SA"),
                        DomainInfo(domain="b.com", registrant="banque sa ")])
    assert extract_signals([], [], [], same)["registrant_mismatch"][0] is False
    # cas lien-court.example -> example.com : titulaire .com masqué -> pas « différent »
    masked = _dom(chain, [DomainInfo(domain="a.fr", registrant="Exemple Recouvrement SAS"),
                          DomainInfo(domain="b.com")])
    assert extract_signals([], [], [], masked)["registrant_mismatch"][0] is False


def test_cross_domain_redirect_signal():
    assert extract_signals([], [], [], _dom(["https://a.fr/", "https://www.a.fr/x"], []))["cross_domain_redirect"][0] is False
    sig = extract_signals([], [], [], _dom(["https://lien-court.example/", "https://example.com/"], []))
    assert sig["cross_domain_redirect"] == (True, "lien-court.example → example.com")


def test_young_domain_redirect_reaches_medium_band():
    dom = _dom(["https://colis-suivi-fr.top/x", "https://www.laposte.fr/"],
               [DomainInfo(domain="colis-suivi-fr.top", age_days=3),
                DomainInfo(domain="laposte.fr", age_days=9000)])
    tri = compute_triage([], verdict="benign", dom=dom)
    assert tri.band == "medium" and tri.second_opinion == "suspicious"


# --- branchement broker ------------------------------------------------------

def _capture_json(chain):
    r = OcularResult(job_id="j", profile="capture", target=chain[0] if chain else "t",
                     timestamp="2026-10-29T20:51:10.370943+00:00", verdict="benign",
                     dom=DomInfo(redirect_chain=chain))
    r.triage = compute_triage([], verdict="benign", dom=r.dom)
    return r.model_dump_json()


def test_enrich_domains_fills_domains_and_recomputes_triage():
    chain = ["https://colis-suivi-fr.top/x", "https://www.laposte.fr/"]
    before = json.loads(_capture_json(chain))
    out = json.loads(enrich_domains(
        json.dumps(before),
        lookup_chain=lambda c: [DomainInfo(domain="colis-suivi-fr.top", age_days=3)],
    ))
    assert out["dom"]["domains"][0]["age_days"] == 3
    assert "young_domain" in {s["key"] for s in out["triage"]["signals"]}
    assert out["triage"]["score"] > before["triage"]["score"]
    assert out["verdict"] == "benign"      # le verdict règles n'est pas touché


def test_enrich_domains_is_noop_without_chain_or_on_garbage():
    no_chain = _capture_json([])
    assert enrich_domains(no_chain, lookup_chain=lambda c: pytest.fail("pas d'appel")) == no_chain
    assert enrich_domains("pas du json", lookup_chain=lambda c: []) == "pas du json"
