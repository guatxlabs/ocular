"""Préférences Firefox/Camoufox DURCIES, partagées par les DEUX tiers réseau-ON
(capture batch `runner_recon/capture.py` et session interactive
`runner_recon_vnc/session_server.py`). Source UNIQUE : sans ça, le durcissement
dérivait entre les deux tiers (le dict était dupliqué — cf. audit sécu 3g/3k).

Modèle de menace : le garde egress (`engine/egress_guard.py`) est un proxy
**TCP** HTTP/CONNECT. Tout ce qui sort du navigateur HORS de ce canal TCP échappe
au garde (pivot SSRF possible vers le réseau interne). On ferme donc côté
navigateur tous les canaux hors-proxy connus :

  - WebRTC (ICE/STUN en UDP direct) ;
  - QUIC / HTTP-3 / WebTransport (UDP direct, pas de transport via proxy CONNECT) ;
  - loopback : Firefox NE route PAS 127.0.0.1/::1/localhost par le proxy par
    défaut -> une page hostile atteindrait les services LOCAUX du conteneur
    (session_server:8090, x11vnc:5900). On force le loopback à passer par le
    proxy (le garde le 403 alors via `resolve_allowed_ip`) ;
  - résolution DNS spéculative (dns-prefetch / predictor / speculative connect) :
    le garde n'intervient qu'au CONNECT TCP, jamais sur le DNS -> une page
    hostile pourrait faire résoudre des noms internes (canal de reco/exfil via
    le resolver du conteneur). On coupe toute résolution spéculative ;
  - DoH/TRR figé OFF (déterminisme, pas de résolveur tiers).

Hygiène (pas des trous SSRF — ces requêtes passent par le proxy et visent des
hôtes publics — mais bruit egress + posture anti-detect) : télémétrie, update,
Safe Browsing, captive-portal, Normandy, push désactivés.
"""
from __future__ import annotations

HARDENED_FIREFOX_PREFS: dict[str, object] = {
    # --- canaux UDP hors proxy TCP (pivots SSRF directs) ---
    "media.peerconnection.enabled": False,          # WebRTC ICE/STUN
    "network.http.http3.enable": False,             # HTTP/3 (QUIC) — clé selon version
    "network.http.http3.enabled": False,
    "network.webtransport.enabled": False,          # WebTransport (UDP)
    # --- loopback DOIT traverser le proxy (sinon accès direct aux services locaux) ---
    "network.proxy.allow_hijacking_localhost": True,
    "network.proxy.no_proxies_on": "",
    # --- résolution DNS spéculative = canal DNS vers le resolver interne ---
    "network.dns.disablePrefetch": True,
    "network.dns.disablePrefetchFromHTTPS": True,
    "network.predictor.enabled": False,
    "network.predictor.enable-prefetch": False,
    "network.http.speculative-parallel-limit": 0,
    "browser.urlbar.speculativeConnect.enabled": False,
    # --- DoH/TRR explicitement OFF ---
    "network.trr.mode": 5,
    # --- services de fond (hygiène egress + anti-detect) ---
    "toolkit.telemetry.enabled": False,
    "datareporting.healthreport.uploadEnabled": False,
    "app.update.enabled": False,
    "network.captive-portal-service.enabled": False,
    "captivedetect.canonicalURL": "",
    "browser.safebrowsing.malware.enabled": False,
    "browser.safebrowsing.phishing.enabled": False,
    "network.connectivity-service.enabled": False,
    "app.normandy.enabled": False,
    "dom.push.enabled": False,
}
