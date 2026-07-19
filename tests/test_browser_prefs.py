# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prefs Firefox durcies partagées (engine/browser_prefs) — ferment les canaux
egress HORS du proxy TCP du garde. Audit sécu 3k, findings 1-4."""
from engine.browser_prefs import HARDENED_FIREFOX_PREFS


def test_udp_off_proxy_channels_closed():
    # WebRTC + QUIC/HTTP3 + WebTransport : UDP direct, hors proxy TCP -> OFF.
    assert HARDENED_FIREFOX_PREFS["media.peerconnection.enabled"] is False
    assert HARDENED_FIREFOX_PREFS["network.http.http3.enable"] is False
    assert HARDENED_FIREFOX_PREFS["network.http.http3.enabled"] is False
    assert HARDENED_FIREFOX_PREFS["network.webtransport.enabled"] is False


def test_loopback_forced_through_proxy():
    # loopback DOIT passer par le proxy (le garde le 403), sinon accès direct
    # aux services locaux du conteneur (session_server:8090, x11vnc:5900).
    assert HARDENED_FIREFOX_PREFS["network.proxy.allow_hijacking_localhost"] is True
    assert HARDENED_FIREFOX_PREFS["network.proxy.no_proxies_on"] == ""


def test_speculative_dns_disabled():
    # pas de résolution DNS spéculative (prefetch/predictor/speculative connect)
    # -> pas de canal DNS vers le resolver interne hors garde.
    assert HARDENED_FIREFOX_PREFS["network.dns.disablePrefetch"] is True
    assert HARDENED_FIREFOX_PREFS["network.predictor.enabled"] is False
    assert HARDENED_FIREFOX_PREFS["browser.urlbar.speculativeConnect.enabled"] is False
    assert HARDENED_FIREFOX_PREFS["network.http.speculative-parallel-limit"] == 0


def test_doh_trr_off():
    assert HARDENED_FIREFOX_PREFS["network.trr.mode"] == 5


def test_both_network_on_tiers_use_the_shared_prefs():
    # Source UNIQUE : les deux tiers réseau-ON obtiennent leurs kwargs (dont les
    # prefs durcies) via engine.egress_policy.hardened_launch_kwargs — plus de
    # dérive possible entre capture batch et session interactive (audit 3m).
    from engine.egress_policy import hardened_launch_kwargs
    assert hardened_launch_kwargs()["firefox_user_prefs"] == HARDENED_FIREFOX_PREFS
    import runner_recon.capture as cap
    assert cap._CAMOUFOX_LAUNCH_KWARGS["firefox_user_prefs"] == HARDENED_FIREFOX_PREFS
    # les deux tiers passent par le helper partagé (vérifié par le source :
    # import direct pour éviter de charger camoufox/uvicorn ici).
    for path in ("runner_recon/capture.py", "runner_recon_vnc/session_server.py"):
        src = open(path).read()
        assert "from engine.egress_policy import hardened_launch_kwargs" in src
        assert "hardened_launch_kwargs()" in src
