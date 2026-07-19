# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Résilience applicative de runner_recon/capture.py : même si le driver/
navigateur Camoufox meurt en cours de capture (page hostile Cloudflare/Auth0,
ex. "Connection closed"), `main()` doit quand même émettre sur stdout un
wrapper `OcularResult` valide — pas de crash silencieux consommé par
broker/launcher.py. Aucun navigateur requis ici : `capture_url` est
monkeypatchée pour lever directement l'exception."""

import json

import runner_recon.capture as cap


def test_main_emits_valid_wrapper_on_driver_failure(monkeypatch, capsys):
    async def boom(url, *a, **k):
        raise RuntimeError("Connection closed")

    monkeypatch.setattr(cap, "capture_url", boom)
    monkeypatch.setattr("sys.argv", ["capture", "--url", "https://example.com"])

    cap.main()

    out = capsys.readouterr().out
    d = json.loads(out)  # doit être un wrapper JSON valide malgré l'échec
    assert d["result"]["profile"] == "capture"
    assert d["result"]["target"] == "https://example.com"
    assert d["result"]["verdict"] == "benign"
    assert any("capture failed" in c["text"] for c in d["result"]["console"])
