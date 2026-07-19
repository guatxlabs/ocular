# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
from pathlib import Path


def _x11vnc_line(ep: str) -> str:
    """Retourne la vraie ligne de commande `x11vnc` (non commentée), ou une
    chaîne vide si introuvable. Évite les faux positifs des tests qui
    grep-aient le fichier entier : les flags de sécu sont aussi cités dans
    les commentaires explicatifs au-dessus de la commande."""
    for line in ep.splitlines():
        s = line.strip()
        if s.startswith("x11vnc "):
            return s
    return ""


def _user_lines(df: str) -> list[str]:
    """Retourne les vraies lignes Dockerfile `USER ...` (instructions, pas
    des commentaires) : un Dockerfile peut légitimement contenir plusieurs
    `USER` (ex. `USER root` le temps d'un apt-get, puis retour non-root)."""
    return [s for line in df.splitlines() if (s := line.strip()).startswith("USER ")]


def test_vnc_dockerfile_noclipboard_nonroot():
    df = Path("runner_recon_vnc/Dockerfile").read_text()
    ep = Path("runner_recon_vnc/entrypoint_vnc.sh").read_text()
    user_lines = _user_lines(df)
    assert "USER 10001" in user_lines, f"USER 10001 absent en tant qu'instruction réelle: {user_lines!r}"
    assert user_lines[-1] == "USER 10001", "le Dockerfile doit finir non-root (dernière instruction USER)"
    assert "novnc" in df.lower() and "x11vnc" in df.lower()
    assert "-p " not in ep  # pas de mapping de port dans l'entrypoint


def test_recon_vnc_clipboard_off_on_real_command():
    ep = Path("runner_recon_vnc/entrypoint_vnc.sh").read_text()
    line = _x11vnc_line(ep)
    assert line, "ligne x11vnc introuvable (hors commentaire)"
    for flag in ("-noclipboard", "-nosetclipboard", "-localhost"):
        assert flag in line, f"{flag} absent de la commande x11vnc réelle"
