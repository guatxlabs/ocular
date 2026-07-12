from pathlib import Path


def test_vnc_dockerfile_noclipboard_nonroot():
    df = Path("runner_recon_vnc/Dockerfile").read_text()
    ep = Path("runner_recon_vnc/entrypoint_vnc.sh").read_text()
    assert "USER 10001" in df and "novnc" in df.lower() and "x11vnc" in df.lower()
    assert "-noclipboard" in ep and "-nosetclipboard" in ep and "-localhost" in ep  # clipboard coupé + VNC local
    assert "-p " not in ep  # pas de mapping de port dans l'entrypoint
