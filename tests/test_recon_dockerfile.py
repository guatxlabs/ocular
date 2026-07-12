from pathlib import Path


def test_recon_dockerfile_nonroot_no_novnc():
    df = Path("runner_recon/Dockerfile").read_text()
    assert "USER" in df and "camoufox" in df
    assert "novnc" not in df.lower()  # noVNC = 3b, pas 3a
