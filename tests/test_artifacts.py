import base64
import hashlib

import pytest

from engine.artifacts import ref_to_filename, store_blobs


def test_valid_ref_maps_to_safe_filename():
    ref = "sha256:" + "a" * 64
    assert ref_to_filename(ref) == "sha256_" + "a" * 64


def test_store_blobs_writes_valid_refs_only(tmp_path):
    data = b"PNGDATA"
    ref = "sha256:" + hashlib.sha256(data).hexdigest()  # ref cohérent : intégrité vérifiée par store_blobs
    store_blobs({ref: base64.b64encode(data).decode(),
                 "../evil": base64.b64encode(b"x").decode()}, str(tmp_path))
    assert (tmp_path / ref_to_filename(ref)).read_bytes() == data
    assert not (tmp_path / "../evil").exists()
    assert list(tmp_path.iterdir()) == [tmp_path / ref_to_filename(ref)]


def test_store_blobs_rejects_ref_not_matching_sha256_of_content(tmp_path):
    """Intégrité : si le ref ne correspond pas au sha256 réel des octets
    (empoisonnement / erreur), store_blobs n'écrit rien pour cette entrée —
    ceci rend un montage /artifacts en rw sûr même pour un écrivain compromis."""
    data = b"PNGDATA"
    bad_ref = "sha256:" + "a" * 64  # ne correspond PAS au sha256 de data
    store_blobs({bad_ref: base64.b64encode(data).decode()}, str(tmp_path))
    assert not (tmp_path / ref_to_filename(bad_ref)).exists()
    assert list(tmp_path.iterdir()) == []


def test_store_blobs_writes_when_ref_matches_sha256_of_content(tmp_path):
    data = b"some artifact bytes"
    ref = "sha256:" + hashlib.sha256(data).hexdigest()
    store_blobs({ref: base64.b64encode(data).decode()}, str(tmp_path))
    assert (tmp_path / ref_to_filename(ref)).read_bytes() == data


@pytest.mark.parametrize("bad", [
    "sha256:xyz", "../../etc/passwd", "sha256:" + "a" * 63,
    "sha256:" + "A" * 64, "md5:" + "a" * 32, "sha256:" + "a" * 64 + "/..",
    "sha256:" + "a" * 64 + "\n",       # newline final (piège $ vs \Z)
    "sha256:" + "a" * 64 + "\x00",     # null byte
    "sha256:" + "a" * 64 + "extra",    # suffixe après 64 hex
    "\nsha256:" + "a" * 64,            # newline en tête
])
def test_invalid_ref_rejected(bad):
    with pytest.raises(ValueError):
        ref_to_filename(bad)
