import base64

import pytest

from engine.artifacts import ref_to_filename, store_blobs


def test_valid_ref_maps_to_safe_filename():
    ref = "sha256:" + "a" * 64
    assert ref_to_filename(ref) == "sha256_" + "a" * 64


def test_store_blobs_writes_valid_refs_only(tmp_path):
    ref = "sha256:" + "d" * 64
    store_blobs({ref: base64.b64encode(b"PNGDATA").decode(),
                 "../evil": base64.b64encode(b"x").decode()}, str(tmp_path))
    assert (tmp_path / ("sha256_" + "d" * 64)).read_bytes() == b"PNGDATA"
    assert not (tmp_path / "../evil").exists()
    assert list(tmp_path.iterdir()) == [tmp_path / ("sha256_" + "d" * 64)]


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
