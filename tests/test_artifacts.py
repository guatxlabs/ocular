import pytest

from engine.artifacts import ref_to_filename


def test_valid_ref_maps_to_safe_filename():
    ref = "sha256:" + "a" * 64
    assert ref_to_filename(ref) == "sha256_" + "a" * 64


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
