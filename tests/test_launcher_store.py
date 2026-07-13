import base64
import json

from broker.launcher import _store_blobs, _parse_and_store


def test_store_blobs_writes_valid_refs_only(tmp_path):
    ref = "sha256:" + "b" * 64
    _store_blobs({ref: base64.b64encode(b"PNGDATA").decode(),
                  "../evil": base64.b64encode(b"x").decode()}, str(tmp_path))
    assert (tmp_path / ("sha256_" + "b" * 64)).read_bytes() == b"PNGDATA"
    assert not (tmp_path / "../evil").exists()
    assert list(tmp_path.iterdir()) == [tmp_path / ("sha256_" + "b" * 64)]


def test_parse_and_store_returns_lean_result_without_blobs(tmp_path):
    ref = "sha256:" + "c" * 64
    wrapper = json.dumps({"result": {"job_id": "j", "profile": "analysis", "target": "t",
                                     "timestamp": "now", "schema_version": "1.0"},
                          "blobs": {ref: base64.b64encode(b"DATA").decode()}})
    lean = _parse_and_store(wrapper, str(tmp_path))
    assert "blobs" not in lean
    assert json.loads(lean)["job_id"] == "j"
    assert (tmp_path / ("sha256_" + "c" * 64)).read_bytes() == b"DATA"
