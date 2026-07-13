import base64
import hashlib
import json

from broker.launcher import _store_blobs, _parse_and_store


def test_store_blobs_writes_valid_refs_only(tmp_path):
    data = b"PNGDATA"
    ref = "sha256:" + hashlib.sha256(data).hexdigest()  # ref cohérent : store_blobs vérifie l'intégrité
    _store_blobs({ref: base64.b64encode(data).decode(),
                  "../evil": base64.b64encode(b"x").decode()}, str(tmp_path))
    fname = "sha256_" + hashlib.sha256(data).hexdigest()
    assert (tmp_path / fname).read_bytes() == data
    assert not (tmp_path / "../evil").exists()
    assert list(tmp_path.iterdir()) == [tmp_path / fname]


def test_parse_and_store_returns_lean_result_without_blobs(tmp_path):
    data = b"DATA"
    ref = "sha256:" + hashlib.sha256(data).hexdigest()  # ref cohérent : store_blobs vérifie l'intégrité
    wrapper = json.dumps({"result": {"job_id": "j", "profile": "analysis", "target": "t",
                                     "timestamp": "now", "schema_version": "1.0"},
                          "blobs": {ref: base64.b64encode(data).decode()}})
    lean = _parse_and_store(wrapper, str(tmp_path))
    assert "blobs" not in lean
    assert json.loads(lean)["job_id"] == "j"
    fname = "sha256_" + hashlib.sha256(data).hexdigest()
    assert (tmp_path / fname).read_bytes() == data
