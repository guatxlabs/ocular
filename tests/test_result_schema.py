import json
from pathlib import Path

import jsonschema

from engine.result import OcularResult


def _minimal_payload() -> dict:
    return {
        "schema_version": "1.0",
        "job_id": "job-123",
        "profile": "analysis",
        "target": "inline-html",
        "timestamp": "2026-07-12T10:00:00Z",
        "verdict": "malicious",
        "screenshots": [{"step": 0, "phase": "initial", "image_ref": "sha256:abc", "viewport": "1280x720"}],
        "network": [],
        "console": [],
        "dom": {"title": "t", "final_url": "about:blank", "redirect_chain": [], "forms": [], "links": []},
        "static_findings": [{"rule": "eval", "severity": "critical", "match": "eval(x)", "line": 3, "context": "..."}],
        "dynamic_steps": [],
        "stealth": {"engine": "chromium", "turnstile_solved": False, "challenge": None},
        "artifacts": {"har_ref": None, "dom_html_ref": "sha256:def"},
    }


def test_ocularresult_accepts_minimal_payload():
    r = OcularResult.model_validate(_minimal_payload())
    assert r.verdict == "malicious"


def test_generated_schema_validates_payload_and_is_written():
    schema = OcularResult.model_json_schema()
    jsonschema.validate(_minimal_payload(), schema)  # ne lève pas
    # le fichier de contrat existe et correspond au modèle
    on_disk = json.loads(Path("schemas/result.schema.json").read_text())
    assert on_disk["properties"]["schema_version"]  # présent


def test_invalid_severity_is_rejected():
    bad = _minimal_payload()
    bad["static_findings"][0]["severity"] = "spicy"
    try:
        OcularResult.model_validate(bad)
        assert False, "should reject invalid severity"
    except Exception:
        pass
