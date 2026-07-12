from __future__ import annotations

from engine.result import StaticFinding, Verdict


def compute_verdict(findings: list[StaticFinding]) -> Verdict:
    sev = {f.severity for f in findings}
    if "critical" in sev:
        return "malicious"
    if "high" in sev:
        return "suspicious"
    return "benign"
