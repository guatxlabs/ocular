# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
import json

import pytest

from broker.launcher import run_analysis_job
from bus.queue import Job


@pytest.mark.integration
def test_end_to_end_analysis_via_broker():
    out = run_analysis_job(Job(job_id="e2e-1", profile="analysis",
                               html="<script>eval(atob('x'))</script>"))
    result = json.loads(out)
    assert result["profile"] == "analysis"
    # eval(atob(...)) = cluster obfuscation (eval=high + atob decode=medium, >=2 _OBF)
    # -> verdict corroboré `malicious` (cf. engine/verdict.py, recalibration 3d-J).
    assert result["verdict"] == "malicious"
    assert any(f["rule"] == "Dynamic code evaluation" for f in result["static_findings"])
    assert result["screenshots"][0]["image_ref"].startswith("sha256:")
