from engine.static import analyze_html
from engine.verdict import compute_verdict


def test_detects_eval_and_atob_are_obfuscation_signals():
    findings = analyze_html("<script>eval(atob('ZG9j'))</script>")
    rules = {f.rule for f in findings}
    assert "Dynamic code evaluation" in rules
    assert "Base64 decode" in rules
    assert all(f.line >= 1 for f in findings)
    by_rule = {f.rule: f.severity for f in findings}
    assert by_rule["Dynamic code evaluation"] == "high"
    assert by_rule["Base64 decode"] == "medium"


def test_detects_password_field_as_low_structural_signal():
    # Password fields are common/structural on their own (login pages) — not
    # a strong signal in isolation under the re-tiered model.
    findings = analyze_html('<input type="password" name="pass">')
    sev = {f.rule: f.severity for f in findings}
    assert sev.get("Password input field") == "low"


def test_benign_html_has_no_high_severity():
    findings = analyze_html("<html><body><h1>Bonjour</h1></body></html>")
    assert not [f for f in findings if f.severity in ("critical", "high")]


def test_external_script_alone_is_medium_and_benign_verdict():
    findings = analyze_html('<script src="https://cdn.example/x.js"></script>')
    by_rule = {f.rule: f.severity for f in findings}
    assert by_rule.get("External script") == "medium"
    assert compute_verdict(findings) == "benign"


def test_external_form_action_detected_as_medium():
    findings = analyze_html('<form action="https://evil.tld/collect" method="post"></form>')
    by_rule = {f.rule: f.severity for f in findings}
    assert by_rule.get("External form action") == "medium"


def test_internal_form_action_not_flagged_as_external():
    findings = analyze_html('<form action="/login" method="post"></form>')
    rules = {f.rule for f in findings}
    assert "External form action" not in rules
    assert "Form action URL" in rules


def test_phishing_language_is_medium():
    findings = analyze_html("<p>Please verify your account now.</p>")
    by_rule = {f.rule: f.severity for f in findings}
    assert by_rule.get("Account verification text") == "medium"
