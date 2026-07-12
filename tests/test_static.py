from engine.static import analyze_html


def test_detects_eval_and_atob_as_critical():
    findings = analyze_html("<script>eval(atob('ZG9j'))</script>")
    rules = {f.rule for f in findings}
    assert "Dynamic code evaluation" in rules
    assert "Base64 decode" in rules
    assert all(f.line >= 1 for f in findings)
    by_rule = {f.rule: f.severity for f in findings}
    assert by_rule["Dynamic code evaluation"] == "critical"
    assert by_rule["Base64 decode"] == "critical"


def test_detects_password_field_critical():
    findings = analyze_html('<input type="password" name="pass">')
    sev = {f.rule: f.severity for f in findings}
    assert sev.get("Password input field") == "critical"


def test_benign_html_has_no_critical():
    findings = analyze_html("<html><body><h1>Bonjour</h1></body></html>")
    assert not [f for f in findings if f.severity == "critical"]
