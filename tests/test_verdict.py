# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
from engine.result import StaticFinding
from engine.verdict import compute_verdict


def _f(sev):
    return StaticFinding(rule="r", severity=sev, match="m", line=1, context="c")


def _rf(rule, sev):
    return StaticFinding(rule=rule, severity=sev, match="m", line=1, context="c")


def test_critical_is_malicious():
    assert compute_verdict([_f("low"), _f("critical")]) == "malicious"


def test_high_is_suspicious():
    assert compute_verdict([_f("medium"), _f("high")]) == "suspicious"


def test_only_low_medium_is_benign():
    assert compute_verdict([_f("low"), _f("medium")]) == "benign"


def test_empty_is_benign():
    assert compute_verdict([]) == "benign"


def test_legitimate_login_is_benign():
    # password + email fields, relative form action, POST form — all "low"
    # structural signals in isolation, no credential+urgency+external-form
    # corroboration.
    findings = [
        _rf("Password input field", "low"),
        _rf("Email input field", "low"),
        _rf("Form action URL", "low"),
        _rf("POST form detected", "low"),
    ]
    assert compute_verdict(findings) == "benign"


def test_legitimate_spa_is_benign():
    # fetch + addEventListener + innerHTML= — common SPA plumbing, no
    # obfuscation cluster, no credentials/urgency.
    findings = [
        _rf("Fetch request", "low"),
        _rf("Event listener", "low"),
        _rf("HTML injection", "low"),
    ]
    assert compute_verdict(findings) == "benign"


def test_eval_alone_is_suspicious():
    # A single "high" obfuscation signal isolated — not corroborated but
    # notable enough to flag.
    findings = [_rf("Dynamic code evaluation", "high")]
    assert compute_verdict(findings) == "suspicious"


def test_full_phishing_kit_is_malicious():
    # credentials + urgency language + external form action = corroborated
    # phishing kit.
    findings = [
        _rf("Password input field", "low"),
        _rf("Account verification text", "medium"),
        _rf("External form action", "medium"),
    ]
    assert compute_verdict(findings) == "malicious"


def test_partial_phishing_signal_is_suspicious():
    # credentials + urgency language, but form posts internally (no external
    # form action) — not fully corroborated.
    findings = [
        _rf("Password input field", "low"),
        _rf("Payment update text", "medium"),
        _rf("Form action URL", "low"),
    ]
    assert compute_verdict(findings) == "suspicious"


def test_obfuscated_malware_cluster_is_malicious():
    # eval + atob "..." + String.fromCharCode -> 3 obfuscation/exec rules
    # corroborate each other (>=2 cluster).
    findings = [
        _rf("Dynamic code evaluation", "high"),
        _rf("Base64 decode", "medium"),
        _rf("String construction", "medium"),
    ]
    assert compute_verdict(findings) == "malicious"


def test_external_script_alone_is_benign():
    findings = [_rf("External script", "medium")]
    assert compute_verdict(findings) == "benign"


# --- Audit 3d-J : faux négatifs corrigés ---


def test_bare_harvester_cred_plus_external_form_is_suspicious():
    # Credentials postés vers un domaine externe SANS langage d'urgence : signal
    # fort (harvester minimaliste) qui doit sortir suspicious, plus benign.
    # Reste suspicious (pas malicious) car un OAuth/SSO légitime poste aussi en
    # externe.
    findings = [
        _rf("Password input field", "low"),
        _rf("Email input field", "low"),
        _rf("External form action", "medium"),
    ]
    assert compute_verdict(findings) == "suspicious"


def test_full_phishing_kit_still_malicious_after_bare_rule():
    # cred + urgency + external form -> malicious doit toujours passer AVANT la
    # règle cred+ext_form -> suspicious.
    findings = [
        _rf("Password input field", "low"),
        _rf("Account verification text", "medium"),
        _rf("External form action", "medium"),
    ]
    assert compute_verdict(findings) == "malicious"


def test_settimeout_string_alone_is_suspicious():
    # Exécution de code par chaîne (comme eval) : high isolé -> suspicious.
    findings = [_rf("Delayed code execution", "high")]
    assert compute_verdict(findings) == "suspicious"


def test_settimeout_string_plus_eval_is_malicious():
    # setTimeout("code") est dans _OBF : eval + setTimeout -> cluster >=2 -> malicious.
    findings = [
        _rf("Dynamic code evaluation", "high"),
        _rf("Delayed code execution", "high"),
    ]
    assert compute_verdict(findings) == "malicious"


def test_french_full_phishing_is_malicious():
    # credential + form externe + urgence FR (« compte suspendu ») -> kit complet.
    findings = [
        _rf("Password input field", "low"),
        _rf("External form action", "medium"),
        _rf("Account suspended text", "medium"),
    ]
    assert compute_verdict(findings) == "malicious"


def test_spanish_full_phishing_is_malicious():
    # credential + form externe + urgence ES -> kit complet, cluster multilingue.
    findings = [
        _rf("Password input field", "low"),
        _rf("External form action", "medium"),
        _rf("Account verification text", "medium"),
    ]
    assert compute_verdict(findings) == "malicious"


def test_german_full_phishing_is_malicious():
    findings = [
        _rf("Password input field", "low"),
        _rf("External form action", "medium"),
        _rf("Account suspended text", "medium"),
    ]
    assert compute_verdict(findings) == "malicious"


def test_portuguese_full_phishing_is_malicious():
    findings = [
        _rf("Password input field", "low"),
        _rf("External form action", "medium"),
        _rf("Identity confirmation text", "medium"),
    ]
    assert compute_verdict(findings) == "malicious"


def test_spanish_partial_phishing_signal_is_suspicious():
    # credential + urgence ES, mais pas de form externe -> pas corroboré.
    findings = [
        _rf("Password input field", "low"),
        _rf("Payment update text", "medium"),
        _rf("Form action URL", "low"),
    ]
    assert compute_verdict(findings) == "suspicious"
