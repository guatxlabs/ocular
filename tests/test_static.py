# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
import time

from engine.static import PATTERNS, analyze_html
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


def test_french_urgency_language_detected():
    # Couverture FR du langage d'urgence : rejoint le cluster _URGENCY via les
    # MÊMES rule names que l'anglais.
    assert "Account suspended text" in {
        f.rule for f in analyze_html("<p>Votre compte a été suspendu.</p>")
    }
    assert "Account verification text" in {
        f.rule for f in analyze_html("<p>Veuillez vérifier votre compte.</p>")
    }
    assert "Identity confirmation text" in {
        f.rule for f in analyze_html("<p>Confirmez votre identité.</p>")
    }
    assert "Payment update text" in {
        f.rule for f in analyze_html("<p>Merci de mettre à jour votre paiement.</p>")
    }


def test_spanish_urgency_language_detected():
    # Couverture ES du langage d'urgence : rejoint le cluster _URGENCY via les
    # MÊMES rule names que l'anglais/le français.
    assert "Account suspended text" in {
        f.rule for f in analyze_html("<p>Su cuenta será suspendida.</p>")
    }
    assert "Account verification text" in {
        f.rule for f in analyze_html("<p>Por favor verifique su cuenta.</p>")
    }
    assert "Identity confirmation text" in {
        f.rule for f in analyze_html("<p>Confirme su identidad ahora.</p>")
    }
    assert "Payment update text" in {
        f.rule for f in analyze_html("<p>Debe actualizar su pago.</p>")
    }


def test_german_urgency_language_detected():
    assert "Account suspended text" in {
        f.rule for f in analyze_html("<p>Ihr Konto wurde gesperrt.</p>")
    }
    assert "Account verification text" in {
        f.rule for f in analyze_html("<p>Bitte verifizieren Sie Ihr Konto.</p>")
    }
    assert "Identity confirmation text" in {
        f.rule for f in analyze_html("<p>Bestätigen Sie Ihre Identität.</p>")
    }
    assert "Payment update text" in {
        f.rule for f in analyze_html("<p>Bitte aktualisieren Sie Ihre Zahlung.</p>")
    }


def test_portuguese_urgency_language_detected():
    assert "Account suspended text" in {
        f.rule for f in analyze_html("<p>Sua conta será suspensa.</p>")
    }
    assert "Account verification text" in {
        f.rule for f in analyze_html("<p>Por favor verifique sua conta.</p>")
    }
    assert "Identity confirmation text" in {
        f.rule for f in analyze_html("<p>Confirme sua identidade.</p>")
    }
    assert "Payment update text" in {
        f.rule for f in analyze_html("<p>Atualize seu pagamento.</p>")
    }


def test_multilingual_urgency_no_false_positive_on_benign_text():
    # Les mots-clés isolés (compte/cuenta/konto/conta) sont trop courants pour
    # être des signaux à eux seuls -> exige une collocation avec un mot
    # d'urgence pour déclencher.
    benign_samples = [
        "<p>Create your account to get started.</p>",  # EN
        "<p>Voici mon compte bancaire habituel.</p>",  # FR
        "<p>Revise su cuenta de correo semanalmente.</p>",  # ES
        "<p>Mein Konto zeigt den aktuellen Kontostand.</p>",  # DE
        "<p>Acesse sua conta de usuário no site.</p>",  # PT
    ]
    for html in benign_samples:
        rules = {f.rule for f in analyze_html(html)}
        assert not (rules & {
            "Account verification text",
            "Identity confirmation text",
            "Payment update text",
            "Account suspended text",
        }), f"false positive urgency match on: {html!r} -> {rules}"


def test_urgency_patterns_are_redos_safe():
    import re
    # DEUX entrées adversariales : l'une cible les variantes non-EN (mots séparés
    # d'espaces), l'AUTRE cible spécifiquement les patterns EN via le mot-clé de
    # tête RÉPÉTÉ sans terminateur (`verify`×k) — c'est ce cas qui faisait
    # exploser l'ancien `verify.*account` non borné (audit sécu 3k, mesuré 38s).
    # Bornés `.{0,20}` -> tout doit rester bien sous 0.5s.
    adversarials = [
        "verificacion cuenta " * 5000 + "x" * 5000,
        "verify" * 40000,          # cible verify.{0,20}account (ex-ReDoS EN)
        "confirm" * 40000,
        "update" * 40000,
        "suspended" * 40000,
    ]
    urgency_patterns = [
        (rx, desc, sev) for rx, desc, sev in PATTERNS
        if desc in {
            "Account verification text",
            "Identity confirmation text",
            "Payment update text",
            "Account suspended text",
        }
    ]
    for pattern, _desc, _sev in urgency_patterns:
        compiled = re.compile(pattern, re.IGNORECASE)
        for adversarial in adversarials:
            start = time.monotonic()
            compiled.findall(adversarial)
            elapsed = time.monotonic() - start
            assert elapsed < 0.5, f"pattern too slow (possible ReDoS): {pattern!r} took {elapsed}s"


def test_settimeout_string_is_high():
    # Exécution de code par chaîne = signal fort (comme eval), pas medium.
    findings = analyze_html('<script>setTimeout("evil()", 100)</script>')
    by_rule = {f.rule: f.severity for f in findings}
    assert by_rule.get("Delayed code execution") == "high"


def test_setinterval_string_is_high():
    findings = analyze_html('<script>setInterval("evil()", 100)</script>')
    by_rule = {f.rule: f.severity for f in findings}
    assert by_rule.get("Repeated code execution") == "high"


# --- Phase 3j : extraction structurée formulaires + mailto -------------------
from engine.static import extract_forms, extract_mailtos  # noqa: E402


def test_extract_forms_action_and_method():
    html = (
        '<form action="https://evil.example/collect" method="POST"></form>'
        '<form></form>'
        '<form action="/local" method="get"></form>'
    )
    forms = extract_forms(html)
    assert forms[0] == {"action": "https://evil.example/collect", "method": "POST"}
    assert forms[1] == {"action": "", "method": "GET"}          # défauts : action vide, GET
    assert forms[2] == {"action": "/local", "method": "GET"}    # méthode normalisée en MAJ


def test_extract_mailtos_from_links_and_forms_dedup():
    html = (
        '<a href="mailto:drop@evil.test">x</a>'
        '<form action="mailto:drop@evil.test"></form>'   # doublon -> une seule entrée
        '<a href="mailto:other@evil.test?subject=hi">y</a>'
    )
    m = extract_mailtos(html)
    assert m == ["mailto:drop@evil.test", "mailto:other@evil.test?subject=hi"]


def test_extract_forms_bounded():
    html = '<form action="/x"></form>' * 500
    assert len(extract_forms(html)) == 100  # borné anti-DoS


def test_extract_no_forms_no_mailtos_is_empty():
    assert extract_forms("<div>rien</div>") == []
    assert extract_mailtos("<div>rien</div>") == []
