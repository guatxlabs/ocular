# SPDX-FileCopyrightText: 2026 GuatX
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from engine.result import StaticFinding, Verdict

# clusters de règles (par `rule`)
# _OBF inclut les exécutions de code par chaîne (setTimeout/setInterval string),
# équivalentes à eval : eval + setTimeout("code") -> cluster >=2 -> malicious.
_OBF = {"Dynamic code evaluation", "Dynamic function creation", "Base64 decode",
        "URL decode", "String construction", "Direct DOM write",
        "Delayed code execution", "Repeated code execution"}
_CRED = {"Password input field", "Password field (name)",
         "Email input field", "Username input field"}
_URGENCY = {"Account verification text", "Identity confirmation text",
            "Payment update text", "Account suspended text"}


def compute_verdict(findings: list[StaticFinding]) -> Verdict:
    rules = {f.rule for f in findings}
    sev = {f.severity for f in findings}
    obf = _OBF & rules
    cred = bool(_CRED & rules)
    urgency = bool(_URGENCY & rules)
    ext_form = "External form action" in rules

    # 1. Menace forte / corroborée -> malicious
    # Branche défensive : aucun pattern de engine/static.py n'émet "critical"
    # aujourd'hui (re-tier 3d-J) ; garde-fou si un futur détecteur en émet.
    if "critical" in sev:
        return "malicious"
    if len(obf) >= 2:                       # cluster obfuscation/exécution
        return "malicious"
    if cred and urgency and ext_form:       # kit phishing complet
        return "malicious"

    # 2. Faisceau d'indices -> suspicious
    if cred and urgency:                    # collecte de credentials + langage d'urgence
        return "suspicious"
    if cred and ext_form:                   # credentials postés vers un domaine externe
        # signal fort quelle que soit la langue ; reste suspicious (pas
        # malicious) car un OAuth/SSO légitime poste aussi en externe.
        return "suspicious"
    if "high" in sev:                       # un eval/Function/setTimeout string isolé
        return "suspicious"
    if obf and (cred or ext_form):          # obfuscation + collecte/form externe
        return "suspicious"

    # 3. Sinon
    return "benign"
