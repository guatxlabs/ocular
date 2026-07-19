# SPDX-FileCopyrightText: 2026 guatx
# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import re

from engine.result import Severity, StaticFinding

# (pattern, description, severity) — porté de malware-html-sandbox/secure_analyzer/main.py
PATTERNS: list[tuple[str, str, Severity]] = [
    # Malicious redirection: not explicitly listed in the Phase 3d-2j re-tier
    # table, but structurally identical to its siblings "Forced URL change" /
    # "Forced navigation" (also plain navigation signals) -> tiered "low" too.
    (r"window\.location\s*[=.].{0,80}?[\"']([^\"']+)[\"']", "Malicious redirection", "low"),
    (r"location\.href\s*=\s*[\"']([^\"']+)[\"']", "Forced URL change", "low"),
    (r"document\.location\s*=\s*[\"']([^\"']+)[\"']", "Forced navigation", "low"),
    (r"eval\s*\(\s*([^)]+)\)", "Dynamic code evaluation", "high"),
    (r"Function\s*\(\s*[\"']([^\"']*)[\"']", "Dynamic function creation", "high"),
    # setTimeout/setInterval avec une chaîne = exécution de code par chaîne
    # (équivalent d'un eval différé) -> signal fort "high", et membres de _OBF
    # côté verdict (cf. engine/verdict.py).
    (r"setTimeout\s*\(\s*[\"']([^\"']+)[\"']", "Delayed code execution", "high"),
    (r"setInterval\s*\(\s*[\"']([^\"']+)[\"']", "Repeated code execution", "high"),
    (r"document\.write\s*\(\s*([^)]+)\)", "Direct DOM write", "medium"),
    (r"innerHTML\s*=\s*([^;]+)", "HTML injection", "low"),
    (r"outerHTML\s*=\s*([^;]+)", "Complete HTML replacement", "low"),
    (r"fetch\s*\(\s*[\"']([^\"']+)[\"']", "Fetch request", "low"),
    (r"XMLHttpRequest\s*\(\s*\)", "AJAX request", "low"),
    (r"\.submit\s*\(\s*\)", "Form submission", "low"),
    (r"<form[^>]*action\s*=\s*[\"']([^\"']+)[\"']", "Form action URL", "low"),
    (r"<form[^>]*action\s*=\s*[\"']https?://[^\"']+[\"']", "External form action", "medium"),
    (r"<form[^>]*method\s*=\s*[\"']post[\"']", "POST form detected", "low"),
    (r"<img[^>]*src\s*=\s*[\"']https?://([^\"']+)[\"']", "External image", "medium"),
    (r"<script[^>]*src\s*=\s*[\"']https?://([^\"']+)[\"']", "External script", "medium"),
    (r"document\.cookie", "Cookie access", "low"),
    (r"localStorage\.getItem\s*\(\s*[\"']([^\"']+)[\"']", "Local storage read", "low"),
    (r"sessionStorage\.getItem\s*\(\s*[\"']([^\"']+)[\"']", "Session storage read", "low"),
    (r"localStorage\.setItem\s*\(\s*[\"']([^\"']+)[\"']", "Local storage write", "low"),
    (r"navigator\.userAgent", "Browser detection", "low"),
    (r"navigator\.platform", "OS detection", "low"),
    (r"screen\.width|screen\.height", "Resolution detection", "low"),
    (r"navigator\.language", "Language detection", "low"),
    (r"on(?:click|load|error|focus|blur|submit)\s*=\s*[\"']([^\"']+)[\"']", "Event handler", "low"),
    (r"addEventListener\s*\(\s*[\"']([^\"']+)[\"']", "Event listener", "low"),
    (r"onsubmit\s*=", "Form submit handler", "low"),
    (r"oncopy\s*=\s*[\"']return\s+false[\"']", "Copy disabled", "low"),
    (r"onpaste\s*=", "Paste handler", "low"),
    # Iframe/object/embed restent "medium" (pas "high") : les embeds tiers
    # (YouTube, maps, widgets, pubs) sont extrêmement courants sur des pages
    # légitimes -> choix anti-faux-positif assumé.
    (r"<iframe[^>]*src\s*=\s*[\"']([^\"']+)[\"']", "Embedded iframe", "medium"),
    (r"<object[^>]*data\s*=\s*[\"']([^\"']+)[\"']", "Embedded object", "medium"),
    (r"<embed[^>]*src\s*=\s*[\"']([^\"']+)[\"']", "Embedded content", "medium"),
    (r"atob\s*\(\s*[\"']([^\"']+)[\"']", "Base64 decode", "medium"),
    (r"atob\s*\(", "Base64 decoding function", "low"),
    (r"btoa\s*\(\s*([^)]+)\)", "Base64 encode", "low"),
    (r"unescape\s*\(\s*[\"']([^\"']+)[\"']", "URL decode", "medium"),
    (r"String\.fromCharCode\s*\(([^)]+)\)", "String construction", "medium"),
    (r"charCodeAt\s*\(", "Character code access", "low"),
    (r"<input[^>]*type\s*=\s*[\"']password[\"']", "Password input field", "low"),
    (r"<input[^>]*name\s*=\s*[\"']pass", "Password field (name)", "low"),
    (r"<input[^>]*name\s*=\s*[\"']email", "Email input field", "low"),
    (r"<input[^>]*name\s*=\s*[\"']user", "Username input field", "low"),
    # Langage d'urgence (phishing) — couverture EN + FR + ES + DE + PT. Tous les
    # patterns non-EN sont mappés sur les MÊMES `rule` names que l'anglais pour
    # rejoindre le cluster _URGENCY côté verdict (cf. engine/verdict.py).
    # Quantificateurs bornés `.{0,20}` (pas d'imbrication) -> ReDoS-safe.
    # Collocations mot-clé+proximité (pas de mot isolé trop courant type
    # compte/cuenta/konto/conta) -> anti-faux-positif.
    # Quantificateurs BORNÉS `.{0,20}` comme les variantes non-EN ci-dessous :
    # un `.*` glouton non borné ici est un ReDoS quadratique (audit sécu 3k) —
    # `verify`×k pinnait un cœur broker plusieurs dizaines de secondes.
    (r"verify.{0,20}account", "Account verification text", "medium"),
    (r"confirm.{0,20}identity", "Identity confirmation text", "medium"),
    (r"update.{0,20}payment", "Payment update text", "medium"),
    (r"suspended.{0,20}account", "Account suspended text", "medium"),
    (r"v[eé]rifi.{0,25}(compte|identit)", "Account verification text", "medium"),
    (r"confirm.{0,25}(identit|compte)", "Identity confirmation text", "medium"),
    (r"(mett|mise).{0,20}jour.{0,20}paiement", "Payment update text", "medium"),
    (r"compte.{0,20}(suspendu|bloqu[eé]|d[eé]sactiv)", "Account suspended text", "medium"),
    # ES — le radical "verific" ne couvre pas la forme "verifique" (c -> qu
    # devant e en espagnol) -> alternance des deux radicaux.
    (r"(?:verific|verifiqu).{0,25}cuenta", "Account verification text", "medium"),
    (r"confirm.{0,25}(identidad|cuenta)", "Identity confirmation text", "medium"),
    (r"actualiz.{0,25}pago", "Payment update text", "medium"),
    (r"cuenta.{0,20}(suspendid|bloquead|desactivad)", "Account suspended text", "medium"),
    # DE — l'allemand place souvent le verbe avant l'objet ("Bitte
    # verifizieren Sie Ihr Konto" / "Bestätigen Sie Ihre Identität") ->
    # alternance des deux ordres, toujours avec écarts bornés `.{0,20}`.
    (
        r"(?:konto|zugang).{0,20}(?:verifizier|best[aä]tig)\w{0,15}"
        r"|(?:verifizier|best[aä]tig).{0,25}(?:konto|zugang)",
        "Account verification text",
        "medium",
    ),
    (
        r"identit[aä]t.{0,20}best[aä]tig\w{0,15}|best[aä]tig.{0,25}identit[aä]t",
        "Identity confirmation text",
        "medium",
    ),
    (
        r"zahlung.{0,25}aktualisier\w{0,15}|aktualisier.{0,25}zahlung",
        "Payment update text",
        "medium",
    ),
    (r"konto.{0,20}(gesperrt|deaktiviert|suspendier)", "Account suspended text", "medium"),
    # PT — même remarque qu'en ES ("verifique" via c -> qu).
    (r"(?:verific|verifiqu).{0,25}conta", "Account verification text", "medium"),
    (r"confirm.{0,25}(identidade|conta)", "Identity confirmation text", "medium"),
    (r"atualiz.{0,25}pagamento", "Payment update text", "medium"),
    (r"conta.{0,20}(suspens|bloquead|desativ)", "Account suspended text", "medium"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), d, s) for p, d, s in PATTERNS]


def analyze_html(html: str) -> list[StaticFinding]:
    findings: list[StaticFinding] = []
    for rx, description, severity in _COMPILED:
        for m in rx.finditer(html):
            line = html.count("\n", 0, m.start()) + 1
            start = max(0, m.start() - 30)
            findings.append(
                StaticFinding(
                    rule=description,
                    severity=severity,
                    match=m.group(0)[:200],
                    line=line,
                    context=html[start : m.end() + 30].replace("\n", " ")[:200],
                )
            )
    return findings


# --- extraction structurée formulaires + mailto (Phase 3j) ---------------------
# Où atterrit la saisie utilisateur d'une page : c'est l'indicateur d'exfiltration
# le plus direct d'un kit de phishing. On expose, pour l'analyste, l'action de
# CHAQUE formulaire (méthode + destination — un POST vers un domaine tiers ou un
# mailto trahit un harvester) et TOUTES les cibles mailto de la page. Tout est
# borné (anti-DoS) et purement regex (pas de dépendance parseur ; même style que
# le reste du module). Partagé par les 4 tiers (analyse HTML, capture, scripté,
# interactif) via le remplissage de `DomInfo.forms` / `DomInfo.mailtos`.
_MAX_FORMS = 100
_MAX_MAILTOS = 100
_FORM_TAG_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_ACTION_RE = re.compile(r"\baction\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
_METHOD_RE = re.compile(r"\bmethod\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)
_MAILTO_RE = re.compile(r"(?:href|action)\s*=\s*[\"']\s*(mailto:[^\"']+)[\"']", re.IGNORECASE)


def extract_forms(html: str) -> list[dict]:
    """Liste `[{action, method}]` des formulaires (méthode en MAJUSCULES, GET par
    défaut ; action vide = soumission vers l'URL courante = auto-post). Borné."""
    forms: list[dict] = []
    for m in _FORM_TAG_RE.finditer(html):
        tag = m.group(0)
        am = _ACTION_RE.search(tag)
        mm = _METHOD_RE.search(tag)
        action = (am.group(1).strip() if am else "")[:500]
        method = (mm.group(1).strip().upper() if mm and mm.group(1).strip() else "GET")[:16]
        forms.append({"action": action, "method": method})
        if len(forms) >= _MAX_FORMS:
            break
    return forms


def extract_mailtos(html: str) -> list[str]:
    """Cibles `mailto:` uniques (liens ET actions de formulaire), ordre stable, bornées."""
    seen: list[str] = []
    for m in _MAILTO_RE.finditer(html):
        val = m.group(1).strip()[:320]
        if val not in seen:
            seen.append(val)
            if len(seen) >= _MAX_MAILTOS:
                break
    return seen
