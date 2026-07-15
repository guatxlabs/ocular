from __future__ import annotations

import re

from engine.result import Severity, StaticFinding

# (pattern, description, severity) — porté de malware-html-sandbox/secure_analyzer/main.py
PATTERNS: list[tuple[str, str, Severity]] = [
    # Malicious redirection: not explicitly listed in the Phase 3d-2j re-tier
    # table, but structurally identical to its siblings "Forced URL change" /
    # "Forced navigation" (also plain navigation signals) -> tiered "low" too.
    (r"window\.location\s*[=.].*?[\"']([^\"']+)[\"']", "Malicious redirection", "low"),
    (r"location\.href\s*=\s*[\"']([^\"']+)[\"']", "Forced URL change", "low"),
    (r"document\.location\s*=\s*[\"']([^\"']+)[\"']", "Forced navigation", "low"),
    (r"eval\s*\(\s*([^)]+)\)", "Dynamic code evaluation", "high"),
    (r"Function\s*\(\s*[\"']([^\"']*)[\"']", "Dynamic function creation", "high"),
    (r"setTimeout\s*\(\s*[\"']([^\"']+)[\"']", "Delayed code execution", "medium"),
    (r"setInterval\s*\(\s*[\"']([^\"']+)[\"']", "Repeated code execution", "medium"),
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
    (r"verify.*account", "Account verification text", "medium"),
    (r"confirm.*identity", "Identity confirmation text", "medium"),
    (r"update.*payment", "Payment update text", "medium"),
    (r"suspended.*account", "Account suspended text", "medium"),
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
