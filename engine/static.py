from __future__ import annotations

import re

from engine.result import Severity, StaticFinding

# (pattern, description, severity) — porté de malware-html-sandbox/secure_analyzer/main.py
PATTERNS: list[tuple[str, str, Severity]] = [
    (r"window\.location\s*[=.].*?[\"']([^\"']+)[\"']", "Malicious redirection", "critical"),
    (r"location\.href\s*=\s*[\"']([^\"']+)[\"']", "Forced URL change", "critical"),
    (r"document\.location\s*=\s*[\"']([^\"']+)[\"']", "Forced navigation", "critical"),
    (r"eval\s*\(\s*([^)]+)\)", "Dynamic code evaluation", "critical"),
    (r"Function\s*\(\s*[\"']([^\"']*)[\"']", "Dynamic function creation", "critical"),
    (r"setTimeout\s*\(\s*[\"']([^\"']+)[\"']", "Delayed code execution", "high"),
    (r"setInterval\s*\(\s*[\"']([^\"']+)[\"']", "Repeated code execution", "high"),
    (r"document\.write\s*\(\s*([^)]+)\)", "Direct DOM write", "high"),
    (r"innerHTML\s*=\s*([^;]+)", "HTML injection", "high"),
    (r"outerHTML\s*=\s*([^;]+)", "Complete HTML replacement", "high"),
    (r"fetch\s*\(\s*[\"']([^\"']+)[\"']", "Fetch request", "high"),
    (r"XMLHttpRequest\s*\(\s*\)", "AJAX request", "high"),
    (r"\.submit\s*\(\s*\)", "Form submission", "critical"),
    (r"<form[^>]*action\s*=\s*[\"']([^\"']+)[\"']", "Form action URL", "critical"),
    (r"<form[^>]*method\s*=\s*[\"']post[\"']", "POST form detected", "critical"),
    (r"<img[^>]*src\s*=\s*[\"']https?://([^\"']+)[\"']", "External image", "medium"),
    (r"<script[^>]*src\s*=\s*[\"']https?://([^\"']+)[\"']", "External script", "critical"),
    (r"document\.cookie", "Cookie access", "high"),
    (r"localStorage\.getItem\s*\(\s*[\"']([^\"']+)[\"']", "Local storage read", "medium"),
    (r"navigator\.userAgent", "Browser detection", "medium"),
    (r"on(?:click|load|error|focus|blur|submit)\s*=\s*[\"']([^\"']+)[\"']", "Event handler", "medium"),
    (r"onsubmit\s*=", "Form submit handler", "critical"),
    (r"<iframe[^>]*src\s*=\s*[\"']([^\"']+)[\"']", "Embedded iframe", "high"),
    (r"<object[^>]*data\s*=\s*[\"']([^\"']+)[\"']", "Embedded object", "high"),
    (r"<embed[^>]*src\s*=\s*[\"']([^\"']+)[\"']", "Embedded content", "high"),
    (r"atob\s*\(\s*[\"']([^\"']+)[\"']", "Base64 decode", "critical"),
    (r"atob\s*\(", "Base64 decoding function", "high"),
    (r"unescape\s*\(\s*[\"']([^\"']+)[\"']", "URL decode", "medium"),
    (r"String\.fromCharCode\s*\(([^)]+)\)", "String construction", "high"),
    (r"<input[^>]*type\s*=\s*[\"']password[\"']", "Password input field", "critical"),
    (r"<input[^>]*name\s*=\s*[\"']pass", "Password field (name)", "critical"),
    (r"<input[^>]*name\s*=\s*[\"']email", "Email input field", "high"),
    (r"<input[^>]*name\s*=\s*[\"']user", "Username input field", "high"),
    (r"verify.*account", "Account verification text", "high"),
    (r"suspended.*account", "Account suspended text", "high"),
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
