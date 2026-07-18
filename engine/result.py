from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low"]
Verdict = Literal["benign", "suspicious", "malicious", "unknown"]
Profile = Literal["capture", "analysis"]


class Screenshot(BaseModel):
    step: int
    phase: str
    image_ref: str
    viewport: str


class NetworkEntry(BaseModel):
    url: str
    method: str
    status: Optional[int] = None
    headers: dict[str, str] = Field(default_factory=dict)
    post_data: Optional[str] = None
    resource_type: Optional[str] = None
    initiator: Optional[str] = None


class ConsoleEntry(BaseModel):
    level: str
    text: str
    location: Optional[str] = None


class StaticFinding(BaseModel):
    rule: str
    severity: Severity
    match: str
    line: int
    context: str


class DynamicStep(BaseModel):
    action: str
    screenshot_ref: Optional[str] = None
    triggered_requests: list[str] = Field(default_factory=list)
    # Champs 3c (mode scripté) : issue d'exécution d'un step rejoué par
    # runner_recon/steps_exec.py::run_steps. Optionnels + valeurs par défaut
    # rétro-compatibles : un `DynamicStep` 3a existant (sans ces champs) reste
    # un payload valide (`ok` défaut à True, les deux autres à None).
    ok: bool = True
    duration_ms: Optional[int] = None
    error: Optional[str] = None


class DomInfo(BaseModel):
    title: str = ""
    final_url: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    forms: list[dict] = Field(default_factory=list)   # [{action, method}] — cf. static.extract_forms
    mailtos: list[str] = Field(default_factory=list)  # cibles mailto: — cf. static.extract_mailtos
    links: list[str] = Field(default_factory=list)


class StealthInfo(BaseModel):
    engine: Literal["camoufox", "chromium"]
    # Tri-état : True = challenge Turnstile résolu ; False = challenge présent
    # mais NON résolu ; None = aucun challenge / non applicable (ex. analyse HTML
    # pure, ou session interactive sans challenge). None n'affiche AUCUN badge
    # « passé/non passé » (cf. saved_store: None -> NULL, UI: badge omis) — évite
    # le faux « Turnstile non passé » sur les captures sans Turnstile.
    turnstile_solved: Optional[bool] = None
    challenge: Optional[str] = None


class TriageSignal(BaseModel):
    key: str
    label: str
    weight: float
    detail: str = ""


class Triage(BaseModel):
    """2e avis natif, parallèle au verdict règles (jamais un écrasement).
    `score` 0-100 = priorité « à regarder » ; sa décomposition intégrale est
    dans `signals` (Σ des weight affichés == score). `weights_version` trace le
    jeu de poids (BUILTIN ou calibré) ayant produit ce score."""
    score: int
    band: Literal["low", "medium", "high"]
    second_opinion: Verdict
    agrees_with_rules: bool
    signals: list[TriageSignal] = Field(default_factory=list)
    weights_version: str


class Artifacts(BaseModel):
    har_ref: Optional[str] = None
    dom_html_ref: Optional[str] = None


class OcularResult(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    job_id: str
    profile: Profile
    target: str
    input_hash: Optional[str] = None
    timestamp: str
    verdict: Verdict = "unknown"
    screenshots: list[Screenshot] = Field(default_factory=list)
    network: list[NetworkEntry] = Field(default_factory=list)
    console: list[ConsoleEntry] = Field(default_factory=list)
    dom: DomInfo = Field(default_factory=DomInfo)
    static_findings: list[StaticFinding] = Field(default_factory=list)
    dynamic_steps: list[DynamicStep] = Field(default_factory=list)
    stealth: Optional[StealthInfo] = None
    triage: Optional[Triage] = None
    artifacts: Artifacts = Field(default_factory=Artifacts)

    @classmethod
    def model_json_schema(cls, *args, **kwargs):
        schema = super().model_json_schema(*args, **kwargs)
        required = set(schema.get("required", []))
        required.add("schema_version")
        schema["required"] = sorted(required)
        return schema
