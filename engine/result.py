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


class DomInfo(BaseModel):
    title: str = ""
    final_url: str = ""
    redirect_chain: list[str] = Field(default_factory=list)
    forms: list[dict] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)


class StealthInfo(BaseModel):
    engine: Literal["camoufox", "chromium"]
    turnstile_solved: bool = False
    challenge: Optional[str] = None


class Artifacts(BaseModel):
    har_ref: Optional[str] = None
    dom_html_ref: Optional[str] = None


class OcularResult(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    job_id: str
    profile: Profile
    target: str
    timestamp: str
    verdict: Verdict = "unknown"
    screenshots: list[Screenshot] = Field(default_factory=list)
    network: list[NetworkEntry] = Field(default_factory=list)
    console: list[ConsoleEntry] = Field(default_factory=list)
    dom: DomInfo = Field(default_factory=DomInfo)
    static_findings: list[StaticFinding] = Field(default_factory=list)
    dynamic_steps: list[DynamicStep] = Field(default_factory=list)
    stealth: Optional[StealthInfo] = None
    artifacts: Artifacts = Field(default_factory=Artifacts)
