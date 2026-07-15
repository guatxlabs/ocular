from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class JobRequest(BaseModel):
    profile: Literal["analysis", "capture"] = "analysis"
    html: Optional[str] = None
    url: Optional[str] = Field(default=None, max_length=2048)
    steps: Optional[list] = None


class JobResponse(BaseModel):
    job_id: str


class SessionRequest(BaseModel):
    url: Optional[str] = Field(default=None, max_length=2048)
    html: Optional[str] = None


class SessionResponse(BaseModel):
    session_id: str
    token: str


class AnalystVerdictRequest(BaseModel):
    analyst_verdict: str
    note: Optional[str] = None
