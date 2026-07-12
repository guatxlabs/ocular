from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel


class JobRequest(BaseModel):
    profile: Literal["analysis"] = "analysis"
    html: Optional[str] = None
    url: Optional[str] = None


class JobResponse(BaseModel):
    job_id: str
