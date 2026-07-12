from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class JobRequest(BaseModel):
    profile: str
    html: Optional[str] = None
    url: Optional[str] = None


class JobResponse(BaseModel):
    job_id: str
