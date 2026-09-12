"""Security decision and evidence contracts."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Evidence(BaseModel):
    evidence_id: str
    signal: str
    points: int
    text: str
    source: str


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    evidence: list[Evidence] = Field(default_factory=list)


class SecurityDecision(BaseModel):
    decision: Decision
    risk: RiskAssessment
    reasons: list[str] = Field(default_factory=list)
    policy_version: str = "v1"
    required_approval: bool = False


class AuditEvent(BaseModel):
    event_id: str
    event_type: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)
    run_id: str = ""
    timestamp: str = ""
