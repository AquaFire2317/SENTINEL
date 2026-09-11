"""Contracts for attack, mitigation, retest, and regression workflows."""

from typing import Any

from pydantic import BaseModel, Field

from sentinel.contracts.security import AuditEvent


class AttackScenario(BaseModel):
    scenario_id: str
    name: str
    input: str
    attack_type: str
    fixture_version: str = "v1"
    forbidden_tools: list[str] = Field(default_factory=list)
    must_detect: bool = True


class Mitigation(BaseModel):
    mitigation_id: str
    version: str
    title: str
    rules: list[str]
    applied: bool = False


class RetestResult(BaseModel):
    status: str
    detected: bool
    forbidden_actions_executed: list[str] = Field(default_factory=list)
    mitigation_effective: bool
    observations: list[dict[str, Any]] = Field(default_factory=list)


class EvaluationReport(BaseModel):
    run_id: str
    scenario_id: str
    attack_detected: bool
    risk_score: int
    risk_level: str
    decision: str
    explanation: str
    mitigation: Mitigation
    retest: RetestResult
    regression_added: bool
    security_score: int
    audit: list[AuditEvent] = Field(default_factory=list)
