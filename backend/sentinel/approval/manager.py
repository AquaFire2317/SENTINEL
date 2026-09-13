"""Authoritative human approval workflow.

When SENTINEL issues an ESCALATE decision, the tool does not execute.
This module tracks the pending escalation and, if a human approves it,
mints a fresh ExecutionPermit and executes the tool through the existing
security boundary.

The approval itself flows through the backend, not the UI. A forged
``approve=true`` from a modified client has no effect: the PolicyEngine
remains the sole authority for minting ExecutionPermits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from sentinel.contracts.procurement import ToolCall
from sentinel.contracts.security import RiskAssessment
from sentinel.security.policy import PolicyEngine
from sentinel.tools.procurement import ProcurementTools


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ApprovalRecord:
    approval_id: str
    tool_name: str
    arguments: dict[str, Any]
    risk_score: int
    risk_level: str
    reasons: list[str]
    status: ApprovalStatus = ApprovalStatus.PENDING
    operator: str | None = None
    decided_at: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class ApprovalManager:
    """Tracks ESCALATE decisions and processes human approval/rejection.

    Security design:
    - Approval is processed through the backend, not the UI.
    - ``approve()`` mints a fresh ExecutionPermit via PolicyEngine.
    - The UI cannot bypass the PolicyEngine by sending ``approve=true``.
    """

    def __init__(self, tools: ProcurementTools, policy: PolicyEngine):
        self.tools = tools
        self.policy = policy
        self._pending: dict[str, ApprovalRecord] = {}
        self._records: dict[str, ApprovalRecord] = {}

    def record_escalation(
        self,
        call: ToolCall,
        risk: RiskAssessment,
        reasons: list[str],
    ) -> ApprovalRecord:
        """Record an ESCALATE decision for future human approval."""
        record = ApprovalRecord(
            approval_id=f"approval-{uuid4().hex[:12]}",
            tool_name=call.tool_name,
            arguments=dict(call.input),
            risk_score=risk.score,
            risk_level=risk.level.value if hasattr(risk.level, "value") else str(risk.level),
            reasons=reasons,
        )
        self._pending[record.approval_id] = record
        self._records[record.approval_id] = record
        return record

    def pending(self) -> list[ApprovalRecord]:
        """Return all pending approval records."""
        return [r for r in self._pending.values()]

    def approve(self, approval_id: str, operator: str = "human") -> dict[str, Any] | None:
        """Approve a pending escalation.

        Executes the tool through the security boundary (PolicyEngine + ExecutionPermit)
        and returns the tool result data. Returns None if the approval_id is not pending.
        """
        record = self._pending.pop(approval_id, None)
        if record is None or record.status != ApprovalStatus.PENDING:
            return None

        record.status = ApprovalStatus.APPROVED
        record.operator = operator
        record.decided_at = datetime.now(UTC).isoformat()

        # Mint a fresh ExecutionPermit through the authoritative PolicyEngine.
        call = ToolCall(
            call_id=f"approval-{record.approval_id}",
            tool_name=record.tool_name,
            input=record.arguments,
            source="human_approval",
        )
        permit = self.policy._mint_permit(call)
        result = self.tools.call(record.tool_name, record.arguments, permit=permit)
        return result.data

    def reject(self, approval_id: str, operator: str = "human") -> bool:
        """Reject a pending escalation. Returns True if found and rejected."""
        record = self._pending.pop(approval_id, None)
        if record is None or record.status != ApprovalStatus.PENDING:
            return False

        record.status = ApprovalStatus.REJECTED
        record.operator = operator
        record.decided_at = datetime.now(UTC).isoformat()
        return True

    def get_record(self, approval_id: str) -> ApprovalRecord | None:
        return self._records.get(approval_id)
