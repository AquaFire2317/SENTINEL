"""Authoritative human approval workflow.

When SENTINEL issues an ESCALATE decision, the tool does not execute.
This module tracks the pending escalation and, if a human approves it,
executes the tool through PolicyEngine.execute_approved() — the same
authoritative security path used for normal agent actions.

The approval itself flows through the backend, not the UI. A forged
``approve=true`` from a modified client has no effect: the PolicyEngine
remains the sole authority for minting ExecutionPermits and recording
executions.
"""

from __future__ import annotations

import threading
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
    EXECUTED = "executed"


@dataclass
class ApprovalRecord:
    approval_id: str
    run_id: str
    tool_name: str
    arguments: dict[str, Any]
    signature: str
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
    - ``approve()`` calls ``PolicyEngine.execute_approved()`` which mints a
      fresh ExecutionPermit, records the execution signature, and produces
      an audit event with ``authorization_source = HUMAN_APPROVAL``.
    - The UI cannot bypass the PolicyEngine by sending ``approve=true``.
    - An approval is bound to: run_id, tool_name, exact arguments (signature).
    - State machine: PENDING -> APPROVED -> EXECUTED, or PENDING -> REJECTED.
      Invalid transitions (e.g., double-approve) return None/False safely.
    """

    def __init__(self, tools: ProcurementTools, policy: PolicyEngine):
        self.tools = tools
        self.policy = policy
        self._pending: dict[str, ApprovalRecord] = {}
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = threading.Lock()

    def record_escalation(
        self,
        call: ToolCall,
        risk: RiskAssessment,
        reasons: list[str],
    ) -> ApprovalRecord:
        """Record an ESCALATE decision for future human approval."""
        record = ApprovalRecord(
            approval_id=f"approval-{uuid4().hex[:12]}",
            run_id=self.policy.run_id,
            tool_name=call.tool_name,
            arguments=dict(call.input),
            signature=PolicyEngine.signature_for(call.tool_name, call.input),
            risk_score=risk.score,
            risk_level=risk.level.value if hasattr(risk.level, "value") else str(risk.level),
            reasons=reasons,
        )
        with self._lock:
            self._pending[record.approval_id] = record
            self._records[record.approval_id] = record
        return record

    def pending(self) -> list[ApprovalRecord]:
        """Return all pending approval records."""
        with self._lock:
            return list(self._pending.values())

    def approve(self, approval_id: str, operator: str = "human") -> dict[str, Any] | None:
        """Approve a pending escalation.

        Executes the tool through PolicyEngine.execute_approved() — the same
        authoritative path as normal agent actions. Returns the tool result
        data on success, or None if the approval cannot be processed.
        """
        with self._lock:
            record = self._pending.get(approval_id)
            if record is None or record.status != ApprovalStatus.PENDING:
                return None

            if record.run_id != self.policy.run_id:
                self.policy._record(
                    "DECISION",
                    f"BLOCK {record.tool_name}",
                    {
                        "decision": "BLOCK",
                        "authorization_source": "CROSS_RUN_APPROVAL_REJECTED",
                        "tool_name": record.tool_name,
                        "approval_id": record.approval_id,
                        "approval_run_id": record.run_id,
                        "engine_run_id": self.policy.run_id,
                        "policy_version": self.policy.policy_version,
                    },
                )
                return None

            # Transition: PENDING -> APPROVED. Lock held prevents a second
            # approve() from seeing this record as PENDING.
            record.status = ApprovalStatus.APPROVED
            record.operator = operator
            record.decided_at = datetime.now(UTC).isoformat()

        # Release lock before executing (the tool path acquires its own locks).
        call = ToolCall(
            call_id=f"approval-{record.approval_id}",
            tool_name=record.tool_name,
            input=record.arguments,
            source="human_approval",
        )

        def execute_with_permit(permit):
            return self.tools.call(record.tool_name, record.arguments, permit=permit)

        observation = self.policy.execute_approved(call, execute_with_permit)

        with self._lock:
            if observation.executed:
                self._pending.pop(approval_id, None)
                record.status = ApprovalStatus.EXECUTED
                return observation.result.data if observation.result else None

            # Execution failed (replay, validation error, etc.).
            # Move to REJECTED so the zombie state is impossible: PENDING
            # no longer exists, and the next approve()/reject() call returns
            # None/False cleanly.
            self._pending.pop(approval_id, None)
            record.status = ApprovalStatus.REJECTED
            record.operator = "system"
            record.decided_at = datetime.now(UTC).isoformat()
            return None

    def reject(self, approval_id: str, operator: str = "human") -> bool:
        """Reject a pending escalation. Returns True if found and rejected."""
        with self._lock:
            record = self._pending.pop(approval_id, None)
            if record is None or record.status != ApprovalStatus.PENDING:
                return False

            record.status = ApprovalStatus.REJECTED
            record.operator = operator
            record.decided_at = datetime.now(UTC).isoformat()

        self.policy._record(
            "DECISION",
            f"REJECTED {record.tool_name}",
            {
                "decision": "REJECTED",
                "authorization_source": "HUMAN_REJECTION",
                "tool_name": record.tool_name,
                "approval_id": record.approval_id,
                "policy_version": self.policy.policy_version,
            },
        )
        return True

    def get_record(self, approval_id: str) -> ApprovalRecord | None:
        return self._records.get(approval_id)
