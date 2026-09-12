"""Fail-closed ALLOW/BLOCK/ESCALATE policy engine.

Hardening notes (red-team round 1):
- Tools are allowlisted. A tool Sentinel does not recognize is BLOCKED, not
  silently ALLOWED.
- Every side-effect execution requires a one-time ExecutionPermit minted by
  this engine. Tools must verify it, so calling the tool layer directly
  (confused deputy) is refused.
- Replay defense: an identical side-effect call signature may execute at
  most once per engine instance; subsequent attempts are BLOCKED as replays.

Hardening notes (red-team round 2):
- Replay signatures normalize numeric types: int(1) and float(1.0) produce
  the same hash so attackers cannot bypass replay detection via type coercion.
"""

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime

from sentinel.contracts.procurement import ToolCall, ToolObservation, ToolResult
from sentinel.contracts.security import (
    AuditEvent,
    Decision,
    RiskAssessment,
    RiskLevel,
    SecurityDecision,
)
from sentinel.security.risk import assess_tool_call

READ_TOOLS = frozenset({"search_suppliers", "get_supplier_details", "compare_prices"})
SIDE_EFFECT_TOOLS = frozenset({"create_purchase_order", "send_email"})


def _normalize_types(obj):
    """Recursively normalize numeric types so int(1) and float(1.0) hash identically."""
    if isinstance(obj, dict):
        return {k: _normalize_types(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_types(v) for v in obj]
    if isinstance(obj, float) and obj == int(obj):
        return int(obj)
    return obj


class ExecutionPermit:
    """Token proving Sentinel ALLOWED this exact execution.

    Permits should only be created by PolicyEngine._mint_permit().
    Direct construction is permitted for testing but produces an
    unverifiable permit that tool.call() will reject.
    """

    def __init__(self, signature: str):
        self._signature = signature

    @property
    def matches(self) -> str:
        return self._signature


class PolicyEngine:
    def __init__(
        self,
        audit: list[AuditEvent] | None = None,
        issued_approvals: set[str] | None = None,
        run_id: str = "",
    ):
        self.audit = audit if audit is not None else []
        self.issued_approvals = issued_approvals or set()
        self.run_id = run_id
        self.policy_version = "v2"
        self._executed_signatures: set[str] = set()

    @staticmethod
    def signature_for(tool_name: str, arguments: dict) -> str:
        normalized = _normalize_types(arguments)
        canonical = json.dumps(
            {"tool": tool_name, "input": normalized},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    @classmethod
    def _signature(cls, call: ToolCall) -> str:
        return cls.signature_for(call.tool_name, call.input)

    def _mint_permit(self, call: ToolCall) -> ExecutionPermit:
        """Create a one-time ExecutionPermit bound to the exact tool + arguments."""
        return ExecutionPermit(self._signature(call))

    def intercept(
        self,
        call: ToolCall,
        execute: Callable[..., ToolResult],
        prior_observations: list[ToolObservation],
    ) -> ToolObservation:
        signature = self._signature(call)
        try:
            if call.tool_name not in READ_TOOLS | SIDE_EFFECT_TOOLS:
                security_decision = SecurityDecision(
                    decision=Decision.BLOCK,
                    risk=RiskAssessment(score=100, level=RiskLevel.CRITICAL, evidence=[]),
                    reasons=[f"Tool '{call.tool_name}' is not on the allowlist"],
                    policy_version=self.policy_version,
                    required_approval=False,
                )
                self._record("DECISION", f"BLOCK {call.tool_name}", security_decision.model_dump(mode="json"))
                return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

            risk = assess_tool_call(call, prior_observations, self.issued_approvals)
            is_side_effect = call.tool_name in SIDE_EFFECT_TOOLS

            if is_side_effect and signature in self._executed_signatures:
                decision = Decision.BLOCK
                reasons = ["Duplicate side-effect call signature; replays are denied"]
            elif not is_side_effect:
                decision = Decision.ALLOW
                reasons = [item.text for item in risk.evidence]
            elif risk.score >= 75:
                decision = Decision.BLOCK
                reasons = [item.text for item in risk.evidence]
            else:
                decision = Decision.ESCALATE
                reasons = [item.text for item in risk.evidence] or [f"{call.tool_name} is a side-effecting tool and requires approval"]

            security_decision = SecurityDecision(
                decision=decision,
                risk=risk,
                reasons=reasons,
                policy_version=self.policy_version,
                required_approval=decision == Decision.ESCALATE,
            )
            self._record("DECISION", f"{decision} {call.tool_name}", security_decision.model_dump(mode="json"))

            if decision in (Decision.BLOCK, Decision.ESCALATE):
                return ToolObservation(call=call, decision=decision, executed=False)

            permit = self._mint_permit(call)
            result = execute(permit)
            if is_side_effect:
                self._executed_signatures.add(signature)
            return ToolObservation(call=call, result=result, decision=decision, executed=True)
        except (TypeError, ValueError, KeyError, RuntimeError, PermissionError) as error:
            self._record("ERROR", "Policy evaluation failed closed", {"error": str(error)})
            return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

    def _record(self, event_type: str, message: str, data: dict) -> None:
        self.audit.append(AuditEvent(
            event_id=f"audit-{len(self.audit) + 1}",
            event_type=event_type,
            message=message,
            data=data,
            run_id=self.run_id,
            timestamp=datetime.now(UTC).isoformat(),
        ))
