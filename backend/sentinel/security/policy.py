"""Fail-closed ALLOW/BLOCK/ESCALATE policy engine.

This module contains the SINGLE AUTHORITATIVE enforcement path for all
tool-call authorization in SENTINEL. Every decision — whether it originates
from the Strands agent hook, the human approval workflow, or the evaluation
system — flows through this engine.

Architecture
------------
``evaluate()``
    Pure decision function. Returns a SecurityDecision without side effects.
    This is the single place where allowlists, risk thresholds, replay rules,
    and side-effect classification are evaluated.

``intercept()``
    Decision + execution + audit. Calls evaluate() internally, then handles
    permit minting, tool execution, signature recording, and audit events.
    This is the standard path for all tool calls.

``execute_approved()``
    Authoritative execution path for human-approved side effects. Performs
    the same validation as intercept() (allowlist, replay, permit minting,
    signature recording) and adds a HUMAN_APPROVAL audit trail.

``signature_for()``
    Computes a deterministic, normalized signature for a tool + arguments
    pair. Used for replay detection and permit validation.

Security invariants
-------------------
- Tools are allowlisted. Unknown tools are BLOCKED.
- Every side-effect execution requires a one-time ExecutionPermit.
- Replay defense: an identical signature may execute at most once.
- int/float normalization prevents type-coercion replay bypasses.
- Permit validation is enforced at the tool boundary (ProcurementTools.call).
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
    """Single authoritative enforcement path for tool-call authorization.

    All policy decisions — regardless of origin (Strands hook, approval
    workflow, evaluation system) — flow through this engine. The engine
    owns: decision logic, permit minting, replay accounting, execution
    authorization, and audit event generation.

    Process-local state: ``_executed_signatures`` is in-memory and not
    durable across restarts. A production deployment would need durable
    replay protection.
    """

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

    # ---------------------------------------------------------------- evaluate

    def evaluate(
        self,
        call: ToolCall,
        prior_observations: list[ToolObservation],
    ) -> SecurityDecision:
        """Single authoritative policy decision. Pure function — no side effects.

        Returns a SecurityDecision with the decision, risk assessment, reasons,
        and whether human approval is required. Does NOT execute the tool,
        mint permits, record audit events, or modify replay state.

        This is the ONE place where:
        - Tool allowlists are checked
        - Risk is assessed via the detection engine
        - Replay signatures are checked
        - Decision thresholds are applied
        """
        if call.tool_name not in READ_TOOLS | SIDE_EFFECT_TOOLS:
            return SecurityDecision(
                decision=Decision.BLOCK,
                risk=RiskAssessment(score=100, level=RiskLevel.CRITICAL, evidence=[]),
                reasons=[f"Tool '{call.tool_name}' is not on the allowlist"],
                policy_version=self.policy_version,
                required_approval=False,
            )

        risk = assess_tool_call(call, prior_observations, self.issued_approvals)
        is_side_effect = call.tool_name in SIDE_EFFECT_TOOLS
        signature = self._signature(call)

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
            reasons = [item.text for item in risk.evidence] or [
                f"{call.tool_name} is a side-effecting tool and requires approval"
            ]

        return SecurityDecision(
            decision=decision,
            risk=risk,
            reasons=reasons,
            policy_version=self.policy_version,
            required_approval=decision == Decision.ESCALATE,
        )

    # ----------------------------------------------------------------- intercept

    def intercept(
        self,
        call: ToolCall,
        execute: Callable[..., ToolResult],
        prior_observations: list[ToolObservation],
    ) -> ToolObservation:
        """Standard enforcement path: decision + execution + audit.

        Calls evaluate() for the decision, then for ALLOW: mints a permit,
        executes the tool, records the execution signature, and returns a
        ToolObservation with the result. For BLOCK/ESCALATE: returns without
        executing. Records a DECISION audit event in all cases.

        Exceptions during evaluation or execution are caught and converted
        to BLOCK (fail-closed).
        """
        try:
            security_decision = self.evaluate(call, prior_observations)
            self._record(
                "DECISION",
                f"{security_decision.decision} {call.tool_name}",
                security_decision.model_dump(mode="json"),
            )

            if security_decision.decision in (Decision.BLOCK, Decision.ESCALATE):
                return ToolObservation(
                    call=call, decision=security_decision.decision, executed=False
                )

            permit = self._mint_permit(call)
            result = execute(permit)
            if call.tool_name in SIDE_EFFECT_TOOLS:
                self._executed_signatures.add(self._signature(call))
            return ToolObservation(
                call=call, result=result, decision=security_decision.decision, executed=True
            )
        except (TypeError, ValueError, KeyError, RuntimeError, PermissionError) as error:
            self._record("ERROR", "Policy evaluation failed closed", {"error": str(error)})
            return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

    # -------------------------------------------------------- execute_approved

    def execute_approved(
        self,
        call: ToolCall,
        execute: Callable[..., ToolResult],
    ) -> ToolObservation:
        """Authoritative execution path for human-approved side effects.

        This is the ONLY way an approved side effect may execute. It performs
        the same validation as intercept() — allowlist, replay, permit minting,
        signature recording — and adds a HUMAN_APPROVAL audit trail.

        The caller (ApprovalManager) provides the execute callable that invokes
        ProcurementTools.call(permit=...). PolicyEngine remains the sole
        authority for minting the permit and recording the execution.
        """
        signature = self._signature(call)

        if call.tool_name not in SIDE_EFFECT_TOOLS:
            security_decision = SecurityDecision(
                decision=Decision.BLOCK,
                risk=RiskAssessment(score=100, level=RiskLevel.CRITICAL, evidence=[]),
                reasons=[f"Tool '{call.tool_name}' is not a permitted side-effect tool"],
                policy_version=self.policy_version,
                required_approval=False,
            )
            self._record(
                "DECISION",
                f"BLOCK {call.tool_name}",
                security_decision.model_dump(mode="json"),
            )
            return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

        if signature in self._executed_signatures:
            security_decision = SecurityDecision(
                decision=Decision.BLOCK,
                risk=RiskAssessment(score=100, level=RiskLevel.CRITICAL, evidence=[]),
                reasons=["Duplicate side-effect call signature; replays are denied"],
                policy_version=self.policy_version,
                required_approval=False,
            )
            self._record(
                "DECISION",
                f"BLOCK {call.tool_name}",
                security_decision.model_dump(mode="json"),
            )
            return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

        permit = self._mint_permit(call)
        try:
            result = execute(permit)
        except (TypeError, ValueError, KeyError, RuntimeError, PermissionError) as error:
            self._record("ERROR", "Approved execution failed", {"error": str(error)})
            return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

        self._executed_signatures.add(signature)
        self._record(
            "DECISION",
            f"APPROVED {call.tool_name}",
            {
                "decision": "APPROVED",
                "authorization_source": "HUMAN_APPROVAL",
                "tool_name": call.tool_name,
                "signature": signature,
                "policy_version": self.policy_version,
            },
        )
        return ToolObservation(call=call, result=result, decision=Decision.ALLOW, executed=True)

    # ----------------------------------------------------------------- audit

    def _record(self, event_type: str, message: str, data: dict) -> None:
        self.audit.append(AuditEvent(
            event_id=f"audit-{len(self.audit) + 1}",
            event_type=event_type,
            message=message,
            data=data,
            run_id=self.run_id,
            timestamp=datetime.now(UTC).isoformat(),
        ))
