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
import hmac
import json
import secrets
import threading
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
    """Unforgeable, single-use token proving SENTINEL authorized this execution.

    A permit binds four things:
    - the exact tool name
    - the exact canonicalized arguments (via ``signature``)
    - the issuing run (``run_id``)
    - the issuing PolicyEngine instance (via an HMAC under that engine's secret)

    The ``token`` is ``HMAC-SHA256(engine_secret, run_id || signature || nonce)``.
    ``signature_for()`` is public and unkeyed on purpose (it is a canonicalization
    helper used for replay bookkeeping), so a permit must NOT be verified by
    recomputing a signature. Verification requires the issuing engine's secret,
    which never leaves the engine. Constructing ``ExecutionPermit(...)`` directly
    therefore cannot produce a token any engine will accept.

    Permits are single-use: the issuing engine records the nonce on redemption
    and refuses it thereafter.
    """

    __slots__ = ("_issuer", "_nonce", "_run_id", "_signature", "_token", "_tool_name")

    def __init__(
        self,
        signature: str,
        tool_name: str = "",
        run_id: str = "",
        nonce: str = "",
        token: str = "",
        issuer: "PolicyEngine | None" = None,
    ):
        self._signature = signature
        self._tool_name = tool_name
        self._run_id = run_id
        self._nonce = nonce
        self._token = token
        self._issuer = issuer

    @property
    def matches(self) -> str:
        """Canonical signature this permit authorizes (tool + arguments)."""
        return self._signature

    @property
    def tool_name(self) -> str:
        return self._tool_name

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def nonce(self) -> str:
        return self._nonce

    @property
    def token(self) -> str:
        return self._token

    @property
    def issuer(self) -> "PolicyEngine | None":
        """The PolicyEngine that minted this permit, or None if hand-constructed."""
        return self._issuer


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
        # Per-engine secret used to sign ExecutionPermits. Never leaves the
        # process and is never exposed through any public accessor. Because a
        # permit token is an HMAC under this secret, permits cannot be forged
        # by recomputing the (public, unkeyed) canonical signature.
        self._permit_secret: bytes = secrets.token_bytes(32)
        # Nonces of permits that have been minted and not yet redeemed.
        # Redemption removes the nonce, making every permit single-use.
        self._live_permits: set[str] = set()
        # Guards the check-then-act sequences that protect against duplicate
        # side effects: replay-signature claiming and permit redemption. Without
        # this, two threads can both pass the replay check before either records
        # its execution, producing two real side effects from one authorization.
        self._lock = threading.RLock()

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

    def _claim_signature(self, signature: str) -> bool:
        """Atomically claim a side-effect signature for execution.

        Returns True if this caller won the claim, False if it was already
        claimed. This closes the window between the replay check and the
        execution record, during which a concurrent caller could otherwise
        also pass the check and produce a second side effect.
        """
        with self._lock:
            if signature in self._executed_signatures:
                return False
            self._executed_signatures.add(signature)
            return True

    def _release_signature(self, signature: str) -> None:
        """Release a claimed signature after a failed execution."""
        with self._lock:
            self._executed_signatures.discard(signature)

    def _permit_token(self, signature: str, nonce: str) -> str:
        """HMAC binding a permit to this engine, this run, and these arguments."""
        message = f"{self.run_id}|{signature}|{nonce}".encode()
        return hmac.new(self._permit_secret, message, hashlib.sha256).hexdigest()

    def _mint_permit(self, call: ToolCall) -> ExecutionPermit:
        """Create a single-use ExecutionPermit bound to tool + arguments + run."""
        signature = self._signature(call)
        nonce = secrets.token_hex(16)
        with self._lock:
            self._live_permits.add(nonce)
        return ExecutionPermit(
            signature=signature,
            tool_name=call.tool_name,
            run_id=self.run_id,
            nonce=nonce,
            token=self._permit_token(signature, nonce),
            issuer=self,
        )

    def verify_permit(
        self,
        permit: object,
        tool_name: str,
        arguments: dict,
    ) -> bool:
        """Return True only if this permit authorizes exactly this execution.

        Fail-closed on every uncertainty. A permit is valid only when ALL hold:

        1. It is an ExecutionPermit instance.
        2. It was minted by THIS engine (HMAC verifies under this engine's
           secret). This provides run isolation: a permit from another run was
           signed with a different secret and will not verify here.
        3. Its nonce is still live (it has not already been redeemed).
        4. Its run_id matches this engine's run_id.
        5. Its tool_name matches the tool being invoked.
        6. Its signature matches the canonical signature of the exact arguments.
        """
        if not isinstance(permit, ExecutionPermit):
            return False
        if not permit.nonce or not permit.token:
            return False
        with self._lock:
            if permit.nonce not in self._live_permits:
                return False
        if permit.run_id != self.run_id:
            return False
        if permit.tool_name != tool_name:
            return False
        if permit.matches != self.signature_for(tool_name, arguments):
            return False
        expected = self._permit_token(permit.matches, permit.nonce)
        return hmac.compare_digest(permit.token, expected)

    def consume_permit(
        self,
        permit: object,
        tool_name: str,
        arguments: dict,
    ) -> bool:
        """Atomically verify a permit and burn it.

        This is the call the tool boundary must use. Verifying and redeeming as
        two separate steps is a check-then-act race: two threads could both
        verify the same permit before either redeemed it, yielding two side
        effects from one authorization. Returns False if the permit is invalid,
        in which case nothing is consumed and the caller must refuse.
        """
        with self._lock:
            if not self.verify_permit(permit, tool_name, arguments):
                return False
            self._live_permits.discard(permit.nonce)  # type: ignore[union-attr]
            return True

    def redeem_permit(self, permit: object) -> None:
        """Consume a permit so it can never be used again."""
        if isinstance(permit, ExecutionPermit) and permit.nonce:
            with self._lock:
                self._live_permits.discard(permit.nonce)

    def revoke_permit(self, permit: object) -> None:
        """Invalidate an unused permit (e.g. after a failed execution)."""
        self.redeem_permit(permit)

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

        Fail-closed: if risk assessment or signature computation raises for any
        reason (malformed arguments, unserializable input, detector failure),
        the result is BLOCK. Detection failure must never become permission.
        """
        if call.tool_name not in READ_TOOLS | SIDE_EFFECT_TOOLS:
            return SecurityDecision(
                decision=Decision.BLOCK,
                risk=RiskAssessment(score=100, level=RiskLevel.CRITICAL, evidence=[]),
                reasons=[f"Tool '{call.tool_name}' is not on the allowlist"],
                policy_version=self.policy_version,
                required_approval=False,
            )

        try:
            risk = assess_tool_call(call, prior_observations, self.issued_approvals)
            signature = self._signature(call)
        except Exception as error:  # noqa: BLE001 - deliberate fail-closed
            return SecurityDecision(
                decision=Decision.BLOCK,
                risk=RiskAssessment(score=100, level=RiskLevel.CRITICAL, evidence=[]),
                reasons=[
                    (
                        "Security evaluation failed closed: "
                        f"{type(error).__name__}: {error}"
                    )
                ],
                policy_version=self.policy_version,
                required_approval=False,
            )

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

            is_side_effect = call.tool_name in SIDE_EFFECT_TOOLS
            signature = self._signature(call)

            # Claim the signature BEFORE executing. evaluate() already checked
            # for replay, but between that check and here a concurrent caller
            # could execute the same side effect. The claim is atomic, so
            # exactly one caller proceeds.
            if is_side_effect and not self._claim_signature(signature):
                self._record(
                    "DECISION",
                    f"BLOCK {call.tool_name}",
                    {
                        "decision": "BLOCK",
                        "reasons": ["Duplicate side-effect call signature; replays are denied"],
                        "tool_name": call.tool_name,
                        "policy_version": self.policy_version,
                    },
                )
                return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

            permit = self._mint_permit(call)
            try:
                result = execute(permit)
            except BaseException:
                # Never leave a usable permit or a claimed signature behind
                # after a failed execution.
                self.revoke_permit(permit)
                if is_side_effect:
                    self._release_signature(signature)
                raise
            self.redeem_permit(permit)
            return ToolObservation(
                call=call, result=result, decision=security_decision.decision, executed=True
            )
        except Exception as error:  # noqa: BLE001 - deliberate fail-closed
            # Fail closed on ANY unexpected failure, not just an expected subset.
            # KeyboardInterrupt/SystemExit deliberately propagate (BaseException).
            self._record(
                "ERROR",
                "Policy evaluation failed closed",
                {
                    "error": f"{type(error).__name__}: {error}",
                    "tool_name": call.tool_name,
                    "decision": "BLOCK",
                    "policy_version": self.policy_version,
                },
            )
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

        # Atomically claim the signature so two concurrent approvals of the
        # same action cannot both execute.
        if not self._claim_signature(signature):
            self._record(
                "DECISION",
                f"BLOCK {call.tool_name}",
                {
                    "decision": "BLOCK",
                    "reasons": ["Duplicate side-effect call signature; replays are denied"],
                    "tool_name": call.tool_name,
                    "authorization_source": "HUMAN_APPROVAL",
                    "policy_version": self.policy_version,
                },
            )
            return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

        permit = self._mint_permit(call)
        try:
            result = execute(permit)
        except Exception as error:  # noqa: BLE001 - deliberate fail-closed
            self.revoke_permit(permit)
            self._release_signature(signature)
            self._record(
                "ERROR",
                "Approved execution failed",
                {
                    "error": f"{type(error).__name__}: {error}",
                    "tool_name": call.tool_name,
                    "decision": "BLOCK",
                    "policy_version": self.policy_version,
                },
            )
            return ToolObservation(call=call, decision=Decision.BLOCK, executed=False)

        self.redeem_permit(permit)
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

    def audit_snapshot(self) -> list[AuditEvent]:
        """Return a deep copy of the audit trail.

        Prevents callers from mutating the engine's authoritative record.
        Every element is a fresh copy — appending to the returned list or
        modifying a returned event has no effect on the engine.
        """
        return [event.model_copy(deep=True) for event in self.audit]

    def _record(self, event_type: str, message: str, data: dict) -> None:
        self.audit.append(AuditEvent(
            event_id=f"audit-{len(self.audit) + 1}",
            event_type=event_type,
            message=message,
            data=data,
            run_id=self.run_id,
            timestamp=datetime.now(UTC).isoformat(),
        ))
