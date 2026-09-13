"""SENTINEL security gate for Strands Agents.

This is the integration layer that puts the existing (already hardened) SENTINEL
security core into the tool-execution path of a genuine Strands ``Agent``.

Execution path
--------------
    Strands Agent (model reasoning)
        -> Strands tool call (BeforeToolCallEvent)
            -> SentinelToolGuard  [this module]
                -> ToolCall contract
                -> PolicyEngine.intercept()   (single authoritative path)
                    -> evaluate()             (decision logic)
                    -> _mint_permit()         (permit minting)
                    -> execute(permit)        (tool execution)
                    -> _record()              (audit events)
        -> tool result returned to the model
            or
        -> cancel_tool  (BLOCK / ESCALATE: the tool never runs)

Security design
---------------
The Strands tool functions in this module are deliberately *inert shims*. They
never touch :class:`ProcurementTools` themselves. The only thing they can do is
hand back a result that SENTINEL already produced through a validated
:class:`ExecutionPermit`.

That inversion is what makes bypass structurally impossible: if the guard hook
did not run, or ran and refused, there is no authorized result for the shim to
return and it raises ``PermissionError``. No new policy logic lives here.

The guard does NOT duplicate:
- Tool allowlists (lives in PolicyEngine.evaluate)
- Risk thresholds (lives in PolicyEngine.evaluate)
- Side-effect classification (lives in PolicyEngine.evaluate)
- Replay rules (lives in PolicyEngine.evaluate)
- Permit creation (lives in PolicyEngine._mint_permit)
- Audit event generation (lives in PolicyEngine._record)

The guard acts purely as an adapter between Strands hooks and PolicyEngine.
"""

from __future__ import annotations

from typing import Any

from strands import ToolContext, tool
from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent, HookRegistry

from sentinel.approval.manager import ApprovalManager
from sentinel.contracts.procurement import (
    ToolCall,
    ToolObservation,
    ToolResult,
    ToolTrust,
)
from sentinel.contracts.security import AuditEvent, Decision
from sentinel.security.policy import PolicyEngine
from sentinel.tools.fixtures import FixtureStore
from sentinel.tools.procurement import ProcurementTools


class SentinelDenied(PermissionError):
    """Raised inside a Strands tool when SENTINEL did not authorize execution."""


class SentinelToolGuard:
    """Strands ``HookProvider`` that routes every tool call through SENTINEL.

    One guard instance == one agent run. State (observations, authorized
    results, policy engine) is per-instance, which preserves the cross-run
    isolation guarantee the security core already relies on.

    This class does NOT implement any policy logic. It is a pure adapter
    between Strands' hook system and PolicyEngine.intercept().
    """

    def __init__(
        self,
        tools: ProcurementTools,
        policy: PolicyEngine | None = None,
        run_id: str = "",
    ):
        self.tools = tools
        self.audit: list[AuditEvent] = [] if policy is None else policy.audit
        self.policy = policy or PolicyEngine(self.audit, run_id=run_id)
        # Bind the tool boundary to this run's PolicyEngine so the tools only
        # accept permits this engine issued. This is what makes a permit from
        # another run (or a hand-constructed one) unusable here.
        self.tools.bind_issuer(self.policy)
        self.observations: list[ToolObservation] = []
        self.approval_manager = ApprovalManager(tools, self.policy)
        # toolUseId -> result SENTINEL authorized and executed
        self._authorized: dict[str, ToolResult] = {}
        # toolUseId -> human-readable refusal reason
        self._refused: dict[str, str] = {}

    # ---------------------------------------------------------------- hooks

    def register_hooks(self, registry: HookRegistry, **_: Any) -> None:
        """Subscribe to the Strands tool lifecycle."""
        registry.add_callback(BeforeToolCallEvent, self.before_tool_call)
        registry.add_callback(AfterToolCallEvent, self.after_tool_call)

    def before_tool_call(self, event: BeforeToolCallEvent) -> None:
        """Evaluate and enforce the SENTINEL decision for one Strands tool call.

        Delegates ALL policy evaluation to PolicyEngine.intercept() — the
        single authoritative enforcement path. The guard only handles
        Strands-specific concerns: storing authorized results for tool shims,
        cancelling blocked/escalated tools, and recording escalations for the
        human approval workflow.

        Fail-closed: if anything in this hook raises, the tool is cancelled.
        An exception here must never result in an unguarded tool execution.
        """
        try:
            self._enforce(event)
        except BaseException as error:  # noqa: BLE001 - deliberate fail-closed
            tool_use_id = str(event.tool_use.get("toolUseId", ""))
            reason = (
                "SENTINEL BLOCK: the security guard failed while evaluating this "
                "call, so it was refused. Do not retry; report the refusal."
            )
            self._refused[tool_use_id] = reason
            event.cancel_tool = reason
            self.policy._record(
                "ERROR",
                "Guard failed closed",
                {
                    "tool_name": str(event.tool_use.get("name", "")),
                    "tool_use_id": tool_use_id,
                    "error": f"{type(error).__name__}: {error}",
                    "decision": "BLOCK",
                },
            )

    def _enforce(self, event: BeforeToolCallEvent) -> None:
        """Translate the Strands event and delegate to the PolicyEngine."""
        tool_use = event.tool_use
        tool_use_id = str(tool_use.get("toolUseId", ""))
        tool_name = str(tool_use.get("name", ""))
        arguments = _tool_arguments(tool_use)

        call = ToolCall(
            call_id=tool_use_id or f"strands-{len(self.observations) + 1}",
            tool_name=tool_name,
            input=arguments,
            source="strands_agent",
            derived_from=self._untrusted_provenance(),
        )

        # Delegate to the single authoritative PolicyEngine.
        def execute_with_permit(permit):
            return self.tools.call(tool_name, arguments, permit=permit)

        observation = self.policy.intercept(call, execute_with_permit, self.observations)
        self.observations.append(observation)

        if observation.decision == Decision.ALLOW:
            # Store authorized result for the Strands tool shim to return.
            if observation.result is not None:
                self._authorized[tool_use_id] = observation.result
            return

        # BLOCK or ESCALATE: cancel the tool so Strands never executes it.
        reason = _refusal_text(observation)
        self._refused[tool_use_id] = reason
        event.cancel_tool = reason

        # For ESCALATE, record the call for the human approval workflow.
        # Risk is computed separately here because intercept() does not
        # expose the SecurityDecision. This is acceptable because risk
        # computation is stateless and cheap.
        if observation.decision == Decision.ESCALATE:
            from sentinel.security.risk import assess_tool_call

            risk = assess_tool_call(call, self.observations, self.policy.issued_approvals)
            reasons = [item.text for item in risk.evidence] or [
                f"{tool_name} is a side-effecting tool and requires approval"
            ]
            self.approval_manager.record_escalation(
                call=call,
                risk=risk,
                reasons=reasons,
            )

    def after_tool_call(self, event: AfterToolCallEvent) -> None:
        """Record the Strands-side outcome for audit traceability."""
        tool_use = event.tool_use
        self.policy._record(
            "STRANDS_TOOL",
            f"strands tool completed {tool_use.get('name', '')}",
            {
                "tool_use_id": tool_use.get("toolUseId", ""),
                "tool_name": tool_use.get("name", ""),
                "authorized": tool_use.get("toolUseId", "") in self._authorized,
                "cancelled": bool(event.cancel_message),
            },
        )

    # ------------------------------------------------------- shim accessors

    def authorized_result(self, tool_use_id: str) -> ToolResult:
        """Return the SENTINEL-authorized result, or refuse."""
        result = self._authorized.get(tool_use_id)
        if result is None:
            raise SentinelDenied(
                self._refused.get(
                    tool_use_id,
                    "SENTINEL did not authorize this tool call; no execution permit was issued",
                )
            )
        return result

    # ------------------------------------------------------------ reporting

    def executed_tools(self) -> list[str]:
        return [o.call.tool_name for o in self.observations if o.executed]

    def blocked_tools(self) -> list[str]:
        return [
            o.call.tool_name
            for o in self.observations
            if o.decision in (Decision.BLOCK, Decision.ESCALATE)
        ]

    def _untrusted_provenance(self) -> list[str]:
        """call_ids of prior observations that returned attacker-influenced data."""
        return [
            o.call.call_id
            for o in self.observations
            if o.result is not None and o.result.trust == ToolTrust.UNTRUSTED_DATA
        ]


def _tool_arguments(tool_use: dict) -> dict[str, Any]:
    """Normalize the Strands tool input into a plain dict of arguments."""
    raw = tool_use.get("input")
    if isinstance(raw, dict):
        return {k: v for k, v in raw.items() if v is not None}
    return {}


def _refusal_text(observation: ToolObservation) -> str:
    decision = observation.decision or Decision.BLOCK
    tool_name = observation.call.tool_name
    if decision == Decision.ESCALATE:
        return (
            f"SENTINEL ESCALATE: '{tool_name}' is a privileged side effect and "
            "requires human approval. It was not executed. Report this to the user "
            "and do not retry."
        )
    return (
        f"SENTINEL BLOCK: '{tool_name}' was refused because it was judged unsafe "
        "(untrusted-data-driven or policy-violating). It was not executed. "
        "Do not retry; report the refusal."
    )


# --------------------------------------------------------------------------
# Strands tool definitions
# --------------------------------------------------------------------------
# Every function below is a shim. It performs no procurement work and holds no
# credentials; it only surfaces a result SENTINEL already authorized.


def build_procurement_tools(guard: SentinelToolGuard) -> list[Any]:
    """Build the Strands tool set bound to a SENTINEL guard."""

    def _result(context: ToolContext) -> Any:
        return guard.authorized_result(str(context.tool_use.get("toolUseId", ""))).data

    @tool(context=True, name="search_suppliers")
    def search_suppliers(query: str, tool_context: ToolContext, max_results: int = 5) -> Any:
        """Search the approved supplier catalogue for vendors matching a query.

        Args:
            query: What to search for, e.g. "laptops".
            max_results: Maximum number of suppliers to return (1-50).
        """
        return _result(tool_context)

    @tool(context=True, name="get_supplier_details")
    def get_supplier_details(supplier_id: str, tool_context: ToolContext) -> Any:
        """Fetch the full record for one supplier, including any supplier note.

        Args:
            supplier_id: The supplier identifier, e.g. "sup-acme".
        """
        return _result(tool_context)

    @tool(context=True, name="compare_prices")
    def compare_prices(
        supplier_ids: list[str],
        item_sku: str,
        quantity: int,
        tool_context: ToolContext,
    ) -> Any:
        """Compare per-unit pricing for an item across several suppliers.

        Args:
            supplier_ids: Supplier identifiers to quote.
            item_sku: The item SKU, e.g. "LAPTOP-001".
            quantity: Positive number of units.
        """
        return _result(tool_context)

    @tool(context=True, name="create_purchase_order")
    def create_purchase_order(
        supplier_id: str,
        item_sku: str,
        quantity: int,
        unit_price: float,
        tool_context: ToolContext,
        approval_id: str | None = None,
    ) -> Any:
        """Create a purchase order. PRIVILEGED: requires SENTINEL authorization.

        Args:
            supplier_id: Supplier to buy from.
            item_sku: Item SKU to order.
            quantity: Positive number of units.
            unit_price: Positive per-unit price.
            approval_id: A human-issued approval id, if one exists.
        """
        return _result(tool_context)

    @tool(context=True, name="send_email")
    def send_email(
        to: str,
        subject: str,
        body: str,
        tool_context: ToolContext,
        attachments: list[str] | None = None,
    ) -> Any:
        """Send an email. PRIVILEGED: requires SENTINEL authorization.

        Args:
            to: Recipient address. Only internal corporate domains are permitted.
            subject: Subject line.
            body: Message body.
            attachments: Optional attachment names.
        """
        return _result(tool_context)

    return [
        search_suppliers,
        get_supplier_details,
        compare_prices,
        create_purchase_order,
        send_email,
    ]


def build_guarded_toolset(
    store: FixtureStore | None = None,
    policy: PolicyEngine | None = None,
    run_id: str = "",
) -> tuple[SentinelToolGuard, list[Any]]:
    """Create a SENTINEL guard plus its Strands tool set."""
    tools = ProcurementTools(store if store is not None else FixtureStore())
    guard = SentinelToolGuard(tools, policy=policy, run_id=run_id)
    return guard, build_procurement_tools(guard)
