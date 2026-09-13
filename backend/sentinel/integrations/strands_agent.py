"""The SENTINEL-protected Strands agent.

Assembles a genuine Strands ``Agent`` whose entire tool surface is gated by the
existing SENTINEL security core.

    USER
      -> Strands Agent (Bedrock or local planner)
        -> Strands tool call
          -> SentinelToolGuard (BeforeToolCallEvent)
            -> RiskEngine -> PolicyEngine -> ExecutionPermit
              -> real procurement tool
      -> result / refusal
    -> audit + retest
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from strands import Agent
from strands.agent.conversation_manager import SlidingWindowConversationManager

from sentinel.contracts.security import AuditEvent, Decision
from sentinel.integrations.strands_guard import build_guarded_toolset
from sentinel.integrations.strands_models import SYSTEM_PROMPT, ProcurementPlannerModel
from sentinel.security.policy import PolicyEngine
from sentinel.tools.fixtures import FixtureStore

DEFAULT_WINDOW_SIZE = 20


class SentinelStrandsAgent:
    """A Strands agent whose tool execution is controlled by SENTINEL.

    Args:
        model: Any Strands model provider. Defaults to the deterministic local
            planner so the agent runs offline. Pass
            ``sentinel.integrations.strands_models.bedrock_model()`` for Bedrock.
        store: Fixture store backing the procurement tools.
        policy: Existing :class:`PolicyEngine` to reuse (for issued approvals or a
            shared audit sink). A fresh, isolated engine is created otherwise.
        vulnerable: Only used when building the default local planner.
        run_id: Correlation id stamped onto every audit event.
        system_prompt: Override the default procurement system prompt.
        window_size: Maximum number of message pairs to retain in conversation
            history. Defaults to ``DEFAULT_WINDOW_SIZE`` (20). Pass ``None`` to
            disable sliding-window management.
    """

    def __init__(
        self,
        model: Any | None = None,
        store: FixtureStore | None = None,
        policy: PolicyEngine | None = None,
        vulnerable: bool = False,
        run_id: str | None = None,
        system_prompt: str | None = None,
        window_size: int | None = DEFAULT_WINDOW_SIZE,
    ):
        self.run_id = run_id or f"strands-{uuid4().hex[:12]}"
        self.guard, tools = build_guarded_toolset(
            store=store, policy=policy, run_id=self.run_id
        )
        self.model = model if model is not None else ProcurementPlannerModel(vulnerable=vulnerable)

        conversation_manager = (
            SlidingWindowConversationManager(window_size=window_size)
            if window_size is not None
            else None
        )

        self.agent = Agent(
            model=self.model,
            tools=tools,
            hooks=[self.guard],
            system_prompt=system_prompt or SYSTEM_PROMPT,
            callback_handler=None,
            conversation_manager=conversation_manager,
            name="sentinel-procurement-agent",
            description="Procurement research agent protected by SENTINEL",
        )

    # ---------------------------------------------------------------- run

    def run(self, request: str) -> str:
        """Invoke the Strands agent and return its final text response."""
        return str(self.agent(request))

    # ------------------------------------------------------------ results

    @property
    def audit(self) -> list[AuditEvent]:
        return self.guard.audit

    @property
    def observations(self) -> list:
        return self.guard.observations

    def executed_tools(self) -> list[str]:
        return self.guard.executed_tools()

    def blocked_tools(self) -> list[str]:
        return self.guard.blocked_tools()

    def decision_for(self, tool_name: str) -> str | None:
        for observation in self.guard.observations:
            if observation.call.tool_name == tool_name:
                return observation.decision
        return None

    def security_events(self) -> list[dict[str, Any]]:
        """Flat, presentable view of every SENTINEL decision in this run.

        Returns a snapshot; does not mutate the underlying audit state.
        """
        events: list[dict[str, Any]] = []
        matched_indices: set[int] = set()
        for observation in self.guard.observations:
            decision_event = None
            for idx, event in enumerate(self.audit):
                if (
                    idx not in matched_indices
                    and event.event_type == "DECISION"
                    and observation.call.tool_name in event.message
                ):
                    decision_event = event
                    matched_indices.add(idx)
                    break
            risk = (decision_event.data.get("risk") if decision_event else None) or {}
            events.append(
                {
                    "call_id": observation.call.call_id,
                    "tool": observation.call.tool_name,
                    "decision": observation.decision,
                    "executed": observation.executed,
                    "risk_score": risk.get("score"),
                    "risk_level": risk.get("level"),
                    "signals": [item.get("signal") for item in risk.get("evidence", [])],
                }
            )
        return events

    def blocked_side_effects(self) -> list[str]:
        return [
            observation.call.tool_name
            for observation in self.guard.observations
            if observation.call.tool_name in ("send_email", "create_purchase_order")
            and observation.decision in (Decision.BLOCK, Decision.ESCALATE)
        ]

    # --------------------------------------------------------- approval workflow

    def pending_approvals(self) -> list[dict[str, Any]]:
        """Return pending ESCALATE decisions awaiting human approval."""
        records = self.guard.approval_manager.pending()
        return [
            {
                "approval_id": r.approval_id,
                "run_id": r.run_id,
                "tool_name": r.tool_name,
                "arguments": r.arguments,
                "signature": r.signature,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "reasons": r.reasons,
                "created_at": r.created_at,
            }
            for r in records
        ]

    def approve(self, approval_id: str, operator: str = "human") -> dict[str, Any] | None:
        """Approve a pending escalation. Executes through PolicyEngine.execute_approved().

        Returns the tool result data on success, or None if not found/not pending.
        """
        result = self.guard.approval_manager.approve(approval_id, operator)
        if result is not None:
            record = self.guard.approval_manager.get_record(approval_id)
            if record:
                from sentinel.contracts.procurement import ToolCall as TC
                from sentinel.contracts.procurement import ToolObservation as TO
                observation = TO(
                    call=TC(
                        call_id=f"approved-{approval_id}",
                        tool_name=record.tool_name,
                        input=record.arguments,
                        source="human_approval",
                    ),
                    executed=True,
                    decision=Decision.ALLOW,
                )
                self.guard.observations.append(observation)
        return result

    def reject(self, approval_id: str, operator: str = "human") -> bool:
        """Reject a pending escalation. The tool is not executed."""
        return self.guard.approval_manager.reject(approval_id, operator)
