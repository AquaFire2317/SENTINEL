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

from sentinel.contracts.security import AuditEvent, Decision
from sentinel.integrations.strands_guard import build_guarded_toolset
from sentinel.integrations.strands_models import SYSTEM_PROMPT, ProcurementPlannerModel
from sentinel.security.policy import PolicyEngine
from sentinel.tools.fixtures import FixtureStore


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
    """

    def __init__(
        self,
        model: Any | None = None,
        store: FixtureStore | None = None,
        policy: PolicyEngine | None = None,
        vulnerable: bool = False,
        run_id: str | None = None,
        system_prompt: str | None = None,
    ):
        self.run_id = run_id or f"strands-{uuid4().hex[:12]}"
        self.guard, tools = build_guarded_toolset(
            store=store, policy=policy, run_id=self.run_id
        )
        self.model = model if model is not None else ProcurementPlannerModel(vulnerable=vulnerable)
        self.agent = Agent(
            model=self.model,
            tools=tools,
            hooks=[self.guard],
            system_prompt=system_prompt or SYSTEM_PROMPT,
            callback_handler=None,
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
        """Flat, presentable view of every SENTINEL decision in this run."""
        events: list[dict[str, Any]] = []
        for observation in self.guard.observations:
            decision_event = next(
                (
                    event
                    for event in self.audit
                    if event.event_type == "DECISION"
                    and observation.call.tool_name in event.message
                    and event.data.get("_matched") is not True
                ),
                None,
            )
            risk = (decision_event.data.get("risk") if decision_event else None) or {}
            if decision_event is not None:
                decision_event.data["_matched"] = True
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
        for event in self.audit:
            event.data.pop("_matched", None)
        return events

    def blocked_side_effects(self) -> list[str]:
        return [
            observation.call.tool_name
            for observation in self.guard.observations
            if observation.call.tool_name in ("send_email", "create_purchase_order")
            and observation.decision in (Decision.BLOCK, Decision.ESCALATE)
        ]
