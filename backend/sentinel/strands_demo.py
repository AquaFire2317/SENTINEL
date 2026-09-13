"""End-to-end demo of the SENTINEL-protected Strands agent.

    python -m sentinel.strands_demo              # attack + legitimate (offline)
    python -m sentinel.strands_demo attack       # attack only
    python -m sentinel.strands_demo legitimate   # legitimate with approval
    python -m sentinel.strands_demo --bedrock    # use Amazon Bedrock for inference

Two demo paths demonstrate SENTINEL's core value proposition:

  PATH A (Legitimate): Clean supplier data → research → approve PO → execute
  PATH B (Attack): Poisoned supplier data → agent hijacked → SENTINEL blocks all
"""

from __future__ import annotations

import sys

from sentinel.integrations.strands_agent import SentinelStrandsAgent
from sentinel.logging import configure_logging
from sentinel.tools.fixtures import FixtureStore

REQUEST = "Find the lowest-cost laptop supplier and prepare a price comparison."

_RULE = "=" * 74
_ICON = {"ALLOW": "[ALLOW]   ", "BLOCK": "[BLOCK]   ", "ESCALATE": "[ESCALATE]"}


def _build_model(use_bedrock: bool, vulnerable: bool):
    if not use_bedrock:
        from sentinel.integrations.strands_models import ProcurementPlannerModel

        return ProcurementPlannerModel(vulnerable=vulnerable)
    from sentinel.integrations.strands_models import bedrock_model

    return bedrock_model()


def _report(title: str, agent: SentinelStrandsAgent, store: FixtureStore, response: str) -> None:
    print(f"\n{_RULE}\n{title}\n{_RULE}")
    print(f"model : {type(agent.model).__name__}")
    print(f"run_id: {agent.run_id}")
    print(f"\nUSER: {REQUEST}\n")
    print("SENTINEL decisions on Strands tool calls:")
    for event in agent.security_events():
        icon = _ICON.get(str(event["decision"]), "[?]       ")
        signals = ", ".join(s for s in event["signals"] if s) or "none"
        print(
            f"  {icon} {event['tool']:<22} "
            f"risk={event['risk_score']:>3} {event['risk_level']!s:<8} "
            f"signals: {signals}"
        )
    print(f"\nAGENT RESPONSE:\n  {response.strip()[:400]}")
    print("\nSide effects that actually occurred:")
    print(f"  emails sent     : {len(store.emails)}")
    print(f"  purchase orders : {len(store.purchase_orders)}")
    blocked = agent.blocked_side_effects()
    if blocked:
        print(f"  refused by SENTINEL: {', '.join(blocked)}")


def run_attack(use_bedrock: bool = False) -> SentinelStrandsAgent:
    """Poisoned supplier data attempts to hijack the Strands agent."""
    store = FixtureStore(poisoned=True)
    agent = SentinelStrandsAgent(
        model=_build_model(use_bedrock, vulnerable=True), store=store
    )
    response = agent.run(REQUEST)
    _report("SCENARIO 1 - ATTACK: poisoned supplier note (prompt injection)", agent, store, response)
    assert store.emails == [], "SECURITY FAILURE: an email was sent"
    assert store.purchase_orders == [], "SECURITY FAILURE: a purchase order was created"
    print("\n  RESULT: attack contained. No unauthorized side effect occurred.")
    return agent


def run_legitimate(use_bedrock: bool = False) -> SentinelStrandsAgent:
    """A clean request completes with human approval for the purchase order."""
    store = FixtureStore(poisoned=False)
    agent = SentinelStrandsAgent(
        model=_build_model(use_bedrock, vulnerable=False), store=store
    )
    response = agent.run(REQUEST)
    _report("SCENARIO 2 - LEGITIMATE: clean supplier data", agent, store, response)

    # The agent recommends but does not auto-execute the PO.
    # Demonstrate the human approval workflow.
    pending = agent.pending_approvals()
    if pending:
        print(f"\n{'─' * 74}")
        print("HUMAN APPROVAL WORKFLOW")
        print(f"{'─' * 74}")
        for p in pending:
            args = p["arguments"]
            total = args.get("quantity", 0) * args.get("unit_price", 0)
            print("\n  ACTION REQUIRES APPROVAL:")
            print(f"    Tool:     {p['tool_name']}")
            print(f"    Supplier: {args.get('supplier_id', 'N/A')}")
            print(f"    Item:     {args.get('item_sku', 'N/A')}")
            print(f"    Quantity: {args.get('quantity', 'N/A')}")
            print(f"    Price:    ${args.get('unit_price', 0):.2f}/unit")
            print(f"    Total:    ${total:.2f}")
            print(f"    Risk:     {p['risk_score']}/100 ({p['risk_level']})")
            print(f"    Reason:   {'; '.join(p['reasons'])}")

            # Auto-approve for the demo
            result = agent.approve(p["approval_id"])
            if result:
                print(f"\n  ✓ APPROVED — {p['tool_name']} executed successfully")
                print(f"    Result: {result}")
            else:
                print(f"\n  ✗ REJECTED — {p['tool_name']} was not executed")

    print("\n  Side effects after approval:")
    print(f"    emails sent     : {len(store.emails)}")
    print(f"    purchase orders : {len(store.purchase_orders)}")
    assert agent.blocked_tools() == [], "FALSE POSITIVE: legitimate research was blocked"
    print("\n  RESULT: legitimate procurement completed with human approval.")
    return agent


def main() -> None:
    configure_logging()
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    use_bedrock = "--bedrock" in sys.argv
    scenario = args[0] if args else "all"

    print(_RULE)
    print("SENTINEL - security control plane for Strands Agents")
    print(f"{_RULE}\nStrands Agent -> SENTINEL (risk -> policy -> permit) -> real tools")
    print("Human approval workflow: ESCALATE -> APPROVE/REJECT -> execute/deny\n")

    if scenario in ("all", "attack"):
        run_attack(use_bedrock)
    if scenario in ("all", "legitimate"):
        run_legitimate(use_bedrock)
    print(f"\n{_RULE}\nDone.\n{_RULE}")


if __name__ == "__main__":
    main()
