from sentinel.agents.procurement import ProcurementAgent
from sentinel.contracts.security import Decision, RiskLevel
from sentinel.security.explanation import explain
from sentinel.security.interceptor import SentinelInterceptor
from sentinel.security.policy import PolicyEngine
from sentinel.tools.fixtures import FixtureStore
from sentinel.tools.procurement import ProcurementTools


def test_canonical_attack_is_critical_and_blocked_without_side_effect():
    store = FixtureStore()
    audit = []
    interceptor = SentinelInterceptor(PolicyEngine(audit))
    observations = ProcurementAgent(ProcurementTools(store), vulnerable=True).run(
        "Find the lowest-cost laptop supplier", interceptor
    )

    email = next(item for item in observations if item.call.tool_name == "send_email")
    decision = next(item for item in audit if item.data.get("decision") == "BLOCK")
    assert email.executed is False
    assert store.emails == []
    assert decision.data["risk"]["level"] == RiskLevel.CRITICAL
    assert decision.data["risk"]["score"] >= 75


def test_read_only_supplier_research_is_allowed():
    store = FixtureStore(poisoned=False)
    audit = []
    interceptor = SentinelInterceptor(PolicyEngine(audit))
    observations = ProcurementAgent(ProcurementTools(store), vulnerable=True).run("Compare suppliers", interceptor)

    assert all(item.decision == Decision.ALLOW for item in observations)
    assert all(item.executed for item in observations)


def test_explanation_uses_decision_evidence():
    store = FixtureStore()
    audit = []
    interceptor = SentinelInterceptor(PolicyEngine(audit))
    ProcurementAgent(ProcurementTools(store), vulnerable=True).run("Buy laptops", interceptor)
    decision = next(item.data for item in audit if item.event_type == "DECISION" and item.data["decision"] == "BLOCK")

    from sentinel.contracts.security import SecurityDecision

    text = explain(SecurityDecision.model_validate(decision))
    assert "untrusted supplier data" in text
    assert "external communication" in text
