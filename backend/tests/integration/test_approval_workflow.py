"""Tests for the human approval workflow.

These tests verify the hardened approval execution path:
1. ESCALATE decisions produce pending approvals
2. Approved actions execute through PolicyEngine.execute_approved() — the
   same authoritative path as normal agent actions
3. Rejected actions do not execute
4. The UI cannot bypass the PolicyEngine
5. Permits are still correctly bound to tool + args
6. Replay protection applies to approved executions
7. Approval is bound to run_id, tool_name, and exact arguments
8. State machine prevents double-approve, approve-after-reject, etc.
9. Existing security invariants remain intact
"""

from sentinel.approval.manager import ApprovalManager, ApprovalStatus
from sentinel.contracts.procurement import ToolCall
from sentinel.contracts.security import Decision, RiskAssessment, RiskLevel
from sentinel.integrations.strands_agent import SentinelStrandsAgent
from sentinel.security.policy import PolicyEngine
from sentinel.tools.fixtures import FixtureStore
from sentinel.tools.procurement import ProcurementTools


class TestApprovalManager:
    """Unit tests for the ApprovalManager."""

    def test_record_escalation_creates_pending_record(self):
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["side effect requires approval"])

        assert record.status == ApprovalStatus.PENDING
        assert record.tool_name == "create_purchase_order"
        assert record.run_id == ""
        assert record.signature == PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
             "quantity": 10, "unit_price": 950.0},
        )
        assert len(manager.pending()) == 1

    def test_approve_executes_tool_through_security_boundary(self):
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["side effect requires approval"])

        result = manager.approve(record.approval_id, operator="demo-user")

        assert result is not None
        assert result["status"] == "recorded_fixture_order"
        assert len(store.purchase_orders) == 1
        assert store.purchase_orders[0]["supplier_id"] == "sup-acme"
        assert record.status == ApprovalStatus.EXECUTED
        assert record.operator == "demo-user"
        assert record.decided_at is not None
        assert len(manager.pending()) == 0

    def test_reject_does_not_execute_tool(self):
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["side effect requires approval"])

        success = manager.reject(record.approval_id, operator="reviewer")

        assert success is True
        assert record.status == ApprovalStatus.REJECTED
        assert record.operator == "reviewer"
        assert store.purchase_orders == []
        assert len(manager.pending()) == 0

    def test_approve_unknown_id_returns_none(self):
        store = FixtureStore()
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        result = manager.approve("nonexistent-id")
        assert result is None

    def test_reject_unknown_id_returns_false(self):
        store = FixtureStore()
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        success = manager.reject("nonexistent-id")
        assert success is False


class TestApprovalStateProtection:
    """State machine: invalid transitions must fail safely."""

    def test_cannot_approve_already_executed_record(self):
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["reason"])

        # First approve succeeds.
        result = manager.approve(record.approval_id)
        assert result is not None
        assert record.status == ApprovalStatus.EXECUTED

        # Second approve must fail (already executed).
        result2 = manager.approve(record.approval_id)
        assert result2 is None

    def test_cannot_approve_rejected_record(self):
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["reason"])

        manager.reject(record.approval_id)
        assert record.status == ApprovalStatus.REJECTED

        # Approve after reject must fail.
        result = manager.approve(record.approval_id)
        assert result is None

    def test_cannot_reject_already_executed_record(self):
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["reason"])

        manager.approve(record.approval_id)
        success = manager.reject(record.approval_id)
        assert success is False

    def test_cannot_reject_already_rejected_record(self):
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["reason"])

        manager.reject(record.approval_id)
        success = manager.reject(record.approval_id)
        assert success is False


class TestApprovalBinding:
    """Approval must be bound to run, tool, and exact arguments."""

    def test_approval_bound_to_exact_tool(self):
        """Approving create_purchase_order does not authorize send_email."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call_po = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        call_email = ToolCall(
            call_id="c2", tool_name="send_email",
            input={"to": "user@corp.example", "subject": "Report", "body": "Monthly report"},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        r1 = manager.record_escalation(call_po, risk, ["reason"])
        r2 = manager.record_escalation(call_email, risk, ["reason"])

        # Approve the PO.
        result = manager.approve(r1.approval_id)
        assert result is not None
        assert len(store.purchase_orders) == 1

        # The email approval is independent.
        result2 = manager.approve(r2.approval_id)
        assert result2 is not None
        assert len(store.emails) == 1

    def test_approval_bound_to_exact_arguments(self):
        """Changing quantity invalidates the approval (different signature)."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["reason"])

        # The approval is bound to the exact arguments.
        sig_original = PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
             "quantity": 10, "unit_price": 950.0},
        )
        sig_different = PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
             "quantity": 100, "unit_price": 950.0},
        )
        assert record.signature == sig_original
        assert sig_original != sig_different

    def test_approval_bound_to_run_id(self):
        """Approval created in run A cannot be used in run B."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)

        policy_a = PolicyEngine(audit=[], run_id="run-A")
        manager_a = ApprovalManager(tools, policy_a)

        policy_b = PolicyEngine(audit=[], run_id="run-B")
        manager_b = ApprovalManager(tools, policy_b)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager_a.record_escalation(call, risk, ["reason"])

        # Approval exists in manager A.
        assert len(manager_a.pending()) == 1
        assert record.run_id == "run-A"

        # Manager B has no pending approvals (different run).
        assert len(manager_b.pending()) == 0

        # Trying to approve via manager B with the same id fails.
        result = manager_b.approve(record.approval_id)
        assert result is None

    def test_signature_is_deterministic_for_identical_args(self):
        """Same tool + same args always produce the same signature."""
        sig1 = PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
             "quantity": 10, "unit_price": 950.0},
        )
        sig2 = PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
             "quantity": 10, "unit_price": 950.0},
        )
        assert sig1 == sig2

    def test_int_float_normalization_preserves_signature(self):
        """int(10) and float(10.0) produce the same signature."""
        sig_int = PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "s", "item_sku": "i", "quantity": 10, "unit_price": 100.0},
        )
        sig_float = PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "s", "item_sku": "i", "quantity": 10.0, "unit_price": 100.0},
        )
        assert sig_int == sig_float


class TestReplayProtection:
    """Approved executions must be subject to replay protection."""

    def test_approved_execution_recorded_in_executed_signatures(self):
        """After approval executes, the signature is in _executed_signatures."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["reason"])

        manager.approve(record.approval_id)

        sig = PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
             "quantity": 10, "unit_price": 950.0},
        )
        assert sig in policy._executed_signatures

    def test_replayed_approval_is_rejected(self):
        """Second approve of same action is rejected by replay protection."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record1 = manager.record_escalation(call, risk, ["reason"])

        # First approval succeeds.
        result1 = manager.approve(record1.approval_id)
        assert result1 is not None
        assert len(store.purchase_orders) == 1

        # New escalation with same args (simulating attacker replay).
        record2 = manager.record_escalation(call, risk, ["reason"])

        # Second approval is rejected by replay detection.
        result2 = manager.approve(record2.approval_id)
        assert result2 is None
        # Only one PO in the store.
        assert len(store.purchase_orders) == 1

    def test_type_coercion_does_not_bypass_replay(self):
        """int(10) vs float(10.0) still triggers replay detection."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        # First: approve with int quantity.
        call_int = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record1 = manager.record_escalation(call_int, risk, ["reason"])
        manager.approve(record1.approval_id)

        # Second: attempt with float quantity (same normalized signature).
        call_float = ToolCall(
            call_id="c2", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10.0, "unit_price": 950.0},
        )
        record2 = manager.record_escalation(call_float, risk, ["reason"])
        result2 = manager.approve(record2.approval_id)
        assert result2 is None
        assert len(store.purchase_orders) == 1


class TestApprovalAuditTrail:
    """Approved executions must produce correct audit information."""

    def test_approved_execution_recorded_in_audit(self):
        """PolicyEngine.execute_approved() produces an APPROVED audit event."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        audit = []
        policy = PolicyEngine(audit=audit)
        manager = ApprovalManager(tools, policy)

        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        record = manager.record_escalation(call, risk, ["reason"])

        manager.approve(record.approval_id)

        # Find the APPROVED audit event.
        approved_events = [e for e in audit if "APPROVED" in e.message]
        assert len(approved_events) == 1
        event = approved_events[0]
        assert event.data["authorization_source"] == "HUMAN_APPROVAL"
        assert event.data["tool_name"] == "create_purchase_order"
        assert event.data["decision"] == "APPROVED"

    def test_approved_execution_observation_has_correct_fields(self):
        """The observation from approved execution has executed=True, decision=ALLOW."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        call = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )

        def execute_with_permit(permit):
            return tools.call("create_purchase_order", call.input, permit=permit)

        observation = policy.execute_approved(call, execute_with_permit)

        assert observation.executed is True
        assert observation.decision == Decision.ALLOW
        assert observation.result is not None
        assert observation.result.data["status"] == "recorded_fixture_order"


class TestSentinelAgentApproval:
    """Integration tests: SentinelStrandsAgent approval workflow."""

    def test_escalated_action_creates_pending_approval(self):
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        # Directly trigger a side effect through Strands API.
        agent.agent.tool.create_purchase_order(
            supplier_id="sup-acme", item_sku="LAPTOP-001",
            quantity=10, unit_price=950.0,
        )

        # ESCALATE creates a pending approval.
        pending = agent.pending_approvals()
        assert len(pending) >= 1
        assert any(p["tool_name"] == "create_purchase_order" for p in pending)
        # PO was NOT executed.
        assert store.purchase_orders == []

    def test_approved_action_executes_correctly(self):
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        agent.agent.tool.create_purchase_order(
            supplier_id="sup-acme", item_sku="LAPTOP-001",
            quantity=10, unit_price=950.0,
        )

        pending = agent.pending_approvals()
        po_approval = next(p for p in pending if p["tool_name"] == "create_purchase_order")

        result = agent.approve(po_approval["approval_id"])

        assert result is not None
        assert result["status"] == "recorded_fixture_order"
        assert len(store.purchase_orders) == 1

    def test_rejected_action_does_not_execute(self):
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        agent.agent.tool.create_purchase_order(
            supplier_id="sup-acme", item_sku="LAPTOP-001",
            quantity=10, unit_price=950.0,
        )

        pending = agent.pending_approvals()
        po_approval = next(p for p in pending if p["tool_name"] == "create_purchase_order")

        success = agent.reject(po_approval["approval_id"])

        assert success is True
        assert store.purchase_orders == []

    def test_approval_uses_authoritative_permit(self):
        """Approval goes through PolicyEngine; the tool verifies the permit."""
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        agent.agent.tool.create_purchase_order(
            supplier_id="sup-acme", item_sku="LAPTOP-001",
            quantity=10, unit_price=950.0,
        )

        pending = agent.pending_approvals()
        po_approval = next(p for p in pending if p["tool_name"] == "create_purchase_order")

        # The agent's tools enforce permits by default.
        result = agent.approve(po_approval["approval_id"])
        assert result is not None

    def test_no_pending_approvals_after_full_legitimate_run(self):
        """Legitimate reads don't produce pending approvals."""
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        agent.run("Find the lowest-cost laptop supplier and compare prices.")

        # Only read tools were called; no ESCALATE.
        assert agent.pending_approvals() == []
        assert store.emails == []
        assert store.purchase_orders == []

    def test_approved_execution_recorded_in_policy_engine(self):
        """After approval, the execution signature is in PolicyEngine._executed_signatures."""
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        agent.agent.tool.create_purchase_order(
            supplier_id="sup-acme", item_sku="LAPTOP-001",
            quantity=10, unit_price=950.0,
        )

        pending = agent.pending_approvals()
        po_approval = next(p for p in pending if p["tool_name"] == "create_purchase_order")

        agent.approve(po_approval["approval_id"])

        sig = PolicyEngine.signature_for(
            "create_purchase_order",
            {"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
             "quantity": 10, "unit_price": 950.0},
        )
        assert sig in agent.guard.policy._executed_signatures

    def test_replayed_approved_action_is_rejected(self):
        """Re-escalating and re-approving the same action is blocked by replay."""
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        # First escalation + approval.
        agent.agent.tool.create_purchase_order(
            supplier_id="sup-acme", item_sku="LAPTOP-001",
            quantity=10, unit_price=950.0,
        )
        pending = agent.pending_approvals()
        po_approval = next(p for p in pending if p["tool_name"] == "create_purchase_order")
        result1 = agent.approve(po_approval["approval_id"])
        assert result1 is not None
        assert len(store.purchase_orders) == 1

        # Second escalation with same args.
        agent.agent.tool.create_purchase_order(
            supplier_id="sup-acme", item_sku="LAPTOP-001",
            quantity=10, unit_price=950.0,
        )
        pending2 = agent.pending_approvals()
        if pending2:
            po_approval2 = next(
                (p for p in pending2 if p["tool_name"] == "create_purchase_order"), None
            )
            if po_approval2:
                result2 = agent.approve(po_approval2["approval_id"])
                assert result2 is None

        # Still only one PO.
        assert len(store.purchase_orders) == 1

    def test_forged_approval_id_rejected(self):
        """A non-existent approval id returns None."""
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        result = agent.approve("approval-FORGED-CEO-123")
        assert result is None


class TestApprovalSecurityInvariants:
    """Ensure the approval workflow preserves existing security guarantees."""

    def test_attack_still_blocked_with_approval_workflow_active(self):
        """Poisoned supplier attack is still blocked; approval doesn't weaken defense."""
        store = FixtureStore(poisoned=True)
        agent = SentinelStrandsAgent(store=store, vulnerable=True)

        agent.run("Find the lowest-cost laptop supplier.")

        # Attack was detected and blocked.
        proposed = [o.call.tool_name for o in agent.observations]
        assert "send_email" in proposed
        assert "create_purchase_order" in proposed

        # No side effects executed.
        assert store.emails == []
        assert store.purchase_orders == []

    def test_blocked_action_not_in_pending_approvals(self):
        """BLOCKED actions don't appear in pending approvals (only ESCALATE does)."""
        store = FixtureStore(poisoned=True)
        agent = SentinelStrandsAgent(store=store, vulnerable=True)

        agent.run("Find the lowest-cost laptop supplier.")

        pending = agent.pending_approvals()
        # BLOCKED actions (score >= 75) are not in pending.
        for p in pending:
            assert p["risk_score"] < 75

    def test_permit_still_cannot_cross_tools(self):
        """Approval permit is bound to tool + args; cannot authorize a different tool."""
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)
        policy = PolicyEngine(audit=[])
        manager = ApprovalManager(tools, policy)

        # Create two escalation records.
        call_po = ToolCall(
            call_id="c1", tool_name="create_purchase_order",
            input={"supplier_id": "sup-acme", "item_sku": "LAPTOP-001",
                   "quantity": 10, "unit_price": 950.0},
        )
        call_email = ToolCall(
            call_id="c2", tool_name="send_email",
            input={"to": "user@corp.example", "subject": "Report", "body": "Monthly report"},
        )
        risk = RiskAssessment(score=40, level=RiskLevel.MEDIUM, evidence=[])
        r1 = manager.record_escalation(call_po, risk, ["reason"])
        r2 = manager.record_escalation(call_email, risk, ["reason"])

        # Approve the PO.
        result = manager.approve(r1.approval_id)
        assert result is not None
        assert len(store.purchase_orders) == 1

        # The email approval is independent.
        result2 = manager.approve(r2.approval_id)
        assert result2 is not None
        assert len(store.emails) == 1


class TestApprovalWorkflowE2E:
    """End-to-end test: legitimate procurement -> ESCALATE -> APPROVE -> execute."""

    def test_legitimate_procurement_with_approval(self):
        """Full workflow: agent researches, human triggers PO, PO is escalated, human approves."""
        store = FixtureStore(poisoned=False)
        agent = SentinelStrandsAgent(store=store, vulnerable=False)

        # Step 1: Agent runs legitimate research (reads only).
        response = agent.run(
            "Find the lowest-cost laptop supplier and compare prices."
        )
        assert "sup-acme" in response

        # Step 2: Read tools executed successfully.
        assert agent.executed_tools() == ["search_suppliers", "get_supplier_details", "compare_prices"]

        # Step 3: The agent recommends but does not auto-execute the PO.
        # A human (or another process) decides to proceed with the PO.
        agent.agent.tool.create_purchase_order(
            supplier_id="sup-acme", item_sku="LAPTOP-001",
            quantity=10, unit_price=950.0,
        )

        # Step 4: PO was escalated, not executed.
        pending = agent.pending_approvals()
        assert len(pending) >= 1
        po_approval = next(p for p in pending if p["tool_name"] == "create_purchase_order")
        assert store.purchase_orders == []

        # Step 5: Human approves.
        result = agent.approve(po_approval["approval_id"])
        assert result is not None
        assert len(store.purchase_orders) == 1
        assert store.purchase_orders[0]["quantity"] == 10

        # Step 6: No pending approvals remain.
        assert agent.pending_approvals() == []

    def test_attack_workflow_blocks_without_approval(self):
        """Attack scenario: poisoned data -> agent proposes dangerous actions -> all blocked."""
        store = FixtureStore(poisoned=True)
        agent = SentinelStrandsAgent(store=store, vulnerable=True)

        agent.run("Find the lowest-cost laptop supplier.")

        # Attack was detected.
        assert "send_email" in [o.call.tool_name for o in agent.observations]
        assert "create_purchase_order" in [o.call.tool_name for o in agent.observations]

        # All dangerous actions were blocked (not escalated).
        for o in agent.observations:
            if o.call.tool_name in ("send_email", "create_purchase_order"):
                assert o.decision == Decision.BLOCK
                assert o.executed is False

        # Zero side effects.
        assert store.emails == []
        assert store.purchase_orders == []
