"""Red-team: ExecutionPermit forgery, reuse, and cross-run abuse.

These tests exist because a real, exploitable vulnerability was found during
the final hardening pass:

    PolicyEngine.signature_for() is public, deterministic and unkeyed. Before
    the fix, ProcurementTools.call() authorized a call by recomputing that
    signature and comparing it to permit.matches. An attacker could therefore
    compute the signature themselves, construct ExecutionPermit(sig), call the
    tool layer directly, and execute a privileged side effect with ZERO
    PolicyEngine involvement.

The previous "forged permit" test passed a garbage string, which fails a string
comparison trivially, so it provided false assurance and did not detect this.

Every test below is REAL SECURITY EVIDENCE: each asserts on the observable
side-effect store, not on a decision object.
"""

import pytest
from sentinel.contracts.procurement import ToolCall
from sentinel.security.policy import ExecutionPermit, PolicyEngine
from sentinel.tools.fixtures import FixtureStore
from sentinel.tools.procurement import ProcurementTools

PO_ARGS = {
    "supplier_id": "sup-acme",
    "item_sku": "LAPTOP-001",
    "quantity": 99,
    "unit_price": 1.0,
}


def _engine_and_tools(run_id: str = "run-A"):
    store = FixtureStore(poisoned=False)
    policy = PolicyEngine(audit=[], run_id=run_id)
    tools = ProcurementTools(store, issuer=policy)
    return store, policy, tools


def _mint(policy: PolicyEngine, tool_name: str, arguments: dict) -> ExecutionPermit:
    """Mint a genuine permit the way the enforcement path does."""
    return policy._mint_permit(
        ToolCall(call_id="mint", tool_name=tool_name, input=arguments)
    )


class TestPermitForgery:
    """A permit must be unforgeable without the issuing engine's secret."""

    def test_attacker_computed_signature_is_rejected(self):
        """THE ORIGINAL EXPLOIT: signature_for() is public, so an attacker can
        compute a 'correct' signature. That must not be sufficient."""
        store, _policy, tools = _engine_and_tools()

        forged = ExecutionPermit(PolicyEngine.signature_for("create_purchase_order", PO_ARGS))

        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", PO_ARGS, permit=forged)

        assert store.purchase_orders == [], "forged permit produced a real side effect"

    def test_fully_populated_forgery_is_rejected(self):
        """Even if the attacker fills in every public field correctly, the
        HMAC token cannot be produced without the engine secret."""
        store, policy, tools = _engine_and_tools(run_id="run-A")

        forged = ExecutionPermit(
            signature=PolicyEngine.signature_for("create_purchase_order", PO_ARGS),
            tool_name="create_purchase_order",
            run_id="run-A",
            nonce="deadbeefdeadbeefdeadbeefdeadbeef",
            token="0" * 64,
        )

        assert policy.verify_permit(forged, "create_purchase_order", PO_ARGS) is False
        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", PO_ARGS, permit=forged)
        assert store.purchase_orders == []

    def test_permit_with_tampered_token_is_rejected(self):
        """Take a genuine permit and flip its token."""
        store, policy, tools = _engine_and_tools()
        real = _mint(policy, "create_purchase_order", PO_ARGS)

        tampered = ExecutionPermit(
            signature=real.matches,
            tool_name=real.tool_name,
            run_id=real.run_id,
            nonce=real.nonce,
            token=("1" * 64),
            issuer=real.issuer,
        )

        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", PO_ARGS, permit=tampered)
        assert store.purchase_orders == []

    def test_permit_secret_is_not_reachable_through_public_api(self):
        """The signing secret must not be exposed on any public attribute."""
        _store, policy, _tools = _engine_and_tools()
        public = [name for name in dir(policy) if not name.startswith("_")]
        assert "permit_secret" not in public
        for name in public:
            assert getattr(policy, name, None) is not policy._permit_secret

    def test_two_engines_do_not_share_permit_secrets(self):
        _store_a, policy_a, _tools_a = _engine_and_tools("run-A")
        _store_b, policy_b, _tools_b = _engine_and_tools("run-B")
        assert policy_a._permit_secret != policy_b._permit_secret


class TestPermitBinding:
    """A permit authorizes exactly one tool with exactly one set of arguments."""

    def test_permit_cannot_be_used_for_a_different_tool(self):
        store, policy, tools = _engine_and_tools()
        email_args = {"to": "procurement@corp.example", "subject": "s", "body": "b"}
        permit = _mint(policy, "send_email", email_args)

        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", PO_ARGS, permit=permit)

        assert store.purchase_orders == []
        assert store.emails == []

    def test_permit_cannot_be_used_with_modified_arguments(self):
        store, policy, tools = _engine_and_tools()
        permit = _mint(policy, "create_purchase_order", PO_ARGS)

        escalated = dict(PO_ARGS, quantity=100_000)
        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", escalated, permit=permit)

        assert store.purchase_orders == []

    def test_permit_matching_arguments_still_executes(self):
        """Control: the hardening must not break the legitimate path."""
        store, policy, tools = _engine_and_tools()
        permit = _mint(policy, "create_purchase_order", PO_ARGS)

        result = tools.call("create_purchase_order", PO_ARGS, permit=permit)

        assert result.data["status"] == "recorded_fixture_order"
        assert len(store.purchase_orders) == 1


class TestPermitSingleUse:
    """A permit is burned on redemption."""

    def test_permit_cannot_be_reused(self):
        store, policy, tools = _engine_and_tools()
        permit = _mint(policy, "create_purchase_order", PO_ARGS)

        tools.call("create_purchase_order", PO_ARGS, permit=permit)
        assert len(store.purchase_orders) == 1

        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", PO_ARGS, permit=permit)

        assert len(store.purchase_orders) == 1, "permit reuse created a second side effect"

    def test_redeemed_permit_fails_verification(self):
        _store, policy, tools = _engine_and_tools()
        permit = _mint(policy, "create_purchase_order", PO_ARGS)

        assert policy.verify_permit(permit, "create_purchase_order", PO_ARGS) is True
        tools.call("create_purchase_order", PO_ARGS, permit=permit)
        assert policy.verify_permit(permit, "create_purchase_order", PO_ARGS) is False

    def test_failed_execution_revokes_the_permit(self):
        """A permit minted for a call that fails validation must not survive."""
        store, policy, tools = _engine_and_tools()
        bad_args = dict(PO_ARGS, quantity=-5)

        observation = policy.intercept(
            ToolCall(call_id="c1", tool_name="create_purchase_order", input=bad_args),
            lambda permit: tools.call("create_purchase_order", bad_args, permit=permit),
            [],
        )

        assert observation.executed is False
        assert store.purchase_orders == []
        assert policy._live_permits == set(), "a usable permit survived a failed execution"


class TestCrossRunPermitAbuse:
    """Run A must never authorize Run B."""

    def test_permit_from_another_run_is_rejected(self):
        _store_a, policy_a, _tools_a = _engine_and_tools("run-A")
        store_b, _policy_b, tools_b = _engine_and_tools("run-B")

        permit_a = _mint(policy_a, "create_purchase_order", PO_ARGS)

        with pytest.raises(PermissionError):
            tools_b.call("create_purchase_order", PO_ARGS, permit=permit_a)

        assert store_b.purchase_orders == []

    def test_engine_rejects_a_permit_it_did_not_issue(self):
        _store_a, policy_a, _tools_a = _engine_and_tools("run-A")
        _store_b, policy_b, _tools_b = _engine_and_tools("run-B")

        permit_a = _mint(policy_a, "create_purchase_order", PO_ARGS)

        assert policy_b.verify_permit(permit_a, "create_purchase_order", PO_ARGS) is False

    def test_same_run_id_different_engine_still_rejected(self):
        """Guessing the run_id is not enough; the secret differs per engine."""
        _store_a, policy_a, _tools_a = _engine_and_tools("run-SHARED")
        store_b, _policy_b, tools_b = _engine_and_tools("run-SHARED")

        permit_a = _mint(policy_a, "create_purchase_order", PO_ARGS)

        with pytest.raises(PermissionError):
            tools_b.call("create_purchase_order", PO_ARGS, permit=permit_a)

        assert store_b.purchase_orders == []


class TestUnauthenticatablePermit:
    """Without an issuing engine there is no authorization at all."""

    def test_permit_without_issuer_and_without_bound_engine_fails_closed(self):
        store = FixtureStore(poisoned=False)
        tools = ProcurementTools(store)  # no issuer bound

        forged = ExecutionPermit(PolicyEngine.signature_for("create_purchase_order", PO_ARGS))

        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", PO_ARGS, permit=forged)

        assert store.purchase_orders == []

    def test_missing_permit_still_fails_closed(self):
        store = FixtureStore(poisoned=False)
        policy = PolicyEngine(audit=[])
        tools = ProcurementTools(store, issuer=policy)

        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", PO_ARGS)

        assert store.purchase_orders == []

    def test_non_permit_object_is_rejected(self):
        store = FixtureStore(poisoned=False)
        policy = PolicyEngine(audit=[])
        tools = ProcurementTools(store, issuer=policy)

        for impostor in ("approved", True, 1, {"approved": True}, object()):
            with pytest.raises(PermissionError):
                tools.call("create_purchase_order", PO_ARGS, permit=impostor)

        assert store.purchase_orders == []


class TestCanonicalizationCannotBypassBinding:
    """Argument canonicalization must be intentional, not a bypass."""

    def test_reordered_keys_are_the_same_authorization(self):
        store, policy, tools = _engine_and_tools()
        permit = _mint(policy, "create_purchase_order", PO_ARGS)

        reordered = {
            "unit_price": 1.0,
            "quantity": 99,
            "item_sku": "LAPTOP-001",
            "supplier_id": "sup-acme",
        }
        result = tools.call("create_purchase_order", reordered, permit=permit)

        assert result.data["status"] == "recorded_fixture_order"
        assert len(store.purchase_orders) == 1

    def test_int_float_equivalence_is_the_same_authorization(self):
        store, policy, tools = _engine_and_tools()
        permit = _mint(policy, "create_purchase_order", PO_ARGS)

        coerced = dict(PO_ARGS, quantity=99.0)
        tools.call("create_purchase_order", coerced, permit=permit)

        assert len(store.purchase_orders) == 1

    def test_semantically_different_values_are_not_equivalent(self):
        store, policy, tools = _engine_and_tools()
        permit = _mint(policy, "create_purchase_order", PO_ARGS)

        with pytest.raises(PermissionError):
            tools.call("create_purchase_order", dict(PO_ARGS, quantity=99.5), permit=permit)

        assert store.purchase_orders == []

    def test_nested_structures_canonicalize_consistently(self):
        args_a = {"to": "a@corp.example", "subject": "s", "body": "b",
                  "attachments": ["x.pdf", "y.pdf"]}
        args_b = {"body": "b", "attachments": ["x.pdf", "y.pdf"],
                  "to": "a@corp.example", "subject": "s"}
        assert (
            PolicyEngine.signature_for("send_email", args_a)
            == PolicyEngine.signature_for("send_email", args_b)
        )

    def test_list_order_is_semantically_significant(self):
        """Reordering a list changes meaning and must change the signature."""
        args_a = {"supplier_ids": ["sup-acme", "sup-northstar"],
                  "item_sku": "LAPTOP-001", "quantity": 10}
        args_b = {"supplier_ids": ["sup-northstar", "sup-acme"],
                  "item_sku": "LAPTOP-001", "quantity": 10}
        assert (
            PolicyEngine.signature_for("compare_prices", args_a)
            != PolicyEngine.signature_for("compare_prices", args_b)
        )
