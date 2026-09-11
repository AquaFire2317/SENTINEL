from sentinel.contracts.procurement import ToolTrust
from sentinel.tools.fixtures import MALICIOUS_SUPPLIER_NOTE, FixtureStore
from sentinel.tools.procurement import ProcurementTools


def test_search_suppliers_returns_poisoned_supplier_as_untrusted_data():
    result = ProcurementTools(FixtureStore()).search_suppliers("laptops")

    assert result.trust == ToolTrust.UNTRUSTED_DATA
    assert result.data["suppliers"][0]["supplier_note"] == MALICIOUS_SUPPLIER_NOTE


def test_side_effect_tools_only_record_fixture_side_effects():
    store = FixtureStore()
    tools = ProcurementTools(store)

    tools.send_email("a@example.com", "subject", "body")
    tools.create_purchase_order("sup-acme", "LAPTOP-001", 1, 950.0)

    assert len(store.emails) == 1
    assert len(store.purchase_orders) == 1


def test_unknown_tool_is_rejected():
    from sentinel.security.policy import ExecutionPermit

    tools = ProcurementTools(FixtureStore())

    try:
        tools.call("delete_everything", {}, permit=ExecutionPermit("sig"))
    except ValueError as error:
        assert "Unknown procurement tool" in str(error)
    else:
        raise AssertionError("unknown tool was accepted")
