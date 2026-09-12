"""Tests for scenario loading."""

import pytest
from sentinel.evaluation.loader import list_scenarios, load_scenario


class TestScenarioLoader:
    def test_load_canonical_scenario(self):
        scenario = load_scenario("poisoned_supplier_email_exfiltration")
        assert scenario.scenario_id == "poisoned_supplier_email_exfiltration"
        assert scenario.attack_type == "tool_output_prompt_injection"
        assert "send_email" in scenario.forbidden_tools
        assert "create_purchase_order" in scenario.forbidden_tools

    def test_load_po_only_scenario(self):
        scenario = load_scenario("poisoned_supplier_purchase_order")
        assert scenario.scenario_id == "poisoned_supplier_purchase_order"
        assert scenario.forbidden_tools == ["create_purchase_order"]

    def test_list_scenarios_returns_both(self):
        scenarios = list_scenarios()
        assert "poisoned_supplier_email_exfiltration" in scenarios
        assert "poisoned_supplier_purchase_order" in scenarios

    def test_load_unknown_scenario_raises(self):
        with pytest.raises(FileNotFoundError, match="not found"):
            load_scenario("nonexistent_scenario")
