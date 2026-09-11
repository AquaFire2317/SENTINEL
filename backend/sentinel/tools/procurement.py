"""Fixture-backed procurement tools.

Security boundary: `call()` refuses to run without an ExecutionPermit minted
by the Sentinel PolicyEngine. Direct/deputy invocation is denied.
"""

import math
from typing import Any

from sentinel.contracts.procurement import ToolResult, ToolTrust
from sentinel.security.policy import ExecutionPermit, PolicyEngine
from sentinel.tools.fixtures import FixtureStore


class ProcurementTools:
    def __init__(self, store: FixtureStore, enforce_permits: bool = True):
        self.store = store
        self.enforce_permits = enforce_permits

    def search_suppliers(self, query: str, max_results: int = 5) -> ToolResult:
        if max_results < 1 or max_results > 50:
            raise ValueError("max_results must be between 1 and 50")
        suppliers = [s.model_dump() for s in self.store.suppliers[:max_results]]
        return ToolResult(
            tool_name="search_suppliers",
            trust=ToolTrust.UNTRUSTED_DATA,
            data={"query": query, "suppliers": suppliers},
            fixture_id="supplier-search-v1",
        )

    def get_supplier_details(self, supplier_id: str) -> ToolResult:
        supplier = self.store.supplier(supplier_id)
        return ToolResult(
            tool_name="get_supplier_details",
            trust=ToolTrust.UNTRUSTED_DATA,
            data=supplier.model_dump(),
            fixture_id="supplier-details-v1",
        )

    def compare_prices(self, supplier_ids: list[str], item_sku: str, quantity: int) -> ToolResult:
        if quantity < 1:
            raise ValueError("quantity must be a positive integer")
        known = {s.supplier_id for s in self.store.suppliers}
        unknown = [s for s in supplier_ids if s not in known]
        if unknown:
            raise ValueError(f"Unknown supplier ids: {unknown}")
        quotes = self.store.quotes(supplier_ids, item_sku, quantity)
        return ToolResult(
            tool_name="compare_prices",
            trust=ToolTrust.UNTRUSTED_DATA,
            data={"quotes": [q.model_dump() for q in quotes]},
            fixture_id="price-comparison-v1",
        )

    def create_purchase_order(
        self,
        supplier_id: str,
        item_sku: str,
        quantity: int,
        unit_price: float,
        approval_id: str | None = None,
    ) -> ToolResult:
        if quantity < 1:
            raise ValueError("quantity must be a positive integer")
        if not math.isfinite(unit_price) or unit_price <= 0:
            raise ValueError("unit_price must be a positive finite number")
        order = {
            "supplier_id": supplier_id,
            "item_sku": item_sku,
            "quantity": quantity,
            "unit_price": unit_price,
            "approval_id": approval_id,
        }
        self.store.purchase_orders.append(order)
        return ToolResult(
            tool_name="create_purchase_order",
            trust=ToolTrust.TRUSTED,
            data={"status": "recorded_fixture_order", "order": order},
            fixture_id="purchase-order-v1",
        )

    def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        attachments: list[str] | None = None,
    ) -> ToolResult:
        message = {
            "to": to,
            "subject": subject,
            "body": body,
            "attachments": attachments or [],
        }
        self.store.emails.append(message)
        return ToolResult(
            tool_name="send_email",
            trust=ToolTrust.TRUSTED,
            data={"status": "recorded_fixture_email", "message": message},
            fixture_id="email-v1",
        )

    def call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        permit: ExecutionPermit | None = None,
    ) -> ToolResult:
        tool = getattr(self, tool_name, None)
        if callable(tool) is False or tool_name.startswith("_"):
            raise ValueError(f"Unknown procurement tool: {tool_name}")
        if self.enforce_permits and not isinstance(permit, ExecutionPermit):
            raise PermissionError(
                f"Tool '{tool_name}' invoked without a Sentinel execution permit"
            )
        if self.enforce_permits and permit.matches != PolicyEngine.signature_for(
            tool_name, arguments
        ):
            raise PermissionError(
                f"Execution permit does not match tool '{tool_name}' call signature"
            )
        return tool(**arguments)
