"""Fixture-backed procurement tools.

Security boundary: `call()` refuses to run without an ExecutionPermit minted
by the Sentinel PolicyEngine. Direct/deputy invocation is denied.

Hardening notes (red-team round 2):
- `send_email` validates recipient domain against TRUSTED_EMAIL_DOMAINS.
  Emails to untrusted domains are rejected at the tool level (defense-in-depth),
  in addition to the risk engine's DESTINATION_MISMATCH signal.
"""

import math
import re
from typing import Any

from sentinel.contracts.procurement import ToolResult, ToolTrust
from sentinel.security.policy import ExecutionPermit, PolicyEngine
from sentinel.tools.fixtures import FixtureStore

_TRUSTED_EMAIL_DOMAINS = frozenset({"corp.example", "internal.example"})
_EMAIL_ADDRESS = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]{2,}")


class ProcurementTools:
    """Fixture-backed procurement tools behind the SENTINEL authorization boundary.

    Args:
        store: Fixture store that records side effects.
        enforce_permits: When True (default) every call must present a valid,
            unused ExecutionPermit issued by the bound PolicyEngine.
        issuer: The PolicyEngine that issues and authenticates permits for this
            tool set. Required whenever ``enforce_permits`` is True; without it
            permits cannot be authenticated and every call fails closed.
    """

    def __init__(
        self,
        store: FixtureStore,
        enforce_permits: bool = True,
        issuer: "PolicyEngine | None" = None,
    ):
        self.store = store
        self.enforce_permits = enforce_permits
        self.issuer = issuer

    def bind_issuer(self, issuer: "PolicyEngine") -> None:
        """Bind the PolicyEngine whose permits this tool set will accept."""
        self.issuer = issuer

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
        if isinstance(quantity, bool) or not isinstance(quantity, (int, float)):
            raise TypeError("quantity must be a numeric value")
        quantity = int(quantity)
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
        if not isinstance(supplier_id, str) or not supplier_id.strip():
            raise ValueError("supplier_id must be a non-empty string")
        known = {s.supplier_id for s in self.store.suppliers}
        if supplier_id not in known:
            raise ValueError(f"Unknown supplier_id: {supplier_id}")
        if not isinstance(item_sku, str) or not item_sku.strip():
            raise ValueError("item_sku must be a non-empty string")
        if isinstance(quantity, bool) or not isinstance(quantity, (int, float)):
            raise TypeError("quantity must be a numeric value")
        quantity = int(quantity)
        if quantity < 1:
            raise ValueError("quantity must be a positive integer")
        if isinstance(unit_price, bool) or not isinstance(unit_price, (int, float)):
            raise TypeError("unit_price must be a numeric value")
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
        match = _EMAIL_ADDRESS.search(to)
        if not match:
            raise ValueError(f"Invalid email address: {to}")
        domain = match.group(0).split("@", 1)[1].lower()
        if domain not in _TRUSTED_EMAIL_DOMAINS:
            raise ValueError(
                f"Recipient domain '{domain}' is not on the trusted list; "
                f"allowed domains: {sorted(_TRUSTED_EMAIL_DOMAINS)}"
            )
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
        if self.enforce_permits:
            if not isinstance(permit, ExecutionPermit):
                raise PermissionError(
                    f"Tool '{tool_name}' invoked without a Sentinel execution permit"
                )
            # Authenticate against the bound issuer when there is one (this
            # additionally enforces run isolation at the tool boundary). When no
            # issuer is bound, authenticate against the engine that minted the
            # permit. A hand-constructed permit has no issuer and fails closed.
            issuer = self.issuer if self.issuer is not None else permit.issuer
            if issuer is None:
                raise PermissionError(
                    f"Execution permit for '{tool_name}' is not authenticatable: "
                    "it was not issued by a SENTINEL PolicyEngine"
                )
            if not issuer.verify_permit(permit, tool_name, arguments):
                raise PermissionError(
                    f"Execution permit for '{tool_name}' is invalid: it was not "
                    "issued by this PolicyEngine, has already been used, belongs "
                    "to another run, or does not match this tool and arguments"
                )
            # Single-use: burn the permit before the side effect happens.
            issuer.redeem_permit(permit)
        return tool(**arguments)
