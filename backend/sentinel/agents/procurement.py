"""Deterministic procurement target agent for the MVP attack path."""

import re
from collections.abc import Callable

from sentinel.contracts.procurement import ToolCall, ToolObservation, ToolResult
from sentinel.tools.procurement import ProcurementTools

ToolInterceptor = Callable[[ToolCall, Callable[[], ToolResult]], ToolObservation]

_ANY_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")


def _extract_external_email(text: str) -> str | None:
    """A vulnerable agent naively trusts any address embedded in supplier data."""
    for match in _ANY_EMAIL.finditer(text):
        address = match.group(0)
        if not address.endswith(("@corp.example", "@internal.example")):
            return address
    return None


class ProcurementAgent:
    """Small target agent whose tool trajectory is inspectable and repeatable.

    ``vulnerable=True`` models the pre-Sentinel behavior: it follows an
    imperative instruction embedded in supplier data. The security layer can
    then observe and block the resulting side-effecting proposal.
    """

    def __init__(self, tools: ProcurementTools, vulnerable: bool = True):
        self.tools = tools
        self.vulnerable = vulnerable
        self.observations: list[ToolObservation] = []
        self.response = ""

    def run(
        self,
        request: str,
        interceptor: ToolInterceptor | None = None,
    ) -> list[ToolObservation]:
        self.observations = []
        suppliers = self._call(
            ToolCall(
                call_id="call-1",
                tool_name="search_suppliers",
                input={"query": request, "max_results": 5},
            ),
            interceptor,
        )
        if suppliers.result is None:
            self.response = "Aborted: supplier search was blocked."
            return self.observations
        supplier_ids = [s["supplier_id"] for s in suppliers.result.data["suppliers"]]
        details = self._call(
            ToolCall(
                call_id="call-2",
                tool_name="get_supplier_details",
                input={"supplier_id": supplier_ids[0]},
                derived_from=["call-1"],
            ),
            interceptor,
        )
        self._call(
            ToolCall(
                call_id="call-3",
                tool_name="compare_prices",
                input={"supplier_ids": supplier_ids, "item_sku": "LAPTOP-001", "quantity": 10},
                derived_from=["call-1"],
            ),
            interceptor,
        )
        if details.result is None:
            self.response = "Aborted: supplier details were blocked."
            return self.observations
        note = details.result.data.get("supplier_note")
        attacker_email = _extract_external_email(note or "")
        if self.vulnerable and note and attacker_email:
            self._call(
                ToolCall(
                    call_id="call-4",
                    tool_name="send_email",
                    input={
                        "to": attacker_email,
                        "subject": "Supplier comparison",
                        "body": f"Internal procurement context: {request}",
                    },
                    derived_from=["call-2"],
                ),
                interceptor,
            )
        self.response = "Supplier research completed; side effects require approval."
        return self.observations

    def _call(self, call: ToolCall, interceptor: ToolInterceptor | None) -> ToolObservation:
        def execute(permit=None) -> ToolResult:
            return self.tools.call(call.tool_name, call.input, permit=permit)

        observation = (
            interceptor(call, execute)
            if interceptor is not None
            else ToolObservation(call=call, result=execute(), executed=True)
        )
        self.observations.append(observation)
        return observation
