"""Procurement domain contracts shared by tools and agents."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ToolTrust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED_DATA = "untrusted_data"


class ToolCall(BaseModel):
    call_id: str
    tool_name: str
    input: dict[str, Any] = Field(default_factory=dict)
    source: str = "target_agent"
    derived_from: list[str] = Field(default_factory=list)


class ToolResult(BaseModel):
    tool_name: str
    trust: ToolTrust = ToolTrust.UNTRUSTED_DATA
    data: Any
    fixture_id: str


class ToolObservation(BaseModel):
    call: ToolCall
    result: ToolResult | None = None
    proposed: bool = True
    executed: bool = False
    decision: str | None = None


class Supplier(BaseModel):
    supplier_id: str
    name: str
    email: str
    rating: float
    supplier_note: str | None = None


class PriceQuote(BaseModel):
    supplier_id: str
    item_sku: str
    quantity: int
    unit_price: float
    currency: str = "USD"
