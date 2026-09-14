"""Presentation catalogs backing the read-only dashboard endpoints.

These describe the *actual* enforcement model in SENTINEL — the tool boundary,
the policy rules, and the guarded agent — so the dashboard reflects real
configuration rather than hardcoded sample data.
"""

from __future__ import annotations

from typing import Any

from sentinel.integrations.providers import describe_active_model
from sentinel.security.policy import READ_TOOLS, SIDE_EFFECT_TOOLS

_TOOL_META: dict[str, dict[str, Any]] = {
    "search_suppliers": {
        "category": "Research",
        "risk": "LOW",
        "requires_approval": False,
        "policy": "Research Policy",
    },
    "get_supplier_details": {
        "category": "Research",
        "risk": "LOW",
        "requires_approval": False,
        "policy": "Research Policy",
    },
    "compare_prices": {
        "category": "Research",
        "risk": "LOW",
        "requires_approval": False,
        "policy": "Research Policy",
    },
    "create_purchase_order": {
        "category": "Financial",
        "risk": "HIGH",
        "requires_approval": True,
        "policy": "Privileged Side Effects",
    },
    "send_email": {
        "category": "Communication",
        "risk": "HIGH",
        "requires_approval": True,
        "policy": "Data Exfiltration Policy",
    },
}

# Ordered so reads appear before side effects in the dashboard.
TOOL_ORDER = (
    "search_suppliers",
    "get_supplier_details",
    "compare_prices",
    "create_purchase_order",
    "send_email",
)


def tool_catalog(call_counts: dict[str, int] | None = None) -> list[dict[str, Any]]:
    """Return metadata for every allowlisted tool.

    Args:
        call_counts: Optional per-tool invocation count for the current period.
    """
    counts = call_counts or {}
    entries: list[dict[str, Any]] = []
    for name in TOOL_ORDER:
        meta = _TOOL_META[name]
        entries.append(
            {
                "name": name,
                "category": meta["category"],
                "risk": meta["risk"],
                "requires_approval": meta["requires_approval"],
                "policy": meta["policy"],
                "status": "protected",
                "calls_today": counts.get(name, 0),
                "kind": "read" if name in READ_TOOLS else "side_effect",
            }
        )
    return entries


def policy_catalog() -> list[dict[str, Any]]:
    """Return the enforcement rules that the PolicyEngine actually applies."""
    return [
        {
            "id": "unknown-tool-block",
            "name": "Unknown Tool Block",
            "description": "Any tool that is not on the allowlist is blocked before it can run.",
            "condition": "tool_name NOT IN allowlist",
            "action": "BLOCK",
            "target_tools": ["*"],
            "enabled": True,
        },
        {
            "id": "prompt-injection-detection",
            "name": "Prompt Injection Detection",
            "description": "Actions following injected instructions in tool output are blocked.",
            "condition": "INSTRUCTION_IN_DATA OR AUTHORITY_CLAIM",
            "action": "BLOCK",
            "target_tools": list(SIDE_EFFECT_TOOLS),
            "enabled": True,
        },
        {
            "id": "external-data-exfiltration",
            "name": "External Data Exfiltration",
            "description": "Sending data to an external destination derived from untrusted output is blocked.",
            "condition": "destination is external AND derived_from UNTRUSTED_DATA",
            "action": "BLOCK",
            "target_tools": ["send_email"],
            "enabled": True,
        },
        {
            "id": "replay-defense",
            "name": "Replay Defense",
            "description": "Duplicate side-effect calls with the same normalized signature are denied.",
            "condition": "signature IN executed_signatures",
            "action": "BLOCK",
            "target_tools": list(SIDE_EFFECT_TOOLS),
            "enabled": True,
        },
        {
            "id": "privileged-side-effect-approval",
            "name": "Privileged Side Effect Approval",
            "description": "Every side effect below the block threshold requires explicit human approval.",
            "condition": "tool IN side_effect_tools AND risk_score < 75",
            "action": "ESCALATE",
            "target_tools": list(SIDE_EFFECT_TOOLS),
            "enabled": True,
        },
        {
            "id": "fail-closed-on-error",
            "name": "Fail Closed On Error",
            "description": "Any evaluation or dispatch failure is converted into a BLOCK.",
            "condition": "evaluation_error OR dispatch_error",
            "action": "BLOCK",
            "target_tools": ["*"],
            "enabled": True,
        },
    ]


def agent_catalog() -> list[dict[str, Any]]:
    """Return the guarded Strands agent with its *live* provider configuration."""
    active = describe_active_model()
    if active["provider"] == "local":
        provider_label = "Local"
        model_label = "Deterministic planner"
    else:
        provider_label = active["provider_name"]
        model_label = active["model_id"] or "unset"
    return [
        {
            "id": "procurement-agent",
            "name": "Procurement Agent",
            "status": "protected",
            "provider": provider_label,
            "model": model_label,
            "tools": list(TOOL_ORDER),
            "risk_profile": "MEDIUM",
            "policy_set": "Procurement Policy",
            "secured_by": "SentinelToolGuard (BeforeToolCallEvent)",
        }
    ]


def config_catalog() -> dict[str, Any]:
    """Return non-secret runtime configuration for the dashboard."""
    from sentinel import __version__
    from sentinel.config.settings import get_settings

    settings = get_settings()
    model = describe_active_model()
    return {
        "version": __version__,
        "environment": settings.environment,
        "mode": settings.mode,
        "policy_version": "v2",
        "allowlisted_tools": list(TOOL_ORDER),
        "read_tools": sorted(READ_TOOLS),
        "side_effect_tools": sorted(SIDE_EFFECT_TOOLS),
        "model": {
            "provider": model["provider"],
            "provider_name": model["provider_name"],
            "model_id": model["model_id"],
            "sdk_installed": model["sdk_installed"],
            "api_key_set": model["api_key_set"],
            "base_url": model["base_url"],
        },
        "persistence": {
            "durable": settings.use_durable_persistence,
            "table_name": settings.table_name,
        },
        "orchestration": {
            "step_functions": bool(settings.state_machine_arn),
        },
        "aws_region": settings.aws_region,
    }
