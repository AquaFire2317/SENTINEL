"""Evidence-backed user-facing explanations."""

from sentinel.contracts.security import SecurityDecision


def explain(decision: SecurityDecision) -> str:
    if decision.decision.value == "BLOCK":
        return (
            "Blocked because the proposed action was derived from untrusted supplier data "
            "and would create a dangerous external side effect. "
            + "; ".join(decision.reasons)
        )
    if decision.decision.value == "ESCALATE":
        return "Escalation required before a side effect: " + "; ".join(decision.reasons)
    return "Allowed because no blocking security signal was found."
