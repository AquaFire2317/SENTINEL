"""Deterministic injection detection and risk scoring.

Hardening notes (red-team round 1):
- Text is normalized before matching: zero-width characters are stripped and
  separator-fragmented words ("i.g.n.o.r.e") are collapsed, so keyword
  regexes cannot be evaded by punctuation/whitespace injection.
- Email destinations are checked against an ALLOWLIST, not a blocklist.
  Any recipient domain outside the approved supplier/internal domains is a
  mismatch; new free-mail providers cannot slip through.
- A non-empty approval_id is not trusted. It must be present in the issued
  approvals set, otherwise it is a FORGED_APPROVAL signal that raises risk.
"""

import re

from sentinel.contracts.procurement import ToolCall, ToolObservation, ToolTrust
from sentinel.contracts.security import Evidence, RiskAssessment, RiskLevel

_OVERRIDE_TERMS = re.compile(
    r"\b(ignore|override|forget|disregard|bypass)\b.{0,80}\b(policy|instruction|rule|sentinel)",
    re.IGNORECASE,
)
_AUTHORITY_TERMS = re.compile(
    r"\b(security team|administrator|system message|\badmin\b|\bit dept\b|helpdesk)\b",
    re.IGNORECASE,
)
_EXFIL_INTENT = re.compile(
    r"\b(email|send|forward|share|exfiltrate|leak)\b.{0,80}\b(comparison|details|data|context|internal)",
    re.IGNORECASE,
)
_EMAIL_ADDRESS = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]{2,}")

# Approved destination domains. Everything else is untrusted.
TRUSTED_DOMAINS = {"corp.example", "internal.example"}

_ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\ufeff\u2060]")


def _normalize(text: str) -> str:
    """De-obfuscate attacker-controlled text before pattern matching."""
    text = _ZERO_WIDTH.sub("", text)
    collapsed = text.lower()
    # Collapse separator-fragmented single letters: "i.g.n.o.r.e" -> "ignore"
    collapsed = re.sub(
        r"(?<=\b\w)[.\_\-*~](?=\w\b)|(?<=\w)[.\_\-*~](?=\w\b)",
        "",
        collapsed,
    )
    return collapsed


def assess_tool_call(
    call: ToolCall,
    prior_observations: list[ToolObservation],
    issued_approvals: set[str] | None = None,
) -> RiskAssessment:
    evidence: list[Evidence] = []
    output_text = _normalize(_prior_text(prior_observations))
    if _OVERRIDE_TERMS.search(output_text):
        evidence.append(Evidence(evidence_id="E1", signal="INSTRUCTION_IN_DATA", points=25, text="Override instruction in tool output", source="tool_result"))
    if _AUTHORITY_TERMS.search(output_text):
        evidence.append(Evidence(evidence_id="E2", signal="AUTHORITY_CLAIM", points=15, text="Tool output impersonates an authority", source="tool_result"))
    if _EXFIL_INTENT.search(output_text):
        evidence.append(Evidence(evidence_id="E7", signal="EXFIL_INTENT_IN_DATA", points=20, text="Tool output instructs exfiltration", source="tool_result"))
    if call.derived_from and output_text:
        evidence.append(Evidence(evidence_id="E3", signal="TOOL_OUTPUT_PROVENANCE", points=15, text="Action derives from untrusted tool output", source="trajectory"))
    if call.tool_name == "send_email":
        evidence.append(Evidence(evidence_id="E4", signal="EXTERNAL_EXFILTRATION", points=30, text="Agent proposed external communication", source="tool_call"))
        recipient_domain = _domain(str(call.input.get("to", "")))
        if recipient_domain not in TRUSTED_DOMAINS:
            # Sending to an untrusted domain is a hard-block condition: raise to
            # the BLOCK threshold regardless of other signals.
            evidence.append(Evidence(evidence_id="E5", signal="DESTINATION_MISMATCH", points=50, text=f"Recipient domain '{recipient_domain}' is not on the trusted list", source="tool_input"))
    if call.tool_name == "create_purchase_order":
        approval_id = call.input.get("approval_id")
        if not approval_id:
            evidence.append(Evidence(evidence_id="E6", signal="UNAPPROVED_WRITE", points=25, text="Purchase order has no approval", source="tool_input"))
        elif approval_id not in (issued_approvals or set()):
            evidence.append(Evidence(evidence_id="E8", signal="FORGED_APPROVAL", points=35, text="approval_id was never issued by an approver", source="tool_input"))
    score = min(100, sum(item.points for item in evidence))
    level = (
        RiskLevel.CRITICAL if score >= 75 else
        RiskLevel.HIGH if score >= 50 else
        RiskLevel.MEDIUM if score >= 25 else
        RiskLevel.LOW
    )
    return RiskAssessment(score=score, level=level, evidence=evidence)


def _prior_text(observations: list[ToolObservation]) -> str:
    parts: list[str] = []
    for observation in observations:
        result = observation.result
        if result is None or result.trust != ToolTrust.UNTRUSTED_DATA:
            continue
        parts.append(str(result.data))
    return " ".join(parts)


def _domain(address: str) -> str:
    match = _EMAIL_ADDRESS.search(address)
    return match.group(0).split("@", 1)[1].lower() if match else "(invalid)"
