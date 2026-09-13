"""Bedrock Guardrails integration for SENTINEL.

Provides a defense-in-depth layer at the model level using Amazon Bedrock
Guardrails. This module validates prompts before they reach the LLM and
content after the LLM generates it, adding an additional security boundary
beyond SENTINEL's tool-level interception.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.contracts.security import Decision, RiskAssessment, RiskLevel, SecurityDecision


@dataclass
class GuardrailResult:
    """Result of a guardrail validation check."""

    passed: bool
    action: str  # "NONE", "BLOCK", "GUARDRAIL_INTERVENED"
    message: str | None = None
    detected_issues: list[str] | None = None


class BedrockGuardrails:
    """Integration with Amazon Bedrock Guardrails for prompt/output validation.

    This provides two validation points:
    1. Pre-inference: Validate the user prompt before sending to the model
    2. Post-inference: Validate the model output before returning to the user

    When AWS credentials are not available, the guardrails gracefully
    degrade to a passthrough mode (logs warning, allows traffic).
    """

    def __init__(
        self,
        guardrail_id: str | None = None,
        guardrail_version: str | None = None,
        region: str | None = None,
    ):
        self.guardrail_id = guardrail_id
        self.guardrail_version = guardrail_version or "DRAFT"
        self.region = region
        self._client: Any = None
        self._available = False

    def _get_client(self) -> Any:
        """Lazy-initialize the Bedrock Runtime client."""
        if self._client is not None:
            return self._client

        if not self.guardrail_id:
            return None

        try:
            import boto3
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self.region or "us-east-1",
            )
            self._available = True
            return self._client
        except (ImportError, RuntimeError):
            return None

    def validate_prompt(self, prompt: str) -> GuardrailResult:
        """Validate user prompt before model inference.

        Args:
            prompt: The user's input text to validate.

        Returns:
            GuardrailResult indicating if the prompt is safe to process.
        """
        client = self._get_client()
        if client is None or not self.guardrail_id:
            return GuardrailResult(
                passed=True,
                action="NONE",
                message="Guardrails not configured; allowing traffic",
            )

        try:
            response = client.apply_guardrail(
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion=self.guardrail_version,
                source="INPUT",
                content=[{"text": {"text": prompt}}],
            )

            action = response.get("action", "NONE")
            detected_issues = []
            for assessment in response.get("outputs", []):
                if "text" in assessment:
                    detected_issues.append(assessment["text"].get("text", ""))

            return GuardrailResult(
                passed=(action == "NONE"),
                action=action,
                message=f"Guardrail action: {action}",
                detected_issues=detected_issues if detected_issues else None,
            )
        except (KeyError, TypeError, ValueError) as e:
            return GuardrailResult(
                passed=True,
                action="NONE",
                message=f"Guardrail check failed (passthrough): {e}",
            )

    def validate_output(self, output: str) -> GuardrailResult:
        """Validate model output before returning to user.

        Args:
            output: The model's generated text to validate.

        Returns:
            GuardrailResult indicating if the output is safe to return.
        """
        client = self._get_client()
        if client is None or not self.guardrail_id:
            return GuardrailResult(
                passed=True,
                action="NONE",
                message="Guardrails not configured; allowing output",
            )

        try:
            response = client.apply_guardrail(
                guardrailIdentifier=self.guardrail_id,
                guardrailVersion=self.guardrail_version,
                source="OUTPUT",
                content=[{"text": {"text": output}}],
            )

            action = response.get("action", "NONE")
            detected_issues = []
            for assessment in response.get("outputs", []):
                if "text" in assessment:
                    detected_issues.append(assessment["text"].get("text", ""))

            return GuardrailResult(
                passed=(action == "NONE"),
                action=action,
                message=f"Guardrail action: {action}",
                detected_issues=detected_issues if detected_issues else None,
            )
        except (KeyError, TypeError, ValueError) as e:
            return GuardrailResult(
                passed=True,
                action="NONE",
                message=f"Guardrail check failed (passthrough): {e}",
            )

    def to_security_decision(self, result: GuardrailResult) -> SecurityDecision | None:
        """Convert a GuardrailResult to a SENTINEL SecurityDecision.

        Args:
            result: The guardrail validation result.

        Returns:
            SecurityDecision if the guardrail intervened, None otherwise.
        """
        if result.passed:
            return None

        risk_level = RiskLevel.CRITICAL if result.action == "GUARDRAIL_INTERVENED" else RiskLevel.HIGH
        return SecurityDecision(
            decision=Decision.BLOCK,
            risk=RiskAssessment(
                score=90 if result.action == "GUARDRAIL_INTERVENED" else 75,
                level=risk_level,
                evidence=[{"signal": "bedrock_guardrail", "text": result.message or "Guardrail intervention"}],
            ),
            reasons=[result.message or "Bedrock Guardrails blocked this content"],
            policy_version="v1",
            required_approval=False,
        )
