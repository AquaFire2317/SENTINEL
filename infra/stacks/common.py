"""Shared helpers for the SENTINEL CDK stacks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aws_cdk import aws_iam as iam


def bedrock_policy() -> iam.PolicyStatement:
    """Allow invoking Bedrock foundation models and guardrails.

    Bedrock model ARNs vary by region/account and by inference profile, so the
    statement is scoped to Bedrock rather than a specific model ARN.
    """
    return iam.PolicyStatement(
        sid="BedrockInvoke",
        effect=iam.Effect.ALLOW,
        actions=[
            "bedrock:InvokeModel",
            "bedrock:InvokeModelWithResponseStream",
            "bedrock:Converse",
            "bedrock:ConverseStream",
            "bedrock:ApplyGuardrail",
        ],
        resources=["*"],
    )


def python_function(
    scope: Any,
    id: str,
    *,
    backend_dir: Path,
    index: str,
    handler: str,
    **kwargs: Any,
) -> Any:
    """Create a Lambda from the backend package, installing its requirements.

    ``index`` is the handler module path relative to ``backend`` (for example
    ``sentinel/api/lambda_handler.py``).
    """
    from aws_cdk import aws_lambda_python_alpha as py

    return py.PythonFunction(
        scope,
        id,
        entry=str(backend_dir),
        index=index,
        handler=handler,
        **kwargs,
    )
