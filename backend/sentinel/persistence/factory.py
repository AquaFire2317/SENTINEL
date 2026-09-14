"""Runtime factories that select durable AWS adapters when configured.

The security core never imports boto3 directly. Boundaries (the API handler,
Lambda entry point, and demo) call these factories, which fall back to the
in-memory adapters when AWS is not configured or unavailable. That keeps the
whole system runnable offline while still wiring real AWS services in prod.
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.config.settings import get_settings
from sentinel.persistence.memory import ReportRepository

logger = logging.getLogger("sentinel.runtime")


def build_report_repository() -> Any:
    """Return a durable report repository when configured, else in-memory."""
    settings = get_settings()
    if settings.use_durable_persistence:
        try:
            from sentinel.persistence.dynamodb import DynamoReportRepository

            logger.info("Using DynamoDB report repository (table=%s)", settings.table_name)
            return DynamoReportRepository(settings.table_name)
        except Exception as error:  # noqa: BLE001 - fall back to memory
            logger.warning(
                "DynamoDB persistence unavailable (%s: %s); falling back to in-memory",
                type(error).__name__,
                error,
            )
    return ReportRepository()


def build_step_functions_launcher() -> Any | None:
    """Return a Step Functions launcher when an ARN is configured, else None."""
    settings = get_settings()
    if not settings.state_machine_arn:
        return None
    try:
        from sentinel.orchestration.step_functions import StepFunctionsLauncher

        logger.info("Step Functions orchestration enabled (arn=%s)", settings.state_machine_arn)
        return StepFunctionsLauncher(settings.state_machine_arn)
    except Exception as error:  # noqa: BLE001 - orchestration is optional
        logger.warning(
            "Step Functions unavailable (%s: %s); running synchronously",
            type(error).__name__,
            error,
        )
        return None
