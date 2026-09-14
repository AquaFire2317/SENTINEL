"""Optional DynamoDB adapters for the AWS deployment phase.

Both adapters accept an injected client so they are unit-testable without AWS.

Architecture:
    Domain/Security -> Persistence Interface -> MemoryPersistence | DynamoDBPersistence

The PolicyEngine never depends directly on boto3. Instead, the persistence
layer is injected at the application boundary (API handler, demo, or Step
Functions lambda).
"""

from __future__ import annotations

import logging
from typing import Any

from sentinel.contracts.security import AuditEvent
from sentinel.contracts.workflow import EvaluationReport

logger = logging.getLogger("sentinel.persistence.dynamodb")


class DynamoReportRepository:
    """DynamoDB-backed report and audit persistence.

    Table schema (single-table design):
        PK: RUN#{run_id}  SK: META          -> EvaluationReport
        PK: RUN#{run_id}  SK: AUDIT#{seq}   -> AuditEvent

    Args:
        table_name: DynamoDB table name.
        client: Injected boto3 Table resource. If None, creates one from env.
    """

    def __init__(self, table_name: str, client: Any | None = None):
        if client is None:
            import boto3

            client = boto3.resource("dynamodb").Table(table_name)
        self.table = client

    def save(self, report: EvaluationReport) -> None:
        item = report.model_dump(mode="json")
        item.update({"PK": f"RUN#{report.run_id}", "SK": "META", "entity": "run"})
        self.table.put_item(Item=item)

    def get(self, run_id: str) -> EvaluationReport | None:
        """Retrieve a report by run_id. Returns None if not found."""
        response = self.table.get_item(Key={"PK": f"RUN#{run_id}", "SK": "META"})
        item = response.get("Item")
        if not item:
            return None
        return EvaluationReport.model_validate(item)

    def list(self) -> list[EvaluationReport]:
        """Return every stored report.

        Uses a filtered scan. This is appropriate for the low-volume
        administrative dashboard; a high-volume deployment would maintain a
        GSI keyed on creation time instead.
        """
        response = self.table.scan(
            FilterExpression="#entity = :entity",
            ExpressionAttributeNames={"#entity": "entity"},
            ExpressionAttributeValues={":entity": "run"},
        )
        reports: list[EvaluationReport] = []
        for item in response.get("Items", []):
            try:
                reports.append(EvaluationReport.model_validate(item))
            except Exception as error:  # noqa: BLE001 - skip malformed items
                logger.warning("Skipping malformed run item: %s", error)
                continue
        return reports

    def save_security_audit(self, run_id: str, audit: list[AuditEvent]) -> int:
        """Persist a run's SENTINEL decisions as a durable audit trail.

        Each event becomes its own item so decisions stay queryable per run.
        Uses batch writer for efficiency.

        Args:
            run_id: Correlation id for the agent run.
            audit: Audit events emitted by the PolicyEngine.

        Returns:
            Number of items written.
        """
        written = 0
        with self.table.batch_writer() as batch:
            for index, event in enumerate(audit, start=1):
                item = event.model_dump(mode="json")
                item.update(
                    {
                        "PK": f"RUN#{run_id}",
                        "SK": f"AUDIT#{index:04d}",
                        "entity": "audit_event",
                    }
                )
                batch.put_item(Item=item)
                written += 1
        return written

    def get_audit(self, run_id: str) -> list[AuditEvent]:
        """Retrieve all audit events for a run, ordered by sequence."""
        response = self.table.query(
            KeyConditionExpression="PK = :pk AND begins_with(SK, :sk_prefix)",
            ExpressionAttributeValues={
                ":pk": f"RUN#{run_id}",
                ":sk_prefix": "AUDIT#",
            },
            ScanIndexForward=True,
        )
        items = response.get("Items", [])
        return [AuditEvent.model_validate(item) for item in items]
