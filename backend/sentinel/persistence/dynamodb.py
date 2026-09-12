"""Optional DynamoDB adapters for the AWS deployment phase.

Both adapters accept an injected client so they are unit-testable without AWS.
"""

from typing import Any

from sentinel.contracts.security import AuditEvent
from sentinel.contracts.workflow import EvaluationReport


class DynamoReportRepository:
    def __init__(self, table_name: str, client: Any | None = None):
        if client is None:
            import boto3

            client = boto3.resource("dynamodb").Table(table_name)
        self.table = client

    def save(self, report: EvaluationReport) -> None:
        item = report.model_dump(mode="json")
        item.update({"PK": f"RUN#{report.run_id}", "SK": "META", "entity": "run"})
        self.table.put_item(Item=item)

    def save_security_audit(self, run_id: str, audit: list[AuditEvent]) -> int:
        """Persist a run's SENTINEL decisions as a durable audit trail.

        Each event becomes its own item so decisions stay queryable per run.

        Args:
            run_id: Correlation id for the agent run.
            audit: Audit events emitted by the PolicyEngine.

        Returns:
            Number of items written.
        """
        written = 0
        for index, event in enumerate(audit, start=1):
            item = event.model_dump(mode="json")
            item.update(
                {
                    "PK": f"RUN#{run_id}",
                    "SK": f"AUDIT#{index:04d}",
                    "entity": "audit_event",
                }
            )
            self.table.put_item(Item=item)
            written += 1
        return written
