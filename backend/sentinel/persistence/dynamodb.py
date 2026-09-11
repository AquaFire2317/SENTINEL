"""Optional DynamoDB report adapter for the AWS deployment phase."""

from typing import Any

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
