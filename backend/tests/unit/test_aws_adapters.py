from sentinel.evaluation.workflow import EvaluationWorkflow
from sentinel.orchestration.step_functions import StepFunctionsLauncher
from sentinel.persistence.dynamodb import DynamoReportRepository


class _FakeBatchWriter:
    """Context manager that delegates put_item to the parent table."""

    def __init__(self, table: "FakeTable"):
        self._table = table

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def put_item(self, Item):
        self._table.items.append(Item)


class FakeTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item):
        self.items.append(Item)

    def batch_writer(self):
        return _FakeBatchWriter(self)

    def get_item(self, Key):
        for item in self.items:
            if item.get("PK") == Key.get("PK") and item.get("SK") == Key.get("SK"):
                return {"Item": item}
        return {}

    def query(self, **kwargs):
        pk = kwargs.get("ExpressionAttributeValues", {}).get(":pk", "")
        items = [i for i in self.items if i.get("PK") == pk]
        return {"Items": items}


class FakeStepFunctions:
    def start_execution(self, **kwargs):
        assert kwargs["stateMachineArn"] == "arn:test"
        return {"executionArn": "arn:execution"}

    def describe_execution(self, executionArn):
        return {
            "executionArn": executionArn,
            "status": "SUCCEEDED",
            "output": '{"result": "ok"}',
        }


def test_dynamodb_adapter_writes_run_item():
    table = FakeTable()
    report = EvaluationWorkflow().run()

    DynamoReportRepository("ignored", table).save(report)

    assert table.items[0]["PK"] == f"RUN#{report.run_id}"


def test_step_functions_adapter_starts_execution():
    launcher = StepFunctionsLauncher("arn:test", FakeStepFunctions())

    assert launcher.start({"run_id": "run-1"}) == "arn:execution"


def test_step_functions_adapter_describes_execution():
    launcher = StepFunctionsLauncher("arn:test", FakeStepFunctions())
    arn = launcher.start({"run_id": "run-1"})
    status = launcher.describe(arn)
    assert status["status"] == "SUCCEEDED"
    assert status["execution_arn"] == arn


def test_dynamodb_adapter_persists_strands_security_audit():
    """The Strands run's SENTINEL decisions are durably persisted per run."""
    from sentinel.integrations.strands_agent import SentinelStrandsAgent
    from sentinel.tools.fixtures import FixtureStore

    agent = SentinelStrandsAgent(store=FixtureStore(poisoned=True), vulnerable=True)
    agent.run("Find the lowest-cost laptop supplier.")

    table = FakeTable()
    repo = DynamoReportRepository("ignored", table)
    written = repo.save_security_audit(agent.run_id, agent.audit)

    assert written == len(agent.audit)
    assert all(item["PK"] == f"RUN#{agent.run_id}" for item in table.items)
    assert all(item["entity"] == "audit_event" for item in table.items)
    # The BLOCK decision on the exfiltration attempt is in the durable trail.
    assert any(
        item["event_type"] == "DECISION"
        and item["data"].get("decision") == "BLOCK"
        and "send_email" in item["message"]
        for item in table.items
    )


def test_dynamodb_adapter_retrieves_audit():
    """save_security_audit + get_audit round-trips correctly."""
    from sentinel.contracts.security import AuditEvent

    table = FakeTable()
    repo = DynamoReportRepository("ignored", table)

    events = [
        AuditEvent(event_id="e1", event_type="DECISION", message="BLOCK send_email", run_id="r1"),
        AuditEvent(event_id="e2", event_type="DECISION", message="ALLOW search", run_id="r1"),
    ]
    repo.save_security_audit("r1", events)
    retrieved = repo.get_audit("r1")
    assert len(retrieved) == 2
    assert retrieved[0].event_type == "DECISION"


def test_dynamodb_adapter_retrieves_report():
    """save + get round-trips a report."""
    table = FakeTable()
    repo = DynamoReportRepository("ignored", table)
    report = EvaluationWorkflow().run()
    repo.save(report)
    retrieved = repo.get(report.run_id)
    assert retrieved is not None
    assert retrieved.run_id == report.run_id


def test_dynamodb_adapter_get_nonexistent():
    table = FakeTable()
    repo = DynamoReportRepository("ignored", table)
    assert repo.get("nonexistent") is None
