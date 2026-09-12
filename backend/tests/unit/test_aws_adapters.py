from sentinel.evaluation.workflow import EvaluationWorkflow
from sentinel.orchestration.step_functions import StepFunctionsLauncher
from sentinel.persistence.dynamodb import DynamoReportRepository


class FakeTable:
    def __init__(self):
        self.items = []

    def put_item(self, Item):
        self.items.append(Item)


class FakeStepFunctions:
    def start_execution(self, **kwargs):
        assert kwargs["stateMachineArn"] == "arn:test"
        return {"executionArn": "arn:execution"}


def test_dynamodb_adapter_writes_run_item():
    table = FakeTable()
    report = EvaluationWorkflow().run()

    DynamoReportRepository("ignored", table).save(report)

    assert table.items[0]["PK"] == f"RUN#{report.run_id}"


def test_step_functions_adapter_starts_execution():
    launcher = StepFunctionsLauncher("arn:test", FakeStepFunctions())

    assert launcher.start({"run_id": "run-1"}) == "arn:execution"


def test_dynamodb_adapter_persists_strands_security_audit():
    """The Strands run's SENTINEL decisions are durably persisted per run."""
    from sentinel.integrations.strands_agent import SentinelStrandsAgent
    from sentinel.tools.fixtures import FixtureStore

    agent = SentinelStrandsAgent(store=FixtureStore(poisoned=True), vulnerable=True)
    agent.run("Find the lowest-cost laptop supplier.")

    table = FakeTable()
    written = DynamoReportRepository("ignored", table).save_security_audit(
        agent.run_id, agent.audit
    )

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
