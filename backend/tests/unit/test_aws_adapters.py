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
