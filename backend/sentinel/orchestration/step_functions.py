"""Optional Step Functions launcher; local execution stays synchronous."""

from typing import Any


class StepFunctionsLauncher:
    def __init__(self, state_machine_arn: str, client: Any | None = None):
        if client is None:
            import boto3

            client = boto3.client("stepfunctions")
        self.client = client
        self.state_machine_arn = state_machine_arn

    def start(self, run_input: dict) -> str:
        import json

        response = self.client.start_execution(
            stateMachineArn=self.state_machine_arn,
            input=json.dumps(run_input),
        )
        return response["executionArn"]
