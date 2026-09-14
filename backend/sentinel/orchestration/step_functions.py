"""Optional Step Functions launcher; local execution stays synchronous.

This adapter wraps the AWS Step Functions StartExecution API. It does NOT
make SENTINEL depend on Step Functions for local execution. The evaluation
workflow runs synchronously in-process by default.

Production deployment would use this adapter inside a Lambda handler to
trigger the full ATTACK->DETECT->EXPLAIN->MITIGATE->RETEST->REGRESS
workflow as a Step Functions state machine.
"""

import json
from typing import Any


class StepFunctionsLauncher:
    """Launch a SENTINEL evaluation workflow via AWS Step Functions.

    Args:
        state_machine_arn: ARN of the Step Functions state machine.
        client: Injected boto3 StepFunctions client. If None, creates one from env.
    """

    def __init__(self, state_machine_arn: str, client: Any | None = None):
        if client is None:
            import boto3

            client = boto3.client("stepfunctions")
        self.client = client
        self.state_machine_arn = state_machine_arn

    def start(self, run_input: dict) -> str:
        """Start a new execution of the state machine.

        Args:
            run_input: JSON-serializable input for the state machine.

        Returns:
            The execution ARN of the started execution.

        Raises:
            RuntimeError: If the execution fails to start.
        """
        try:
            response = self.client.start_execution(
                stateMachineArn=self.state_machine_arn,
                input=json.dumps(run_input),
            )
            return response["executionArn"]
        except Exception as e:
            raise RuntimeError(
                f"Failed to start Step Functions execution: {e}"
            ) from e

    def describe(self, execution_arn: str) -> dict:
        """Get the current status of a running execution.

        Args:
            execution_arn: ARN of the execution to describe.

        Returns:
            Dictionary with execution status, output, and error info.
        """
        response = self.client.describe_execution(executionArn=execution_arn)
        return {
            "execution_arn": response.get("executionArn"),
            "status": response.get("status"),
            "output": response.get("output"),
            "error": response.get("error"),
            "cause": response.get("cause"),
        }
