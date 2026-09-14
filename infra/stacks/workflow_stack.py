"""Workflow stack: durable Step Functions orchestration of evaluation runs."""

from __future__ import annotations

from aws_cdk import Duration, Stack
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_stepfunctions as sfn
from aws_cdk import aws_stepfunctions_tasks as tasks
from constructs import Construct


class WorkflowStack(Stack):
    """State machine that runs the ATTACK -> REGRESS workflow durably."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        worker: lambda_.IFunction,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        run_evaluation = tasks.LambdaInvoke(
            self,
            "RunEvaluation",
            lambda_function=worker,
            payload=sfn.TaskInput.from_object(
                {"scenario_id.$": "$.scenario_id"}
            ),
            output_path="$.Payload",
        )

        fail = sfn.Fail(
            self,
            "EvaluationFailed",
            error="EvaluationError",
            cause="The evaluation worker returned an error status",
        )
        succeeded = sfn.Succeed(self, "EvaluationSucceeded")
        check = sfn.Choice(self, "CheckStatus")
        check.when(sfn.Condition.string_equals("$.status", "COMPLETED"), succeeded)
        check.otherwise(fail)

        definition = run_evaluation.next(check)

        self.state_machine = sfn.StateMachine(
            self,
            "EvaluationStateMachine",
            state_machine_name="sentinel-evaluation",
            definition_body=sfn.DefinitionBody.from_chainable(definition),
            timeout=Duration.minutes(15),
            tracing_enabled=True,
            logs=sfn.LogOptions(
                destination=logs.LogGroup(self, "StateMachineLogs"),
                level=sfn.LogLevel.ALL,
                include_execution_data=True,
            ),
        )
