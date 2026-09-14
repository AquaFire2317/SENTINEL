"""Compute stack: the evaluation worker Lambda."""

from __future__ import annotations

from pathlib import Path

from aws_cdk import Duration, Stack
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_logs as logs
from constructs import Construct

from stacks.common import bedrock_policy, python_function


class ComputeStack(Stack):
    """The worker Lambda that executes one SENTINEL evaluation.

    It is invoked by the Step Functions state machine (or directly) and writes
    reports + audit events to DynamoDB.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        table: dynamodb.Table,
        bucket: s3.Bucket,
        backend_dir: Path,
        model_config: dict[str, str],
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        environment = {
            **{k: v for k, v in model_config.items() if v},
            "SENTINEL_TABLE_NAME": table.table_name,
            "SENTINEL_BUCKET_NAME": bucket.bucket_name,
            "AWS_REGION": self.region,
        }

        self.worker_function = python_function(
            self,
            "WorkerFunction",
            backend_dir=backend_dir,
            index="sentinel/orchestration/lambda_worker.py",
            handler="handler",
            runtime=lambda_.Runtime.PYTHON_3_13,
            timeout=Duration.minutes(5),
            memory_size=512,
            environment=environment,
            tracing=lambda_.Tracing.ACTIVE,
            log_retention=logs.RetentionDays.ONE_MONTH,
        )

        table.grant_read_write_data(self.worker_function)
        bucket.grant_read_write(self.worker_function)
        self.worker_function.add_to_role_policy(bedrock_policy())
