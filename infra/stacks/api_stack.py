"""API stack: HTTP API (Lambda), CloudFront-hosted dashboard, and S3 site bucket."""

from __future__ import annotations

from pathlib import Path

from aws_cdk import CfnOutput, Duration, Fn, RemovalPolicy, Stack
from aws_cdk import aws_apigatewayv2 as apigwv2
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as origins
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_s3_deployment as s3deploy
from aws_cdk import aws_stepfunctions as sfn
from constructs import Construct

from stacks.common import bedrock_policy, python_function


class ApiStack(Stack):
    """Public HTTP API plus a CloudFront distribution for the SPA dashboard.

    CloudFront routes ``/api/*`` to the HTTP API and everything else to S3,
    so the browser talks to the API on the same origin (``/api`` base).
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        table: dynamodb.Table,
        bucket: s3.Bucket,
        state_machine: sfn.StateMachine,
        backend_dir: Path,
        frontend_dist: Path,
        model_config: dict[str, str],
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        environment = {
            **{k: v for k, v in model_config.items() if v},
            "SENTINEL_TABLE_NAME": table.table_name,
            "SENTINEL_BUCKET_NAME": bucket.bucket_name,
            "SENTINEL_STATE_MACHINE_ARN": state_machine.state_machine_arn,
            "SENTINEL_SERVE_FRONTEND": "false",
            "AWS_REGION": self.region,
        }

        self.api_function = python_function(
            self,
            "ApiFunction",
            backend_dir=backend_dir,
            index="sentinel/api/lambda_handler.py",
            handler="handler",
            runtime=lambda_.Runtime.PYTHON_3_13,
            timeout=Duration.seconds(29),
            memory_size=512,
            environment=environment,
            tracing=lambda_.Tracing.ACTIVE,
            log_retention=logs.RetentionDays.ONE_MONTH,
        )
        table.grant_read_write_data(self.api_function)
        bucket.grant_read_write(self.api_function)
        state_machine.grant_start_execution(self.api_function)
        self.api_function.add_to_role_policy(bedrock_policy())

        self.http_api = apigwv2.HttpApi(
            self,
            "SentinelHttpApi",
            api_name="sentinel-api",
            create_default_stage=True,
            default_integration=integrations.HttpLambdaIntegration(
                "ApiIntegration", self.api_function
            ),
        )

        CfnOutput(self, "ApiEndpoint", value=self.http_api.api_endpoint)

        # --- Frontend hosting ------------------------------------------------
        site_bucket = s3.Bucket(
            self,
            "SiteBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        distribution = cloudfront.Distribution(
            self,
            "Dashboard",
            default_root_object="index.html",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3Origin(site_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                cache_policy=cloudfront.CachePolicy.CACHING_OPTIMIZED,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
            ),
            additional_behaviors={
                "/api/*": cloudfront.BehaviorOptions(
                    origin=origins.HttpOrigin(
                        Fn.select(1, Fn.split("://", self.http_api.api_endpoint)),
                        protocol_policy=cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
                    ),
                    viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                    cache_policy=cloudfront.CachePolicy.CACHING_DISABLED,
                    origin_request_policy=cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
                    allowed_methods=cloudfront.AllowedMethods.ALLOW_ALL,
                )
            },
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=200,
                    response_page_path="/index.html",
                ),
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                ),
            ],
        )

        self.api_function.add_environment(
            "SENTINEL_CORS_ORIGIN", f"https://{distribution.distribution_domain_name}"
        )

        if frontend_dist.is_dir():
            s3deploy.BucketDeployment(
                self,
                "DeployDashboard",
                sources=[s3deploy.Source.asset(str(frontend_dist))],
                destination_bucket=site_bucket,
                distribution=distribution,
                distribution_paths=["/*"],
            )
        else:
            print(
                f"[warn] frontend build not found at {frontend_dist}; "
                "run `npm run build` in frontend/ before deploying the dashboard."
            )

        CfnOutput(self, "DashboardUrl", value=f"https://{distribution.distribution_domain_name}")
        CfnOutput(self, "SiteBucketName", value=site_bucket.bucket_name)
