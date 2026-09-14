#!/usr/bin/env python3
"""SENTINEL AWS CDK application.

Deploys the SENTINEL control plane to AWS:

    SentinelDataStack      DynamoDB audit/report table + S3 artifact bucket
    SentinelComputeStack   Evaluation worker Lambda (Step Functions target)
    SentinelWorkflowStack  Step Functions state machine for durable runs
    SentinelApiStack       API Lambda (HTTP API) + CloudFront-hosted dashboard

The model provider is provider-agnostic. Configure it with the environment
variables below before ``cdk deploy``:

    SENTINEL_MODEL_PROVIDER   local | bedrock | anthropic | openai | openrouter
                              | openai_compatible | litellm | ollama | gemini
                              | mistral                (default: bedrock)
    SENTINEL_MODEL_ID         Model id (e.g. an OpenRouter or Bedrock model id)
    SENTINEL_MODEL_API_KEY    API key for hosted providers (prefer Secrets Manager)
    SENTINEL_MODEL_BASE_URL   Base URL for OpenAI-compatible endpoints
    AWS_REGION / CDK_DEFAULT_REGION

Usage:
    pip install -r requirements.txt
    cdk bootstrap
    cdk deploy --all
"""

import os
from pathlib import Path

import aws_cdk as cdk

from stacks.api_stack import ApiStack
from stacks.compute_stack import ComputeStack
from stacks.data_stack import DataStack
from stacks.workflow_stack import WorkflowStack

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
FRONTEND_DIST = REPO_ROOT / "frontend" / "dist"

app = cdk.App()

region = os.environ.get("CDK_DEFAULT_REGION") or os.environ.get("AWS_REGION", "us-east-1")
env = cdk.Environment(
    account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
    region=region,
)

# Provider configuration shared by both Lambdas. Values are non-secret except
# the API key; for production, store the key in Secrets Manager and reference
# it here instead of passing it in plaintext.
model_config = {
    "SENTINEL_MODEL_PROVIDER": os.environ.get("SENTINEL_MODEL_PROVIDER", "bedrock"),
    "SENTINEL_MODEL_ID": os.environ.get("SENTINEL_MODEL_ID", ""),
    "SENTINEL_MODEL_API_KEY": os.environ.get("SENTINEL_MODEL_API_KEY", ""),
    "SENTINEL_MODEL_BASE_URL": os.environ.get("SENTINEL_MODEL_BASE_URL", ""),
    "SENTINEL_MODE": os.environ.get("SENTINEL_MODE", "local"),
    "SENTINEL_ENV": os.environ.get("SENTINEL_ENV", "production"),
    "SENTINEL_LOG_LEVEL": os.environ.get("SENTINEL_LOG_LEVEL", "INFO"),
}

data_stack = DataStack(app, "SentinelDataStack", env=env)

compute_stack = ComputeStack(
    app,
    "SentinelComputeStack",
    table=data_stack.table,
    bucket=data_stack.bucket,
    backend_dir=BACKEND_DIR,
    model_config=model_config,
    env=env,
)
compute_stack.add_dependency(data_stack)

workflow_stack = WorkflowStack(
    app,
    "SentinelWorkflowStack",
    worker=compute_stack.worker_function,
    env=env,
)
workflow_stack.add_dependency(compute_stack)

api_stack = ApiStack(
    app,
    "SentinelApiStack",
    table=data_stack.table,
    bucket=data_stack.bucket,
    state_machine=workflow_stack.state_machine,
    backend_dir=BACKEND_DIR,
    frontend_dist=FRONTEND_DIST,
    model_config=model_config,
    env=env,
)
api_stack.add_dependency(data_stack)
api_stack.add_dependency(workflow_stack)

app.synth()
