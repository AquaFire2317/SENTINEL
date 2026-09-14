# SENTINEL AWS Deployment (CDK)

This directory contains a deployable AWS CDK (Python) application. The
application logic is provider-agnostic; the AWS services back the *control
plane* (durable audit, orchestration, hosting), not the model.

## Stacks

| Stack | Resources | Purpose |
|---|---|---|
| `SentinelDataStack` | DynamoDB table (`sentinel-audit`), S3 artifact bucket | Durable evaluation reports + per-run security audit trail |
| `SentinelComputeStack` | Worker Lambda | Executes one ATTACK→REGRESS evaluation, writes audit to DynamoDB |
| `SentinelWorkflowStack` | Step Functions state machine (`sentinel-evaluation`) | Durable, retryable orchestration of evaluation runs |
| `SentinelApiStack` | API Lambda + API Gateway HTTP API + CloudFront + S3 site bucket | JSON API and the hosted dashboard (CloudFront routes `/api/*` to the API, everything else to the SPA) |

## Prerequisites

- AWS CLI configured with credentials
- Node.js 18+ (`npm install -g aws-cdk`)
- Python 3.11+
- Docker (used by CDK to bundle the Lambda dependencies)

## Deploy

```bash
cd infra
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Build the dashboard so it is uploaded by the API stack
cd ../frontend && npm ci && npm run build && cd ../infra

cdk bootstrap aws://<account>/<region>
cdk deploy --all
```

After deployment, CloudFront serves the dashboard; its URL is printed as
`SentinelApiStack.DashboardUrl`. The dashboard talks to the same origin at
`/api/*`.

## Model provider configuration

The provider is selected entirely by environment variables at deploy time —
SENTINEL does not depend on Bedrock:

```bash
# OpenRouter (OpenAI-compatible)
export SENTINEL_MODEL_PROVIDER=openrouter
export SENTINEL_MODEL_ID=anthropic/claude-3.7-sonnet
export SENTINEL_MODEL_API_KEY=sk-or-...

# Anthropic direct
export SENTINEL_MODEL_PROVIDER=anthropic
export SENTINEL_MODEL_ID=claude-3-7-sonnet-latest
export SENTINEL_MODEL_API_KEY=sk-ant-...

# Amazon Bedrock (uses the Lambda execution role; no API key needed)
export SENTINEL_MODEL_PROVIDER=bedrock
export SENTINEL_MODEL_ID=us.anthropic.claude-3-5-sonnet-20241022-v2:0

cdk deploy --all
```

Supported providers: `local`, `bedrock`, `anthropic`, `openai`, `openrouter`,
`openai_compatible`, `litellm`, `ollama`, `gemini`, `mistral`.

> **Secrets:** passing `SENTINEL_MODEL_API_KEY` as an environment variable is
> convenient for evaluation. For production, store the key in AWS Secrets
> Manager and reference it from the Lambda (grant `secretsmanager:GetSecretValue`
> and read it at cold start) instead of embedding it in the stack.

## Notes

- The API Lambda and worker both receive `SENTINEL_TABLE_NAME` and
  `SENTINEL_BUCKET_NAME`, which activate the DynamoDB adapters automatically.
- The API Lambda is granted `states:StartExecution` so it can dispatch durable
  runs to the state machine.
- Provider SDKs other than Bedrock (`anthropic`, `litellm`, `ollama`, `google`,
  `mistralai`, `openai`) must be installed in the Lambda bundle. Add them to
  `backend/requirements.txt` (or install the matching
  `strands-agents[<provider>]` extra) before deploying.
