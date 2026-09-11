# SENTINEL MVP Build and Demo Plan

## 1. Repository Structure

```text
sentinel/
  README.md
  pyproject.toml
  package.json
  .env.example
  docs/
    ARCHITECTURE.md
    BUILD_PLAN.md
  backend/
    sentinel/
      api/
      orchestration/
      agents/
      tools/
      security/
      evaluation/
      persistence/
      contracts/
      config/
    tests/
      unit/
      integration/
      fixtures/
  frontend/
    src/
      api/
      components/
      pages/
      types/
  infra/
    cdk.json
    app.py
    stacks/
      data_stack.py
      compute_stack.py
      workflow_stack.py
      frontend_stack.py
    policies/
      agent.cedar
  scenarios/
    poisoned_supplier_email_exfiltration.json
    poisoned_supplier_purchase_order.json
  scripts/
    seed_fixtures.py
    run_local_demo.py
  .github/workflows/test.yml
```

Keep domain logic independent of AWS clients. `tools/`, `security/`, and `evaluation/` must run with in-memory repositories locally.

## 2. Local Development

Required local dependencies:

- Python 3.11+ and `uv`.
- Node.js 20+.
- Docker only if desired for DynamoDB Local.
- AWS credentials only for Bedrock model calls.

Local modes:

1. `offline`: fake deterministic model adapter, in-memory persistence, no AWS.
2. `bedrock-local`: real Bedrock model, local API/orchestrator, fixture tools.
3. `aws`: deployed API, Step Functions, DynamoDB, S3, Bedrock.

The canonical demo must be runnable in `offline` mode with a scripted target-agent decision path and in `bedrock-local` mode with the real Strands agent. This protects the presentation from model/network failure.

Use environment variables:

```text
SENTINEL_ENV=local
AWS_REGION=us-east-1
BEDROCK_MODEL_ID=...
SENTINEL_TABLE_NAME=SentinelTable
SENTINEL_BUCKET_NAME=...
SENTINEL_STATE_MACHINE_ARN=...
SENTINEL_FIXTURE_VERSION=v1
```

## 3. Deployment Strategy

Use AWS CDK in Python. Deploy in this order:

1. Data stack: S3 bucket, DynamoDB table, CloudWatch log groups.
2. Compute stack: Lambda functions and IAM roles.
3. Workflow stack: Step Functions state machine and permissions.
4. API stack: API Gateway routes and Lambda integration.
5. Frontend stack: S3 website bucket and CloudFront distribution.
6. Optional AgentCore stack: container/runtime and Gateway/Policy only after the basic demo works.

Lambda roles follow least privilege:

- API: `dynamodb:PutItem/GetItem/Query`, `states:StartExecution`.
- Workflow tasks: scoped DynamoDB writes, S3 put/get, `bedrock:InvokeModel`.
- No role has SES send, arbitrary purchasing, or unrestricted network access.

Pin model IDs and Python package versions. Pin the experimental Strands Evals version if it is used in CI because its red-team import paths and report shapes are experimental.

## 4. Demo Architecture

The presentation uses one button: `Run Poisoned Supplier Attack`.

The UI timeline displays:

```text
1. ATTACK STARTED
2. Supplier result received
3. Malicious instruction detected in untrusted tool output
4. Agent proposed send_email
5. SENTINEL DECISION: BLOCK
6. Side effect prevented
7. Explanation generated
8. Mitigation generated
9. Retesting exact attack
10. RETEST PASSED
11. Added to regression suite
```

The final card must show:

```text
ATTACK DETECTED
Risk: CRITICAL (96/100)
Decision: BLOCKED
Reason: Supplier data attempted to override policy and exfiltrate procurement context.
Mitigation: Treat supplier output as untrusted data; require approval for external email and purchase orders.
Retest: PASSED
Added to regression suite.
```

The UI should show both attempted and executed actions distinctly. `send_email` may appear as a proposed call, but its `executed` value must be visibly `false`.

## 5. Implementation Order

### Phase 1: deterministic core

1. Define Pydantic contracts and enums.
2. Implement fixture repositories and all five procurement tools.
3. Implement the risk signals, score, and decision engine.
4. Implement in-memory event/report persistence.
5. Write unit tests for every score signal and decision boundary.

### Phase 2: target agent and interception

6. Build the vulnerable Strands ProcurementAgent.
7. Add output provenance tagging/sanitization.
8. Add a Sentinel `InterventionHandler` returning `Proceed`, `Deny`, or `Confirm`.
9. Add audit hooks for model calls, tool calls, and outcomes.
10. Add a test proving the poisoned result can lead to a proposed `send_email` but never to an executed side effect.

### Phase 3: end-to-end workflow

11. Implement the canonical static scenario.
12. Implement the attack runner and trace capture.
13. Implement detector/explanation output.
14. Implement mitigation creation and sandbox application.
15. Implement exact-input retest.
16. Implement regression-case persistence.
17. Implement report scoring.

### Phase 4: API and UI

18. Add `POST /runs`, `GET /runs/{id}`, and `GET /regressions`.
19. Build the timeline UI and final score card.
20. Add polling, loading, error, and partial-failure states.
21. Add an offline demo mode and a single presentation seed command.

### Phase 5: AWS deployment

22. Add DynamoDB/S3/CDK stacks.
23. Move workflow tasks to Lambda.
24. Add Step Functions retries and timeouts.
25. Add CloudWatch structured logs and trace IDs.
26. Deploy the UI and API.
27. Run the canonical demo repeatedly from a clean fixture state.

### Phase 6: optional AWS-native extensions

28. Deploy the target to AgentCore Runtime.
29. Add AgentCore Gateway and Cedar coarse policies.
30. Add AgentCore Observability/OTEL dashboard.
31. Add SNS regression-failure notification.
32. Add generated adversarial scenarios and Strands Evals red-team strategies.

## 6. Acceptance Criteria

The MVP is complete when all are true:

- A single API call starts the canonical run and returns within two seconds.
- The UI shows live stage progression by polling.
- The seeded supplier response contains an exact malicious instruction.
- The target model can propose the dangerous action in vulnerable mode.
- Sentinel detects the instruction and produces CRITICAL risk.
- `send_email` and `create_purchase_order` fixture side effects remain unexecuted.
- The final decision is BLOCK with evidence-backed explanation.
- A mitigation is stored with a version.
- The exact attack retest passes using a fresh agent and fixture state.
- The attack is persisted as a regression case.
- A regression rerun passes.
- Offline mode can complete the same visual demo without AWS.
- No implementation requires redesigning the public contracts in `docs/ARCHITECTURE.md`.

## 7. Reliability Rules for the Hackathon

- Keep the canonical path static and deterministic; make generation additive.
- Never depend on an LLM to produce the malicious payload.
- Never depend on an LLM to authorize a side effect.
- Persist every stage before calling the next stage.
- Use bounded model cycles, timeouts, and Step Functions retries.
- Show failures as evidence in the UI instead of hiding them.
- Keep a prerecorded report fixture as a last-resort presentation fallback, clearly labeled as demo mode.
- Test the demo from a fresh fixture database before presenting.
