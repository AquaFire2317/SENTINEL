# Changelog

All notable changes to SENTINEL will be documented in this file.

## [0.3.0] - 2026-09-14

### Added
- Provider-agnostic model factory: `local`, `bedrock`, `anthropic`, `openai`,
  `openrouter`, `openai_compatible`, `litellm`, `ollama`, `gemini`, `mistral`.
  SENTINEL guards any Strands-supported model, not just Bedrock.
- Read-only API endpoints: `/config`, `/providers`, `/agents`, `/tools`,
  `/policies`, `/scenarios`, `/scenarios/{id}`, `/runs` (list).
- Scenario-aware `POST /runs` (accepts `scenario_id`) and run-summary listing.
- Unified request router used by the local server, Vercel, and AWS Lambda.
- AWS Lambda entry points for the HTTP API and the evaluation worker.
- Deployable AWS CDK application (`infra/`): data, compute, workflow, and
  API/CloudFront stacks with DynamoDB, S3, Step Functions, and IAM wiring.
- Runtime persistence factory: DynamoDB when `SENTINEL_TABLE_NAME` is set,
  in-memory otherwise.
- Frontend: real data wired across Agents, Tools, Policies, Integrations,
  Scenarios, Evaluations, and Settings; runtime-configurable backend URL;
  loading/error states; scenario report viewer.
- Tests for the provider factory and the new API endpoints.

### Fixed
- Production routing: the served frontend calls `/api/*`, but the API handlers
  expected unprefixed paths, so `--serve-frontend` (and the Docker image) 404'd
  on every API call. The router now normalizes the `/api` prefix.
- `POST /runs` ignored `scenario_id`, so Scenarios-page cards ran the wrong
  scenario. Scenarios are now loaded and validated by id.
- Docker `HEALTHCHECK` and CMD now pass end-to-end; the image installs from
  `backend/requirements.txt` and runs as a non-root user.
- Toast animation referenced `tailwindcss-animate` (not installed); replaced
  with a local keyframe.
- `SecurityPipeline` had eight steps but seven icons, misaligning the pipeline.

### Changed
- HTTP server is now multi-threaded (`ThreadingHTTPServer`) with configurable
  host, port, and CORS origin, plus security headers and request-size limits.
- `pyproject.toml` version bumped to 0.3.0 and provider SDK extras added.

## [0.1.0] - 2026-09-12

### Added
- Initial project scaffold
- Backend package structure (agents, api, config, contracts, evaluation, orchestration, persistence, security, tools)
- Procurement agent with fixture tools
- Sentinel interceptor and policy engine
- Risk scoring and detection pipeline
- Evaluation workflow
- DynamoDB and in-memory persistence adapters
- Step Functions orchestration
- Demo CLI entry point
- Unit tests for all core modules
- Integration tests for workflow
- Red-team attack tests
- Frontend demo UI with dark theme
- Architecture documentation
- Build plan documentation
- Contributing guidelines
- MIT License

### Security
- Deterministic fail-closed interceptor
- Tool output provenance tracking
- Prompt injection detection
- External exfiltration prevention
