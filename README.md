# SENTINEL

SENTINEL is an autonomous reliability and security engineer for AI agents.
The MVP evaluates a procurement agent through:

`ATTACK -> DETECT -> EXPLAIN -> FIX -> RETEST -> LEARN`

The approved architecture is documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
The implementation plan is in [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md).

## Local setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest
```

Copy `.env.example` to `.env` when local configuration is needed. AWS and Bedrock
dependencies are optional until the cloud phase.

## Project layout

- `backend/sentinel`: application package
- `backend/tests`: unit and integration tests
- `infra`: AWS CDK infrastructure (added during the AWS phase)
- `frontend`: demo UI (added during the demo phase)
- `docs`: approved architecture and build plan
