# SENTINEL

**Autonomous Reliability & Security Engineer for AI Agents**

Built for the **AWS Hackathon**

## Overview

SENTINEL continuously monitors AI agents, detects vulnerabilities, explains risks, and autonomously applies fixes — then retests to confirm the fix works. Think of it as an immune system for AI agents.

## How It Works

```
ATTACK -> DETECT -> EXPLAIN -> FIX -> RETEST -> LEARN
```

1. **Attack** — Red-team probes attempt to bypass the agent's safeguards
2. **Detect** — Security interceptor catches suspicious behavior in real-time
3. **Explain** — Risk engine classifies severity and generates human-readable explanations
4. **Fix** — Policy engine autonomously updates agent defenses
5. **Retest** — Regression tests verify the fix doesn't break core functionality
6. **Learn** — Results are persisted to improve future detection

## Tech Stack

- **Backend:** Python 3.11, FastAPI
- **AI/ML:** AWS Bedrock, Amazon Titan
- **Infrastructure:** AWS CDK, DynamoDB, Step Functions
- **Testing:** pytest, custom red-team attack suite

## Project Structure

```
SENTINEL/
├── backend/
│   ├── sentinel/           # Core application
│   │   ├── agents/         # Agent wrappers
│   │   ├── api/            # FastAPI handlers
│   │   ├── config/         # Settings & configuration
│   │   ├── contracts/      # Data models & schemas
│   │   ├── evaluation/     # Regression & workflow tests
│   │   ├── orchestration/  # AWS Step Functions integration
│   │   ├── persistence/    # DynamoDB & in-memory stores
│   │   ├── security/       # Interceptor, risk engine, policy
│   │   └── tools/          # Procurement tools & fixtures
│   └── tests/              # Unit, integration & red-team tests
├── docs/                   # Architecture & build plan
├── frontend/               # Demo UI
└── infra/                  # AWS CDK infrastructure
```

## Local Setup

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest
```

Copy `.env.example` to `.env` when local configuration is needed. AWS and Bedrock dependencies are optional until the cloud phase.

## License

MIT
