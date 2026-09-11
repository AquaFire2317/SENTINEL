# Contributing to SENTINEL

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```powershell
# Clone the repo
git clone https://github.com/AquaFire2317/SENTINEL.git
cd SENTINEL

# Create virtual environment
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install -e ".[dev]"

# Run tests
pytest
```

## Code Style

- We use **ruff** for linting and formatting
- Run `ruff check .` before committing
- Run `ruff format .` to auto-format

## Pull Requests

1. Create a feature branch from `main`
2. Make your changes with clear commit messages
3. Add tests for new functionality
4. Ensure all tests pass
5. Open a PR with a clear description

## Reporting Issues

Open an issue on GitHub with:
- Steps to reproduce
- Expected vs actual behavior
- Environment details
