"""Load attack scenarios from JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.contracts.workflow import AttackScenario

SCENARIOS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "scenarios"


class ScenarioNotFoundError(FileNotFoundError):
    """Raised when a scenario id has no backing JSON file."""


def _scenario_path(scenario_id: str) -> Path:
    # Guard against path traversal: only allow simple ids.
    if not scenario_id or any(part in scenario_id for part in ("/", "\\", "..")):
        raise ScenarioNotFoundError(f"Invalid scenario id: {scenario_id!r}")
    return SCENARIOS_DIR / f"{scenario_id}.json"


def load_scenario(scenario_id: str) -> AttackScenario:
    """Load and validate a scenario into the typed contract."""
    path = _scenario_path(scenario_id)
    if not path.exists():
        available = list_scenarios()
        raise ScenarioNotFoundError(
            f"Scenario '{scenario_id}' not found. Available: {available}"
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    return AttackScenario(**data)


def load_scenario_raw(scenario_id: str) -> dict[str, Any]:
    """Load a scenario's raw JSON, including presentation-only metadata."""
    path = _scenario_path(scenario_id)
    if not path.exists():
        raise ScenarioNotFoundError(
            f"Scenario '{scenario_id}' not found. Available: {list_scenarios()}"
        )
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return data


def list_scenarios() -> list[str]:
    """Return the ids of all available scenarios."""
    return sorted(p.stem for p in SCENARIOS_DIR.glob("*.json"))


def list_scenario_catalog() -> list[dict[str, Any]]:
    """Return presentation metadata for every scenario."""
    catalog: list[dict[str, Any]] = []
    for scenario_id in list_scenarios():
        try:
            raw = load_scenario_raw(scenario_id)
        except (ScenarioNotFoundError, json.JSONDecodeError):
            continue
        catalog.append(
            {
                "scenario_id": raw.get("scenario_id", scenario_id),
                "name": raw.get("name", scenario_id),
                "input": raw.get("input", ""),
                "attack_type": raw.get("attack_type", "unknown"),
                "description": raw.get("description", ""),
                "expected_result": raw.get("expected_result", ""),
                "forbidden_tools": raw.get("forbidden_tools", []),
                "must_detect": raw.get("must_detect", True),
                "fixture_version": raw.get("fixture_version", "v1"),
            }
        )
    return catalog
