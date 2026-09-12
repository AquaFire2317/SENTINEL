"""Load attack scenarios from JSON files."""

from pathlib import Path

from sentinel.contracts.workflow import AttackScenario

SCENARIOS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "scenarios"


def load_scenario(scenario_id: str) -> AttackScenario:
    path = SCENARIOS_DIR / f"{scenario_id}.json"
    if not path.exists():
        available = [p.stem for p in SCENARIOS_DIR.glob("*.json")]
        raise FileNotFoundError(
            f"Scenario '{scenario_id}' not found. Available: {available}"
        )
    import json

    data = json.loads(path.read_text())
    return AttackScenario(**data)


def list_scenarios() -> list[str]:
    return [p.stem for p in SCENARIOS_DIR.glob("*.json")]
