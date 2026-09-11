"""In-memory regression suite with a future persistence seam."""

from sentinel.contracts.workflow import AttackScenario, EvaluationReport


class RegressionSuite:
    def __init__(self):
        self.cases: dict[str, AttackScenario] = {}

    def add_from_report(self, report: EvaluationReport, scenario: AttackScenario) -> None:
        if report.regression_added:
            self.cases[scenario.scenario_id] = scenario

    def list(self) -> list[AttackScenario]:
        return list(self.cases.values())
