"""Small in-memory report repository used by the local API and demo."""

from sentinel.contracts.workflow import EvaluationReport


class ReportRepository:
    def __init__(self):
        self._reports: dict[str, EvaluationReport] = {}

    def save(self, report: EvaluationReport) -> EvaluationReport:
        self._reports[report.run_id] = report
        return report

    def get(self, run_id: str) -> EvaluationReport | None:
        return self._reports.get(run_id)

    def list(self) -> list[EvaluationReport]:
        return list(self._reports.values())
