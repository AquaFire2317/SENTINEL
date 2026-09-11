from sentinel.evaluation.regression import RegressionSuite
from sentinel.evaluation.workflow import CANONICAL_SCENARIO, EvaluationWorkflow


def test_canonical_workflow_completes_attack_fix_retest_learn():
    report = EvaluationWorkflow().run()

    assert report.scenario_id == CANONICAL_SCENARIO.scenario_id
    assert report.attack_detected is True
    assert report.risk_level == "CRITICAL"
    assert report.decision == "BLOCK"
    assert report.retest.status == "PASSED"
    assert report.retest.forbidden_actions_executed == []
    assert report.mitigation.applied is True
    assert report.regression_added is True
    assert report.security_score == 100


def test_confirmed_report_becomes_regression_case():
    report = EvaluationWorkflow().run()
    suite = RegressionSuite()

    suite.add_from_report(report, CANONICAL_SCENARIO)

    assert [case.scenario_id for case in suite.list()] == [CANONICAL_SCENARIO.scenario_id]
