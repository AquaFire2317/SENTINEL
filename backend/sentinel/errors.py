"""Application-level errors with stable error codes."""


class SentinelError(Exception):
    """Base class for expected application failures."""

    code = "SENTINEL_ERROR"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ConfigurationError(SentinelError):
    code = "CONFIGURATION_ERROR"


class ScenarioNotFoundError(SentinelError):
    code = "SCENARIO_NOT_FOUND"


class PolicyEvaluationError(SentinelError):
    code = "POLICY_EVALUATION_ERROR"
