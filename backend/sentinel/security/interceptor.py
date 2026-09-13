"""Thin compatibility adapter for the SentinelInterceptor.

This module exists so that legacy code and tests that reference
``SentinelInterceptor`` continue to work without modification. It contains
NO policy logic, NO risk assessment, and NO decision making. It is a
pure pass-through to ``PolicyEngine.intercept()``.

New code should use ``PolicyEngine.intercept()`` directly.
"""

from sentinel.contracts.procurement import ToolCall, ToolObservation
from sentinel.security.policy import PolicyEngine


class SentinelInterceptor:
    """Compatibility adapter: converts ``(call, execute)`` into a
    ``PolicyEngine.intercept()`` call and accumulates observations.

    This class is NOT an enforcement path on its own. It delegates entirely
    to the single authoritative ``PolicyEngine.intercept()`` method and adds
    nothing beyond observation bookkeeping.
    """

    def __init__(self, policy: PolicyEngine):
        self.policy = policy
        self.observations: list[ToolObservation] = []

    def __call__(self, call: ToolCall, execute: callable) -> ToolObservation:
        observation = self.policy.intercept(call, execute, self.observations)
        self.observations.append(observation)
        return observation
