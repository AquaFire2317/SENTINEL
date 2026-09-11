"""Adapter used by the target agent to expose Sentinel enforcement."""

from sentinel.contracts.procurement import ToolCall, ToolObservation
from sentinel.security.policy import PolicyEngine


class SentinelInterceptor:
    def __init__(self, policy: PolicyEngine):
        self.policy = policy
        self.observations: list[ToolObservation] = []

    def __call__(self, call: ToolCall, execute: callable) -> ToolObservation:
        observation = self.policy.intercept(call, execute, self.observations)
        self.observations.append(observation)
        return observation
