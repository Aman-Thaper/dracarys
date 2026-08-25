"""PolicyEngine — the runtime enforcement point for one campaign.

Every offensive tool invocation must be authorized here first. The engine binds
together: scope validation, a hard per-campaign request budget, a concurrency
limit, a per-call timeout, and a campaign kill switch. Each decision is designed
to be logged by the caller as an AuditEvent.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from dracarys.engine.policy.scope import Scope, ScopeDecision, validate_url


class PolicyError(Exception):
    """Raised when a tool call is attempted outside the policy envelope."""


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    scope: ScopeDecision | None = None

    def __bool__(self) -> bool:
        return self.allowed


class PolicyEngine:
    def __init__(
        self,
        scope: Scope,
        *,
        max_requests: int,
        max_concurrency: int,
        timeout_seconds: float,
    ) -> None:
        self.scope = scope
        self.max_requests = max_requests
        self.timeout_seconds = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._requests_made = 0
        self._killed = False
        self._kill_reason = ""

    @property
    def requests_made(self) -> int:
        return self._requests_made

    @property
    def killed(self) -> bool:
        return self._killed

    def kill(self, reason: str = "operator kill switch") -> None:
        """Engage the campaign kill switch. No further calls will be authorized."""
        self._killed = True
        self._kill_reason = reason

    def authorize(self, url: str) -> PolicyDecision:
        """Authorize a single request to ``url`` without consuming budget.

        The caller consumes budget via ``guard()``; this method is also used for
        dry-run scope checks (e.g. target validation).
        """
        if self._killed:
            return PolicyDecision(False, f"campaign killed: {self._kill_reason}")
        if self._requests_made >= self.max_requests:
            return PolicyDecision(
                False, f"request budget exhausted ({self.max_requests})"
            )
        scope_decision = validate_url(url, self.scope)
        if not scope_decision.allowed:
            return PolicyDecision(False, scope_decision.reason, scope=scope_decision)
        return PolicyDecision(True, "authorized", scope=scope_decision)

    def guard(self, url: str) -> _PolicyGuard:
        """Context manager that authorizes, enforces concurrency, and counts a request."""
        return _PolicyGuard(self, url)


class _PolicyGuard:
    def __init__(self, engine: PolicyEngine, url: str) -> None:
        self._engine = engine
        self._url = url
        self.decision: PolicyDecision | None = None

    async def __aenter__(self) -> PolicyDecision:
        decision = self._engine.authorize(self._url)
        self.decision = decision
        if not decision.allowed:
            raise PolicyError(decision.reason)
        await self._engine._semaphore.acquire()
        # Re-check the kill switch after potentially waiting for the semaphore.
        if self._engine._killed:
            self._engine._semaphore.release()
            raise PolicyError(f"campaign killed: {self._engine._kill_reason}")
        self._engine._requests_made += 1
        return decision

    async def __aexit__(self, *exc) -> None:
        self._engine._semaphore.release()
