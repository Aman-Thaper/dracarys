"""Attack planner — turns observations into prioritized, testable hypotheses.

The planner is pluggable (see llm_planner.LLMPlanner). Whatever proposes a
hypothesis, the hypothesis is only ever *confirmed* by a deterministic attack
module. The planner decides WHAT to try and in what order — never whether a
vulnerability exists.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from dracarys.agents.attacks import ATTACK_MODULES
from dracarys.domain.enums import VulnCategory

# Modules whose confirmation reaches the protected canary (chain endpoints).
CANARY_MODULES = {"LAB-IDOR-001", "LAB-SQL-001"}


@dataclass
class ObservationView:
    id: str
    kind: str
    description: str
    asset_address: str | None = None
    data: dict = field(default_factory=dict)


@dataclass
class PlannedHypothesis:
    module_id: str
    category: VulnCategory
    title: str
    rationale: str
    target_asset: str
    expected_outcome: str
    success_criteria: str
    priority: float
    observation_refs: list[str] = field(default_factory=list)
    planner: str = "heuristic"


@runtime_checkable
class Planner(Protocol):
    name: str

    async def plan(
        self, observations: list[ObservationView]
    ) -> list[PlannedHypothesis]: ...


def _priority(module_id: str) -> float:
    module = ATTACK_MODULES[module_id]
    score = module.severity.rank * 10.0
    if module_id in CANARY_MODULES:
        score += 5.0  # chain potential toward the crown jewel
    return score


class HeuristicPlanner:
    """Deterministic, offline planner. Always available (no API key required)."""

    name = "heuristic"

    async def plan(self, observations):
        by_kind: dict[str, list[ObservationView]] = {}
        by_asset: dict[str, list[ObservationView]] = {}
        for obs in observations:
            by_kind.setdefault(obs.kind, []).append(obs)
            if obs.asset_address:
                by_asset.setdefault(obs.asset_address, []).append(obs)

        planned: list[PlannedHypothesis] = []

        def add(module_id, rationale, target_asset, expected, refs):
            module = ATTACK_MODULES[module_id]
            planned.append(
                PlannedHypothesis(
                    module_id=module_id,
                    category=module.category,
                    title=module.title,
                    rationale=rationale,
                    target_asset=target_asset,
                    expected_outcome=expected,
                    success_criteria="",  # filled by the module at run time
                    priority=_priority(module_id),
                    observation_refs=refs,
                    planner=self.name,
                )
            )

        info_obs = by_kind.get("info_disclosure", [])
        if info_obs:
            refs = [o.id for o in info_obs]
            add(
                "LAB-INFO-001",
                "A diagnostic endpoint appears to disclose verbose debug material; "
                "it may leak credentials.",
                "/api/system/status", "Credentials or internal detail are disclosed.",
                refs,
            )
            add(
                "LAB-AUTH-001",
                "If credentials are disclosed, they may authenticate against the "
                "production login (exposed staging account).",
                "/api/login", "Leaked credentials yield a valid session.",
                refs,
            )

        # IDOR: a resource addressed by id behind an auth boundary.
        if any(o.asset_address == "/api/accounts/{id}" for o in by_kind.get("parameter", [])):
            refs = [o.id for o in observations if (o.asset_address or "") == "/api/accounts/{id}"]
            add(
                "LAB-IDOR-001",
                "Accounts are addressed by a guessable numeric id behind auth; "
                "object-level authorization may be missing.",
                "/api/accounts/{id}",
                "A non-owner session reads the treasury account and its canary.",
                refs,
            )

        # SQLi: a free-text query parameter.
        if any(o.asset_address == "/api/accounts/search" for o in by_kind.get("parameter", [])):
            refs = [o.id for o in observations if o.asset_address == "/api/accounts/search"]
            add(
                "LAB-SQL-001",
                "The search endpoint takes free-text input that may be concatenated "
                "into a SQL query.",
                "/api/accounts/search", "A UNION injection exfiltrates the secrets table.",
                refs,
            )

        # Privilege escalation on the admin endpoint.
        if any(
            o.asset_address == "/api/admin/users" for o in by_kind.get("auth_boundary", [])
        ):
            refs = [o.id for o in observations if o.asset_address == "/api/admin/users"]
            add(
                "LAB-MISCONFIG-001",
                "An admin-only endpoint exists; its authorization may rely on "
                "client-controlled input.",
                "/api/admin/users", "A forged role header escalates to admin data.",
                refs,
            )

        planned.sort(key=lambda h: h.priority, reverse=True)
        return planned
