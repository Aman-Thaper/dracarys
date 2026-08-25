"""LLM-driven attack planner (provider-agnostic).

The model chooses which typed attack modules to try and how to prioritize them,
citing the observations that motivate each choice. Its output is validated against
a strict schema; unknown modules are dropped and any failure falls back to the
deterministic HeuristicPlanner. Titles/categories come from the module registry —
never from the model — so the LLM cannot fabricate a capability, and it can never
decide that a vulnerability exists (only the module's deterministic criterion can).
"""
from __future__ import annotations

import json

from pydantic import BaseModel, ValidationError

from dracarys.agents.attacks import ATTACK_MODULES
from dracarys.agents.planner import (
    CANARY_MODULES,
    HeuristicPlanner,
    ObservationView,
    PlannedHypothesis,
    Planner,
    _priority,
)
from dracarys.llm.provider import LLMError, LLMProvider
from dracarys.logging import get_logger

log = get_logger("agents.llm_planner")

# Generic capability catalogue shown to the model. Deliberately NOT the lab's
# answer key — just what each module tests and the signal that suggests it.
MODULE_CATALOG = {
    "LAB-INFO-001": "information disclosure — suspect when a diagnostic/status/debug endpoint is reachable.",
    "LAB-AUTH-001": "broken authentication via exposed credentials — suspect when credentials are disclosed anywhere.",
    "LAB-IDOR-001": "broken object-level authorization — suspect when a resource is addressed by a guessable id behind auth.",
    "LAB-SQL-001": "SQL injection — suspect when a free-text query parameter feeds a search/lookup.",
    "LAB-MISCONFIG-001": "privilege escalation via trusted client input — suspect when an admin endpoint exists behind auth.",
}

SYSTEM = (
    "You are the attack-planning module of an authorized, scope-bounded red-team "
    "system operating against a local test lab. Given observed attack surface, "
    "select which typed attack modules to run and prioritize them. You never assert "
    "that a vulnerability exists; a separate deterministic engine validates every "
    "hypothesis with evidence."
)


class _LLMHypothesis(BaseModel):
    module_id: str
    rationale: str = ""
    priority: float = 0.0
    observation_refs: list[str] = []


class LLMPlanner:
    name = "llm"

    def __init__(self, provider: LLMProvider, fallback: Planner | None = None) -> None:
        self.provider = provider
        self.fallback = fallback or HeuristicPlanner()

    def _build_prompt(self, observations: list[ObservationView]) -> str:
        obs_lines = [
            f"- id={o.id} kind={o.kind} asset={o.asset_address or '-'} :: {o.description}"
            for o in observations
        ]
        catalog = [f"- {mid}: {desc}" for mid, desc in MODULE_CATALOG.items()]
        return (
            "OBSERVED ATTACK SURFACE:\n" + "\n".join(obs_lines) +
            "\n\nAVAILABLE ATTACK MODULES:\n" + "\n".join(catalog) +
            "\n\nReturn a JSON array of objects with keys: module_id, rationale, "
            "priority (0-100), observation_refs (list of observation ids). Only use "
            "module ids from the catalogue. Prioritize modules that could chain "
            "toward high-impact access."
        )

    async def plan(self, observations: list[ObservationView]) -> list[PlannedHypothesis]:
        try:
            raw = await self.provider.complete_json(SYSTEM, self._build_prompt(observations))
            planned = self._parse(raw)
            if not planned:
                raise LLMError("model returned no usable hypotheses")
            log.info("llm_plan", provider=self.provider.name, hypotheses=len(planned))
            return planned
        except (LLMError, ValidationError, json.JSONDecodeError, ValueError) as exc:
            log.warning("llm_plan_fallback", error=str(exc))
            return await self.fallback.plan(observations)

    def _parse(self, raw) -> list[PlannedHypothesis]:
        if not isinstance(raw, list):
            raise LLMError("expected a JSON array of hypotheses")
        out: list[PlannedHypothesis] = []
        seen: set[str] = set()
        for item in raw:
            try:
                h = _LLMHypothesis.model_validate(item)
            except ValidationError:
                continue
            module = ATTACK_MODULES.get(h.module_id)
            if module is None or h.module_id in seen:
                continue  # reject unknown/duplicate modules
            seen.add(h.module_id)
            # Model influences priority but cannot exceed the module's ceiling by much.
            base = _priority(h.module_id)
            priority = max(0.0, min(h.priority, 100.0)) if h.priority else base
            out.append(PlannedHypothesis(
                module_id=h.module_id,
                category=module.category,
                title=module.title,          # from registry, not the model
                rationale=h.rationale or "proposed by LLM planner",
                target_asset=h.observation_refs[0] if h.observation_refs else "",
                expected_outcome="",
                success_criteria="",
                priority=priority + (5.0 if h.module_id in CANARY_MODULES else 0.0),
                observation_refs=h.observation_refs,
                planner=self.name,
            ))
        out.sort(key=lambda x: x.priority, reverse=True)
        return out
