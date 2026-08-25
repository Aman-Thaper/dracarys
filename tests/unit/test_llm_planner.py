"""The LLM planner must validate structured output and never bypass the engine."""
from dracarys.agents.llm_planner import LLMPlanner
from dracarys.agents.planner import HeuristicPlanner, ObservationView
from dracarys.llm.provider import MockProvider

OBS = [
    ObservationView("obs_1", "info_disclosure", "verbose debug leak", "/api/system/status"),
    ObservationView("obs_2", "parameter", "account id", "/api/accounts/{id}"),
    ObservationView("obs_3", "parameter", "search q", "/api/accounts/search"),
    ObservationView("obs_4", "auth_boundary", "admin", "/api/admin/users"),
]


async def test_llm_planner_parses_valid_output():
    provider = MockProvider([
        {"module_id": "LAB-IDOR-001", "rationale": "guessable id", "priority": 90, "observation_refs": ["obs_2"]},
        {"module_id": "LAB-SQL-001", "rationale": "free-text q", "priority": 88, "observation_refs": ["obs_3"]},
        {"module_id": "LAB-INFO-001", "rationale": "debug endpoint", "priority": 50, "observation_refs": ["obs_1"]},
    ])
    planned = await LLMPlanner(provider).plan(OBS)
    ids = [p.module_id for p in planned]
    assert ids[0] in {"LAB-IDOR-001", "LAB-SQL-001"}  # highest priority first
    assert all(p.planner == "llm" for p in planned)
    # titles come from the registry, not the model
    from dracarys.agents.attacks import ATTACK_MODULES
    for p in planned:
        assert p.title == ATTACK_MODULES[p.module_id].title


async def test_llm_planner_drops_unknown_modules():
    provider = MockProvider([
        {"module_id": "LAB-IDOR-001", "priority": 90},
        {"module_id": "TOTALLY-MADE-UP", "priority": 99},  # must be dropped
        {"module_id": "'; DROP TABLE findings; --", "priority": 99},  # must be dropped
    ])
    planned = await LLMPlanner(provider).plan(OBS)
    assert [p.module_id for p in planned] == ["LAB-IDOR-001"]


async def test_llm_planner_falls_back_on_malformed():
    class BadProvider:
        name = "bad"
        async def complete_json(self, system, user):
            return {"not": "a list"}
    planned = await LLMPlanner(BadProvider(), fallback=HeuristicPlanner()).plan(OBS)
    # fell back to heuristic → still proposes the full set
    assert len(planned) == 5
    assert all(p.planner == "heuristic" for p in planned)


async def test_llm_planner_falls_back_on_provider_error():
    from dracarys.llm.provider import LLMError

    class ExplodingProvider:
        name = "boom"
        async def complete_json(self, system, user):
            raise LLMError("network down")
    planned = await LLMPlanner(ExplodingProvider()).plan(OBS)
    assert len(planned) == 5 and all(p.planner == "heuristic" for p in planned)
