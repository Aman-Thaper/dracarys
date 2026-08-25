"""A full campaign driven by a (mock) LLM planner must still be evidence-backed."""
import pytest
from sqlalchemy import select

from dracarys.agents.llm_planner import LLMPlanner
from dracarys.db.models import Campaign, Finding, Hypothesis, Target
from dracarys.domain.enums import CampaignState
from dracarys.engine.orchestrator.lab_controller import InProcessLabController
from dracarys.engine.orchestrator.orchestrator import Orchestrator
from dracarys.llm.provider import MockProvider
from lab.ground_truth import CANARY_TOKEN

pytestmark = pytest.mark.integration


async def test_campaign_with_llm_planner(db, settings):
    # The mock model proposes every module (the deterministic engine still decides truth).
    provider = MockProvider([
        {"module_id": mid, "rationale": "llm", "priority": 60}
        for mid in ["LAB-INFO-001", "LAB-AUTH-001", "LAB-IDOR-001", "LAB-SQL-001", "LAB-MISCONFIG-001"]
    ])
    planner = LLMPlanner(provider)

    async with db.session_factory() as s:
        t = Target(name="lab", base_url=settings.lab_base_url,
                   allowed_hosts=["127.0.0.1"], allowed_ports=[8888, 8889])
        s.add(t)
        await s.flush()
        c = Campaign(target_id=t.id, policy={"canary_token": CANARY_TOKEN})
        s.add(c)
        await s.flush()
        cid = c.id
        await s.commit()

    orch = Orchestrator(db, InProcessLabController(settings), planner=planner, settings=settings)
    await orch.run_campaign(cid)

    async with db.session_factory() as s:
        c = await s.get(Campaign, cid)
        assert c.state == CampaignState.COMPLETE
        hyps = (await s.execute(select(Hypothesis).where(Hypothesis.campaign_id == cid))).scalars().all()
        assert all(h.planner == "llm" for h in hyps)
        findings = (await s.execute(select(Finding).where(Finding.campaign_id == cid))).scalars().all()
        assert len(findings) == 5  # same evidence-backed result regardless of planner
