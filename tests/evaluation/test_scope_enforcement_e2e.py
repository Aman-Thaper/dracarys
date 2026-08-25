"""A campaign whose target is out of scope must fail closed at the scope gate."""
import pytest
from sqlalchemy import select

from dracarys.db.models import AuditEvent, Campaign, Finding, Target
from dracarys.domain.enums import CampaignState
from dracarys.engine.orchestrator.lab_controller import InProcessLabController
from dracarys.engine.orchestrator.orchestrator import Orchestrator

pytestmark = pytest.mark.evaluation


async def test_out_of_scope_target_fails_closed(db, settings):
    # Target base_url points at a host that is not on the allowlist.
    async with db.session_factory() as s:
        target = Target(
            name="oos", base_url="http://10.11.12.13:8888",
            allowed_hosts=["127.0.0.1"], allowed_ports=[8888, 8889], is_lab=False,
        )
        s.add(target)
        await s.flush()
        campaign = Campaign(target_id=target.id, name="oos", policy={"canary_token": "x"})
        s.add(campaign)
        await s.flush()
        cid = campaign.id
        await s.commit()

    orch = Orchestrator(db, InProcessLabController(settings), settings=settings)
    await orch.run_campaign(cid)

    async with db.session_factory() as s:
        c = await s.get(Campaign, cid)
        assert c.state == CampaignState.FAILED
        # No findings should be produced when the scope gate blocks the campaign.
        findings = (await s.execute(select(Finding).where(Finding.campaign_id == cid))).scalars().all()
        assert findings == []
        audits = (await s.execute(select(AuditEvent).where(AuditEvent.campaign_id == cid))).scalars().all()
        assert any(a.action == "scope_validated" and a.result == "denied" for a in audits)
