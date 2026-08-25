"""End-to-end: the complete ATTACK -> PROVE -> FIX -> RETEST loop.

Runs a real campaign through the orchestrator against the in-process lab and
asserts the whole evidence-backed pipeline, then scores it with the evaluation
harness.
"""
import pytest
from sqlalchemy import select

from dracarys.db.models import (
    AttackPath,
    AuditEvent,
    Campaign,
    Evidence,
    Finding,
    Retest,
    Target,
)
from dracarys.domain.enums import CampaignState, FindingStatus, RetestResult
from dracarys.engine.orchestrator.lab_controller import InProcessLabController
from dracarys.engine.orchestrator.orchestrator import Orchestrator
from dracarys.evaluation import evaluate_campaign
from lab.ground_truth import CANARY_TOKEN

pytestmark = pytest.mark.e2e


async def _seed_campaign(db, settings):
    async with db.session_factory() as s:
        target = Target(
            name="DRACARYS BANK", base_url=settings.lab_base_url,
            allowed_hosts=["127.0.0.1"], allowed_ports=[8888, 8889], is_lab=True,
        )
        s.add(target)
        await s.flush()
        campaign = Campaign(
            target_id=target.id, name="e2e",
            objective="prove a chain and verify fixes",
            policy={"canary_token": CANARY_TOKEN},
        )
        s.add(campaign)
        await s.flush()
        cid = campaign.id
        await s.commit()
    return cid


async def test_full_loop(db, settings):
    cid = await _seed_campaign(db, settings)
    orch = Orchestrator(db, InProcessLabController(settings), settings=settings)
    await orch.run_campaign(cid)

    async with db.session_factory() as s:
        c = await s.get(Campaign, cid)
        assert c.state == CampaignState.COMPLETE
        assert c.progress["target_compromised"] is True
        assert c.security_score < 50  # criticals + highs heavily penalize

        findings = (await s.execute(select(Finding).where(Finding.campaign_id == cid))).scalars().all()
        assert len(findings) == 5
        assert all(f.status == FindingStatus.FIX_VERIFIED for f in findings)
        # every finding is evidence-backed
        assert all(f.evidence_refs for f in findings)

        # canary reached by two independent paths, ending in the two distinct
        # canary-reaching vulnerabilities (IDOR and SQLi) — not any other node.
        paths = (await s.execute(select(AttackPath).where(AttackPath.campaign_id == cid))).scalars().all()
        canary_paths = [p for p in paths if p.reaches_canary]
        assert len(canary_paths) >= 2
        penultimate = {p.nodes[-2]["ref"] for p in canary_paths}
        assert penultimate == {"vuln:LAB-IDOR-001", "vuln:LAB-SQL-001"}

        # evidence integrity: every record carries a sha256
        ev = (await s.execute(select(Evidence).where(Evidence.campaign_id == cid))).scalars().all()
        assert ev and all(e.sha256 for e in ev)

        # retests genuinely flipped confirmed -> disproven
        retests = (await s.execute(select(Retest).where(Retest.campaign_id == cid))).scalars().all()
        assert len(retests) == 5
        assert all(r.result == RetestResult.FIX_VERIFIED for r in retests)
        assert all(r.before_outcome.value == "confirmed" and r.after_outcome.value == "disproven"
                   for r in retests)

        # audit trail recorded the key offensive actions
        actions = {a.action for a in (await s.execute(
            select(AuditEvent).where(AuditEvent.campaign_id == cid))).scalars().all()}
        assert {"scope_validated", "recon_completed", "finding_confirmed",
                "attack_chain_analyzed", "retest_completed", "campaign_complete"} <= actions


async def test_evaluation_scores_perfect(db, settings):
    cid = await _seed_campaign(db, settings)
    orch = Orchestrator(db, InProcessLabController(settings), settings=settings)
    await orch.run_campaign(cid)
    metrics = await evaluate_campaign(db, cid)
    assert metrics.recall == 1.0
    assert metrics.precision == 1.0
    assert metrics.validation_rate == 1.0
    assert metrics.evidence_completeness == 1.0
    assert metrics.attack_chain_discovered is True
    assert metrics.retest_success == 1.0
    assert metrics.regression_rate == 0.0
