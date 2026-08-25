from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.api.deps import get_session
from dracarys.db.models import (
    AttackPath,
    Evidence,
    Finding,
    GraphEdge,
    GraphNode,
    Hypothesis,
    Observation,
    Remediation,
    Retest,
    TestRun,
)
from dracarys.domain.schemas import (
    AttackPathOut,
    EvidenceOut,
    FindingOut,
    GraphEdgeOut,
    GraphNodeOut,
    GraphOut,
    HypothesisOut,
    ObservationOut,
    RemediationOut,
    RetestOut,
    TestRunOut,
)

router = APIRouter(prefix="/api/campaigns/{campaign_id}", tags=["campaign-resources"])


async def _list(session, model, campaign_id, order=None):
    stmt = select(model).where(model.campaign_id == campaign_id)
    if order is not None:
        stmt = stmt.order_by(order)
    return list((await session.execute(stmt)).scalars().all())


@router.get("/observations", response_model=list[ObservationOut])
async def observations(campaign_id: str, session: AsyncSession = Depends(get_session)):
    return await _list(session, Observation, campaign_id, Observation.created_at)


@router.get("/hypotheses", response_model=list[HypothesisOut])
async def hypotheses(campaign_id: str, session: AsyncSession = Depends(get_session)):
    return await _list(session, Hypothesis, campaign_id, Hypothesis.priority.desc())


@router.get("/findings", response_model=list[FindingOut])
async def findings(campaign_id: str, session: AsyncSession = Depends(get_session)):
    return await _list(session, Finding, campaign_id, Finding.created_at)


@router.get("/test-runs", response_model=list[TestRunOut])
async def test_runs(campaign_id: str, session: AsyncSession = Depends(get_session)):
    return await _list(session, TestRun, campaign_id, TestRun.created_at)


@router.get("/evidence", response_model=list[EvidenceOut])
async def evidence(campaign_id: str, session: AsyncSession = Depends(get_session)):
    return await _list(session, Evidence, campaign_id, Evidence.created_at)


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
async def evidence_item(
    campaign_id: str, evidence_id: str, session: AsyncSession = Depends(get_session)
):
    ev = await session.get(Evidence, evidence_id)
    if ev is None or ev.campaign_id != campaign_id:
        raise HTTPException(status_code=404, detail="evidence not found")
    return ev


@router.get("/attack-paths", response_model=list[AttackPathOut])
async def attack_paths(campaign_id: str, session: AsyncSession = Depends(get_session)):
    return await _list(session, AttackPath, campaign_id, AttackPath.created_at)


@router.get("/graph", response_model=GraphOut)
async def graph(campaign_id: str, session: AsyncSession = Depends(get_session)):
    nodes = await _list(session, GraphNode, campaign_id)
    edges = await _list(session, GraphEdge, campaign_id)
    return GraphOut(
        nodes=[
            GraphNodeOut(ref=n.ref, type=n.type.value, label=n.label, data=n.data)
            for n in nodes
        ],
        edges=[
            GraphEdgeOut(source=e.source_ref, target=e.target_ref, type=e.type.value, data=e.data)
            for e in edges
        ],
    )


@router.get("/remediations", response_model=list[RemediationOut])
async def remediations(campaign_id: str, session: AsyncSession = Depends(get_session)):
    # Remediation has no campaign_id; join through Finding.
    rows = (await session.execute(
        select(Remediation).join(Finding, Remediation.finding_id == Finding.id)
        .where(Finding.campaign_id == campaign_id)
    )).scalars().all()
    return list(rows)


@router.get("/retests", response_model=list[RetestOut])
async def retests(campaign_id: str, session: AsyncSession = Depends(get_session)):
    return await _list(session, Retest, campaign_id, Retest.created_at)
