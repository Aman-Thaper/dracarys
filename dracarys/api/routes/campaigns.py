from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.api.deps import get_campaign_or_404, get_service, get_session
from dracarys.api.service import CampaignService
from dracarys.db.models import Campaign, Finding, Target
from dracarys.domain.enums import (
    TERMINAL_STATES,
    CampaignState,
    Severity,
)
from dracarys.domain.schemas import (
    CampaignCreate,
    CampaignOut,
    CampaignSummary,
)

router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])


@router.post("", response_model=CampaignOut, status_code=201)
async def create_campaign(
    payload: CampaignCreate,
    service: CampaignService = Depends(get_service),
    session: AsyncSession = Depends(get_session),
) -> Campaign:
    target = await session.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"target {payload.target_id} not found")
    return await service.create_campaign(
        session, target, payload.name, payload.objective, payload.canary_token
    )


@router.get("", response_model=list[CampaignOut])
async def list_campaigns(session: AsyncSession = Depends(get_session)) -> list[Campaign]:
    rows = (await session.execute(
        select(Campaign).order_by(Campaign.created_at.desc())
    )).scalars().all()
    return list(rows)


@router.get("/{campaign_id}", response_model=CampaignOut)
async def get_campaign(campaign: Campaign = Depends(get_campaign_or_404)) -> Campaign:
    return campaign


@router.post("/{campaign_id}/start", response_model=CampaignOut)
async def start_campaign(
    campaign: Campaign = Depends(get_campaign_or_404),
    service: CampaignService = Depends(get_service),
) -> Campaign:
    state = campaign.state if isinstance(campaign.state, CampaignState) else CampaignState(campaign.state)
    if state != CampaignState.CREATED:
        raise HTTPException(
            status_code=409,
            detail=f"campaign cannot be started from state {state.value}",
        )
    await service.start_campaign(campaign.id)
    return campaign


@router.post("/{campaign_id}/pause", response_model=CampaignOut)
async def pause_campaign(
    campaign: Campaign = Depends(get_campaign_or_404),
    service: CampaignService = Depends(get_service),
    session: AsyncSession = Depends(get_session),
) -> Campaign:
    state = campaign.state if isinstance(campaign.state, CampaignState) else CampaignState(campaign.state)
    if state in TERMINAL_STATES or state == CampaignState.PAUSED:
        raise HTTPException(status_code=409, detail=f"cannot pause from state {state.value}")
    await service.set_control(session, campaign, "pause")
    return campaign


@router.post("/{campaign_id}/resume", response_model=CampaignOut)
async def resume_campaign(
    campaign: Campaign = Depends(get_campaign_or_404),
    service: CampaignService = Depends(get_service),
    session: AsyncSession = Depends(get_session),
) -> Campaign:
    ok = await service.resume_campaign(session, campaign)
    if not ok:
        raise HTTPException(status_code=409, detail="campaign is not paused")
    return campaign


@router.post("/{campaign_id}/stop", response_model=CampaignOut)
async def stop_campaign(
    campaign: Campaign = Depends(get_campaign_or_404),
    service: CampaignService = Depends(get_service),
    session: AsyncSession = Depends(get_session),
) -> Campaign:
    state = campaign.state if isinstance(campaign.state, CampaignState) else CampaignState(campaign.state)
    if state in TERMINAL_STATES:
        raise HTTPException(status_code=409, detail=f"campaign already {state.value}")
    await service.set_control(session, campaign, "stop")
    return campaign


@router.get("/{campaign_id}/summary", response_model=CampaignSummary)
async def campaign_summary(
    campaign: Campaign = Depends(get_campaign_or_404),
    session: AsyncSession = Depends(get_session),
) -> CampaignSummary:
    findings = (await session.execute(
        select(Finding).where(Finding.campaign_id == campaign.id)
    )).scalars().all()
    severity_breakdown = {s.value: 0 for s in Severity}
    for f in findings:
        sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
        severity_breakdown[sev.value] += 1
    progress = campaign.progress or {}
    counts = {
        "findings": len(findings),
        "observations": progress.get("observations", 0),
        "hypotheses": progress.get("hypotheses", 0),
        "attack_paths": progress.get("attack_paths", 0),
        "graph_nodes": progress.get("graph_nodes", 0),
        "graph_edges": progress.get("graph_edges", 0),
        "requests_made": campaign.requests_made,
    }
    return CampaignSummary(
        campaign=CampaignOut.model_validate(campaign),
        counts=counts,
        severity_breakdown=severity_breakdown,
        target_compromised=bool(progress.get("target_compromised", False)),
        fixes_verified=progress.get("fixes_verified", 0),
        fixes_attempted=progress.get("fixes_attempted", 0),
    )
