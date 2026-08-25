from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.api.deps import get_service, get_session
from dracarys.api.service import CampaignService
from dracarys.db.models import Target
from dracarys.domain.schemas import (
    ScopeDecisionOut,
    TargetCreate,
    TargetOut,
    ValidateTargetRequest,
)

router = APIRouter(prefix="/api/targets", tags=["targets"])


@router.post("", response_model=TargetOut, status_code=201)
async def create_target(
    payload: TargetCreate,
    service: CampaignService = Depends(get_service),
    session: AsyncSession = Depends(get_session),
) -> Target:
    decision, _ = service.validate_target_scope(
        payload.base_url, payload.allowed_hosts, payload.allowed_ports
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=422,
            detail=f"target is out of the allowed scope: {decision.reason}",
        )
    target = Target(
        name=payload.name, base_url=payload.base_url, description=payload.description,
        allowed_hosts=payload.allowed_hosts or [decision.host],
        allowed_ports=payload.allowed_ports or ([decision.port] if decision.port else []),
        is_lab=payload.is_lab, validated=True,
    )
    session.add(target)
    await session.flush()
    return target


@router.get("", response_model=list[TargetOut])
async def list_targets(session: AsyncSession = Depends(get_session)) -> list[Target]:
    rows = (await session.execute(select(Target).order_by(Target.created_at.desc()))).scalars().all()
    return list(rows)


@router.get("/{target_id}", response_model=TargetOut)
async def get_target(
    target_id: str, session: AsyncSession = Depends(get_session)
) -> Target:
    target = await session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail=f"target {target_id} not found")
    return target


@router.post("/validate", response_model=ScopeDecisionOut)
async def validate_target(
    payload: ValidateTargetRequest,
    service: CampaignService = Depends(get_service),
) -> ScopeDecisionOut:
    decision, _ = service.validate_target_scope(
        payload.base_url, payload.allowed_hosts, payload.allowed_ports
    )
    return ScopeDecisionOut(
        allowed=decision.allowed, reason=decision.reason,
        host=decision.host, port=decision.port,
        resolved_ips=list(decision.resolved_ips),
    )


@router.post("/lab", response_model=TargetOut, status_code=201)
async def register_lab(
    service: CampaignService = Depends(get_service),
    session: AsyncSession = Depends(get_session),
) -> Target:
    return await service.register_lab_target(session)
