from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.api.deps import get_session
from dracarys.db.models import AuditEvent
from dracarys.domain.schemas import AuditEventOut

router = APIRouter(tags=["audit"])


@router.get("/api/campaigns/{campaign_id}/audit", response_model=list[AuditEventOut])
async def campaign_audit(campaign_id: str, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(AuditEvent).where(AuditEvent.campaign_id == campaign_id)
        .order_by(AuditEvent.created_at)
    )).scalars().all()
    return list(rows)


@router.get("/api/audit", response_model=list[AuditEventOut])
async def all_audit(limit: int = 200, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    )).scalars().all()
    return list(rows)
