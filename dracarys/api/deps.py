"""FastAPI dependencies: process-wide database/service access and DB sessions."""
from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.api.service import CampaignService
from dracarys.db.base import Database
from dracarys.db.models import Campaign


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_settings_dep(request: Request):
    return request.app.state.settings


def get_service(request: Request) -> CampaignService:
    return request.app.state.service


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    db: Database = request.app.state.db
    async with db.session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_campaign_or_404(
    campaign_id: str, session: AsyncSession = Depends(get_session)
) -> Campaign:
    campaign = await session.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail=f"campaign {campaign_id} not found")
    return campaign
