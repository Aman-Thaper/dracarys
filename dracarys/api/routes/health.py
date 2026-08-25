from __future__ import annotations

from fastapi import APIRouter, Depends

from dracarys import __version__
from dracarys.api.deps import get_settings_dep

router = APIRouter(tags=["health"])


@router.get("/api/health")
async def health(settings=Depends(get_settings_dep)) -> dict:
    return {
        "status": "ok",
        "service": "dracarys",
        "version": __version__,
        "environment": settings.environment,
        "llm_provider": settings.llm_provider,
    }
