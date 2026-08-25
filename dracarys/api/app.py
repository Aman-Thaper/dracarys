"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from dracarys.api.service import CampaignService
from dracarys.config import Settings, get_settings
from dracarys.db.base import Database
from dracarys.logging import configure_logging, get_logger

log = get_logger("api")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.debug)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = Database(settings)
        await db.create_all()
        service = CampaignService(db, settings)
        app.state.db = db
        app.state.settings = settings
        app.state.service = service
        # Ensure the bundled lab target exists for the one-click demo.
        async with db.session_factory() as s:
            await service.register_lab_target(s)
            await s.commit()
        log.info("api_started", environment=settings.environment)
        try:
            yield
        finally:
            await service.shutdown()
            await db.dispose()

    app = FastAPI(
        title="DRACARYS",
        description="Autonomous, controlled red-team platform. ATTACK. PROVE. FIX. RETEST.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(HTTPException)
    async def http_exc_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": str(exc.detail), "detail": None},
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception):
        log.exception("unhandled_error", path=str(request.url), error=str(exc))
        return JSONResponse(
            status_code=500,
            content={"error": "internal server error", "detail": str(exc)},
        )

    from dracarys.api.routes import (
        audit,
        campaigns,
        health,
        metrics,
        resources,
        scan,
        targets,
    )

    app.include_router(health.router)
    app.include_router(targets.router)
    app.include_router(campaigns.router)
    app.include_router(resources.router)
    app.include_router(audit.router)
    app.include_router(metrics.router)
    app.include_router(scan.router)
    return app


app = create_app()
