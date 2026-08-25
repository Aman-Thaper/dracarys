"""Campaign service — orchestration entry point behind the HTTP API.

Owns the process-wide database and lab controller, launches campaigns as tracked
background tasks, and exposes the control operations (start/pause/resume/stop).
Campaign state itself lives in the database, so the API stays thin.
"""
from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.agents.planner import HeuristicPlanner, Planner
from dracarys.config import Settings, get_settings
from dracarys.db.base import Database
from dracarys.db.models import Campaign, Target
from dracarys.domain.enums import CampaignState
from dracarys.engine.orchestrator.lab_controller import (
    InProcessLabController,
    LabController,
    SubprocessLabController,
)
from dracarys.engine.orchestrator.orchestrator import Orchestrator
from dracarys.engine.orchestrator.state_machine import transition
from dracarys.engine.policy import Scope, validate_url
from dracarys.logging import get_logger

log = get_logger("api.service")


def build_planner(settings: Settings) -> Planner:
    if settings.llm_provider == "anthropic" and settings.anthropic_api_key:
        try:
            from dracarys.agents.llm_planner import LLMPlanner
            from dracarys.llm.anthropic_provider import AnthropicProvider

            provider = AnthropicProvider(settings)
            return LLMPlanner(provider, fallback=HeuristicPlanner())
        except Exception as exc:  # noqa: BLE001
            log.warning("llm_planner_unavailable", error=str(exc))
    return HeuristicPlanner()


def build_lab_controller(settings: Settings) -> LabController:
    mode = getattr(settings, "lab_mode", "inprocess")
    if mode == "live":
        return SubprocessLabController(settings)
    return InProcessLabController(settings)


class CampaignService:
    def __init__(self, db: Database, settings: Settings | None = None) -> None:
        self.db = db
        self.settings = settings or get_settings()
        self.lab: LabController = build_lab_controller(self.settings)
        self.planner = build_planner(self.settings)
        self._tasks: dict[str, asyncio.Task] = {}

    def _new_orchestrator(self) -> Orchestrator:
        return Orchestrator(self.db, self.lab, planner=self.planner, settings=self.settings)

    # -- targets ---------------------------------------------------------
    async def register_lab_target(self, s: AsyncSession) -> Target:
        """Idempotently ensure the bundled DRACARYS LAB target exists."""
        existing = (await s.execute(
            select(Target).where(Target.base_url == self.settings.lab_base_url)
        )).scalars().first()
        if existing:
            return existing
        target = Target(
            name="DRACARYS BANK (lab)",
            base_url=self.settings.lab_base_url,
            description="Bundled deliberately-vulnerable target. Synthetic data only.",
            allowed_hosts=[self.settings.lab_host, "127.0.0.1", "localhost"],
            allowed_ports=[self.settings.lab_port, self.settings.lab_patched_port],
            is_lab=True,
        )
        s.add(target)
        await s.flush()
        return target

    def validate_target_scope(self, base_url, hosts, ports):
        scope = Scope.create(
            hosts or self.settings.scope_allowlist,
            ports or self.settings.scope_allowed_ports,
        )
        return validate_url(base_url, scope), scope

    # -- campaigns -------------------------------------------------------
    async def create_campaign(
        self, s: AsyncSession, target: Target, name: str, objective: str,
        canary_token: str | None,
    ) -> Campaign:
        canary = canary_token
        if canary is None and target.is_lab:
            from lab.ground_truth import CANARY_TOKEN
            canary = CANARY_TOKEN
        scope = Scope.create(
            target.allowed_hosts or self.settings.scope_allowlist,
            target.allowed_ports or self.settings.scope_allowed_ports,
        )
        campaign = Campaign(
            target_id=target.id, name=name, objective=objective,
            scope=scope.to_dict(),
            policy={"canary_token": canary or ""},
            budget={
                "max_requests": self.settings.max_requests_per_campaign,
                "seconds": self.settings.campaign_budget_seconds,
            },
            progress={},
        )
        s.add(campaign)
        await s.flush()
        return campaign

    async def start_campaign(self, campaign_id: str) -> None:
        if campaign_id in self._tasks and not self._tasks[campaign_id].done():
            return  # already running
        orch = self._new_orchestrator()
        task = asyncio.create_task(orch.run_campaign(campaign_id))
        self._tasks[campaign_id] = task

    async def set_control(self, s: AsyncSession, campaign: Campaign, control: str) -> None:
        campaign.control = control
        if control == "stop":
            campaign.kill_switch = True

    async def resume_campaign(self, s: AsyncSession, campaign: Campaign) -> bool:
        state = campaign.state if isinstance(campaign.state, CampaignState) else CampaignState(campaign.state)
        if state != CampaignState.PAUSED:
            return False
        resume_from = (campaign.progress or {}).get("resume_from")
        target_state = CampaignState(resume_from) if resume_from else CampaignState.CREATED
        transition(campaign, target_state)
        campaign.control = ""
        campaign.kill_switch = False
        await s.commit()
        await self.start_campaign(campaign.id)
        return True

    def is_running(self, campaign_id: str) -> bool:
        t = self._tasks.get(campaign_id)
        return t is not None and not t.done()

    async def shutdown(self) -> None:
        for t in self._tasks.values():
            if not t.done():
                t.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
