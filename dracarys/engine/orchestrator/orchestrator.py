"""Campaign orchestrator — the autonomous OBSERVE -> HYPOTHESIS -> TEST ->
VALIDATE -> CHAIN -> REMEDIATE -> RETEST loop, persisted end to end.

Every phase reloads campaign state from the database, does bounded work through
the policy engine and typed tools, writes its results (observations, hypotheses,
test runs, evidence, findings, graph, remediations, retests, audit events), and
advances the state machine. The database is the source of truth, so a campaign's
progress is inspectable at any time and survives a restart.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.agents.attacks import ATTACK_MODULES, modules_in_order
from dracarys.agents.context import AttackContext
from dracarys.agents.planner import HeuristicPlanner, ObservationView, Planner
from dracarys.agents.recon import ReconAgent
from dracarys.agents.remediation import RemediationAgent
from dracarys.config import Settings, get_settings
from dracarys.db.base import Database
from dracarys.db.models import (
    Asset,
    AttackPath,
    AuditEvent,
    Campaign,
    Evidence,
    Finding,
    Hypothesis,
    Observation,
    Remediation,
    Retest,
    Target,
    TestRun,
)
from dracarys.domain.enums import (
    CampaignState,
    Confidence,
    FindingStatus,
    HypothesisStatus,
    RetestResult,
    Severity,
    TestOutcome,
)
from dracarys.engine.evidence import EvidenceStore
from dracarys.engine.graph import build_graph, discover_attack_paths, persist_graph
from dracarys.engine.orchestrator.lab_controller import LabController, LabHandle
from dracarys.engine.orchestrator.state_machine import transition
from dracarys.engine.policy import PolicyEngine, Scope
from dracarys.logging import get_logger
from dracarys.tools import HttpTool

log = get_logger("orchestrator")

_SEVERITY_PENALTY = {
    Severity.CRITICAL: 25, Severity.HIGH: 15, Severity.MEDIUM: 8,
    Severity.LOW: 3, Severity.INFO: 0,
}


class CampaignCancelled(Exception):
    pass


class CampaignPaused(Exception):
    pass


@dataclass
class RunState:
    campaign_id: str
    settings: Settings
    scope: Scope
    policy: PolicyEngine
    primary: LabHandle
    context: AttackContext
    canary_finding_ids: set[str] = field(default_factory=set)
    leaked_identity: str | None = None


class Orchestrator:
    def __init__(
        self,
        db: Database,
        lab_controller: LabController,
        planner: Planner | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.db = db
        self.lab = lab_controller
        self.planner = planner or HeuristicPlanner()
        self.settings = settings or get_settings()

    # -- audit helper -----------------------------------------------------
    async def _audit(self, s, campaign_id, action, *, target="", result="ok", detail=None):
        s.add(AuditEvent(
            campaign_id=campaign_id, actor="orchestrator", action=action,
            target=target, result=result, detail=detail or {},
        ))

    async def _load_campaign(self, s: AsyncSession, campaign_id: str) -> Campaign:
        c = await s.get(Campaign, campaign_id)
        if c is None:
            raise ValueError(f"campaign {campaign_id} not found")
        return c

    async def _load_target(self, s: AsyncSession, target_id: str) -> Target:
        t = await s.get(Target, target_id)
        if t is None:
            raise ValueError(f"target {target_id} not found")
        return t

    async def _check_kill(self, campaign_id: str, rs: RunState) -> None:
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, campaign_id)
            if c.kill_switch or c.control == "stop":
                rs.policy.kill("operator STOP")
                raise CampaignCancelled()

    # -- entry point ------------------------------------------------------
    # Maps a completed pipeline state to the phase that runs next. Because the
    # mapping is keyed on persisted state, a paused or restarted campaign resumes
    # exactly where it left off without repeating completed work.
    @property
    def _next_phase(self):
        return {
            CampaignState.CREATED: self._scoping,
            CampaignState.SCOPING: self._recon,
            CampaignState.RECON: self._planning,
            CampaignState.ATTACK_PLANNING: self._testing,
            CampaignState.VALIDATION: self._chain_analysis,
            CampaignState.ATTACK_CHAIN_ANALYSIS: self._reporting,
            CampaignState.REPORTING: self._remediation,
            CampaignState.REMEDIATION: self._retest,
            CampaignState.RETEST: self._finish,
        }

    async def run_campaign(self, campaign_id: str) -> None:
        settings = self.settings
        async with self.db.session_factory() as s:
            campaign = await self._load_campaign(s, campaign_id)
            target = await self._load_target(s, campaign.target_id)
            scope = Scope.create(
                target.allowed_hosts or settings.scope_allowlist,
                target.allowed_ports or settings.scope_allowed_ports,
            )
            canary = (campaign.policy or {}).get("canary_token", "")
        policy = PolicyEngine(
            scope,
            max_requests=settings.max_requests_per_campaign,
            max_concurrency=settings.max_concurrency,
            timeout_seconds=settings.tool_timeout_seconds,
        )
        primary = await self.lab.primary()
        rs = RunState(
            campaign_id=campaign_id, settings=settings, scope=scope, policy=policy,
            primary=primary, context=AttackContext(canary_token=canary),
        )
        try:
            while True:
                state = await self._control_check(campaign_id, rs)
                phase = self._next_phase.get(state)
                if phase is None:  # terminal or nothing left to do
                    break
                await phase(rs)
        except CampaignPaused:
            await self._pause(campaign_id)
        except CampaignCancelled:
            await self._terminate(campaign_id, CampaignState.CANCELLED, "cancelled by operator")
        except Exception as exc:  # noqa: BLE001
            log.exception("campaign_failed", campaign_id=campaign_id, error=str(exc))
            await self._terminate(campaign_id, CampaignState.FAILED, str(exc))
        finally:
            await primary.aclose()

    async def _control_check(self, campaign_id: str, rs: RunState) -> CampaignState:
        """Return the current pipeline state, honoring stop/pause requests."""
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, campaign_id)
            if c.control == "stop" or c.kill_switch:
                rs.policy.kill("operator STOP")
                raise CampaignCancelled()
            if c.control == "pause":
                raise CampaignPaused()
            return c.state if isinstance(c.state, CampaignState) else CampaignState(c.state)

    async def _pause(self, campaign_id: str) -> None:
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, campaign_id)
            resume_from = c.state.value if isinstance(c.state, CampaignState) else c.state
            c.progress = {**(c.progress or {}), "resume_from": resume_from}
            transition(c, CampaignState.PAUSED)
            c.control = ""
            await self._audit(s, campaign_id, "campaign_paused",
                              detail={"resume_from": resume_from})
            await s.commit()

    async def _terminate(self, campaign_id, state, reason):
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, campaign_id)
            if c.state in {CampaignState.COMPLETE, CampaignState.CANCELLED, CampaignState.FAILED}:
                return
            transition(c, state)
            c.error = reason
            await self._audit(s, campaign_id, f"campaign_{state.value.lower()}", result=reason)
            await s.commit()

    # -- phases -----------------------------------------------------------
    async def _scoping(self, rs: RunState) -> None:
        await self._check_kill(rs.campaign_id, rs)
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            target = await self._load_target(s, c.target_id)
            transition(c, CampaignState.SCOPING)
            decision = rs.policy.authorize(target.base_url)
            await self._audit(
                s, c.id, "scope_validated", target=target.base_url,
                result="allowed" if decision.allowed else "denied",
                detail={"reason": decision.reason, "scope": rs.scope.to_dict()},
            )
            if not decision.allowed:
                transition(c, CampaignState.FAILED)
                c.error = f"target out of scope: {decision.reason}"
                await s.commit()
                raise CampaignCancelled()
            target.validated = True
            c.progress = {**(c.progress or {}), "scoping": "done"}
            await s.commit()

    async def _recon(self, rs: RunState) -> None:
        await self._check_kill(rs.campaign_id, rs)
        tool = HttpTool(rs.primary.base_url, rs.policy, rs.primary.client)
        result = await ReconAgent(tool).run()
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            transition(c, CampaignState.RECON)
            store = EvidenceStore(s, c.id)
            seen_assets: set[tuple] = set()
            for obs in result.observations:
                obs_data = {**obs.data}
                if obs.asset_address:
                    obs_data["asset_address"] = obs.asset_address
                o = Observation(
                    campaign_id=c.id, source="recon", kind=obs.kind,
                    description=obs.description, data=obs_data, confidence=obs.confidence,
                )
                s.add(o)
                await s.flush()
                if obs.exchange is not None:
                    ev = await store.record_exchange(
                        obs.exchange, summary=obs.description, observation_id=o.id,
                    )
                    o.evidence_refs = [ev.id]
                if obs.asset_type and obs.asset_address:
                    key = (obs.asset_type, obs.asset_address)
                    if key not in seen_assets:
                        seen_assets.add(key)
                        s.add(Asset(
                            campaign_id=c.id, type=obs.asset_type,
                            address=obs.asset_address, asset_metadata=obs.asset_metadata,
                        ))
            if result.technology:
                s.add(Observation(
                    campaign_id=c.id, source="recon", kind="technology",
                    description=f"Server technology: {result.technology}",
                    data=result.technology,
                ))
            c.progress = {
                **(c.progress or {}), "recon": "done",
                "endpoints": len(result.endpoints),
                "observations": len(result.observations),
            }
            await self._audit(
                s, c.id, "recon_completed", target=rs.primary.base_url,
                detail={"endpoints": len(result.endpoints),
                        "observations": len(result.observations)},
            )
            await s.commit()

    async def _planning(self, rs: RunState) -> None:
        await self._check_kill(rs.campaign_id, rs)
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            transition(c, CampaignState.ATTACK_PLANNING)
            obs_rows = (await s.execute(
                select(Observation).where(Observation.campaign_id == c.id)
            )).scalars().all()
            views = [
                ObservationView(
                    id=o.id, kind=o.kind, description=o.description,
                    asset_address=(o.data or {}).get("asset_address"),
                    data=o.data or {},
                )
                for o in obs_rows
            ]
            planned = await self.planner.plan(views)
            for h in planned:
                s.add(Hypothesis(
                    campaign_id=c.id, category=h.category, module_id=h.module_id,
                    title=h.title, rationale=h.rationale,
                    observation_refs=h.observation_refs, target_asset=h.target_asset,
                    expected_outcome=h.expected_outcome, success_criteria=h.success_criteria,
                    priority=h.priority, status=HypothesisStatus.PROPOSED, planner=h.planner,
                ))
            c.progress = {**(c.progress or {}), "planning": "done", "hypotheses": len(planned)}
            await self._audit(
                s, c.id, "planning_completed",
                detail={"hypotheses": len(planned), "planner": self.planner.name},
            )
            await s.commit()

    async def _testing(self, rs: RunState) -> None:
        tool = HttpTool(rs.primary.base_url, rs.policy, rs.primary.client)
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            transition(c, CampaignState.TESTING)
            await s.commit()

        confirmed: set[str] = set()
        while True:
            await self._check_kill(rs.campaign_id, rs)
            async with self.db.session_factory() as s:
                c = await self._load_campaign(s, rs.campaign_id)
                store = EvidenceStore(s, c.id)
                pending = (await s.execute(
                    select(Hypothesis).where(
                        Hypothesis.campaign_id == c.id,
                        Hypothesis.status == HypothesisStatus.PROPOSED,
                    ).order_by(Hypothesis.priority.desc())
                )).scalars().all()
                # Select the highest-priority hypothesis whose dependencies are met.
                target_h = None
                for h in pending:
                    module = ATTACK_MODULES.get(h.module_id)
                    if module is None:
                        h.status = HypothesisStatus.INCONCLUSIVE
                        continue
                    if all(dep in confirmed for dep in module.depends_on):
                        target_h = h
                        break
                if target_h is None:
                    await s.commit()
                    break

                module = ATTACK_MODULES[target_h.module_id]
                target_h.status = HypothesisStatus.TESTING
                await s.flush()
                outcome = await module.run(tool, rs.context)
                rs.context.merge(outcome.extracted)

                run = TestRun(
                    campaign_id=c.id, hypothesis_id=target_h.id, tool="http",
                    parameters={"module": module.id, "hypothesis": outcome.hypothesis},
                    outcome=outcome.outcome, detail=outcome.detail,
                    result={"success_criteria": outcome.success_criteria,
                            "reached_canary": outcome.reached_canary},
                )
                s.add(run)
                await s.flush()
                ev_ids = []
                for le in outcome.exchanges:
                    ev = await store.record_exchange(
                        le.exchange, summary=f"{module.id}: {le.label}",
                        test_run_id=run.id,
                    )
                    ev_ids.append(ev.id)
                run.evidence_refs = ev_ids

                target_h.success_criteria = {"text": outcome.success_criteria}
                if outcome.outcome == TestOutcome.CONFIRMED:
                    target_h.status = HypothesisStatus.CONFIRMED
                    finding = Finding(
                        campaign_id=c.id, hypothesis_id=target_h.id,
                        ground_truth_id=module.id, category=module.category,
                        title=outcome.title, severity=module.severity,
                        confidence=Confidence.CONFIRMED,
                        affected_asset=outcome.affected_asset, root_cause=outcome.root_cause,
                        impact=outcome.impact, description=outcome.detail,
                        evidence_refs=ev_ids, status=FindingStatus.OPEN,
                    )
                    s.add(finding)
                    await s.flush()
                    for eid in ev_ids:
                        ev_obj = await s.get(Evidence, eid)
                        if ev_obj:
                            ev_obj.finding_id = finding.id
                    confirmed.add(module.id)
                    if outcome.reached_canary:
                        rs.canary_finding_ids.add(module.id)
                    if module.id == "LAB-AUTH-001":
                        tok = rs.context.any_non_admin_token()
                        rs.leaked_identity = tok[0] if tok else None
                    await self._audit(
                        s, c.id, "finding_confirmed", target=outcome.affected_asset,
                        detail={"finding": finding.id, "ground_truth": module.id,
                                "reached_canary": outcome.reached_canary},
                    )
                elif outcome.outcome == TestOutcome.DISPROVEN:
                    target_h.status = HypothesisStatus.DISPROVEN
                else:
                    target_h.status = HypothesisStatus.INCONCLUSIVE
                await self._audit(
                    s, c.id, "test_run", target=module.id, result=outcome.outcome.value,
                    detail={"hypothesis": target_h.id},
                )
                await s.commit()

        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            transition(c, CampaignState.VALIDATION)
            c.progress = {**(c.progress or {}), "testing": "done",
                          "confirmed_findings": len(confirmed)}
            c.requests_made = rs.policy.requests_made
            await self._audit(s, c.id, "validation_completed",
                              detail={"confirmed": sorted(confirmed)})
            await s.commit()

    async def _chain_analysis(self, rs: RunState) -> None:
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            target = await self._load_target(s, c.target_id)
            transition(c, CampaignState.ATTACK_CHAIN_ANALYSIS)
            findings = (await s.execute(
                select(Finding).where(Finding.campaign_id == c.id)
            )).scalars().all()
            host = _host_of(target.base_url)
            graph = build_graph(
                target_host=host, findings=list(findings),
                leaked_identity=rs.leaked_identity,
                canary_finding_ids=rs.canary_finding_ids,
            )
            await persist_graph(s, c.id, graph)
            paths = discover_attack_paths(graph=graph, findings=list(findings))
            reaches = False
            for p in paths:
                reaches = reaches or p.reaches_canary
                s.add(AttackPath(
                    campaign_id=c.id, title=p.title, nodes=p.nodes, edges=p.edges,
                    finding_ids=p.finding_ids, impact=p.impact, severity=p.severity,
                    confidence=p.confidence, reaches_canary=p.reaches_canary,
                ))
            c.progress = {
                **(c.progress or {}), "chain_analysis": "done",
                "attack_paths": len(paths), "target_compromised": reaches,
                "graph_nodes": len(graph.nodes), "graph_edges": len(graph.edges),
            }
            await self._audit(
                s, c.id, "attack_chain_analyzed",
                detail={"paths": len(paths), "reaches_canary": reaches},
            )
            await s.commit()

    async def _reporting(self, rs: RunState) -> None:
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            transition(c, CampaignState.REPORTING)
            findings = (await s.execute(
                select(Finding).where(Finding.campaign_id == c.id)
            )).scalars().all()
            score = 100
            for f in findings:
                sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
                score -= _SEVERITY_PENALTY.get(sev, 0)
            c.security_score = max(0, score)
            c.progress = {**(c.progress or {}), "reporting": "done",
                          "findings": len(findings)}
            await s.commit()

    async def _remediation(self, rs: RunState) -> None:
        agent = RemediationAgent()
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            transition(c, CampaignState.REMEDIATION)
            findings = (await s.execute(
                select(Finding).where(Finding.campaign_id == c.id)
            )).scalars().all()
            count = 0
            for f in findings:
                plan = agent.plan_for(f.ground_truth_id)
                if plan is None:
                    continue
                s.add(Remediation(
                    finding_id=f.id, ground_truth_id=f.ground_truth_id,
                    summary=plan.summary, root_cause=f.root_cause,
                    recommendation=plan.recommendation, patch_diff=plan.patch_diff,
                    patch_ref=plan.patch_ref, verification_test=plan.verification_test,
                    generated_by=agent.name,
                ))
                f.status = FindingStatus.REMEDIATION_PROPOSED
                count += 1
            c.progress = {**(c.progress or {}), "remediation": "done",
                          "remediations": count}
            await self._audit(s, c.id, "remediation_generated", detail={"count": count})
            await s.commit()

    async def _retest(self, rs: RunState) -> None:
        # Load the findings + remediations to replay.
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            transition(c, CampaignState.RETEST)
            await s.commit()
            rows = (await s.execute(
                select(Finding, Remediation)
                .join(Remediation, Remediation.finding_id == Finding.id)
                .where(Finding.campaign_id == rs.campaign_id)
            )).all()
            work = [(f.id, f.ground_truth_id, r.id, r.patch_ref) for f, r in rows]

        verified = 0
        for finding_id, gt_id, rem_id, patch_ref in work:
            module = ATTACK_MODULES.get(gt_id)
            if module is None:
                continue
            patched = await self.lab.patched({patch_ref}, label=patch_ref)
            try:
                retest_policy = PolicyEngine(
                    rs.scope, max_requests=200, max_concurrency=4,
                    timeout_seconds=self.settings.tool_timeout_seconds,
                )
                tool = HttpTool(patched.base_url, retest_policy, patched.client)
                ctx = AttackContext(canary_token=rs.context.canary_token)
                target_out = None
                for pre in modules_in_order():
                    out = await pre.run(tool, ctx)
                    ctx.merge(out.extracted)
                    if pre.id == module.id:
                        target_out = out
                        break
            finally:
                pass
            after = target_out.outcome if target_out else TestOutcome.ERROR
            fixed = target_out is not None and not target_out.confirmed
            result = RetestResult.FIX_VERIFIED if fixed else RetestResult.FIX_FAILED

            async with self.db.session_factory() as s:
                c = await self._load_campaign(s, rs.campaign_id)
                store = EvidenceStore(s, c.id)
                after_ev_id = None
                if target_out:
                    for le in target_out.exchanges:
                        ev = await store.record_exchange(
                            le.exchange, summary=f"RETEST {module.id}: {le.label}",
                            kind="retest_exchange", finding_id=finding_id,
                        )
                        after_ev_id = ev.id
                s.add(Retest(
                    campaign_id=c.id, finding_id=finding_id, remediation_id=rem_id,
                    result=result, patched_base_url=patched.base_url,
                    before_outcome=TestOutcome.CONFIRMED, after_outcome=after,
                    detail=(target_out.detail if target_out else "retest error"),
                    after_evidence_id=after_ev_id,
                ))
                f = await s.get(Finding, finding_id)
                if f:
                    f.status = FindingStatus.FIX_VERIFIED if fixed else FindingStatus.FIX_FAILED
                if fixed:
                    verified += 1
                await self._audit(
                    s, c.id, "retest_completed", target=module.id, result=result.value,
                    detail={"finding": finding_id, "patch_ref": patch_ref,
                            "after_outcome": after.value},
                )
                await s.commit()
            await patched.aclose()

        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            c.progress = {**(c.progress or {}), "retest": "done",
                          "fixes_verified": verified, "fixes_attempted": len(work)}
            await s.commit()

    async def _finish(self, rs: RunState) -> None:
        async with self.db.session_factory() as s:
            c = await self._load_campaign(s, rs.campaign_id)
            transition(c, CampaignState.COMPLETE)
            c.progress = {**(c.progress or {}), "complete": True}
            c.requests_made = rs.policy.requests_made
            await self._audit(s, c.id, "campaign_complete",
                              detail={"requests_made": rs.policy.requests_made})
            await s.commit()


def _host_of(url: str) -> str:
    from urllib.parse import urlparse
    return (urlparse(url).hostname or "target").lower()


